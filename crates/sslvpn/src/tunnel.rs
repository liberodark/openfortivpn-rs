//! No specification: the FortiGate SSL VPN tunnel (PPP over TLS) as
//! openfortivpn drives it.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use ofv_net::{Dns, Routes, Tun};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio_util::sync::CancellationToken;

use crate::config::{Config, DnsSetup, MTU, Prompt, Routing};
use crate::portal::{Portal, VpnConfig};
use crate::ppp::{Action, Addresses, Ppp};
use crate::{Error, Result, saml};
use ofv_https::{Connector, TlsStream};

/// Every packet on the TLS connection starts with this: total length,
/// magic, payload length.
const FRAME_HEADER: usize = 6;
const FRAME_HEADER_LEN: u16 = 6;
const FRAME_MAGIC: [u8; 2] = [0x50, 0x50];
/// How long we wait for the gateway to acknowledge the end of the link.
const CLOSE_GRACE: Duration = Duration::from_secs(7);
/// How long the logout may take once the tunnel is closed.
const LOGOUT_GRACE: Duration = Duration::from_secs(10);

/// Why [`run`] returned without error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The tunnel was closed because the caller asked for it.
    Stopped,
    /// The tunnel went down (gateway closed it, PPP terminated...).
    Down,
}

/// Sets up the tunnel and keeps it up until `cancel` fires or it goes
/// down. Whatever happens, the host is put back as it was and the
/// session is logged out before returning.
pub async fn run(
    config: &Config,
    prompt: &impl Prompt,
    cancel: &CancellationToken,
) -> Result<Outcome> {
    config.validate_settings()?;
    let saml_session = match config.saml_port {
        Some(port) => match saml::wait_for_session(config, port, cancel).await? {
            Some(session) => Some(session),
            None => return Ok(Outcome::Stopped),
        },
        None => None,
    };
    let connector = Connector::new(&config.https)?;
    let mut portal = Portal::new(&connector, config);

    let setup = async {
        portal.log_in(prompt, saml_session.as_ref()).await?;
        tracing::info!("Authenticated.");
        portal.allocate().await?;
        tracing::info!("Remote gateway has allocated a VPN.");
        let vpn = portal.fetch_config().await?;
        let stream = portal.start_tunnel().await?;
        Ok::<_, Error>((vpn, stream))
    };
    let result = tokio::select! {
        result = setup => Some(result),
        () = cancel.cancelled() => None,
    };
    let outcome = match result {
        Some(Ok((vpn, stream))) => {
            let mut link = Link::new(config, vpn, stream);
            let outcome = link.run(cancel).await;
            link.teardown().await;
            tracing::info!("Closed connection to gateway.");
            outcome
        }
        Some(Err(error)) => Err(error),
        None => {
            tracing::info!("Interrupted while establishing the tunnel.");
            Ok(Outcome::Stopped)
        }
    };
    // Whatever happened, a session that was opened is closed: the gateway
    // would otherwise keep it (and its address) until it times out.
    if portal.cookie().is_some()
        && tokio::time::timeout(LOGOUT_GRACE, portal.log_out())
            .await
            .is_err()
    {
        tracing::info!("Could not log out (the gateway did not answer).");
    }
    outcome
}

/// The host side of an established link.
struct Host {
    tun: Tun,
    routes: Option<Routes>,
    dns: Option<Dns>,
}

/// The PPP link over the TLS connection.
struct Link<'a> {
    config: &'a Config,
    vpn: VpnConfig,
    /// Address the TLS connection goes to (the proxy, if any).
    gateway: Option<IpAddr>,
    reader: ReadHalf<TlsStream>,
    writer: WriteHalf<TlsStream>,
    /// Bytes received and not framed yet.
    inbox: Vec<u8>,
    ppp: Ppp,
    host: Option<Host>,
}

impl<'a> Link<'a> {
    fn new(config: &'a Config, vpn: VpnConfig, stream: TlsStream) -> Self {
        let gateway = stream
            .get_ref()
            .0
            .peer_addr()
            .ok()
            .map(|address| address.ip());
        let (reader, writer) = tokio::io::split(stream);
        Self {
            config,
            vpn,
            gateway,
            reader,
            writer,
            inbox: Vec::with_capacity(65536),
            ppp: Ppp::new(MTU, config.peer_dns),
            host: None,
        }
    }

    /// Negotiates PPP and pumps packets until the link ends.
    async fn run(&mut self, cancel: &CancellationToken) -> Result<Outcome> {
        tracing::debug!("starting the PPP negotiation");
        let actions = self.ppp.open(Instant::now());
        if let Some(outcome) = self.perform(actions).await? {
            return Ok(outcome);
        }
        let mut chunk = vec![0u8; 16384];
        let mut packet = vec![0u8; 65536];
        loop {
            let deadline = self.ppp.next_timeout();
            let actions = tokio::select! {
                read = self.reader.read(&mut chunk) => {
                    let read = read?;
                    if read == 0 {
                        tracing::warn!("The gateway closed the connection.");
                        return Ok(Outcome::Down);
                    }
                    self.inbox.extend_from_slice(&chunk[..read]);
                    self.unframe()?
                }
                received = recv_tun(self.host.as_ref(), &mut packet) => {
                    let received = received.map_err(ofv_net::Error::Tun)?;
                    tracing::trace!("tun ---> gateway ({received} bytes)");
                    self.send(&Ppp::encode_ip(&packet[..received])).await?;
                    Vec::new()
                }
                () = sleep_until(deadline) => self.ppp.timeout(Instant::now()),
                () = cancel.cancelled() => {
                    tracing::info!("Closing the tunnel...");
                    return Ok(Outcome::Stopped);
                }
            };
            if let Some(outcome) = self.perform(actions).await? {
                return Ok(outcome);
            }
        }
    }

    /// Feeds the framed packets of the inbox to PPP.
    fn unframe(&mut self) -> Result<Vec<Action>> {
        let mut actions = Vec::new();
        let now = Instant::now();
        loop {
            let Some(header) = self.inbox.first_chunk::<FRAME_HEADER>() else {
                return Ok(actions);
            };
            if self.inbox.starts_with(b"HTTP/1") {
                tracing::error!(
                    "Could not authenticate to the gateway. Please make sure tunnel mode is allowed by the gateway, check the realm, etc."
                );
                return Err(Error::Ppp("the gateway answered with HTTP".into()));
            }
            let total = usize::from(u16::from_be_bytes([header[0], header[1]]));
            let length = usize::from(u16::from_be_bytes([header[4], header[5]]));
            if header[2..4] != FRAME_MAGIC
                || total < FRAME_HEADER + 1
                || total - FRAME_HEADER != length
            {
                tracing::error!("Received bad header from gateway: {:02x?}", header);
                return Err(Error::Ppp("bad packet header".into()));
            }
            if self.inbox.len() < total {
                return Ok(actions);
            }
            let packet: Vec<u8> = self.inbox.drain(..total).skip(FRAME_HEADER).collect();
            tracing::trace!("gateway ---> ppp ({} bytes)", packet.len());
            actions.extend(self.ppp.input(&packet, now));
        }
    }

    async fn send(&mut self, packet: &[u8]) -> Result<()> {
        let length = u16::try_from(packet.len())
            .ok()
            .and_then(|length| length.checked_add(FRAME_HEADER_LEN))
            .ok_or_else(|| Error::Ppp("packet too long".into()))?;
        let mut frame = Vec::with_capacity(packet.len() + FRAME_HEADER);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&FRAME_MAGIC);
        frame.extend_from_slice(&(length - FRAME_HEADER_LEN).to_be_bytes());
        frame.extend_from_slice(packet);
        self.writer.write_all(&frame).await?;
        self.writer.flush().await?;
        Ok(())
    }

    /// Carries out what PPP asked for; the outcome once the link ended.
    async fn perform(&mut self, actions: Vec<Action>) -> Result<Option<Outcome>> {
        for action in actions {
            match action {
                Action::Send(packet) => self.send(&packet).await?,
                Action::Deliver(packet) => {
                    if let Some(host) = &self.host {
                        tracing::trace!("gateway ---> tun ({} bytes)", packet.len());
                        if let Err(error) = host.tun.send(&packet).await {
                            tracing::debug!("could not write to the TUN device: {error}");
                        }
                    }
                }
                Action::Up(addresses) => self.bring_up(addresses).await?,
                Action::Down(reason) => {
                    tracing::info!("PPP link down: {reason}.");
                    return Ok(Some(Outcome::Down));
                }
            }
        }
        Ok(None)
    }

    /// IPCP is open: creates the interface, the routes and the DNS
    /// configuration.
    async fn bring_up(&mut self, addresses: Addresses) -> Result<()> {
        let config = self.config;
        // The nameservers negotiated over IPCP, when asked for, take
        // precedence over those of the XML configuration.
        let servers = if addresses.dns.is_empty() {
            &self.vpn.dns
        } else {
            &addresses.dns
        };
        tracing::info!(
            "Got addresses: [{}], ns [{}], ns_suffix [{}]",
            addresses.local,
            servers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            self.vpn.domains.join(" ")
        );
        tracing::info!("Negotiation complete.");
        let tun = Tun::create(
            config.tun_name.as_deref(),
            addresses.local,
            Some(addresses.peer),
            addresses.mtu,
        )?;
        tracing::info!("Interface {} is UP.", tun.name());
        let mut host = Host {
            tun,
            routes: None,
            dns: None,
        };
        if config.routing != Routing::Off {
            tracing::info!("Setting new routes...");
            host.routes = Some(self.set_routes(host.tun.name()).await);
        }
        if config.dns != DnsSetup::Off {
            if servers.is_empty() && self.vpn.domains.is_empty() {
                tracing::info!("No VPN nameservers to add.");
            } else {
                tracing::info!("Adding VPN nameservers...");
                match Dns::install(
                    host.tun.name(),
                    servers,
                    &self.vpn.domains,
                    if config.dns == DnsSetup::File {
                        ofv_net::DnsTool::File
                    } else {
                        ofv_net::DnsTool::Auto
                    },
                )
                .await
                {
                    Ok(dns) => host.dns = Some(dns),
                    Err(error) => tracing::warn!("Could not add the VPN nameservers ({error})."),
                }
            }
        }
        self.host = Some(host);
        tracing::info!("Tunnel is up and running.");
        sd_notify::notify(false, &[sd_notify::NotifyState::Ready]).ok();
        Ok(())
    }

    /// The gateway's split routes, or everything, through the interface.
    async fn set_routes(&self, interface: &str) -> Routes {
        let mut routes = Routes::new(interface);
        let gateway = match self.gateway {
            Some(IpAddr::V4(address)) => Some(address),
            _ => None,
        };
        let protected = match gateway {
            Some(gateway) => routes.protect_gateway(gateway).await,
            None => Ok(()),
        };
        let result = if self.vpn.routes.is_empty() {
            match protected {
                // Everything into the tunnel, except the tunnel itself.
                Ok(()) => {
                    routes
                        .set_default(self.config.routing == Routing::HalfInternet)
                        .await
                }
                Err(error) => {
                    tracing::warn!(
                        "Not setting the default route: the route to the gateway could not be protected ({error})."
                    );
                    Ok(())
                }
            }
        } else {
            if let Err(error) = protected {
                tracing::warn!("Could not protect the route to the gateway ({error}).");
            }
            let mut result = Ok(());
            for &(address, prefix) in &self.vpn.routes {
                if Some(address) == gateway {
                    tracing::debug!("skipping the route to the tunnel gateway {address}/{prefix}");
                    continue;
                }
                if let Err(error) = routes.add(address, prefix).await {
                    tracing::warn!("Could not add route {address}/{prefix} ({error}).");
                    result = Err(error);
                }
            }
            result
        };
        if let Err(error) = result {
            tracing::warn!("Adding route table is incomplete ({error}). Please check route table.");
        }
        routes
    }

    /// Puts the host back, closes the PPP link and the connection.
    async fn teardown(&mut self) {
        if let Some(mut host) = self.host.take() {
            sd_notify::notify(false, &[sd_notify::NotifyState::Stopping]).ok();
            tracing::info!("Setting {} interface down.", host.tun.name());
            if let Some(mut dns) = host.dns.take() {
                tracing::info!("Removing VPN nameservers...");
                dns.remove().await;
            }
            if let Some(mut routes) = host.routes.take() {
                tracing::info!("Restoring routes...");
                routes.restore().await;
            }
            drop(host);
        }
        if let Err(error) = self.close_ppp().await {
            tracing::debug!("could not close the PPP link cleanly: {error}");
        }
        if let Err(error) = self.writer.shutdown().await {
            tracing::debug!("could not shut the TLS connection down: {error}");
        }
    }

    /// Sends the Terminate-Request, unless the link is already finished,
    /// and waits for the gateway's answer.
    async fn close_ppp(&mut self) -> Result<()> {
        let actions = self.ppp.close(Instant::now());
        self.perform(actions).await?;
        if !self.ppp.is_closing() {
            return Ok(());
        }
        let mut chunk = vec![0u8; 16384];
        let closing = async {
            loop {
                let deadline = self.ppp.next_timeout();
                let actions = tokio::select! {
                    read = self.reader.read(&mut chunk) => {
                        let read = read?;
                        if read == 0 {
                            return Ok(());
                        }
                        self.inbox.extend_from_slice(&chunk[..read]);
                        self.unframe()?
                    }
                    () = sleep_until(deadline) => self.ppp.timeout(Instant::now()),
                };
                self.perform(actions).await?;
                if !self.ppp.is_closing() {
                    return Ok(());
                }
            }
        };
        match tokio::time::timeout(CLOSE_GRACE, closing).await {
            Ok(result) => result,
            Err(_) => Err(Error::Ppp("no Terminate-Ack from the gateway".into())),
        }
    }
}

/// Reads one packet from the TUN device; pends forever without one.
async fn recv_tun(host: Option<&Host>, buffer: &mut [u8]) -> std::io::Result<usize> {
    match host {
        Some(host) => host.tun.recv(buffer).await,
        None => std::future::pending().await,
    }
}

/// Sleeps until `deadline`; forever without one.
async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
        None => std::future::pending().await,
    }
}
