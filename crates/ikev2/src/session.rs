//! RFC 7296 (retransmissions, INFORMATIONAL, rekeys initiated by the peer), RFC
//! 3948 (ESP in UDP, keepalives).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use ofv_net::{Dns, Routes, Tun};
use rand_core::{OsRng, RngCore};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::auth::GatewayVerifier;
use crate::child::ChildSa;
use crate::config::Config;
use crate::crypto::{Group, HashAlgorithm, KeyExchange, PrivateKey};
use crate::forticlient;
use crate::message::payload::{
    self, Delete, Identity, Notify, RawPayload, TrafficSelector, notify,
};
use crate::message::proposal::{Proposal, Protocol};
use crate::message::{Exchange, Header, Message, Packet, Reassembler, types};
use crate::proposals::{EspAlgorithms, IkeAlgorithms, esp_proposals, ike_proposals};
use crate::rekey::CHILD_LIFETIME;
use crate::sa::IkeKeys;
use crate::{Error, Result};

/// IKE port, for the first exchange.
pub const IKE_PORT: u16 = 500;
/// NAT traversal port, for everything else.
pub const NAT_PORT: u16 = 4500;
/// The non-ESP marker in front of IKE messages on the NAT port.
const NON_ESP_MARKER: [u8; 4] = [0; 4];
/// Largest datagram we send when the gateway supports fragmentation.
const FRAGMENT_LEN: usize = 1280;
/// Our retransmission schedule: doubling delays, then giving up.
const FIRST_RETRANSMIT: Duration = Duration::from_secs(1);
const RETRANSMITS: u32 = 5;
/// NAT keepalive interval (RFC 3948 section 4).
const KEEPALIVE: Duration = Duration::from_secs(20);
/// MTU of the tunnel interface: room for IP, UDP and ESP overhead.
pub const MTU: u16 = 1400;

/// The tunnel interface with its routes and DNS settings.
pub struct Host {
    pub tun: Tun,
    pub routes: Option<Routes>,
    pub dns: Option<Dns>,
}

/// What the gateway assigned through the configuration payload.
#[derive(Debug, Default, Clone)]
pub struct Assigned {
    pub address: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub subnets: Vec<(Ipv4Addr, u8)>,
    pub domains: Vec<String>,
}

/// Something received from the gateway.
pub enum Inbound {
    Ike(Packet),
    Esp(Vec<u8>),
}

/// A request of the gateway, decrypted.
pub struct PeerRequest {
    pub header: Header,
    pub payloads: Vec<RawPayload>,
}

/// The gateway's response to a request of ours.
pub struct Reply {
    pub header: Header,
    pub payloads: Vec<RawPayload>,
    /// The datagram of the response (of its last fragment).
    pub raw: Vec<u8>,
}

impl Reply {
    /// The first payload of a kind.
    pub fn payload(&self, kind: u8) -> Option<&RawPayload> {
        payload::find(&self.payloads, kind)
    }

    pub fn notifies(&self) -> impl Iterator<Item = Notify> + '_ {
        self.payloads
            .iter()
            .filter(|payload| payload.kind == types::NOTIFY)
            .filter_map(|payload| Notify::decode(&payload.data).ok())
    }

    /// The first error notification, as an error.
    pub fn check(&self) -> Result<()> {
        match self.notifies().find(|notify| notify::is_error(notify.kind)) {
            Some(error) => Err(Error::Notify(notify::name(error.kind))),
            None => Ok(()),
        }
    }
}

/// Why the session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// The caller asked for it.
    Stopped,
    /// The gateway closed it or stopped answering.
    Down,
}

/// How far the session got: IKE_SA_INIT on the IKE port, IKE_AUTH on
/// the NAT traversal port, then established. The gateway has an IKE SA
/// to delete only once established; before that it has at most a
/// half-open one, which it discards itself when the authentication
/// fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Init,
    Auth,
    Established,
}

/// The IKE SA with everything around it.
pub struct Session<'a> {
    pub config: &'a Config,
    pub gateway: Ipv4Addr,
    socket_ike: UdpSocket,
    socket_nat: UdpSocket,
    pub stage: Stage,
    pub local_address: Ipv4Addr,
    /// Whether we initiated the current IKE SA (the gateway did, after
    /// rekeying it): the SPI order and the initiator flag follow.
    initiator: bool,
    pub spi_i: u64,
    pub spi_r: u64,
    pub keys: Option<IkeKeys>,
    pub ike_algorithms: Vec<IkeAlgorithms>,
    pub esp_algorithms: Vec<EspAlgorithms>,
    pub message_id: u32,
    pub peer_message_id: u32,
    last_response: Option<(u32, Vec<Vec<u8>>)>,
    pub peer_fragments: bool,
    pub peer_hash_algorithms: Vec<HashAlgorithm>,
    reassembler: Reassembler,
    /// The datagram of our last request, for the AUTH octets.
    pub last_request: Vec<u8>,
    pub init_request: Vec<u8>,
    pub init_response: Vec<u8>,
    pub nonce_i: Vec<u8>,
    pub nonce_r: Vec<u8>,
    pub children: Vec<ChildSa>,
    pub host: Option<Host>,
    pub assigned: Assigned,
    pub verifier: Option<GatewayVerifier>,
    pub private_key: Option<PrivateKey>,
    pub certificates: Vec<Vec<u8>>,
    /// What we tell the gateway about ourselves in IKE_AUTH, as
    /// FortiClient does (for its SAML login).
    pub forticlient: Option<forticlient::Device>,
    last_received: Instant,
    last_sent: Instant,
    /// The gateway asked to close the session, or stopped answering.
    pub down: Option<String>,
    /// An IKE SA rekeyed by the gateway, taking over once it deletes
    /// the old one.
    pub next_ike: Option<NextIke>,
}

/// The keys of a rekeyed IKE SA, until it takes over.
pub struct NextIke {
    pub spi_i: u64,
    pub spi_r: u64,
    pub keys: IkeKeys,
}

/// Whether an error means the gateway is not answering, so that there
/// is no point in telling it anything more.
pub fn gateway_gone(error: &Error) -> bool {
    matches!(error, Error::Timeout(_))
}

/// Datagrams that fail to parse or to authenticate are dropped, as RFC
/// 7296 section 2.1 wants; anything else is a real failure.
fn drop_or_fail(error: Error) -> Result<()> {
    match error {
        Error::Malformed(what) | Error::Crypto(what) => {
            tracing::debug!("ignoring a bad datagram: {what}");
            Ok(())
        }
        other => Err(other),
    }
}

pub fn random_spi() -> u64 {
    loop {
        let spi = OsRng.next_u64();
        if spi != 0 {
            return spi;
        }
    }
}

/// A fresh nonce (RFC 7296: at least 128 bits, at most 256).
pub fn nonce() -> Vec<u8> {
    let mut nonce = vec![0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

async fn bind(port: u16) -> Result<UdpSocket> {
    let socket = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).await {
        Ok(socket) => socket,
        Err(error) => {
            tracing::debug!("cannot bind UDP port {port} ({error}), using any port");
            UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?
        }
    };
    Ok(socket)
}

impl<'a> Session<'a> {
    /// Resolves the gateway and opens the sockets.
    pub async fn connect(config: &'a Config) -> Result<Session<'a>> {
        let what = format!("{}:{}", config.gateway, config.port);
        let connect_error = |source| Error::Connect {
            what: what.clone(),
            source,
        };
        let gateway = tokio::net::lookup_host((config.gateway.as_str(), config.port))
            .await
            .map_err(connect_error)?
            .find_map(|address| match address.ip() {
                IpAddr::V4(address) => Some(address),
                IpAddr::V6(_) => None,
            })
            .ok_or_else(|| {
                connect_error(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no IPv4 address for the gateway",
                ))
            })?;
        let socket_ike = bind(IKE_PORT).await?;
        socket_ike
            .connect(SocketAddr::from((gateway, config.port)))
            .await
            .map_err(connect_error)?;
        let socket_nat = bind(NAT_PORT).await?;
        socket_nat
            .connect(SocketAddr::from((gateway, NAT_PORT)))
            .await
            .map_err(connect_error)?;
        let local_address = match socket_ike.local_addr()?.ip() {
            IpAddr::V4(address) => address,
            IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
        };
        tracing::debug!(
            "gateway {gateway}:{} from {local_address}, NAT port {}",
            config.port,
            socket_nat.local_addr()?.port()
        );
        Ok(Session {
            config,
            gateway,
            socket_ike,
            socket_nat,
            stage: Stage::Init,
            local_address,
            initiator: true,
            spi_i: random_spi(),
            spi_r: 0,
            keys: None,
            ike_algorithms: Vec::new(),
            esp_algorithms: Vec::new(),
            message_id: 0,
            peer_message_id: 0,
            last_response: None,
            peer_fragments: false,
            peer_hash_algorithms: Vec::new(),
            reassembler: Reassembler::default(),
            last_request: Vec::new(),
            init_request: Vec::new(),
            init_response: Vec::new(),
            nonce_i: Vec::new(),
            nonce_r: Vec::new(),
            children: Vec::new(),
            host: None,
            assigned: Assigned::default(),
            verifier: None,
            private_key: None,
            certificates: Vec::new(),
            forticlient: None,
            last_received: Instant::now(),
            last_sent: Instant::now(),
            down: None,
            next_ike: None,
        })
    }

    /// Whether we talk on the NAT traversal port, with UDP encapsulation:
    /// from IKE_AUTH on, or from the start when configured so.
    fn nat(&self) -> bool {
        self.stage != Stage::Init || self.config.port == NAT_PORT
    }

    /// Our identity: the configured one, else our certificate's subject,
    /// else our address.
    pub fn local_identity(&self) -> Identity {
        if let Some(id) = &self.config.local_id {
            return Identity::parse(id);
        }
        if let Some(subject) = self
            .certificates
            .first()
            .and_then(|der| X509Certificate::from_der(der).ok())
            .map(|(_, cert)| cert.subject().as_raw().to_vec())
        {
            return Identity {
                kind: payload::id_types::DER_ASN1_DN,
                data: subject,
            };
        }
        Identity {
            kind: payload::id_types::IPV4_ADDR,
            data: self.local_address.octets().to_vec(),
        }
    }

    // --- transport ------------------------------------------------------

    async fn send_datagram(&mut self, bytes: &[u8]) -> Result<()> {
        self.last_sent = Instant::now();
        if self.nat() {
            let mut framed = Vec::with_capacity(bytes.len() + 4);
            framed.extend_from_slice(&NON_ESP_MARKER);
            framed.extend_from_slice(bytes);
            self.socket_nat.send(&framed).await?;
        } else {
            self.socket_ike.send(bytes).await?;
        }
        Ok(())
    }

    async fn send_esp(&mut self, esp: &[u8]) -> Result<()> {
        self.last_sent = Instant::now();
        self.socket_nat.send(esp).await?;
        Ok(())
    }

    /// Sends the NAT keepalive byte.
    async fn keepalive(&mut self) -> Result<()> {
        self.last_sent = Instant::now();
        self.socket_nat.send(&[0xff]).await?;
        Ok(())
    }

    async fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.nat() {
            self.socket_nat.recv(buffer).await
        } else {
            self.socket_ike.recv(buffer).await
        }
    }

    /// What a datagram from the gateway is.
    fn inbound(&mut self, datagram: &[u8]) -> Result<Option<Inbound>> {
        self.last_received = Instant::now();
        if !self.nat() {
            return Ok(Some(Inbound::Ike(Packet::parse(datagram)?)));
        }
        if datagram.len() == 1 {
            return Ok(None); // keepalive
        }
        if let Some(ike) = datagram.strip_prefix(&NON_ESP_MARKER) {
            return Ok(Some(Inbound::Ike(Packet::parse(ike)?)));
        }
        Ok(Some(Inbound::Esp(datagram.to_vec())))
    }

    /// Encodes a message: in the clear for IKE_SA_INIT, encrypted otherwise.
    fn encode(&self, message: &Message) -> Result<Vec<Vec<u8>>> {
        match &self.keys {
            None => Ok(vec![message.encode_plain()?]),
            Some(keys) => message
                .encode_encrypted(&keys.outbound, self.peer_fragments.then_some(FRAGMENT_LEN)),
        }
    }

    /// A request message with the next identifier.
    pub fn new_request(&self, exchange: Exchange) -> Message {
        Message {
            from_initiator: self.initiator,
            ..Message::request(exchange, self.message_id, self.spi_i, self.spi_r)
        }
    }

    /// Our response to the gateway's request `id`.
    fn new_response(&self, exchange: Exchange, id: u32) -> Message {
        Message {
            from_initiator: self.initiator,
            ..Message::response(exchange, id, self.spi_i, self.spi_r)
        }
    }

    /// Whether the tunnel interface is up.
    pub fn is_up(&self) -> bool {
        self.host.is_some()
    }

    // --- our requests ---------------------------------------------------

    /// Sends a request and waits for its response, retransmitting on the
    /// way; the gateway's own requests and the tunnel traffic are handled
    /// meanwhile.
    pub async fn request(&mut self, message: Message, cancel: &CancellationToken) -> Result<Reply> {
        let id = message.id;
        let datagrams = self.encode(&message)?;
        self.last_request.clone_from(&datagrams[0]);
        self.message_id = id.wrapping_add(1);
        let mut delay = FIRST_RETRANSMIT;
        let mut buffer = vec![0u8; 65536];
        let mut tun_buffer = vec![0u8; 65536];
        for attempt in 1..=RETRANSMITS {
            if attempt > 1 {
                tracing::debug!("retransmitting message {id} (attempt {attempt})");
            }
            for datagram in &datagrams {
                self.send_datagram(datagram).await?;
            }
            let deadline = tokio::time::Instant::now() + delay;
            loop {
                let read = tokio::select! {
                    read = self.recv(&mut buffer) => read?,
                    received = recv_tun(self.host.as_ref(), &mut tun_buffer) => {
                        let received = received.map_err(ofv_net::Error::Tun)?;
                        self.on_tun_packet(&tun_buffer[..received]).await?;
                        continue;
                    }
                    () = tokio::time::sleep_until(deadline) => break,
                    () = cancel.cancelled() => return Err(Error::Interrupted),
                };
                let inbound = match self.inbound(&buffer[..read]) {
                    Ok(Some(inbound)) => inbound,
                    Ok(None) => continue,
                    Err(error) => {
                        drop_or_fail(error)?;
                        continue;
                    }
                };
                match inbound {
                    Inbound::Esp(esp) => self.on_esp(&esp).await,
                    Inbound::Ike(packet) => {
                        if packet.header.is_response && packet.header.message_id == id {
                            match self.open_response(&packet) {
                                Ok(Some(payloads)) => {
                                    return Ok(Reply {
                                        header: packet.header,
                                        payloads,
                                        raw: packet.raw().to_vec(),
                                    });
                                }
                                Ok(None) => {}
                                Err(error) => drop_or_fail(error)?,
                            }
                        } else {
                            self.handle_packet(packet).await?;
                        }
                    }
                }
                if let Some(reason) = &self.down {
                    return Err(Error::Down(reason.clone()));
                }
            }
            delay *= 2;
        }
        Err(Error::Timeout(format!(
            "no response to message {id} after {RETRANSMITS} attempts"
        )))
    }

    /// The payloads of a response to us: checked, decrypted, reassembled.
    fn open_response(&mut self, packet: &Packet) -> Result<Option<Vec<RawPayload>>> {
        // The IKE_SA_INIT response brings the responder's SPI.
        if packet.header.initiator_spi != self.spi_i
            || (self.spi_r != 0 && packet.header.responder_spi != self.spi_r)
        {
            return Err(Error::Malformed("response for another IKE SA".into()));
        }
        let (Some(keys), true) = (&self.keys, packet.is_encrypted()) else {
            if self.keys.is_none() && !packet.is_encrypted() {
                return Ok(Some(packet.payloads.clone()));
            }
            // An unprotected message once the SA has keys means nothing
            // (RFC 7296 section 2.21.2), nor does a protected one before.
            return Err(Error::Malformed(
                "response with the wrong protection".into(),
            ));
        };
        let decrypted = packet.decrypt(&keys.inbound)?;
        if decrypted.fragment.is_some() {
            return match self.reassembler.add(packet.header.message_id, decrypted)? {
                Some(whole) => Ok(Some(whole.payloads()?)),
                None => Ok(None),
            };
        }
        Ok(Some(decrypted.payloads()?))
    }

    // --- the gateway's requests and the tunnel traffic ------------------

    /// Handles a packet that is not the response we wait for: a request
    /// of the gateway, or noise, which is dropped. Sets `down` when the
    /// gateway ends the session.
    pub async fn handle_packet(&mut self, packet: Packet) -> Result<()> {
        if packet.header.is_response {
            tracing::debug!(
                "ignoring a stray response (message {})",
                packet.header.message_id
            );
            return Ok(());
        }
        if (packet.header.initiator_spi, packet.header.responder_spi) != (self.spi_i, self.spi_r) {
            tracing::debug!("ignoring a request for another IKE SA");
            return Ok(());
        }
        let id = packet.header.message_id;
        if id == self.peer_message_id.wrapping_sub(1) {
            // A retransmission, if it is one: resend our response.
            let datagrams = self
                .last_response
                .as_ref()
                .filter(|(last_id, _)| *last_id == id)
                .map(|(_, datagrams)| datagrams.clone());
            if let Some(datagrams) = datagrams
                && self.open_request(&packet).is_ok()
            {
                tracing::debug!("resending our response to message {id}");
                for datagram in datagrams {
                    self.send_datagram(&datagram).await?;
                }
            }
            return Ok(());
        }
        if id != self.peer_message_id {
            tracing::debug!("ignoring request {id}, expected {}", self.peer_message_id);
            return Ok(());
        }
        let request = match self.open_request(&packet) {
            Ok(Some(request)) => request,
            Ok(None) => return Ok(()),
            Err(error) => return drop_or_fail(error),
        };
        self.peer_message_id = self.peer_message_id.wrapping_add(1);
        match request.header.exchange {
            Exchange::Informational => self.on_informational(&request).await,
            Exchange::CreateChildSa => match self.on_create_child_sa(&request).await {
                // A request we cannot make sense of is refused, not fatal.
                Err(Error::Malformed(what) | Error::Crypto(what)) => {
                    tracing::debug!("bad CREATE_CHILD_SA request: {what}");
                    self.refuse(id, notify::INVALID_SYNTAX).await
                }
                result => result,
            },
            other => {
                tracing::debug!("unexpected {other:?} request from the gateway");
                let mut response = self.new_response(other, id);
                response.push(
                    types::NOTIFY,
                    Notify::new(notify::INVALID_SYNTAX, Vec::new()).encode(),
                );
                self.respond(response).await
            }
        }
    }

    /// Decrypts a request of the gateway; `None` for a fragment that does
    /// not complete a message yet.
    fn open_request(&mut self, packet: &Packet) -> Result<Option<PeerRequest>> {
        let keys = self
            .keys
            .as_ref()
            .ok_or_else(|| Error::Malformed("request before the keys".into()))?;
        if !packet.is_encrypted() {
            return Err(Error::Malformed(
                "unencrypted request from the gateway".into(),
            ));
        }
        let decrypted = packet.decrypt(&keys.inbound)?;
        let decrypted = if decrypted.fragment.is_some() {
            match self.reassembler.add(packet.header.message_id, decrypted)? {
                Some(whole) => whole,
                None => return Ok(None),
            }
        } else {
            decrypted
        };
        Ok(Some(PeerRequest {
            header: packet.header,
            payloads: decrypted.payloads()?,
        }))
    }

    /// Sends our response to a request of the gateway.
    pub async fn respond(&mut self, message: Message) -> Result<()> {
        let datagrams = self.encode(&message)?;
        for datagram in &datagrams {
            self.send_datagram(datagram).await?;
        }
        self.last_response = Some((message.id, datagrams));
        Ok(())
    }

    /// An INFORMATIONAL request: dead peer detection, or a DELETE.
    async fn on_informational(&mut self, request: &PeerRequest) -> Result<()> {
        let id = request.header.message_id;
        let mut response = self.new_response(Exchange::Informational, id);
        let mut ended = None;
        for payload in &request.payloads {
            match payload.kind {
                types::DELETE => {
                    let Ok(delete) = Delete::decode(&payload.data) else {
                        tracing::debug!("ignoring a bad DELETE payload");
                        continue;
                    };
                    if delete.protocol == 1 {
                        tracing::info!("The gateway closed the IKE SA.");
                        ended = Some("the gateway closed the tunnel".to_owned());
                    } else {
                        let mut ours = Vec::new();
                        for spi in &delete.spis {
                            let spi =
                                <[u8; 4]>::try_from(spi.as_slice()).map_or(0, u32::from_be_bytes);
                            if let Some(index) =
                                self.children.iter().position(|child| child.spi_out == spi)
                            {
                                let child = self.children.remove(index);
                                tracing::info!("The gateway deleted CHILD_SA {}.", child.summary());
                                ours.push(child.spi_in.to_be_bytes().to_vec());
                            }
                        }
                        if !ours.is_empty() {
                            response.push(
                                types::DELETE,
                                Delete {
                                    protocol: 3,
                                    spis: ours,
                                }
                                .encode(),
                            );
                        }
                        if self.children.is_empty() && self.is_up() {
                            ended = Some("the gateway deleted the CHILD_SA".to_owned());
                        }
                    }
                }
                types::NOTIFY => match Notify::decode(&payload.data) {
                    Ok(notify) if notify::is_error(notify.kind) => {
                        tracing::warn!("The gateway reports {}.", notify::name(notify.kind));
                    }
                    Ok(notify) => tracing::debug!("notification {} from the gateway", notify.kind),
                    Err(_) => tracing::debug!("ignoring a bad NOTIFY payload"),
                },
                other => tracing::debug!("ignoring payload {other} in an INFORMATIONAL request"),
            }
        }
        if request.payloads.is_empty() {
            tracing::debug!("answering a dead peer detection request");
        }
        self.respond(response).await?;
        match (ended, self.next_ike.take()) {
            (Some(_), Some(next)) => {
                // The old IKE SA is gone: the rekeyed one takes over.
                self.switch_ike(next);
                tracing::info!("Switched to the rekeyed IKE SA.");
            }
            (Some(reason), None) => self.down = Some(reason),
            (None, next) => self.next_ike = next,
        }
        Ok(())
    }

    /// Makes an IKE SA the gateway rekeyed the current one: it is the
    /// initiator of that one.
    pub fn switch_ike(&mut self, next: NextIke) {
        self.initiator = false;
        self.spi_i = next.spi_i;
        self.spi_r = next.spi_r;
        self.keys = Some(next.keys);
        self.message_id = 0;
        self.peer_message_id = 0;
        self.last_response = None;
        self.reassembler = Reassembler::default();
    }

    /// A CREATE_CHILD_SA request of the gateway: a rekey of the IKE SA or
    /// of a CHILD SA.
    async fn on_create_child_sa(&mut self, request: &PeerRequest) -> Result<()> {
        let id = request.header.message_id;
        let find = |kind: u8| request.payloads.iter().find(|payload| payload.kind == kind);
        let (Some(sa), Some(nonce_payload)) = (find(types::SA), find(types::NONCE)) else {
            tracing::debug!("CREATE_CHILD_SA without an SA or nonce payload");
            return self.refuse(id, notify::INVALID_SYNTAX).await;
        };
        let proposals = payload::decode_sa(&sa.data)?;
        let peer_nonce = nonce_payload.data.clone();
        let ke = find(types::KE)
            .map(|payload| payload::decode_ke(&payload.data))
            .transpose()?
            .map(|(group, public)| (group, public.to_vec()));
        if proposals
            .first()
            .is_some_and(|proposal| proposal.protocol == Protocol::Ike)
        {
            return self.on_ike_rekey(id, &proposals, &peer_nonce, ke).await;
        }
        let rekeyed = request
            .payloads
            .iter()
            .filter(|payload| payload.kind == types::NOTIFY)
            .filter_map(|payload| Notify::decode(&payload.data).ok())
            .find(|notify| notify.kind == notify::REKEY_SA)
            .and_then(|notify| <[u8; 4]>::try_from(notify.spi.as_slice()).ok())
            .map(u32::from_be_bytes);
        let Some(old_spi) = rekeyed else {
            tracing::debug!("the gateway asked for an additional CHILD_SA; refusing");
            return self.refuse(id, notify::NO_ADDITIONAL_SAS).await;
        };
        let selectors = payload::selectors(&request.payloads)?;
        self.on_child_rekey(id, old_spi, &proposals, &peer_nonce, ke, selectors)
            .await
    }

    /// Refuses a CREATE_CHILD_SA request with an error notification.
    async fn refuse(&mut self, id: u32, kind: u16) -> Result<()> {
        self.refuse_with(id, Notify::new(kind, Vec::new())).await
    }

    async fn refuse_with(&mut self, id: u32, notify: Notify) -> Result<()> {
        let mut response = self.new_response(Exchange::CreateChildSa, id);
        response.push(types::NOTIFY, notify.encode());
        self.respond(response).await
    }

    /// The gateway rekeys the IKE SA: the new keys are kept aside until
    /// it deletes the old one.
    async fn on_ike_rekey(
        &mut self,
        id: u32,
        proposals: &[Proposal],
        peer_nonce: &[u8],
        ke: Option<(u16, Vec<u8>)>,
    ) -> Result<()> {
        let Some((group, peer_public)) = ke else {
            return self.refuse(id, notify::INVALID_SYNTAX).await;
        };
        let select = |group| {
            proposals.iter().find_map(|proposal| {
                crate::proposals::select_ike(proposal, &self.ike_algorithms, group)
                    .ok()
                    .map(|algorithms| (proposal, algorithms))
            })
        };
        let selected = Group::from_id(group).and_then(|group| select(Some(group)));
        let Some((chosen, algorithms)) = selected else {
            // Acceptable with another group: ask for it (RFC 7296 1.3.2).
            if let Some((_, other)) = select(None) {
                let wanted = other.group.id().to_be_bytes().to_vec();
                return self
                    .refuse_with(id, Notify::new(notify::INVALID_KE_PAYLOAD, wanted))
                    .await;
            }
            tracing::warn!("The gateway proposed no acceptable algorithms to rekey the IKE SA.");
            return self.refuse(id, notify::NO_PROPOSAL_CHOSEN).await;
        };
        let number = chosen.number;
        let exchange = KeyExchange::generate(algorithms.group);
        let shared = exchange.shared(&peer_public)?;
        let new_spi_i = <[u8; 8]>::try_from(chosen.spi.as_slice())
            .map(u64::from_be_bytes)
            .map_err(|_| Error::Malformed("IKE rekey without an 8-byte SPI".into()))?;
        let new_spi_r = random_spi();
        let our_nonce = nonce();
        let old_keys = self.keys.as_ref().expect("keys");
        // The gateway is the initiator of this exchange: its nonce and
        // SPI come first, and its keys are the initiator's ones.
        let keys = swap_roles(IkeKeys::derive(
            algorithms,
            new_spi_i,
            new_spi_r,
            peer_nonce,
            &our_nonce,
            &shared,
            Some(&old_keys.sk_d),
        ));
        let mut answer = ike_proposals(&[algorithms]).remove(0);
        answer.number = number;
        answer.spi = new_spi_r.to_be_bytes().to_vec();
        let mut response = self.new_response(Exchange::CreateChildSa, id);
        response.push(types::SA, payload::encode_sa(&[answer])?);
        response.push(types::NONCE, our_nonce);
        response.push(types::KE, payload::encode_ke(group, exchange.public()));
        self.respond(response).await?;
        tracing::info!("The gateway rekeyed the IKE SA.");
        self.next_ike = Some(NextIke {
            spi_i: new_spi_i,
            spi_r: new_spi_r,
            keys,
        });
        Ok(())
    }

    /// The gateway rekeys a CHILD SA (`old_spi` is its inbound SPI, our
    /// outbound one): the new one carries the traffic, the old one stays
    /// until the gateway deletes it.
    async fn on_child_rekey(
        &mut self,
        id: u32,
        old_spi: u32,
        proposals: &[Proposal],
        peer_nonce: &[u8],
        ke: Option<(u16, Vec<u8>)>,
        (ts_i, ts_r): (Vec<TrafficSelector>, Vec<TrafficSelector>),
    ) -> Result<()> {
        let Some(index) = self
            .children
            .iter()
            .position(|child| child.spi_out == old_spi)
        else {
            let not_found = Notify {
                protocol: 3,
                spi: old_spi.to_be_bytes().to_vec(),
                kind: notify::CHILD_SA_NOT_FOUND,
                data: Vec::new(),
            };
            return self.refuse_with(id, not_found).await;
        };
        // A KE payload for a group we do not know is one we do not offer.
        let ke_group = match &ke {
            Some((group, _)) => Some(Group::from_id(*group).ok_or_else(|| {
                Error::Malformed(format!("KE payload for unknown group {group}"))
            })?),
            None => None,
        };
        let Some((number, (algorithms, peer_spi))) = proposals.iter().find_map(|proposal| {
            crate::proposals::select_esp(proposal, &self.esp_algorithms, ke_group)
                .ok()
                .map(|selected| (proposal.number, selected))
        }) else {
            tracing::warn!("The gateway proposed no acceptable algorithms to rekey the CHILD_SA.");
            return self.refuse(id, notify::NO_PROPOSAL_CHOSEN).await;
        };
        let (shared, ke_answer) = match (algorithms.group, ke) {
            (Some(group), Some((_, peer_public))) => {
                let exchange = KeyExchange::generate(group);
                let shared = exchange.shared(&peer_public)?;
                (Some(shared), Some((group.id(), exchange.public().to_vec())))
            }
            (Some(group), None) => {
                let wanted = group.id().to_be_bytes().to_vec();
                return self
                    .refuse_with(id, Notify::new(notify::INVALID_KE_PAYLOAD, wanted))
                    .await;
            }
            (None, _) => (None, None),
        };
        let our_spi = ChildSa::random_spi();
        let our_nonce = nonce();
        let keys = self.keys.as_ref().expect("keys");
        // The gateway initiated: its nonce first, its keys first, and
        // the selectors are from its point of view.
        let keymat = keys.child_keymat(
            shared.as_deref().map(Vec::as_slice),
            peer_nonce,
            &our_nonce,
            ChildSa::keymat_len(algorithms),
        );
        let child = ChildSa::new(
            algorithms,
            (our_spi, peer_spi),
            &keymat,
            false,
            (ts_r.clone(), ts_i.clone()),
        )?;
        let mut answer = esp_proposals(&[algorithms], our_spi, true).remove(0);
        answer.number = number;
        let mut response = self.new_response(Exchange::CreateChildSa, id);
        response.push(types::SA, payload::encode_sa(&[answer])?);
        response.push(types::NONCE, our_nonce);
        if let Some((group, public)) = ke_answer {
            response.push(types::KE, payload::encode_ke(group, &public));
        }
        response.push(types::TSI, payload::encode_selectors(&ts_i));
        response.push(types::TSR, payload::encode_selectors(&ts_r));
        self.respond(response).await?;
        tracing::info!(
            "The gateway rekeyed CHILD_SA {} into {:#010x}/{:#010x}.",
            self.children[index].summary(),
            child.spi_in,
            child.spi_out
        );
        self.children[index].replaced = true;
        self.children.insert(0, child);
        Ok(())
    }

    /// An ESP packet from the gateway, into the TUN device.
    async fn on_esp(&mut self, esp: &[u8]) {
        if esp.len() < 4 {
            return;
        }
        let spi = u32::from_be_bytes([esp[0], esp[1], esp[2], esp[3]]);
        let Some(child) = self.children.iter_mut().find(|child| child.spi_in == spi) else {
            tracing::debug!("ESP packet for unknown SPI {spi:#010x}");
            return;
        };
        match child.decapsulate(esp) {
            Ok(Some(packet)) => {
                if let Some(host) = &self.host
                    && let Err(error) = host.tun.send(&packet).await
                {
                    tracing::debug!("could not write to the TUN device: {error}");
                }
            }
            Ok(None) => {}
            Err(error) => tracing::debug!("dropping an ESP packet: {error}"),
        }
    }

    /// An IP packet from the TUN device, to the gateway in ESP.
    async fn on_tun_packet(&mut self, packet: &[u8]) -> Result<()> {
        // IPv4 only, to the newest CHILD SA whose selectors cover the
        // destination.
        let Some(destination) = packet
            .get(16..20)
            .filter(|_| packet[0] >> 4 == 4)
            .map(|octets| {
                TrafficSelector::host(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
            })
        else {
            return Ok(());
        };
        let Some(child) = self.children.iter_mut().find(|child| {
            child
                .ts_r
                .iter()
                .any(|selector| selector.covers(&destination))
        }) else {
            return Ok(());
        };
        let esp = match child.encapsulate(packet) {
            Ok(esp) => esp,
            Err(error) => {
                tracing::debug!("could not encapsulate a packet: {error}");
                return Ok(());
            }
        };
        self.send_esp(&esp).await
    }

    // --- the established tunnel -----------------------------------------

    /// Carries the traffic until the session ends: dead peer detection,
    /// keepalives and rekeys included.
    pub async fn watch(&mut self, cancel: &CancellationToken) -> Result<Ended> {
        let dpd = (self.config.dpd_delay > 0)
            .then(|| Duration::from_secs(u64::from(self.config.dpd_delay)));
        let mut buffer = vec![0u8; 65536];
        let mut tun_buffer = vec![0u8; 65536];
        loop {
            if let Some(reason) = &self.down {
                tracing::warn!("The tunnel went down: {reason}.");
                return Ok(Ended::Down);
            }
            let now = Instant::now();
            let keepalive_at = self.last_sent + KEEPALIVE;
            let dpd_at = dpd.map(|delay| self.last_received + delay);
            let rekey_at = self
                .children
                .iter()
                .filter(|child| !child.replaced)
                .map(|child| child.rekey_at(CHILD_LIFETIME))
                .min();
            let next = [Some(keepalive_at), dpd_at, rekey_at]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(now + KEEPALIVE);
            let read = tokio::select! {
                read = self.recv(&mut buffer) => read?,
                received = recv_tun(self.host.as_ref(), &mut tun_buffer) => {
                    let received = received.map_err(ofv_net::Error::Tun)?;
                    self.on_tun_packet(&tun_buffer[..received]).await?;
                    continue;
                }
                () = tokio::time::sleep_until(next.into()) => {
                    self.on_timer(dpd, cancel).await?;
                    continue;
                }
                () = cancel.cancelled() => return Ok(Ended::Stopped),
            };
            match self.inbound(&buffer[..read]) {
                Ok(Some(Inbound::Esp(esp))) => self.on_esp(&esp).await,
                Ok(Some(Inbound::Ike(packet))) => self.handle_packet(packet).await?,
                Ok(None) => {}
                Err(error) => drop_or_fail(error)?,
            }
        }
    }

    /// The timers of the established tunnel.
    async fn on_timer(&mut self, dpd: Option<Duration>, cancel: &CancellationToken) -> Result<()> {
        let now = Instant::now();
        if let Some(delay) = dpd
            && now >= self.last_received + delay
        {
            tracing::debug!("dead peer detection");
            let request = self.new_request(Exchange::Informational);
            match self.request(request, cancel).await {
                Ok(_) => {}
                Err(Error::Timeout(_)) => {
                    self.down = Some("the gateway stopped answering".into());
                }
                Err(error) => return Err(error),
            }
            return Ok(());
        }
        if self
            .children
            .iter()
            .any(|child| !child.replaced && child.is_due(CHILD_LIFETIME))
        {
            return crate::rekey::rekey_child(self, cancel).await;
        }
        if now >= self.last_sent + KEEPALIVE {
            self.keepalive().await?;
        }
        Ok(())
    }

    // --- teardown -------------------------------------------------------

    /// Tells the gateway the IKE SA is gone and puts the host back.
    pub async fn teardown(&mut self) {
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
        if self.stage == Stage::Established && self.down.is_none() {
            let mut request = self.new_request(Exchange::Informational);
            request.push(
                types::DELETE,
                Delete {
                    protocol: 1,
                    spis: Vec::new(),
                }
                .encode(),
            );
            tracing::info!("Deleting the IKE SA...");
            let never = CancellationToken::new();
            match tokio::time::timeout(Duration::from_secs(5), self.request(request, &never)).await
            {
                Ok(Ok(_)) => tracing::info!("IKE SA deleted."),
                Ok(Err(error)) => {
                    tracing::debug!("the gateway did not acknowledge the deletion: {error}");
                }
                Err(_) => tracing::debug!("the gateway did not acknowledge the deletion in time"),
            }
        }
        self.children.clear();
    }
}

/// The keys as derived with the gateway as initiator, seen from our side.
fn swap_roles(keys: IkeKeys) -> IkeKeys {
    IkeKeys {
        algorithms: keys.algorithms,
        sk_d: keys.sk_d,
        outbound: keys.inbound,
        inbound: keys.outbound,
        sk_pi: keys.sk_pr,
        sk_pr: keys.sk_pi,
    }
}

/// Reads one packet from the TUN device; pends forever without one.
async fn recv_tun(host: Option<&Host>, buffer: &mut [u8]) -> std::io::Result<usize> {
    match host {
        Some(host) => host.tun.recv(buffer).await,
        None => std::future::pending().await,
    }
}
