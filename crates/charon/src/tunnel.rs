use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Duration;

use ofv_vici::{ANY, Client, Event, Section};
use tokio_util::sync::CancellationToken;

use crate::charon::{self, CONN_NAME, Child, Daemon, LogLine};
use crate::{Error, Result};
use ofv_ikev2::Config;

/// How long we give the CHILD_SA event to arrive after charon reported the
/// initiation successful (it travels on the other connection).
const CHILD_EVENT_GRACE: Duration = Duration::from_secs(3);
/// How many failure-related charon lines we keep for the error report.
const HINTS_MAX: usize = 3;
/// How long an abandoned "initiate" may take to create its IKE_SA.
const ABANDONED_INITIATE_GRACE: Duration = Duration::from_millis(500);

/// Why [`run`] returned without error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The tunnel was closed because the caller asked for it.
    Stopped,
    /// The tunnel went down (gateway, dead peer detection...).
    Down,
}

/// Sets up the tunnel and keeps it up until `cancel` fires or it goes down.
/// Whatever happens, what was loaded into charon is removed before
/// returning.
pub async fn run(config: &Config, cancel: &CancellationToken) -> Result<Outcome> {
    config.validate()?;
    let socket = config
        .vici_socket
        .clone()
        .unwrap_or_else(charon::default_socket);
    tracing::debug!("connecting to charon vici socket {}", socket.display());
    // Two connections: "cmd" carries the (possibly long-running) commands,
    // "evt" only receives events. Cancelling a command leaves its
    // connection unusable, the event connection then does the cleanup.
    let cmd = connect(&socket).await?;
    let evt = connect(&socket).await?;

    let mut tunnel = Tunnel {
        config,
        cmd: Some(cmd),
        evt,
        children: Child::plan(&config.split_include),
        state: State::default(),
        loaded: Loaded::default(),
        hints: VecDeque::new(),
        dns_handled: false,
    };
    let outcome = tunnel.establish_and_watch(cancel).await;
    tunnel.teardown().await;
    outcome
}

async fn connect(socket: &PathBuf) -> Result<Client> {
    Client::connect(socket).await.map_err(|error| match error {
        ofv_vici::Error::Io(source) => Error::Connect {
            path: socket.clone(),
            source,
        },
        other => Error::Vici(other),
    })
}

#[derive(Debug, Default)]
struct State {
    ike_up: bool,
    /// The IKE_SA went down after having been up.
    ike_down: bool,
    tunnel_up: bool,
    vip: Option<String>,
    remote_host: Option<String>,
}

/// What we loaded into charon and must unload.
#[derive(Debug, Default)]
struct Loaded {
    conn: bool,
    psk: bool,
    eap: bool,
    key_id: Option<String>,
}

enum Step {
    Done,
    Cancelled,
}

/// The command connection was abandoned on cancellation.
const ABANDONED: Error = Error::Lost(ofv_vici::Error::Poisoned);

struct Tunnel<'a> {
    config: &'a Config,
    /// `None` once a command had to be abandoned on cancellation.
    cmd: Option<Client>,
    evt: Client,
    children: Vec<Child>,
    state: State,
    loaded: Loaded,
    hints: VecDeque<String>,
    dns_handled: bool,
}

impl Tunnel<'_> {
    fn cmd(&mut self) -> Result<&mut Client> {
        self.cmd.as_mut().ok_or(ABANDONED)
    }

    /// The connection to use for control commands: the command connection,
    /// or the event connection once the former was abandoned.
    fn control(&mut self) -> &mut Client {
        match self.cmd.as_mut() {
            Some(cmd) => cmd,
            None => &mut self.evt,
        }
    }

    fn children_up(&self) -> usize {
        self.children.iter().filter(|child| child.up).count()
    }

    async fn establish_and_watch(&mut self, cancel: &CancellationToken) -> Result<Outcome> {
        let daemon = Daemon::query(self.cmd()?).await?;
        tracing::info!("Connected to {}.", daemon.description);
        self.check_daemon(&daemon)?;
        self.dns_handled = daemon.has_dns_handler();

        // control-log carries charon's log while a command is running
        self.cmd()?.register("control-log").await?;
        self.evt.register("ike-updown").await?;
        self.evt.register("child-updown").await?;

        if self.terminate(true, -1).await? > 0 {
            tracing::warn!("Terminated a stale IKE_SA left by a previous run.");
        }
        if cancel.is_cancelled() {
            return Ok(Outcome::Stopped);
        }

        tracing::debug!("loading credentials and connection into charon");
        self.load_credentials().await?;
        self.load_connection().await?;

        let config = self.config;
        tracing::info!(
            "Establishing IKEv2 tunnel to {}:{} as {} ({})...",
            config.gateway,
            config.port,
            if config.username.is_empty() {
                "certificate"
            } else {
                &config.username
            },
            config.auth.charon_name()
        );
        for index in 0..self.children.len() {
            if cancel.is_cancelled() {
                tracing::info!("Interrupted while establishing the tunnel.");
                return Ok(Outcome::Stopped);
            }
            if let Step::Cancelled = self.initiate(index, cancel).await? {
                return Ok(Outcome::Stopped);
            }
            if let Step::Cancelled = self.wait_child_up(index, cancel).await {
                return Ok(Outcome::Stopped);
            }
            self.hints.clear();
        }
        if !self.state.tunnel_up && !self.state.ike_down {
            // Should not happen: charon reported success, trust it.
            tracing::warn!("charon reported the tunnel up but no CHILD_SA event was received.");
            for child in &mut self.children {
                child.up = true;
            }
            self.tunnel_up();
        }
        // Also show what charon has to say about our IKE_SA from now on.
        if let Err(error) = self.evt.register("log").await {
            tracing::debug!("cannot subscribe to charon's log: {error}");
        }
        self.watch(cancel).await
    }

    fn check_daemon(&self, daemon: &Daemon) -> Result<()> {
        let config = self.config;
        if !daemon.has_kernel_plugin() {
            tracing::warn!(
                "charon has no kernel interface plugin loaded, the tunnel will not carry traffic."
            );
        }
        if config.auth.is_eap() {
            let method = config.auth.charon_name();
            if !daemon.has_plugin(method) {
                return Err(Error::MissingPlugin(method.to_owned()));
            }
            if !daemon.has_plugin("eap-identity") {
                tracing::warn!(
                    "charon does not have the eap-identity plugin loaded, the gateway may reject the EAP identity exchange."
                );
            }
        }
        match (config.set_dns, daemon.has_dns_handler()) {
            (true, false) => tracing::warn!(
                "charon has no DNS handler plugin (resolve, osx-attr) loaded, VPN nameservers will not be configured."
            ),
            (false, true) => tracing::warn!(
                "charon's DNS handler plugin will configure the VPN nameservers regardless of set-dns; disable it in strongswan.conf to keep the resolver untouched."
            ),
            _ => {}
        }
        Ok(())
    }

    async fn load_credentials(&mut self) -> Result<()> {
        let config = self.config;
        if config.needs_psk() {
            let message = charon::psk_secret(config)?;
            let response = self.cmd()?.request("load-shared", message).await?;
            charon::check(&response, "loading the pre-shared key into charon")?;
            self.loaded.psk = true;
        }
        if config.auth.is_eap() {
            let message = charon::eap_secret(config)?;
            let response = self.cmd()?.request("load-shared", message).await?;
            charon::check(&response, "loading the EAP secret into charon")?;
            self.loaded.eap = true;
        }
        if config.auth == ofv_ikev2::Auth::Pubkey {
            let message = charon::private_key(config)?;
            let response = self.cmd()?.request("load-key", message).await?;
            charon::check(&response, "loading the private key into charon")?;
            self.loaded.key_id = response.get_str(&["id"]).map(str::to_owned);
            tracing::debug!("loaded the private key into charon");
        }
        Ok(())
    }

    async fn load_connection(&mut self) -> Result<()> {
        let message = charon::connection(self.config, &self.children)?;
        let response = self.cmd()?.request("load-conn", message).await?;
        charon::check(&response, "loading the connection into charon")?;
        self.loaded.conn = true;
        tracing::debug!("loaded connection \"{CONN_NAME}\" into charon");
        Ok(())
    }

    /// Initiates one CHILD_SA; the first one also sets up the IKE_SA. This
    /// is the only long-running command: a cancellation abandons it and the
    /// command connection with it.
    async fn initiate(&mut self, index: usize, cancel: &CancellationToken) -> Result<Step> {
        let child = &self.children[index];
        tracing::debug!("initiating CHILD_SA {} ({})", child.name, child.remote_ts);
        let request = charon::initiate(child);
        let result = {
            let Tunnel { cmd, hints, .. } = self;
            let cmd = cmd.as_mut().ok_or(ABANDONED)?;
            let mut on_event = |event: Event| relay_command_log(&event, hints);
            tokio::select! {
                result = cmd.request_with("initiate", request, &mut on_event) => Some(result),
                () = cancel.cancelled() => None,
            }
        };
        let Some(result) = result else {
            self.cmd = None;
            tracing::info!("Interrupted while establishing the tunnel.");
            return Ok(Step::Cancelled);
        };
        let response = result?;
        if let Err(Error::Command { message, .. }) =
            charon::check(&response, "establishing the IPsec tunnel")
        {
            return Err(Error::Establish {
                message,
                hints: self.hints.drain(..).collect(),
            });
        }
        Ok(Step::Done)
    }

    /// The CHILD_SA events travel on the event connection while `initiate`
    /// blocks on the command connection: give them a moment to arrive.
    async fn wait_child_up(&mut self, index: usize, cancel: &CancellationToken) -> Step {
        let wait = async {
            while !self.children[index].up && !self.state.ike_down {
                let next = tokio::select! {
                    event = self.evt.next_event() => Some(event),
                    () = cancel.cancelled() => None,
                };
                match next {
                    Some(Ok(event)) => self.handle_event(&event),
                    Some(Err(_)) => break,
                    None => return Step::Cancelled,
                }
            }
            Step::Done
        };
        let step = tokio::time::timeout(CHILD_EVENT_GRACE, wait)
            .await
            .unwrap_or(Step::Done);
        if !self.children[index].up {
            tracing::debug!(
                "no event received for CHILD_SA {}",
                self.children[index].name
            );
        }
        step
    }

    /// Waits until the tunnel goes down or the caller asks to stop.
    async fn watch(&mut self, cancel: &CancellationToken) -> Result<Outcome> {
        loop {
            if self.state.ike_down || self.children_up() == 0 {
                tracing::warn!("The tunnel went down.");
                return Ok(Outcome::Down);
            }
            let next = tokio::select! {
                event = self.evt.next_event() => Some(event),
                () = cancel.cancelled() => None,
            };
            match next {
                Some(Ok(event)) => self.handle_event(&event),
                Some(Err(error)) => return Err(Error::Lost(error)),
                None => {
                    tracing::info!("Closing the tunnel...");
                    return Ok(Outcome::Stopped);
                }
            }
        }
    }

    fn handle_event(&mut self, event: &Event) {
        match event.name.as_str() {
            "log" => {
                if let Some(line) = LogLine::parse(event) {
                    // The generic log event covers every IKE_SA of the daemon.
                    if line.ike_sa.is_none_or(|name| name == CONN_NAME) {
                        line.relay();
                    }
                }
            }
            "ike-updown" => self.on_ike_updown(&event.message),
            "child-updown" => self.on_child_updown(&event.message),
            other => tracing::debug!("ignoring vici event \"{other}\""),
        }
    }

    /// Reads the virtual IP and the remote host out of an IKE_SA description.
    fn read_ike_sa(&mut self, ike: &Section) {
        if let Some(vip) = ike.get_str_list(&["local-vips"]).next() {
            self.state.vip = Some(vip.to_owned());
        }
        if let Some(host) = ike.get_str(&["remote-host"]) {
            self.state.remote_host = Some(host.to_owned());
        }
    }

    fn remote_host(&self) -> &str {
        self.state
            .remote_host
            .as_deref()
            .unwrap_or(&self.config.gateway)
    }

    fn on_ike_updown(&mut self, message: &Section) {
        let Some(ike) = message.get_section(&[CONN_NAME]) else {
            return; // another connection of this daemon
        };
        self.read_ike_sa(ike);
        if message.get_str(&["up"]) == Some("yes") {
            self.state.ike_up = true;
            self.state.ike_down = false;
            tracing::info!(
                "IKE_SA established with {} [{}].",
                self.remote_host(),
                ike.get_str(&["remote-id"]).unwrap_or("?")
            );
            return;
        }
        if !self.state.ike_up {
            return;
        }
        self.state.ike_up = false;
        self.state.ike_down = true;
        for child in &mut self.children {
            child.up = false;
        }
        tracing::info!("IKE_SA with {} closed.", self.remote_host());
        self.tunnel_down();
    }

    fn on_child_updown(&mut self, message: &Section) {
        let Some(ike) = message.get_section(&[CONN_NAME]) else {
            return;
        };
        self.read_ike_sa(ike);
        let Some(sa) = ike.get_section(&["child-sas", ANY]) else {
            return;
        };
        let Some(name) = sa.get_str(&["name"]) else {
            return;
        };
        let Some(child) = self.children.iter_mut().find(|child| child.name == name) else {
            tracing::debug!("ignoring event for unknown CHILD_SA \"{name}\"");
            return;
        };
        let join = |key| sa.get_str_list(&[key]).collect::<Vec<_>>().join(" ");
        if message.get_str(&["up"]) == Some("yes") {
            child.up = true;
            tracing::info!(
                "CHILD_SA {name} established: {} === {}",
                join("local-ts"),
                join("remote-ts")
            );
            if self.children_up() == self.children.len() {
                self.tunnel_up();
            }
            return;
        }
        child.up = false;
        tracing::info!("CHILD_SA {name} closed.");
        if self.children_up() == 0 {
            self.tunnel_down();
        }
    }

    fn tunnel_up(&mut self) {
        if self.state.tunnel_up {
            return;
        }
        self.state.tunnel_up = true;
        if let Some(vip) = &self.state.vip {
            tracing::info!("Virtual IP address {vip} assigned by the gateway.");
        } else {
            tracing::warn!("The gateway did not assign a virtual IP address.");
        }
        tracing::info!("Routes are installed by charon for the negotiated traffic selectors.");
        if self.config.set_dns {
            if self.dns_handled {
                tracing::info!("VPN nameservers are handled by charon's DNS handler plugin.");
            } else {
                tracing::warn!(
                    "VPN nameservers are not configured (no charon DNS handler plugin)."
                );
            }
        }
        tracing::info!("Tunnel is up and running.");
        sd_notify::notify(false, &[sd_notify::NotifyState::Ready]).ok();
    }

    fn tunnel_down(&mut self) {
        self.state.tunnel_up = false;
    }

    /// Terminates our IKE_SA(s), whatever their state. "No matching SA" is
    /// not an error. Returns the number of SAs matched.
    async fn terminate(&mut self, force: bool, timeout_ms: i32) -> Result<u32> {
        let request = charon::terminate(force, timeout_ms);
        let mut relay = |event: Event| {
            if let Some(line) = LogLine::parse(&event) {
                line.relay();
            }
        };
        let response = self
            .control()
            .request_with("terminate", request, &mut relay)
            .await?;
        let matches: u32 = response
            .get_str(&["matches"])
            .and_then(|matches| matches.parse().ok())
            .unwrap_or(0);
        if matches > 0 {
            tracing::debug!("terminated {matches} IKE_SA(s)");
            if let Err(Error::Command { message, .. }) = charon::check(&response, "terminate") {
                tracing::warn!(
                    "The gateway did not acknowledge the deletion of the tunnel ({message}), closed it locally."
                );
            }
        }
        Ok(matches)
    }

    async fn unload(&mut self) {
        let mut requests: Vec<(&str, Section)> = Vec::new();
        if self.loaded.conn {
            requests.push(("unload-conn", Section::new().kv("name", CONN_NAME)));
        }
        if self.loaded.psk {
            requests.push(("unload-shared", Section::new().kv("id", charon::PSK_ID)));
        }
        if self.loaded.eap {
            requests.push(("unload-shared", Section::new().kv("id", charon::EAP_ID)));
        }
        if let Some(id) = self.loaded.key_id.take() {
            requests.push(("unload-key", Section::new().kv("id", id)));
        }
        for (command, message) in requests {
            if let Err(error) = self.control().request(command, message).await {
                tracing::debug!("{command} failed: {error}");
            }
        }
        self.loaded = Loaded::default();
    }

    /// Removes the tunnel and everything we loaded. Always terminates: a
    /// failed initiation may have left an IKE_SA behind.
    async fn teardown(&mut self) {
        let abandoned = self.cmd.is_none();
        if abandoned {
            for event in ["log", "ike-updown", "child-updown"] {
                if let Err(error) = self.evt.unregister(event).await {
                    tracing::debug!("cannot unsubscribe from {event}: {error}");
                }
            }
        }
        match self.terminate(true, charon::TERMINATE_TIMEOUT_MS).await {
            // An abandoned "initiate" may still be creating the IKE_SA in
            // charon: look again once it had time to appear.
            Ok(0) if abandoned => {
                tokio::time::sleep(ABANDONED_INITIATE_GRACE).await;
                if let Err(error) = self.terminate(true, charon::TERMINATE_TIMEOUT_MS).await {
                    tracing::debug!("terminate failed: {error}");
                }
            }
            Ok(_) => {}
            Err(error) => tracing::debug!("terminate failed: {error}"),
        }
        self.tunnel_down();
        self.unload().await;
        tracing::info!("Closed the tunnel.");
    }
}

/// Relays a `control-log` event and remembers the failure-related lines.
fn relay_command_log(event: &Event, hints: &mut VecDeque<String>) {
    let Some(line) = LogLine::parse(event) else {
        return;
    };
    line.relay();
    if line.is_failure_hint() {
        if hints.len() == HINTS_MAX {
            hints.pop_front();
        }
        hints.push_back(line.text.to_owned());
    }
}
