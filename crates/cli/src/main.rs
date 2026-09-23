#![forbid(unsafe_code)]

mod prompt;
mod settings;

use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{ArgAction, Parser};
use ofv_https::MinTls;
use ofv_ikev2::Auth;
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;

use settings::{Backend, DEFAULT_CONFIG, Mode, Settings};

/// Client for Fortinet VPN gateways: SSL VPN or IKEv2/IPsec.
#[derive(Parser)]
// Command line flags are what they are.
#[allow(clippy::struct_excessive_bools)]
#[command(name = "openfortivpn-rs", version, about, long_about = None)]
#[command(after_help = "\
Options may also come from the configuration file (key = value, same names \
without the leading dashes); the command line takes precedence. The IPsec \
mode is native; with --ipsec-backend charon it drives a running strongSwan \
daemon (charon) with the vici plugin instead.")]
struct Cli {
    /// Gateway host, with an optional port (host:port; default 443, or 500 for IPsec).
    host: Option<String>,

    /// VPN account user name.
    #[arg(short, long)]
    username: Option<String>,

    /// VPN account password (prefer the configuration file or a prompt).
    #[arg(short, long)]
    password: Option<String>,

    /// One-time password (prefer a prompt).
    #[arg(short, long)]
    otp: Option<String>,

    /// Text identifying the OTP prompt in the gateway's form.
    #[arg(long)]
    otp_prompt: Option<String>,

    /// Seconds to wait before sending the one-time password.
    #[arg(long, value_name = "SECONDS")]
    otp_delay: Option<u32>,

    /// Do not try FortiToken Mobile push, ask for the token instead.
    #[arg(long)]
    no_ftm_push: bool,

    /// Session cookie (the SVPNCOOKIE value) replacing the login.
    #[arg(long)]
    cookie: Option<String>,

    /// Read the session cookie from the standard input.
    #[arg(long, conflicts_with = "cookie")]
    cookie_on_stdin: bool,

    /// Log in with SAML in a browser (SSL VPN, or IPsec with ike-saml-server); PORT is the local redirect port.
    #[arg(long, value_name = "PORT", num_args = 0..=1, require_equals = true,
          default_missing_value = "", value_parser = settings::parse_saml_port)]
    saml_login: Option<u16>,

    /// Authentication realm.
    #[arg(long)]
    realm: Option<String>,

    /// Configuration file.
    #[arg(short, long, default_value = DEFAULT_CONFIG)]
    config: PathBuf,

    /// Tunnel protocol: sslvpn (default) or ipsec.
    #[arg(long)]
    protocol: Option<String>,

    /// Program to supply secrets with instead of asking on the terminal.
    #[arg(long)]
    pinentry: Option<String>,

    /// Network interface to send the tunnel traffic through.
    #[arg(long)]
    ifname: Option<String>,

    /// Name of the tunnel interface (openfortivpn's pppd-ifname).
    #[arg(long, alias = "pppd-ifname")]
    tun_name: Option<String>,

    /// Whether routes are configured.
    #[arg(long, value_parser = parse_bool)]
    set_routes: Option<bool>,

    /// Same as --set-routes=0.
    #[arg(long, conflicts_with = "set_routes")]
    no_routes: bool,

    /// Two /1 routes instead of replacing the default route.
    #[arg(long, value_parser = parse_bool)]
    half_internet_routes: Option<bool>,

    /// Whether the VPN nameservers are configured.
    #[arg(long, value_parser = parse_bool)]
    set_dns: Option<bool>,

    /// Same as --set-dns=0.
    #[arg(long, conflicts_with = "set_dns")]
    no_dns: bool,

    /// Install the nameservers with resolvconf/resolvectl when available (default 1; 0: edit /etc/resolv.conf).
    #[arg(long, value_parser = parse_bool)]
    use_resolvconf: Option<bool>,

    /// Ask the gateway for nameservers over IPCP.
    #[arg(long, value_parser = parse_bool)]
    pppd_use_peerdns: Option<bool>,

    /// Same as --pppd-use-peerdns=0.
    #[arg(long, conflicts_with = "pppd_use_peerdns")]
    pppd_no_peerdns: bool,

    /// Server name sent in the TLS handshake instead of the host.
    #[arg(long)]
    sni: Option<String>,

    /// SHA-256 digest of a gateway certificate to accept (repeatable).
    #[arg(long)]
    trusted_cert: Vec<String>,

    /// Accepted for compatibility: TLS 1.2+ with secure cipher suites only.
    #[arg(long)]
    insecure_ssl: bool,

    /// Lowest TLS version accepted: 1.2 (default) or 1.3.
    #[arg(long)]
    min_tls: Option<MinTls>,

    /// User-Agent sent to the portal.
    #[arg(long)]
    user_agent: Option<String>,

    /// Value reported to the gateway's host check.
    #[arg(long)]
    hostcheck: Option<String>,

    /// Value reported to the gateway's virtual desktop check.
    #[arg(long)]
    check_virtual_desktop: Option<String>,

    /// Reconnect every SECONDS when the tunnel drops (0: never).
    #[arg(long, value_name = "SECONDS")]
    persistent: Option<u32>,

    /// PEM bundle authenticating the gateway certificate.
    #[arg(long)]
    ca_file: Option<PathBuf>,

    /// PEM client certificate.
    #[arg(long)]
    user_cert: Option<PathBuf>,

    /// PEM client private key.
    #[arg(long)]
    user_key: Option<PathBuf>,

    /// Passphrase of an encrypted client private key.
    #[arg(long)]
    pem_passphrase: Option<String>,

    /// Pre-shared key of the gateway (prefer the configuration file or a prompt).
    #[arg(long)]
    ipsec_psk: Option<String>,

    /// IPsec client authentication: eap-mschapv2 (default), eap-gtc, eap-md5, psk, pubkey.
    #[arg(long)]
    ipsec_auth: Option<Auth>,

    /// IKE identity sent to the gateway ("Local ID" in FortiClient).
    #[arg(long)]
    ipsec_local_id: Option<String>,

    /// IKE identity expected from the gateway.
    #[arg(long)]
    ipsec_remote_id: Option<String>,

    /// IKE proposals in strongSwan syntax, comma separated.
    #[arg(long)]
    ipsec_ike_proposals: Option<String>,

    /// ESP proposals in strongSwan syntax, comma separated.
    #[arg(long)]
    ipsec_esp_proposals: Option<String>,

    /// Networks to route through the IPsec tunnel, comma separated (default: everything).
    #[arg(long)]
    ipsec_split_include: Option<String>,

    /// IPsec implementation: native (default) or charon (strongSwan).
    #[arg(long)]
    ipsec_backend: Option<Backend>,

    /// Port of the gateway's SAML login for IPsec: FortiOS auth-ike-saml-port (default 1001).
    #[arg(long)]
    ipsec_saml_port: Option<u16>,

    /// Path of the charon vici socket if not standard (charon backend).
    #[arg(long)]
    ipsec_vici_socket: Option<PathBuf>,

    /// Force ESP-in-UDP encapsulation (charon backend; always on natively).
    #[arg(long, value_parser = parse_bool)]
    ipsec_udp_encap: Option<bool>,

    /// Dead peer detection interval in seconds (0: off).
    #[arg(long)]
    ipsec_dpd_delay: Option<u32>,

    /// Accepted for compatibility with openfortivpn, without effect.
    #[arg(long, hide = true)]
    cipher_list: Option<String>,

    /// Accepted for compatibility with openfortivpn, without effect.
    #[arg(long, hide = true)]
    seclevel_1: bool,

    /// Accepted for compatibility with openfortivpn, without effect.
    #[arg(long, hide = true)]
    use_syslog: bool,

    /// Accepted for compatibility with openfortivpn, without effect.
    #[arg(long, hide = true)]
    pppd_log: Option<String>,

    /// Accepted for compatibility with openfortivpn, without effect.
    #[arg(long, hide = true)]
    pppd_plugin: Option<String>,

    /// Accepted for compatibility with openfortivpn, without effect.
    #[arg(long, hide = true)]
    pppd_ipparam: Option<String>,

    /// Accepted for compatibility with openfortivpn, without effect.
    #[arg(long, hide = true)]
    pppd_call: Option<String>,

    /// Accepted for compatibility with openfortivpn, without effect.
    #[arg(long, hide = true, num_args = 0..=1, require_equals = true,
          default_missing_value = "1", value_parser = parse_bool)]
    pppd_accept_remote: Option<bool>,

    /// Increase verbosity (repeatable).
    #[arg(short, action = ArgAction::Count)]
    verbose: u8,

    /// Decrease verbosity (repeatable).
    #[arg(short, action = ArgAction::Count)]
    quiet: u8,
}

fn parse_bool(value: &str) -> Result<bool, String> {
    settings::parse_bool(value).ok_or_else(|| format!("expected 0 or 1, got \"{value}\""))
}

impl Cli {
    fn settings(&self) -> Result<Settings, String> {
        let (host, port) = match &self.host {
            Some(spec) => {
                let (host, port) = settings::parse_host(spec)?;
                (Some(host), port)
            }
            None => (None, None),
        };
        let secret = |value: &Option<String>| value.as_deref().map(SecretString::from);
        let disabled = |flag: bool, value: Option<bool>| if flag { Some(false) } else { value };
        let cookie = self.cookie.as_deref().map(ofv_sslvpn::normalize_cookie);
        Ok(Settings {
            protocol: self.protocol.clone(),
            host,
            port,
            username: self.username.clone(),
            password: secret(&self.password),
            pinentry: self.pinentry.clone(),
            realm: self.realm.clone(),
            otp: secret(&self.otp),
            otp_prompt: self.otp_prompt.clone(),
            otp_delay: self.otp_delay,
            no_ftm_push: self.no_ftm_push.then_some(true),
            cookie,
            saml_login: self.saml_login,
            ifname: self.ifname.clone(),
            tun_name: self.tun_name.clone(),
            set_routes: disabled(self.no_routes, self.set_routes),
            half_internet_routes: self.half_internet_routes,
            set_dns: disabled(self.no_dns, self.set_dns),
            use_resolvconf: self.use_resolvconf,
            peer_dns: disabled(self.pppd_no_peerdns, self.pppd_use_peerdns),
            sni: self.sni.clone(),
            trusted_certs: self.trusted_cert.clone(),
            insecure_ssl: self.insecure_ssl.then_some(true),
            min_tls: self.min_tls,
            user_agent: self.user_agent.clone(),
            hostcheck: self.hostcheck.clone(),
            check_virtual_desktop: self.check_virtual_desktop.clone(),
            persistent: self.persistent,
            ca_file: self.ca_file.clone(),
            user_cert: self.user_cert.clone(),
            user_key: self.user_key.clone(),
            pem_passphrase: secret(&self.pem_passphrase),
            ipsec_psk: secret(&self.ipsec_psk),
            ipsec_auth: self.ipsec_auth,
            ipsec_local_id: self.ipsec_local_id.clone(),
            ipsec_remote_id: self.ipsec_remote_id.clone(),
            ipsec_ike_proposals: self.ipsec_ike_proposals.clone(),
            ipsec_esp_proposals: self.ipsec_esp_proposals.clone(),
            ipsec_split_include: self.ipsec_split_include.clone(),
            ipsec_vici_socket: self.ipsec_vici_socket.clone(),
            ipsec_udp_encap: self.ipsec_udp_encap,
            ipsec_dpd_delay: self.ipsec_dpd_delay,
            ipsec_backend: self.ipsec_backend,
            ipsec_saml_port: self.ipsec_saml_port,
        })
    }

    /// Options accepted for compatibility only.
    fn ignored_options(&self) -> Vec<&'static str> {
        let mut ignored = Vec::new();
        for (given, name) in [
            (self.cipher_list.is_some(), "cipher-list"),
            (self.seclevel_1, "seclevel-1"),
            (self.use_syslog, "use-syslog"),
            (self.pppd_log.is_some(), "pppd-log"),
            (self.pppd_plugin.is_some(), "pppd-plugin"),
            (self.pppd_ipparam.is_some(), "pppd-ipparam"),
            (self.pppd_call.is_some(), "pppd-call"),
            (self.pppd_accept_remote.is_some(), "pppd-accept-remote"),
        ] {
            if given {
                ignored.push(name);
            }
        }
        ignored
    }
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("{0}")]
    Usage(String),
    #[error(transparent)]
    Settings(#[from] settings::Error),
    #[error(transparent)]
    Prompt(#[from] prompt::Error),
    #[error("this program needs root privileges")]
    NotRoot,
    #[error(transparent)]
    Ipsec(#[from] ofv_charon::Error),
    #[error(transparent)]
    Ikev2(#[from] ofv_ikev2::Error),
    #[error(transparent)]
    Sslvpn(#[from] ofv_sslvpn::Error),
    #[error(transparent)]
    Credentials(#[from] ofv_pki::Error),
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose, cli.quiet);
    match Box::pin(run(cli)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report(&error);
            ExitCode::FAILURE
        }
    }
}

/// Our own crates log at the requested level; the libraries (rustls...)
/// only chime in with their details at `-vv`.
fn init_logging(verbose: u8, quiet: u8) {
    use tracing_subscriber::filter::{LevelFilter, Targets};
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    let level = match i16::from(verbose) - i16::from(quiet) {
        i16::MIN..=-3 => LevelFilter::OFF,
        -2 => LevelFilter::ERROR,
        -1 => LevelFilter::WARN,
        0 => LevelFilter::INFO,
        1 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };
    let libraries = if verbose >= 2 {
        level
    } else {
        level.min(LevelFilter::INFO)
    };
    let ours = [
        "openfortivpn_rs",
        "ofv_sslvpn",
        "ofv_ikev2",
        "ofv_charon",
        "ofv_net",
        "ofv_vici",
        "ofv_pki",
    ];
    let filter = Targets::new()
        .with_default(libraries)
        .with_targets(ours.map(|target| (target, level)));
    tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .with_writer(std::io::stderr)
        // The builder's own ceiling is INFO: lift it, the targets decide.
        .with_max_level(level)
        .finish()
        .with(filter)
        .init();
}

/// Logs an error, with the explanation the tunnel has for it.
fn report(error: &Error) {
    match error {
        Error::Ipsec(ofv_charon::Error::Establish { message, hints }) => {
            tracing::error!("Establishing the IPsec tunnel failed: {message}");
            for hint in hints {
                tracing::error!("charon reported: {hint}");
            }
            tracing::error!(
                "Could not establish the IPsec tunnel. Please check the pre-shared key, the credentials and the gateway logs."
            );
        }
        Error::Sslvpn(
            ofv_sslvpn::Error::Authentication
            | ofv_sslvpn::Error::PermissionDenied
            | ofv_sslvpn::Error::Https(ofv_https::Error::Status(_)),
        ) => {
            tracing::error!(
                "Could not authenticate to gateway ({error}). Please check the password, client certificate, etc."
            );
        }
        Error::Ikev2(ofv_ikev2::Error::Authentication(_) | ofv_ikev2::Error::Notify(_)) => {
            tracing::error!(
                "Could not establish the IPsec tunnel ({error}). Please check the pre-shared key, the credentials and the gateway logs."
            );
        }
        _ => tracing::error!("{error}"),
    }
}

async fn run(cli: Cli) -> Result<(), Error> {
    for (given, what) in [
        (cli.password.is_some(), "password"),
        (cli.otp.is_some(), "one-time password"),
        (cli.cookie.is_some(), "cookie"),
        (cli.ipsec_psk.is_some(), "pre-shared key"),
        (cli.pem_passphrase.is_some(), "key passphrase"),
    ] {
        if given {
            tracing::warn!(
                "You should not pass the {what} on the command line. Type it interactively or use a configuration file instead."
            );
        }
    }
    for option in cli.ignored_options() {
        tracing::warn!("ignoring option \"{option}\": not applicable to this version");
    }
    let from_file = load_file(&cli.config)?;
    let mut from_cli = cli.settings().map_err(Error::Usage)?;
    if cli.cookie_on_stdin {
        from_cli.cookie = Some(ofv_sslvpn::normalize_cookie(&read_stdin_line()?));
    }
    let settings = from_file.merge(from_cli);
    let pinentry = Pinentry(settings.pinentry.clone());
    let persistent = settings.persistent.unwrap_or(0);
    let mode = settings.into_config()?;

    let cancel = CancellationToken::new();
    tokio::spawn(stop_on_signal(cancel.clone()));
    let result = match mode {
        Mode::Sslvpn(mut config) => {
            config.validate_settings()?;
            require_root()?;
            ask_sslvpn_secrets(&mut config, &pinentry).await?;
            // A one-time password is exactly that: a reconnection asks for
            // a new one.
            let later = ofv_sslvpn::Config {
                otp: None,
                ..config.clone()
            };
            let (pinentry, cancel) = (&pinentry, &cancel);
            keep_running(cancel, persistent, |first| {
                let config = if first { &config } else { &later };
                async move {
                    let outcome = ofv_sslvpn::run(config, pinentry, cancel).await?;
                    Ok(outcome == ofv_sslvpn::Outcome::Stopped)
                }
            })
            .await
        }
        Mode::Ipsec(mut config, backend) => {
            config.validate_settings()?;
            require_root()?;
            ask_ipsec_secrets(&mut config, &pinentry).await?;
            keep_running(&cancel, persistent, |_| async {
                let stopped = match backend {
                    Backend::Native => {
                        ofv_ikev2::run(&config, &cancel).await? == ofv_ikev2::Outcome::Stopped
                    }
                    Backend::Charon => {
                        ofv_charon::run(&config, &cancel).await? == ofv_charon::Outcome::Stopped
                    }
                };
                Ok(stopped)
            })
            .await
        }
    };
    sd_notify::notify(false, &[sd_notify::NotifyState::Stopping]).ok();
    result
}

fn require_root() -> Result<(), Error> {
    if nix::unistd::geteuid().is_root() {
        Ok(())
    } else {
        Err(Error::NotRoot)
    }
}

/// Runs the tunnel, again after `persistent` seconds whenever it drops,
/// until the tunnel is closed on request or `persistent` is zero. The
/// closure is told whether this is the first attempt, and returns whether
/// the tunnel was closed on request.
async fn keep_running<F, Fut>(
    cancel: &CancellationToken,
    persistent: u32,
    mut connect: F,
) -> Result<(), Error>
where
    F: FnMut(bool) -> Fut,
    Fut: Future<Output = Result<bool, Error>>,
{
    let interval = Duration::from_secs(u64::from(persistent));
    let mut first = true;
    loop {
        let result = connect(first).await;
        first = false;
        match result {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => {
                if persistent == 0 || cancel.is_cancelled() {
                    return Err(error);
                }
                report(&error);
            }
        }
        if persistent == 0 || cancel.is_cancelled() {
            return Err(Error::Usage("the tunnel is down".into()));
        }
        tracing::info!("Reconnecting in {persistent} seconds...");
        tokio::select! {
            () = tokio::time::sleep(interval) => {}
            () = cancel.cancelled() => return Ok(()),
        }
    }
}

/// Reads the configuration file; a missing default file is not an error.
fn load_file(path: &Path) -> Result<Settings, Error> {
    match Settings::from_file(path) {
        Ok(settings) => {
            tracing::debug!("loaded configuration file {}", path.display());
            Ok(settings)
        }
        Err(settings::Error::Read { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound
                && path.as_os_str() == DEFAULT_CONFIG =>
        {
            tracing::debug!("no configuration file at {}", path.display());
            Ok(Settings::default())
        }
        Err(error) => Err(error.into()),
    }
}

/// One line of the standard input, wiped afterwards.
fn read_stdin_line() -> Result<zeroize::Zeroizing<String>, Error> {
    let mut line = zeroize::Zeroizing::new(String::new());
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|error| Error::Usage(format!("could not read the cookie from stdin: {error}")))?;
    Ok(line)
}

/// Secrets asked on the terminal or through the pinentry program.
struct Pinentry(Option<String>);

impl Pinentry {
    async fn secret(&self, key_info: &str, message: &str) -> Result<SecretString, prompt::Error> {
        prompt::secret(self.0.as_deref(), key_info, message).await
    }
}

impl ofv_sslvpn::Prompt for Pinentry {
    async fn secret(&self, key_info: &str, message: &str) -> Result<SecretString, String> {
        Pinentry::secret(self, key_info, message)
            .await
            .map_err(|error| error.to_string())
    }
}

/// Asks the passphrase of an encrypted client key.
async fn ask_pem_passphrase(
    key: Option<&Path>,
    passphrase: &mut Option<SecretString>,
    gateway: &str,
    pinentry: &Pinentry,
) -> Result<(), Error> {
    if let Some(key) = key
        && passphrase.is_none()
        && ofv_pki::key_needs_passphrase(key)?
    {
        let key_info = format!("{gateway}_pem");
        *passphrase = Some(pinentry.secret(&key_info, "Enter PEM pass phrase:").await?);
    }
    Ok(())
}

/// Asks interactively for the SSL VPN secrets that are still missing.
async fn ask_sslvpn_secrets(
    config: &mut ofv_sslvpn::Config,
    pinentry: &Pinentry,
) -> Result<(), Error> {
    if config.password.is_none()
        && !config.username.is_empty()
        && !config.logs_in_without_password()
    {
        let key_info = format!(
            "{}_{}_{}_password",
            config.username, config.realm, config.https.gateway
        );
        config.password = Some(pinentry.secret(&key_info, "VPN account password:").await?);
    }
    ask_pem_passphrase(
        config.https.user_key.as_deref(),
        &mut config.https.pem_passphrase,
        &config.https.gateway,
        pinentry,
    )
    .await
}

/// Asks interactively for the IPsec secrets that are still missing.
async fn ask_ipsec_secrets(
    config: &mut ofv_ikev2::Config,
    pinentry: &Pinentry,
) -> Result<(), Error> {
    if config.auth.is_eap()
        && config.password.is_none()
        && !config.username.is_empty()
        && config.saml_port.is_none()
    {
        let key_info = format!("{}_ipsec_{}_password", config.username, config.gateway);
        config.password = Some(pinentry.secret(&key_info, "VPN account password:").await?);
    }
    if config.needs_psk() && config.psk.is_none() {
        let key_info = format!("ipsec_{}_psk", config.gateway);
        config.psk = Some(pinentry.secret(&key_info, "IPsec pre-shared key:").await?);
    }
    if config.auth == Auth::Pubkey {
        ask_pem_passphrase(
            config.user_key.as_deref(),
            &mut config.pem_passphrase,
            &config.gateway,
            pinentry,
        )
        .await?;
    }
    Ok(())
}

/// Cancels the token on SIGINT or SIGTERM; a second signal exits at
/// once, for when the teardown hangs. SIGHUP is ignored, like
/// openfortivpn does, so that the tunnel survives its terminal.
async fn stop_on_signal(cancel: CancellationToken) {
    use tokio::signal::unix::{Signal, SignalKind, signal};
    // Registering the handler is what turns the default action off; the
    // stream itself is never read.
    let _hangup = signal(SignalKind::hangup());
    let kinds = [SignalKind::interrupt(), SignalKind::terminate()];
    let mut signals: Vec<Signal> = kinds
        .into_iter()
        .filter_map(|kind| match signal(kind) {
            Ok(stream) => Some(stream),
            Err(error) => {
                tracing::warn!("cannot listen for signal {kind:?}: {error}");
                None
            }
        })
        .collect();
    wait_any(&mut signals).await;
    cancel.cancel();
    wait_any(&mut signals).await;
    tracing::warn!("Second signal received, exiting without cleanup.");
    std::process::exit(130);
}

/// Completes when any of the signals arrives.
async fn wait_any(signals: &mut [tokio::signal::unix::Signal]) {
    if signals.is_empty() {
        std::future::pending::<()>().await;
    }
    std::future::poll_fn(|context| {
        if signals
            .iter_mut()
            .any(|stream| stream.poll_recv(context).is_ready())
        {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    })
    .await;
}
