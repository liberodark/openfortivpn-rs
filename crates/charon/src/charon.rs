use std::path::{Path, PathBuf};

use ofv_vici::{Client, Event, Section};
use secrecy::ExposeSecret;

use crate::{Error, Result};
use ofv_ikev2::Config;

/// Name of the connection, the IKE_SA and the single CHILD_SA we load.
pub(crate) const CONN_NAME: &str = "openfortivpn";
/// Identifier of the pre-shared key we load.
pub(crate) const PSK_ID: &str = "openfortivpn-psk";
/// Identifier of the EAP secret we load.
pub(crate) const EAP_ID: &str = "openfortivpn-eap";

/// How long charon may negotiate before giving up, in milliseconds.
pub(crate) const INITIATE_TIMEOUT_MS: u32 = 120_000;
/// How long charon waits for the gateway to acknowledge our DELETE.
pub(crate) const TERMINATE_TIMEOUT_MS: i32 = 5_000;

/// Default proposals: the FortiOS 7.x defaults (AES-CBC/GCM, SHA-256/384,
/// ChaCha20, DH group 14) plus SHA-1 for older gateways. ESP proposals
/// without PFS come last, for gateways with PFS disabled.
const DEFAULT_IKE_PROPOSALS: &str = "aes256-sha256-modp2048,aes128-sha256-modp2048,\
aes256gcm16-prfsha384-modp2048,aes128gcm16-prfsha256-modp2048,\
chacha20poly1305-prfsha256-modp2048,aes256-sha384-modp2048,\
aes256-sha1-modp2048,aes128-sha1-modp2048,\
aes256-sha256-ecp256,aes256gcm16-prfsha384-ecp384";
const DEFAULT_ESP_PROPOSALS: &str = "aes256-sha256-modp2048,aes128-sha256-modp2048,\
aes256gcm16-modp2048,aes128gcm16-modp2048,\
chacha20poly1305-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048,\
aes256-sha256,aes128-sha256,aes256gcm16,aes128gcm16,aes256-sha1,aes128-sha1";

/// Words that mark a charon log line as explaining a failure.
const FAILURE_KEYWORDS: [&str; 22] = [
    "failed",
    "mismatch",
    "error",
    "unable",
    "giving up",
    "not responding",
    "no matching",
    "no shared key",
    "no private key",
    "no trusted",
    "no acceptable",
    "unacceptable",
    "denied",
    "rejected",
    "invalid",
    "constraint",
    "NO_PROPOSAL_CHOSEN",
    "AUTHENTICATION_FAILED",
    "TS_UNACCEPTABLE",
    "INVALID_",
    "timed out",
    "unsupported",
];

/// The vici socket path for this platform: the first existing candidate,
/// or the Linux/FreeBSD default.
pub(crate) fn default_socket() -> PathBuf {
    const CANDIDATES: [&str; 4] = [
        "/var/run/charon.vici",              // Linux, FreeBSD, MacPorts
        "/opt/homebrew/var/run/charon.vici", // Homebrew, Apple Silicon
        "/usr/local/var/run/charon.vici",    // Homebrew, Intel
        "/run/charon.vici",
    ];
    CANDIDATES
        .iter()
        .map(Path::new)
        .find(|path| path.exists())
        .unwrap_or_else(|| Path::new(CANDIDATES[0]))
        .to_path_buf()
}

/// Splits a comma/space separated option into vici list items.
fn split_list(list: &str) -> impl Iterator<Item = &str> {
    list.split([',', ' ', '\t']).filter(|item| !item.is_empty())
}

/// A CHILD_SA to negotiate: one per traffic selector, since the FortiGate
/// accepts a single selector per CHILD_SA.
#[derive(Debug, Clone)]
pub(crate) struct Child {
    pub(crate) name: String,
    pub(crate) remote_ts: String,
    pub(crate) up: bool,
}

impl Child {
    /// One child for everything, or one per split-include network.
    pub(crate) fn plan(split_include: &[String]) -> Vec<Self> {
        if split_include.is_empty() {
            return vec![Self {
                name: CONN_NAME.to_owned(),
                remote_ts: "0.0.0.0/0".to_owned(),
                up: false,
            }];
        }
        split_include
            .iter()
            .enumerate()
            .map(|(index, network)| Self {
                name: format!("{CONN_NAME}-{}", index + 1),
                remote_ts: network.clone(),
                up: false,
            })
            .collect()
    }
}

/// What the daemon offers, as reported by `version` and `stats`.
pub(crate) struct Daemon {
    pub(crate) description: String,
    pub(crate) plugins: Vec<String>,
}

impl Daemon {
    pub(crate) async fn query(client: &mut Client) -> Result<Self> {
        let version = client.request("version", Section::new()).await?;
        let field = |key| version.get_str(&[key]).unwrap_or("?").to_owned();
        let description = format!(
            "{} {} ({})",
            field("daemon"),
            field("version"),
            field("sysname")
        );
        let stats = client.request("stats", Section::new()).await?;
        let plugins = stats
            .get_str_list(&["plugins"])
            .map(str::to_owned)
            .collect();
        Ok(Self {
            description,
            plugins,
        })
    }

    pub(crate) fn has_plugin(&self, name: &str) -> bool {
        self.plugins.iter().any(|plugin| plugin == name)
    }

    pub(crate) fn has_kernel_plugin(&self) -> bool {
        self.plugins
            .iter()
            .any(|plugin| plugin.starts_with("kernel-"))
    }

    /// Whether a plugin installing the pushed DNS servers is loaded
    /// (`resolve` on Linux/BSD, `osx-attr` on macOS).
    pub(crate) fn has_dns_handler(&self) -> bool {
        self.has_plugin("resolve") || self.has_plugin("osx-attr")
    }
}

/// The `load-shared` message for the pre-shared key. Without owners the key
/// is valid for whatever identity the gateway sends.
pub(crate) fn psk_secret(config: &Config) -> Result<Section> {
    let psk = config
        .psk
        .as_ref()
        .ok_or_else(|| Error::Config("a pre-shared key is needed".into()))?;
    Ok(Section::new()
        .kv("id", PSK_ID)
        .kv("type", "IKE")
        .kv("data", psk.expose_secret()))
}

/// The `load-shared` message for the EAP secret.
pub(crate) fn eap_secret(config: &Config) -> Result<Section> {
    let password = config
        .password
        .as_ref()
        .ok_or_else(|| Error::Config("EAP authentication needs a password".into()))?;
    Ok(Section::new()
        .kv("id", EAP_ID)
        .kv("type", "EAP")
        .kv("data", password.expose_secret())
        .list("owners", [config.username.as_str()]))
}

/// The `load-key` message for the client private key. charon receives an
/// unencrypted PEM blob over the local socket only.
pub(crate) fn private_key(config: &Config) -> Result<Section> {
    let path = config
        .user_key
        .as_ref()
        .ok_or_else(|| Error::Config("certificate authentication needs a key".into()))?;
    let key = ofv_pki::private_key(path, config.pem_passphrase.as_ref())?;
    Ok(Section::new()
        .kv("type", "any")
        .kv("data", key.to_pem().as_bytes()))
}

/// The certificates of a PEM file as vici list items.
fn certificates(path: &std::path::Path) -> Result<Vec<String>> {
    Ok(ofv_pki::certificates(path)?
        .iter()
        .map(ofv_pki::Certificate::to_pem)
        .collect())
}

/// The `load-conn` message.
pub(crate) fn connection(config: &Config, children: &[Child]) -> Result<Section> {
    let ike_proposals = config
        .ike_proposals
        .as_deref()
        .unwrap_or(DEFAULT_IKE_PROPOSALS);
    let esp_proposals = config
        .esp_proposals
        .as_deref()
        .unwrap_or(DEFAULT_ESP_PROPOSALS);

    let mut local = Section::new().kv("auth", config.auth.charon_name());
    if config.auth.is_eap() {
        local = local.kv("eap_id", &config.username);
    }
    if let Some(id) = &config.local_id {
        local = local.kv("id", id);
    }
    if config.auth == ofv_ikev2::Auth::Pubkey {
        let path = config.user_cert.as_ref().ok_or_else(|| {
            Error::Config("certificate authentication needs a certificate".into())
        })?;
        local = local.list("certs", certificates(path)?);
    }

    let remote = if config.gateway_uses_cert() {
        let mut remote = Section::new()
            .kv("auth", "pubkey")
            .kv("id", config.remote_id.as_deref().unwrap_or(&config.gateway));
        if let Some(path) = &config.ca_file {
            remote = remote.list("cacerts", certificates(path)?);
        }
        remote
    } else {
        Section::new()
            .kv("auth", "psk")
            .kv("id", config.remote_id.as_deref().unwrap_or("%any"))
    };

    let mut child_sections = Section::new();
    for child in children {
        child_sections = child_sections.section(
            &child.name,
            Section::new()
                .list("remote_ts", [child.remote_ts.as_str()])
                .list("esp_proposals", split_list(esp_proposals))
                .kv("mode", "tunnel")
                .kv("dpd_action", "clear")
                .kv("close_action", "none")
                .kv("start_action", "none"),
        );
    }

    let conn = Section::new()
        .kv("version", "2")
        .list("remote_addrs", [config.gateway.as_str()])
        .kv("remote_port", config.port.to_string())
        .list("vips", ["0.0.0.0"])
        .kv("dpd_delay", format!("{}s", config.dpd_delay))
        .kv("fragmentation", "yes")
        .kv("encap", if config.udp_encap { "yes" } else { "no" })
        .kv("keyingtries", "1")
        .list("proposals", split_list(ike_proposals))
        .section("local", local)
        .section("remote", remote)
        .section("children", child_sections);
    Ok(Section::new().section(CONN_NAME, conn))
}

/// The `initiate` message for one CHILD_SA.
pub(crate) fn initiate(child: &Child) -> Section {
    Section::new()
        .kv("child", &child.name)
        .kv("ike", CONN_NAME)
        .kv("timeout", INITIATE_TIMEOUT_MS.to_string())
        .kv("loglevel", log_level().to_string())
}

/// The `terminate` message for our IKE_SA. With `force`, charon sends a
/// DELETE but does not wait longer than `timeout_ms` for the answer; a
/// negative timeout returns at once.
pub(crate) fn terminate(force: bool, timeout_ms: i32) -> Section {
    let message = Section::new()
        .kv("ike", CONN_NAME)
        .kv("timeout", timeout_ms.to_string())
        .kv("loglevel", log_level().to_string());
    if force {
        message.kv("force", "yes")
    } else {
        message
    }
}

/// The charon log level to stream while a command runs, from our own
/// verbosity.
fn log_level() -> u8 {
    if tracing::enabled!(tracing::Level::TRACE) {
        4
    } else if tracing::enabled!(tracing::Level::DEBUG) {
        2
    } else {
        1
    }
}

/// Checks the `success` flag of a command response.
pub(crate) fn check(response: &Section, what: &'static str) -> Result<()> {
    if response.get_str(&["success"]) == Some("yes") {
        return Ok(());
    }
    Err(Error::Command {
        what,
        message: response
            .get_str(&["errmsg"])
            .unwrap_or("unknown error")
            .to_owned(),
    })
}

/// A charon log line received through a `control-log` or `log` event.
pub(crate) struct LogLine<'a> {
    pub(crate) level: u8,
    pub(crate) group: &'a str,
    pub(crate) text: &'a str,
    pub(crate) ike_sa: Option<&'a str>,
}

impl<'a> LogLine<'a> {
    pub(crate) fn parse(event: &'a Event) -> Option<Self> {
        let message = &event.message;
        Some(Self {
            level: message
                .get_str(&["level"])
                .and_then(|level| level.parse().ok())
                .unwrap_or(1),
            group: message.get_str(&["group"]).unwrap_or("?"),
            text: message.get_str(&["msg"])?,
            ike_sa: message.get_str(&["ikesa-name"]),
        })
    }

    /// Whether the line explains a failure.
    pub(crate) fn is_failure_hint(&self) -> bool {
        self.level <= 1
            && FAILURE_KEYWORDS
                .iter()
                .any(|keyword| self.text.contains(keyword))
    }

    /// Relays the line to our own log at the matching verbosity.
    pub(crate) fn relay(&self) {
        match self.level {
            0 => tracing::info!("charon: {}", self.text),
            1 => tracing::debug!("charon[{}]: {}", self.group, self.text),
            _ => tracing::trace!("charon[{}]: {}", self.group, self.text),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            gateway: "vpn.example.com".into(),
            port: 500,
            auth: ofv_ikev2::Auth::EapMschapv2,
            username: "alice".into(),
            password: Some("secret".into()),
            psk: Some("psk".into()),
            local_id: None,
            remote_id: None,
            ike_proposals: None,
            esp_proposals: Some("aes256-sha256, aes128-sha1".into()),
            split_include: vec![],
            udp_encap: false,
            dpd_delay: 30,
            vici_socket: None,
            ca_file: None,
            user_cert: None,
            user_key: None,
            pem_passphrase: None,
            set_dns: true,
            set_routes: true,
            tun_name: None,
            saml_port: None,
            saml_gateway_port: 1001,
            trusted_certs: Vec::new(),
        }
    }

    #[test]
    fn plans_children() {
        let single = Child::plan(&[]);
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].name, CONN_NAME);
        assert_eq!(single[0].remote_ts, "0.0.0.0/0");
        let split = Child::plan(&["10.0.0.0/8".into(), "192.168.1.0/24".into()]);
        let names: Vec<&str> = split.iter().map(|child| child.name.as_str()).collect();
        assert_eq!(names, ["openfortivpn-1", "openfortivpn-2"]);
    }

    #[test]
    fn builds_the_connection() {
        let config = config();
        let children = Child::plan(&config.split_include);
        let message = connection(&config, &children).expect("connection");
        assert_eq!(message.get_str(&[CONN_NAME, "version"]), Some("2"));
        assert_eq!(
            message.get_str(&[CONN_NAME, "local", "auth"]),
            Some("eap-mschapv2")
        );
        assert_eq!(
            message.get_str(&[CONN_NAME, "local", "eap_id"]),
            Some("alice")
        );
        assert_eq!(message.get_str(&[CONN_NAME, "remote", "auth"]), Some("psk"));
        assert_eq!(message.get_str(&[CONN_NAME, "remote", "id"]), Some("%any"));
        let esp: Vec<&str> = message
            .get_str_list(&[CONN_NAME, "children", CONN_NAME, "esp_proposals"])
            .collect();
        assert_eq!(esp, ["aes256-sha256", "aes128-sha1"]);
        assert!(message.get_str_list(&[CONN_NAME, "proposals"]).count() > 5);
    }

    #[test]
    fn gateway_certificate_switches_to_pubkey() {
        let mut config = config();
        config.ca_file = Some("/nonexistent/ca.pem".into());
        assert!(config.gateway_uses_cert());
        assert!(!config.needs_psk());
        assert!(matches!(
            connection(&config, &Child::plan(&[])),
            Err(Error::Credentials(_))
        ));
        config.ca_file = None;
        config.remote_id = Some("gw".into());
        let message = connection(&config, &Child::plan(&[])).expect("connection");
        assert_eq!(message.get_str(&[CONN_NAME, "remote", "id"]), Some("gw"));
    }

    #[test]
    fn detects_failure_hints() {
        let event = Event {
            name: "control-log".into(),
            message: Section::new()
                .kv("level", "1")
                .kv("group", "IKE")
                .kv("msg", "received AUTHENTICATION_FAILED notify"),
        };
        let line = LogLine::parse(&event).expect("line");
        assert!(line.is_failure_hint());
        let event = Event {
            name: "control-log".into(),
            message: Section::new().kv("level", "1").kv("msg", "sending packet"),
        };
        assert!(!LogLine::parse(&event).expect("line").is_failure_hint());
    }
}
