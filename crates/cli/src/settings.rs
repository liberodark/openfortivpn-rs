use std::path::{Path, PathBuf};

use ofv_https::MinTls;
use ofv_ikev2::Auth;
use ofv_sslvpn::{DnsSetup, Routing};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

/// Where openfortivpn looks for its configuration file by default.
pub const DEFAULT_CONFIG: &str = "/etc/openfortivpn/config";

const HTTPS_PORT: u16 = 443;
const IKE_PORT: u16 = 500;
/// FortiOS `auth-ike-saml-port`: where FortiClient's IPsec SAML login goes.
const IKE_SAML_PORT: u16 = 1001;
const DPD_DELAY: u32 = 30;

/// Every option, unset unless given. The command line and the file produce
/// one each, then [`Settings::merge`] combines them.
#[derive(Debug, Default)]
pub struct Settings {
    pub protocol: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    /// An empty password means "no password", not "ask".
    pub password: Option<SecretString>,
    pub pinentry: Option<String>,
    pub realm: Option<String>,
    pub otp: Option<SecretString>,
    pub otp_prompt: Option<String>,
    pub otp_delay: Option<u32>,
    pub no_ftm_push: Option<bool>,
    pub cookie: Option<SecretString>,
    pub saml_login: Option<u16>,
    pub ifname: Option<String>,
    pub tun_name: Option<String>,
    pub set_routes: Option<bool>,
    pub half_internet_routes: Option<bool>,
    pub set_dns: Option<bool>,
    pub use_resolvconf: Option<bool>,
    pub peer_dns: Option<bool>,
    pub sni: Option<String>,
    pub trusted_certs: Vec<String>,
    pub insecure_ssl: Option<bool>,
    pub min_tls: Option<MinTls>,
    pub user_agent: Option<String>,
    pub hostcheck: Option<String>,
    pub check_virtual_desktop: Option<String>,
    pub persistent: Option<u32>,
    pub ca_file: Option<PathBuf>,
    pub user_cert: Option<PathBuf>,
    pub user_key: Option<PathBuf>,
    pub pem_passphrase: Option<SecretString>,
    pub ipsec_psk: Option<SecretString>,
    pub ipsec_auth: Option<Auth>,
    pub ipsec_local_id: Option<String>,
    pub ipsec_remote_id: Option<String>,
    pub ipsec_ike_proposals: Option<String>,
    pub ipsec_esp_proposals: Option<String>,
    pub ipsec_split_include: Option<String>,
    pub ipsec_vici_socket: Option<PathBuf>,
    pub ipsec_udp_encap: Option<bool>,
    pub ipsec_dpd_delay: Option<u32>,
    pub ipsec_backend: Option<Backend>,
    pub ipsec_saml_port: Option<u16>,
}

/// What runs the IKEv2/IPsec tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Backend {
    /// The IKEv2 and ESP implementation of this program.
    #[default]
    Native,
    /// A strongSwan charon daemon, driven through its vici socket.
    Charon,
}

impl std::str::FromStr for Backend {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name.to_ascii_lowercase().as_str() {
            "native" => Ok(Backend::Native),
            "charon" | "strongswan" => Ok(Backend::Charon),
            other => Err(format!(
                "unknown IPsec backend \"{other}\" (native or charon)"
            )),
        }
    }
}

/// The tunnel configuration of the selected protocol.
#[derive(Debug)]
pub enum Mode {
    Sslvpn(ofv_sslvpn::Config),
    Ipsec(ofv_ikev2::Config, Backend),
}

/// A problem in the configuration file or the settings.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not read configuration file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path}:{line}: {message}")]
    Parse {
        path: PathBuf,
        line: usize,
        message: String,
    },
    #[error("{0}")]
    Invalid(String),
}

impl Settings {
    /// Reads a configuration file. Unknown options are reported and
    /// ignored.
    pub fn from_file(path: &Path) -> Result<Self, Error> {
        // The file may hold secrets: wipe the buffer afterwards.
        let text = std::fs::read_to_string(path)
            .map(Zeroizing::new)
            .map_err(|source| Error::Read {
                path: path.to_path_buf(),
                source,
            })?;
        let mut settings = Self::default();
        for (index, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parse_error = |message: String| Error::Parse {
                path: path.to_path_buf(),
                line: index + 1,
                message,
            };
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| parse_error(format!("bad line \"{line}\"")))?;
            settings
                .set(key.trim(), value.trim())
                .map_err(parse_error)?;
        }
        Ok(settings)
    }

    /// Applies one `key = value` option.
    fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
        let bool_value = || parse_bool(value).ok_or_else(|| format!("bad boolean \"{value}\""));
        match key {
            "protocol" => self.protocol = Some(value.to_owned()),
            "host" => self.host = Some(value.to_owned()),
            "port" => self.port = Some(parse_port(value)?),
            "username" => self.username = Some(value.to_owned()),
            "password" => self.password = Some(value.into()),
            "pinentry" => self.pinentry = Some(value.to_owned()),
            "realm" => self.realm = Some(value.to_owned()),
            "otp" => self.otp = Some(value.into()),
            "otp-prompt" => self.otp_prompt = Some(value.to_owned()),
            "otp-delay" => self.otp_delay = Some(parse_number(value, key)?),
            "no-ftm-push" => self.no_ftm_push = Some(bool_value()?),
            "cookie" => self.cookie = Some(ofv_sslvpn::normalize_cookie(value)),
            "saml-login" => self.saml_login = Some(parse_saml_port(value)?),
            "ifname" => self.ifname = Some(value.to_owned()),
            "pppd-ifname" => self.tun_name = Some(value.to_owned()),
            "set-routes" => self.set_routes = Some(bool_value()?),
            "half-internet-routes" => self.half_internet_routes = Some(bool_value()?),
            "set-dns" => self.set_dns = Some(bool_value()?),
            "use-resolvconf" => self.use_resolvconf = Some(bool_value()?),
            "pppd-use-peerdns" => self.peer_dns = Some(bool_value()?),
            "pppd-no-peerdns" => self.peer_dns = Some(!bool_value()?),
            "sni" => self.sni = Some(value.to_owned()),
            "trusted-cert" => self.trusted_certs.push(value.to_owned()),
            "insecure-ssl" => self.insecure_ssl = Some(bool_value()?),
            "min-tls" => self.min_tls = Some(value.parse()?),
            "user-agent" => self.user_agent = Some(value.to_owned()),
            "hostcheck" => self.hostcheck = Some(value.to_owned()),
            "check-virtual-desktop" => self.check_virtual_desktop = Some(value.to_owned()),
            "persistent" => self.persistent = Some(parse_number(value, key)?),
            "ca-file" => self.ca_file = Some(value.into()),
            "user-cert" => self.user_cert = Some(value.into()),
            "user-key" => self.user_key = Some(value.into()),
            "pem-passphrase" => self.pem_passphrase = Some(value.into()),
            "ipsec-psk" => self.ipsec_psk = Some(value.into()),
            "ipsec-auth" => self.ipsec_auth = Some(value.parse()?),
            "ipsec-local-id" => self.ipsec_local_id = Some(value.to_owned()),
            "ipsec-remote-id" => self.ipsec_remote_id = Some(value.to_owned()),
            "ipsec-ike-proposals" => self.ipsec_ike_proposals = Some(value.to_owned()),
            "ipsec-esp-proposals" => self.ipsec_esp_proposals = Some(value.to_owned()),
            "ipsec-split-include" => self.ipsec_split_include = Some(value.to_owned()),
            "ipsec-vici-socket" => self.ipsec_vici_socket = Some(value.into()),
            "ipsec-udp-encap" => self.ipsec_udp_encap = Some(bool_value()?),
            "ipsec-dpd-delay" => self.ipsec_dpd_delay = Some(parse_number(value, key)?),
            "ipsec-backend" => self.ipsec_backend = Some(value.parse()?),
            "ipsec-saml-port" => self.ipsec_saml_port = Some(parse_port(value)?),
            "cipher-list" | "seclevel-1" | "use-syslog" | "pppd-log" | "pppd-plugin"
            | "pppd-ipparam" | "pppd-call" | "pppd-accept-remote" | "pppd" | "ppp-system" => {
                tracing::warn!("ignoring option \"{key}\": not applicable to this version");
            }
            other => tracing::warn!("ignoring unknown option \"{other}\""),
        }
        Ok(())
    }

    /// Combines two sets of settings, `other` taking precedence.
    #[must_use]
    pub fn merge(self, other: Self) -> Self {
        let mut trusted_certs = self.trusted_certs;
        trusted_certs.extend(other.trusted_certs);
        Self {
            protocol: other.protocol.or(self.protocol),
            host: other.host.or(self.host),
            port: other.port.or(self.port),
            username: other.username.or(self.username),
            password: other.password.or(self.password),
            pinentry: other.pinentry.or(self.pinentry),
            realm: other.realm.or(self.realm),
            otp: other.otp.or(self.otp),
            otp_prompt: other.otp_prompt.or(self.otp_prompt),
            otp_delay: other.otp_delay.or(self.otp_delay),
            no_ftm_push: other.no_ftm_push.or(self.no_ftm_push),
            cookie: other.cookie.or(self.cookie),
            saml_login: other.saml_login.or(self.saml_login),
            ifname: other.ifname.or(self.ifname),
            tun_name: other.tun_name.or(self.tun_name),
            set_routes: other.set_routes.or(self.set_routes),
            half_internet_routes: other.half_internet_routes.or(self.half_internet_routes),
            set_dns: other.set_dns.or(self.set_dns),
            use_resolvconf: other.use_resolvconf.or(self.use_resolvconf),
            peer_dns: other.peer_dns.or(self.peer_dns),
            sni: other.sni.or(self.sni),
            trusted_certs,
            insecure_ssl: other.insecure_ssl.or(self.insecure_ssl),
            min_tls: other.min_tls.or(self.min_tls),
            user_agent: other.user_agent.or(self.user_agent),
            hostcheck: other.hostcheck.or(self.hostcheck),
            check_virtual_desktop: other.check_virtual_desktop.or(self.check_virtual_desktop),
            persistent: other.persistent.or(self.persistent),
            ca_file: other.ca_file.or(self.ca_file),
            user_cert: other.user_cert.or(self.user_cert),
            user_key: other.user_key.or(self.user_key),
            pem_passphrase: other.pem_passphrase.or(self.pem_passphrase),
            ipsec_psk: other.ipsec_psk.or(self.ipsec_psk),
            ipsec_auth: other.ipsec_auth.or(self.ipsec_auth),
            ipsec_local_id: other.ipsec_local_id.or(self.ipsec_local_id),
            ipsec_remote_id: other.ipsec_remote_id.or(self.ipsec_remote_id),
            ipsec_ike_proposals: other.ipsec_ike_proposals.or(self.ipsec_ike_proposals),
            ipsec_esp_proposals: other.ipsec_esp_proposals.or(self.ipsec_esp_proposals),
            ipsec_split_include: other.ipsec_split_include.or(self.ipsec_split_include),
            ipsec_vici_socket: other.ipsec_vici_socket.or(self.ipsec_vici_socket),
            ipsec_udp_encap: other.ipsec_udp_encap.or(self.ipsec_udp_encap),
            ipsec_dpd_delay: other.ipsec_dpd_delay.or(self.ipsec_dpd_delay),
            ipsec_backend: other.ipsec_backend.or(self.ipsec_backend),
            ipsec_saml_port: other.ipsec_saml_port.or(self.ipsec_saml_port),
        }
    }

    /// Turns the settings into a tunnel configuration, applying defaults.
    /// Secrets that are still missing are left unset for the caller to ask
    /// for.
    pub fn into_config(self) -> Result<Mode, Error> {
        match self.protocol.as_deref() {
            None | Some("sslvpn") => self.into_sslvpn().map(Mode::Sslvpn),
            Some("ipsec") => {
                let backend = self.ipsec_backend.unwrap_or_default();
                self.into_ipsec(backend)
                    .map(|config| Mode::Ipsec(config, backend))
            }
            Some(other) => Err(Error::Invalid(format!("unknown protocol \"{other}\""))),
        }
    }

    fn gateway(&self) -> Result<String, Error> {
        self.host
            .clone()
            .ok_or_else(|| Error::Invalid("specify a gateway host".into()))
    }

    fn into_sslvpn(self) -> Result<ofv_sslvpn::Config, Error> {
        let gateway = self.gateway()?;
        if self.ipsec_psk.is_some() || self.ipsec_auth.is_some() {
            tracing::warn!("Ignoring the ipsec-* options: the protocol is sslvpn.");
        }
        if self.insecure_ssl == Some(true) {
            tracing::warn!(
                "insecure-ssl has no effect: this version only speaks TLS 1.2 and 1.3 with secure cipher suites."
            );
        }
        Ok(ofv_sslvpn::Config {
            https: ofv_https::Settings {
                gateway,
                port: self.port.unwrap_or(HTTPS_PORT),
                sni: self.sni,
                bind_interface: self.ifname,
                trusted_certs: self.trusted_certs,
                min_tls: self.min_tls.unwrap_or_default(),
                ca_file: self.ca_file,
                user_cert: self.user_cert,
                user_key: self.user_key,
                pem_passphrase: self.pem_passphrase,
                user_agent: self
                    .user_agent
                    .unwrap_or_else(|| ofv_sslvpn::USER_AGENT.to_owned()),
            },
            username: self.username.unwrap_or_default(),
            password: self.password,
            realm: self.realm.unwrap_or_default(),
            otp: self.otp,
            otp_prompt: self.otp_prompt,
            otp_delay: self.otp_delay.unwrap_or(0),
            ftm_push: !self.no_ftm_push.unwrap_or(false),
            cookie: self.cookie,
            saml_port: self.saml_login,
            tun_name: self.tun_name,
            routing: match (
                self.set_routes.unwrap_or(true),
                self.half_internet_routes.unwrap_or(false),
            ) {
                (false, _) => Routing::Off,
                (true, false) => Routing::Default,
                (true, true) => Routing::HalfInternet,
            },
            dns: match (
                self.set_dns.unwrap_or(true),
                self.use_resolvconf.unwrap_or(true),
            ) {
                (false, _) => DnsSetup::Off,
                (true, true) => DnsSetup::Auto,
                (true, false) => DnsSetup::File,
            },
            peer_dns: self.peer_dns.unwrap_or(false),
            hostcheck: self.hostcheck,
            check_virtual_desktop: self.check_virtual_desktop,
        })
    }

    fn into_ipsec(self, backend: Backend) -> Result<ofv_ikev2::Config, Error> {
        let gateway = self.gateway()?;
        if self.cookie.is_some() {
            return Err(Error::Invalid(
                "The session cookie is specific to the SSL VPN protocol.".into(),
            ));
        }
        if self.saml_login.is_some() && backend == Backend::Charon {
            return Err(Error::Invalid(
                "The SAML login is only available with the native IPsec backend.".into(),
            ));
        }
        if self.realm.is_some_and(|realm| !realm.is_empty()) {
            tracing::warn!(
                "Ignoring realm: IKEv2 has no authentication realm, the gateway maps the EAP identity to a user group."
            );
        }
        if !self.trusted_certs.is_empty() && self.saml_login.is_none() {
            tracing::warn!(
                "Ignoring trusted-cert: use --ca-file to authenticate the gateway certificate in IPsec mode."
            );
        }
        if self.ifname.is_some() {
            tracing::warn!("Ignoring ifname: not applicable to the IPsec mode.");
        }
        if backend == Backend::Native {
            if self.ipsec_vici_socket.is_some() {
                tracing::warn!(
                    "Ignoring ipsec-vici-socket: the native backend does not use charon."
                );
            }
            if self.ipsec_udp_encap == Some(false) {
                tracing::warn!(
                    "Ignoring ipsec-udp-encap: the native backend always encapsulates ESP in UDP."
                );
            }
        }
        Ok(ofv_ikev2::Config {
            gateway,
            port: self.port.unwrap_or(IKE_PORT),
            auth: self.ipsec_auth.unwrap_or_default(),
            username: self.username.unwrap_or_default(),
            // An empty EAP secret is never what is meant.
            password: self
                .password
                .filter(|password| !password.expose_secret().is_empty()),
            psk: self.ipsec_psk,
            local_id: self.ipsec_local_id,
            remote_id: self.ipsec_remote_id,
            ike_proposals: self.ipsec_ike_proposals,
            esp_proposals: self.ipsec_esp_proposals,
            split_include: self
                .ipsec_split_include
                .map(|list| {
                    list.split([',', ' '])
                        .filter(|item| !item.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            udp_encap: self.ipsec_udp_encap.unwrap_or(false),
            dpd_delay: self.ipsec_dpd_delay.unwrap_or(DPD_DELAY),
            vici_socket: self.ipsec_vici_socket,
            ca_file: self.ca_file,
            user_cert: self.user_cert,
            user_key: self.user_key,
            pem_passphrase: self.pem_passphrase,
            set_dns: self.set_dns.unwrap_or(true),
            set_routes: self.set_routes.unwrap_or(true),
            tun_name: self.tun_name,
            saml_port: self.saml_login,
            saml_gateway_port: self.ipsec_saml_port.unwrap_or(IKE_SAML_PORT),
            trusted_certs: self.trusted_certs,
        })
    }
}

/// Parses `host[:port]` as given on the command line.
pub fn parse_host(spec: &str) -> Result<(String, Option<u16>), String> {
    match spec.rsplit_once(':') {
        // An IPv6 literal without brackets contains several colons.
        Some((host, port)) if !host.contains(':') => Ok((host.to_owned(), Some(parse_port(port)?))),
        _ => Ok((spec.to_owned(), None)),
    }
}

/// Parses a boolean the way openfortivpn does: `0`/`1`, `true`/`false`.
pub fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" => Some(true),
        "0" | "false" | "" => Some(false),
        _ => None,
    }
}

fn parse_port(value: &str) -> Result<u16, String> {
    match value.parse::<u16>() {
        Ok(port) if port > 0 => Ok(port),
        _ => Err(format!("bad port \"{value}\"")),
    }
}

/// The port of `saml-login[=port]`; empty and `1` mean the default.
pub fn parse_saml_port(value: &str) -> Result<u16, String> {
    match value {
        "" | "1" => Ok(ofv_sslvpn::SAML_PORT),
        port => parse_port(port).map_err(|_| {
            format!(
                "Invalid saml listen port: {port}! Default port is {}",
                ofv_sslvpn::SAML_PORT
            )
        }),
    }
}

fn parse_number(value: &str, what: &str) -> Result<u32, String> {
    value
        .parse()
        .map_err(|_| format!("bad value for {what}: \"{value}\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_specs() {
        assert_eq!(parse_host("gw"), Ok(("gw".into(), None)));
        assert_eq!(parse_host("gw:4500"), Ok(("gw".into(), Some(4500))));
        assert_eq!(parse_host("fd00::1"), Ok(("fd00::1".into(), None)));
        assert!(parse_host("gw:0").is_err());
        assert!(parse_host("gw:x").is_err());
        assert_eq!(parse_saml_port(""), Ok(ofv_sslvpn::SAML_PORT));
        assert_eq!(parse_saml_port("8021"), Ok(8021));
        assert!(parse_saml_port("x").is_err());
    }

    #[test]
    fn reads_and_merges_files() {
        let dir = std::env::temp_dir().join(format!("ofv-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("config");
        std::fs::write(
            &path,
            "# comment\nhost = gw\nport = 4500\nusername = alice\nipsec-auth = eap-gtc\n\
             ipsec-split-include = 10.0.0.0/8, 192.168.1.0/24\nset-dns = 0\nrealm = ignored\n\
             trusted-cert = aa\ntrusted-cert = bb\npppd-log = /tmp/x\n",
        )
        .expect("write");
        let file = Settings::from_file(&path).expect("file");
        let cli = Settings {
            protocol: Some("ipsec".into()),
            port: Some(500),
            ..Settings::default()
        };
        let Mode::Ipsec(config, backend) = file.merge(cli).into_config().expect("config") else {
            panic!("expected the IPsec mode");
        };
        assert_eq!(backend, Backend::Native);
        assert_eq!(config.gateway, "gw");
        assert_eq!(config.port, 500);
        assert_eq!(config.username, "alice");
        assert_eq!(config.auth, Auth::EapGtc);
        assert_eq!(config.split_include, ["10.0.0.0/8", "192.168.1.0/24"]);
        assert!(!config.set_dns);
        assert_eq!(config.dpd_delay, DPD_DELAY);

        let file = Settings::from_file(&path).expect("file");
        let cli = Settings {
            trusted_certs: vec!["cc".into()],
            half_internet_routes: Some(true),
            ..Settings::default()
        };
        let Mode::Sslvpn(config) = file.merge(cli).into_config().expect("config") else {
            panic!("expected the SSL VPN mode");
        };
        assert_eq!(config.https.port, 4500);
        assert_eq!(config.realm, "ignored");
        assert_eq!(config.https.trusted_certs, ["aa", "bb", "cc"]);
        assert_eq!(config.routing, Routing::HalfInternet);
        assert_eq!(config.dns, DnsSetup::Off);
        assert_eq!(config.https.user_agent, ofv_sslvpn::USER_AGENT);

        std::fs::write(&path, "port = 70000\n").expect("write");
        assert!(matches!(
            Settings::from_file(&path),
            Err(Error::Parse { line: 1, .. })
        ));
        // The SAML login is for the SSL VPN and the native IPsec backend.
        std::fs::write(&path, "protocol = ipsec\nhost = gw\nsaml-login = 1\n").expect("write");
        let Mode::Ipsec(config, _) = Settings::from_file(&path)
            .expect("file")
            .into_config()
            .expect("config")
        else {
            panic!("expected the IPsec mode");
        };
        assert_eq!(config.saml_port, Some(ofv_sslvpn::SAML_PORT));
        assert_eq!(config.saml_gateway_port, IKE_SAML_PORT);
        std::fs::write(
            &path,
            "protocol = ipsec\nhost = gw\nsaml-login = 1\nipsec-backend = charon\n",
        )
        .expect("write");
        assert!(matches!(
            Settings::from_file(&path).expect("file").into_config(),
            Err(Error::Invalid(_))
        ));
        std::fs::write(&path, "protocol = ipsec\nhost = gw\ncookie = abc\n").expect("write");
        assert!(matches!(
            Settings::from_file(&path).expect("file").into_config(),
            Err(Error::Invalid(_))
        ));
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
