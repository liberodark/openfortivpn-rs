use std::future::Future;

use secrecy::{ExposeSecret, SecretString};

use crate::{Error, Result};

/// The MRU we ask for, which becomes the MTU of the tunnel interface.
pub const MTU: u16 = 1354;
/// Default `User-Agent` sent to the portal.
pub const USER_AGENT: &str = "Mozilla/5.0 SV1";
/// Default port of the local server receiving the SAML redirect.
pub const SAML_PORT: u16 = 8020;

/// Which routes send traffic into the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Routing {
    /// Leave the routing table alone.
    Off,
    /// The gateway's split routes, or the default route.
    #[default]
    Default,
    /// The gateway's split routes, or two `/1` routes covering everything
    /// (survives a DHCP renewal of the real default route).
    HalfInternet,
}

/// How the VPN nameservers are installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsSetup {
    /// Leave the resolver alone.
    Off,
    /// `resolvconf` when installed, `resolvectl` on systemd-resolved,
    /// `/etc/resolv.conf` otherwise.
    #[default]
    Auto,
    /// Always edit `/etc/resolv.conf` (openfortivpn's `use-resolvconf=0`).
    File,
}

/// Asks the user for a one-time password during the login.
pub trait Prompt {
    /// Asks for the secret described by `message`; `key_info` identifies it
    /// for a caching pinentry.
    fn secret(
        &self,
        key_info: &str,
        message: &str,
    ) -> impl Future<Output = std::result::Result<SecretString, String>>;
}

/// Settings of an SSL VPN tunnel.
#[derive(Debug, Clone)]
pub struct Config {
    /// The gateway's web side: host, port, TLS settings, `User-Agent`.
    pub https: ofv_https::Settings,
    /// VPN account user name; empty with a cookie, a SAML login or a
    /// client certificate alone.
    pub username: String,
    /// VPN account password; empty means logging in without one.
    pub password: Option<SecretString>,
    /// Authentication realm, empty by default.
    pub realm: String,
    /// One-time password given up front.
    pub otp: Option<SecretString>,
    /// Text identifying the OTP prompt in the gateway's form.
    pub otp_prompt: Option<String>,
    /// Seconds to wait before sending the OTP.
    pub otp_delay: u32,
    /// Try FortiToken Mobile push when the gateway offers it.
    pub ftm_push: bool,
    /// A `SVPNCOOKIE=...` session cookie replacing the login.
    pub cookie: Option<SecretString>,
    /// Port of the local HTTP server receiving the SAML login redirect.
    pub saml_port: Option<u16>,
    pub tun_name: Option<String>,
    pub routing: Routing,
    pub dns: DnsSetup,
    /// Ask the gateway for nameservers over IPCP (pppd's `usepeerdns`),
    /// which then take precedence over those of the XML configuration.
    pub peer_dns: bool,
    /// Value reported to the host check, when the gateway runs one.
    pub hostcheck: Option<String>,
    /// Value reported to the virtual desktop check.
    pub check_virtual_desktop: Option<String>,
}

impl Config {
    /// The password, unless it is empty.
    #[must_use]
    pub fn password(&self) -> Option<&SecretString> {
        self.password
            .as_ref()
            .filter(|password| !password.expose_secret().is_empty())
    }

    /// Whether the tunnel is set up without a user name and password.
    #[must_use]
    pub fn logs_in_without_password(&self) -> bool {
        self.cookie.is_some() || self.saml_port.is_some()
    }

    /// Checks everything but the secrets, which may still be asked for.
    pub fn validate_settings(&self) -> Result<()> {
        if self.https.gateway.is_empty() {
            return Err(Error::Config("no gateway host given".into()));
        }
        if self.username.is_empty()
            && !self.logs_in_without_password()
            && self.https.user_cert.is_none()
        {
            return Err(Error::Config("specify a username".into()));
        }
        if self.https.user_cert.is_some() != self.https.user_key.is_some() {
            return Err(Error::Config(
                "a client certificate needs its private key, and the other way round".into(),
            ));
        }
        for digest in &self.https.trusted_certs {
            if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(Error::Config(format!(
                    "Invalid trusted-cert \"{digest}\": expected a SHA-256 digest in hexadecimal"
                )));
            }
        }
        if self
            .cookie
            .as_ref()
            .is_some_and(|cookie| !crate::portal::is_cookie(cookie))
        {
            return Err(Error::Config("the cookie is empty".into()));
        }
        Ok(())
    }
}
