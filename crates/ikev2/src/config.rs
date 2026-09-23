use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use secrecy::SecretString;

use crate::{Error, Result};

/// How the client authenticates to the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Auth {
    /// Pre-shared key for the gateway, EAP-MSCHAPv2 for the user
    /// (FortiClient's default).
    #[default]
    EapMschapv2,
    /// Pre-shared key for the gateway, EAP-GTC for the user.
    EapGtc,
    /// Pre-shared key for the gateway, EAP-MD5 for the user.
    EapMd5,
    /// Pre-shared key on both sides, no user authentication.
    Psk,
    /// Client certificate; the gateway uses a certificate too.
    Pubkey,
}

impl Auth {
    /// The strongSwan name of the local authentication method.
    #[must_use]
    pub fn charon_name(self) -> &'static str {
        match self {
            Auth::EapMschapv2 => "eap-mschapv2",
            Auth::EapGtc => "eap-gtc",
            Auth::EapMd5 => "eap-md5",
            Auth::Psk => "psk",
            Auth::Pubkey => "pubkey",
        }
    }

    /// Whether the user authenticates with an EAP method.
    #[must_use]
    pub fn is_eap(self) -> bool {
        matches!(self, Auth::EapMschapv2 | Auth::EapGtc | Auth::EapMd5)
    }
}

impl std::str::FromStr for Auth {
    type Err = String;

    fn from_str(name: &str) -> std::result::Result<Self, Self::Err> {
        match name.to_ascii_lowercase().as_str() {
            "eap-mschapv2" => Ok(Auth::EapMschapv2),
            "eap-gtc" => Ok(Auth::EapGtc),
            "eap-md5" => Ok(Auth::EapMd5),
            "psk" => Ok(Auth::Psk),
            "pubkey" | "cert" => Ok(Auth::Pubkey),
            other => Err(format!("unknown IPsec authentication method \"{other}\"")),
        }
    }
}

/// Settings of an IPsec tunnel.
#[derive(Debug, Clone)]
pub struct Config {
    /// Gateway host name or address.
    pub gateway: String,
    /// IKE port of the gateway, 500 unless the gateway listens elsewhere.
    pub port: u16,
    pub auth: Auth,
    /// EAP identity (user name) for the EAP methods.
    pub username: String,
    /// EAP secret (user password) for the EAP methods.
    pub password: Option<SecretString>,
    /// Pre-shared key of the gateway.
    pub psk: Option<SecretString>,
    /// IKE identity sent to the gateway (FortiClient "Local ID").
    pub local_id: Option<String>,
    /// IKE identity expected from the gateway.
    pub remote_id: Option<String>,
    /// IKE proposals in strongSwan syntax, comma separated.
    pub ike_proposals: Option<String>,
    /// ESP proposals in strongSwan syntax, comma separated.
    pub esp_proposals: Option<String>,
    /// Networks to route through the tunnel; everything when empty.
    pub split_include: Vec<String>,
    /// Force ESP-in-UDP encapsulation (the native backend always uses it).
    pub udp_encap: bool,
    /// Dead peer detection interval in seconds, 0 to disable.
    pub dpd_delay: u32,
    /// Path of charon's vici socket; a platform default when `None`.
    pub vici_socket: Option<PathBuf>,
    /// CA bundle authenticating the gateway certificate.
    pub ca_file: Option<PathBuf>,
    /// Client certificate (PEM) for [`Auth::Pubkey`].
    pub user_cert: Option<PathBuf>,
    /// Client private key (PEM) for [`Auth::Pubkey`].
    pub user_key: Option<PathBuf>,
    /// Passphrase of an encrypted client private key.
    pub pem_passphrase: Option<SecretString>,
    /// Whether the user expects the VPN nameservers to be configured.
    pub set_dns: bool,
    /// Whether routes to the tunnel are installed (native backend).
    pub set_routes: bool,
    /// Name to give the tunnel interface (native backend).
    pub tun_name: Option<String>,
    /// SAML login (native backend): the port of the local server the
    /// browser is sent back to; the EAP credentials then come from the
    /// gateway's SAML login rather than `username`/`password`.
    pub saml_port: Option<u16>,
    /// HTTPS port of the gateway's SAML login (FortiOS `auth-ike-saml-port`,
    /// 1001 by default).
    pub saml_gateway_port: u16,
    /// SHA-256 digests (hex) of gateway certificates accepted as such on
    /// the HTTPS side (`trusted-cert`).
    pub trusted_certs: Vec<String>,
}

impl Config {
    /// Whether the gateway authenticates with a certificate rather than the
    /// pre-shared key.
    #[must_use]
    pub fn gateway_uses_cert(&self) -> bool {
        self.auth == Auth::Pubkey || self.ca_file.is_some()
    }

    /// Whether a pre-shared key is needed.
    #[must_use]
    pub fn needs_psk(&self) -> bool {
        self.auth == Auth::Psk || !self.gateway_uses_cert()
    }

    /// Checks everything but the secrets, which may still be asked for.
    pub fn validate_settings(&self) -> Result<()> {
        if self.gateway.is_empty() {
            return Err(Error::Config("no gateway host given".into()));
        }
        if self.auth.is_eap() && self.username.is_empty() && self.saml_port.is_none() {
            return Err(Error::Config("EAP authentication needs a username".into()));
        }
        if self.auth == Auth::Pubkey && (self.user_cert.is_none() || self.user_key.is_none()) {
            return Err(Error::Config(
                "certificate authentication needs a client certificate and key".into(),
            ));
        }
        for network in &self.split_include {
            parse_network(network)?;
        }
        Ok(())
    }

    /// The `split_include` networks, which the native backend routes
    /// through one CHILD SA each (IPv4 only).
    pub(crate) fn split_networks(&self) -> Result<Vec<(Ipv4Addr, u8)>> {
        self.split_include
            .iter()
            .map(|network| match parse_network(network)? {
                (IpAddr::V4(address), prefix) => Ok((address, prefix)),
                (IpAddr::V6(_), _) => Err(Error::Config(format!(
                    "split-include network {network} is not IPv4: this backend does IPv4 only"
                ))),
            })
            .collect()
    }

    /// Checks the settings and the presence of the secrets they need.
    pub fn validate(&self) -> Result<()> {
        self.validate_settings()?;
        if self.auth.is_eap() && self.password.is_none() && self.saml_port.is_none() {
            return Err(Error::Config("EAP authentication needs a password".into()));
        }
        if self.needs_psk() && self.psk.is_none() {
            return Err(Error::Config("a pre-shared key is needed".into()));
        }
        Ok(())
    }
}

/// An IP address with an optional prefix length (a host without one).
fn parse_network(network: &str) -> Result<(IpAddr, u8)> {
    let invalid = || Error::Config(format!("Invalid split-include network: \"{network}\""));
    let (address, prefix) = match network.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (network, None),
    };
    let address: IpAddr = address.parse().map_err(|_| invalid())?;
    let max = if address.is_ipv4() { 32 } else { 128 };
    let bits = match prefix {
        Some(prefix) => prefix
            .parse()
            .ok()
            .filter(|bits| *bits <= max)
            .ok_or_else(invalid)?,
        None => max,
    };
    Ok((address, bits))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networks_are_validated() {
        assert_eq!(
            parse_network("10.0.0.0/8").expect("network"),
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)
        );
        assert_eq!(parse_network("10.0.0.1").expect("host").1, 32);
        assert_eq!(parse_network("fd00::/64").expect("network").1, 64);
        assert!(parse_network("10.0.0.0/33").is_err());
        assert!(parse_network("fd00::/129").is_err());
        assert!(parse_network("10.0.0/8").is_err());
        assert!(parse_network("10.0.0.0/x").is_err());
    }

    #[test]
    fn auth_names_round_trip() {
        for auth in [
            Auth::EapMschapv2,
            Auth::EapGtc,
            Auth::EapMd5,
            Auth::Psk,
            Auth::Pubkey,
        ] {
            assert_eq!(auth.charon_name().parse::<Auth>(), Ok(auth));
        }
        assert_eq!("CERT".parse::<Auth>(), Ok(Auth::Pubkey));
        assert!("xauth".parse::<Auth>().is_err());
    }
}
