/// Errors of the SSL VPN mode.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Config(String),
    /// A credential file could not be read or parsed.
    #[error(transparent)]
    Credentials(#[from] ofv_pki::Error),
    /// The web side of the gateway could not be reached or understood.
    #[error(transparent)]
    Https(#[from] ofv_https::Error),
    #[error("connection failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("authentication failed")]
    Authentication,
    #[error("permission denied by the gateway")]
    PermissionDenied,
    /// The one-time password could not be obtained.
    #[error("no one-time password: {0}")]
    Otp(String),
    /// The SAML login did not produce a session.
    #[error("SAML login failed: {0}")]
    Saml(String),
    /// The VPN configuration could not be understood.
    #[error("could not parse the VPN configuration: {0}")]
    VpnConfig(String),
    #[error("PPP negotiation failed: {0}")]
    Ppp(String),
    /// The host side (TUN device, routes, DNS) failed.
    #[error(transparent)]
    Net(#[from] ofv_net::Error),
}
