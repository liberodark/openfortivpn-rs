/// Errors of the native IKEv2 mode.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Config(String),
    /// A credential file could not be read or parsed.
    #[error(transparent)]
    Credentials(#[from] ofv_pki::Error),
    #[error("cryptography: {0}")]
    Crypto(String),
    /// A message from the gateway could not be parsed.
    #[error("malformed message from the gateway: {0}")]
    Malformed(String),
    /// The gateway answered with an error notification.
    #[error("the gateway answered {0}")]
    Notify(String),
    /// The gateway did not answer.
    #[error("the gateway did not answer: {0}")]
    Timeout(String),
    /// The gateway ended the session.
    #[error("the tunnel went down: {0}")]
    Down(String),
    #[error("interrupted")]
    Interrupted,
    #[error("authentication failed: {0}")]
    Authentication(String),
    /// The gateway could not be reached.
    #[error("could not connect to {what}: {source}")]
    Connect {
        /// What was being connected to.
        what: String,
        source: std::io::Error,
    },
    #[error("network: {0}")]
    Io(#[from] std::io::Error),
    /// The host side (TUN device, routes, DNS) failed.
    #[error(transparent)]
    Net(#[from] ofv_net::Error),
    /// The gateway's web side, for the SAML login.
    #[error(transparent)]
    Https(#[from] ofv_https::Error),
    /// The SAML login did not produce credentials.
    #[error("SAML login failed: {0}")]
    Saml(String),
}
