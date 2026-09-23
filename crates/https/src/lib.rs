#![forbid(unsafe_code)]

pub mod http;
pub mod redirect;
pub mod tls;

use std::path::PathBuf;

use secrecy::SecretString;

pub use tls::{Connector, MinTls, TlsStream};

/// Errors of the HTTPS client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Config(String),
    /// A credential file could not be read or parsed.
    #[error(transparent)]
    Credentials(#[from] ofv_pki::Error),
    /// The TLS client could not be set up.
    #[error("TLS setup failed: {0}")]
    Tls(rustls::Error),
    /// The gateway (or the proxy) could not be reached.
    #[error("could not connect to {what}: {source}")]
    Connect {
        /// What was being connected to.
        what: String,
        source: std::io::Error,
    },
    /// The proxy refused the CONNECT request.
    #[error("the proxy refused the connection: {0}")]
    Proxy(String),
    /// The gateway certificate is not trusted.
    #[error("the gateway certificate is not trusted")]
    Certificate,
    #[error("TLS connection failed: {0}")]
    Io(#[from] std::io::Error),
    /// The gateway answered something that is not HTTP.
    #[error("bad HTTP response from the gateway: {0}")]
    Http(String),
    /// The gateway returned an unexpected status.
    #[error("the gateway answered {0}")]
    Status(u16),
    /// The browser did not bring a valid redirect.
    #[error("browser login failed: {0}")]
    Redirect(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// How to reach the gateway's web side.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Gateway host name or address.
    pub gateway: String,
    pub port: u16,
    /// TLS server name, when different from the gateway host.
    pub sni: Option<String>,
    /// Interface the connection is sent through.
    pub bind_interface: Option<String>,
    /// SHA-256 digests (hex) of gateway certificates accepted as such.
    pub trusted_certs: Vec<String>,
    /// Lowest TLS version accepted.
    pub min_tls: MinTls,
    /// CA bundle authenticating the gateway certificate.
    pub ca_file: Option<PathBuf>,
    /// Client certificate (PEM).
    pub user_cert: Option<PathBuf>,
    /// Client private key (PEM).
    pub user_key: Option<PathBuf>,
    /// Passphrase of an encrypted client private key.
    pub pem_passphrase: Option<SecretString>,
    /// `User-Agent` sent with every request.
    pub user_agent: String,
}
