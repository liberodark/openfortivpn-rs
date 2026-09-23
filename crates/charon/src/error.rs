use std::path::PathBuf;

/// Errors of the IPsec mode.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Config(String),
    #[error(transparent)]
    Validation(#[from] ofv_ikev2::Error),
    /// charon's vici socket could not be opened.
    #[error(
        "could not talk to strongSwan through {path} ({source}); is charon running with the vici plugin, and are you root?"
    )]
    Connect {
        path: PathBuf,
        source: std::io::Error,
    },
    /// charon lacks a plugin this configuration needs.
    #[error("charon does not have the {0} plugin loaded")]
    MissingPlugin(String),
    /// A credential file could not be read or parsed.
    #[error(transparent)]
    Credentials(#[from] ofv_pki::Error),
    /// A vici command was refused by charon.
    #[error("{what} failed: {message}")]
    Command {
        /// What the command was doing.
        what: &'static str,
        message: String,
    },
    /// The tunnel could not be established.
    #[error("could not establish the IPsec tunnel: {message}")]
    Establish {
        message: String,
        /// Failure-related lines from charon's log.
        hints: Vec<String>,
    },
    /// The connection to charon was lost while the tunnel was up.
    #[error("lost the connection to charon: {0}")]
    Lost(#[source] ofv_vici::Error),
    /// Protocol or transport failure on the vici socket.
    #[error("vici: {0}")]
    Vici(#[from] ofv_vici::Error),
}
