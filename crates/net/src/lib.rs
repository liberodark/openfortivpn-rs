#![forbid(unsafe_code)]

mod command;
mod dns;
mod routes;
mod tun;

pub use dns::{Dns, DnsTool};
pub use routes::Routes;
pub use tun::Tun;

/// What went wrong on the host side.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not create the TUN device: {0}")]
    Tun(std::io::Error),
    #[error("could not run {command}: {source}")]
    Spawn {
        command: String,
        source: std::io::Error,
    },
    #[error("{command} failed: {stderr}")]
    Command { command: String, stderr: String },
    #[error("cannot parse the output of {command}: {output}")]
    Parse { command: String, output: String },
    #[error("could not update {path}: {source}")]
    Resolver {
        path: String,
        source: std::io::Error,
    },
}

pub type Result<T> = std::result::Result<T, Error>;
