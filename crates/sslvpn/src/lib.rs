#![forbid(unsafe_code)]

mod config;
mod error;
mod portal;
mod ppp;
mod saml;
mod tunnel;

pub use config::{Config, DnsSetup, Prompt, Routing, SAML_PORT, USER_AGENT};
pub use error::Error;
pub use portal::normalize_cookie;
pub use tunnel::{Outcome, run};

pub type Result<T> = std::result::Result<T, Error>;
