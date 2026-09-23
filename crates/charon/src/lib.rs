#![forbid(unsafe_code)]

mod charon;
mod error;
mod tunnel;

pub use error::Error;
pub use ofv_ikev2::{Auth, Config};
pub use tunnel::{Outcome, run};

pub type Result<T> = std::result::Result<T, Error>;
