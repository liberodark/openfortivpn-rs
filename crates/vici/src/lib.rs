#![forbid(unsafe_code)]

mod client;
mod error;
mod message;
mod packet;

pub use client::{Client, Event};
pub use error::Error;
pub use message::{ANY, Item, Section};
pub use packet::Packet;

pub type Result<T> = std::result::Result<T, Error>;

/// Largest message charon accepts or sends, in bytes.
pub const MESSAGE_SIZE_MAX: usize = 512 * 1024;
