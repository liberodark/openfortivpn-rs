/// Errors of the vici protocol layer and transport.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A message element name is empty or longer than 255 bytes.
    #[error("invalid element name length ({0} bytes)")]
    NameLength(usize),
    /// A value is longer than 65535 bytes.
    #[error("value too long ({0} bytes)")]
    ValueLength(usize),
    /// A message or packet exceeds [`crate::MESSAGE_SIZE_MAX`].
    #[error("message too large ({0} bytes)")]
    MessageSize(usize),
    /// Incoming data ended in the middle of an element.
    #[error("truncated message")]
    Truncated,
    /// Sections or lists are not balanced, or a list is nested.
    #[error("malformed message: {0}")]
    Malformed(&'static str),
    /// An element or packet type is not defined by the protocol.
    #[error("unknown {kind} type {value}")]
    UnknownType {
        /// "element" or "packet".
        kind: &'static str,
        /// The offending type byte.
        value: u8,
    },
    /// charon does not implement the requested command.
    #[error("charon does not know command \"{0}\"")]
    UnknownCommand(String),
    /// charon does not implement the requested event.
    #[error("charon does not know event \"{0}\"")]
    UnknownEvent(String),
    /// charon answered with a packet type that is not valid at this point.
    #[error("unexpected packet from charon")]
    UnexpectedPacket,
    /// A previous request on this connection was cancelled half-way: the
    /// stream may hold a partial packet and the connection must be dropped.
    #[error("connection poisoned by a cancelled request")]
    Poisoned,
    #[error("connection closed by charon")]
    Closed,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
