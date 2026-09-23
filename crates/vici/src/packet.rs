//! strongSwan vici protocol (src/libcharon/plugins/vici/README.md in
//! strongSwan): packet framing.

use crate::message::{Reader, put_name};
use crate::{Error, MESSAGE_SIZE_MAX, Result, Section};

const CMD_REQUEST: u8 = 0;
const CMD_RESPONSE: u8 = 1;
const CMD_UNKNOWN: u8 = 2;
const EVENT_REGISTER: u8 = 3;
const EVENT_UNREGISTER: u8 = 4;
const EVENT_CONFIRM: u8 = 5;
const EVENT_UNKNOWN: u8 = 6;
const EVENT: u8 = 7;

/// A unit of the transport layer: a 32-bit big endian length, a type byte,
/// an optional name and an optional message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// A named command sent by the client.
    CmdRequest {
        name: String,
        message: Section,
    },
    CmdResponse(Section),
    CmdUnknown,
    EventRegister(String),
    EventUnregister(String),
    /// Event (un)subscription succeeded.
    EventConfirm,
    EventUnknown,
    /// A named event raised by charon.
    Event {
        name: String,
        message: Section,
    },
}

impl Packet {
    /// Serializes the packet, length prefix included.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        match self {
            Packet::CmdRequest { name, message } => {
                body.push(CMD_REQUEST);
                put_name(&mut body, name)?;
                body.extend(message.encode()?);
            }
            Packet::CmdResponse(message) => {
                body.push(CMD_RESPONSE);
                body.extend(message.encode()?);
            }
            Packet::CmdUnknown => body.push(CMD_UNKNOWN),
            Packet::EventRegister(name) => {
                body.push(EVENT_REGISTER);
                put_name(&mut body, name)?;
            }
            Packet::EventUnregister(name) => {
                body.push(EVENT_UNREGISTER);
                put_name(&mut body, name)?;
            }
            Packet::EventConfirm => body.push(EVENT_CONFIRM),
            Packet::EventUnknown => body.push(EVENT_UNKNOWN),
            Packet::Event { name, message } => {
                body.push(EVENT);
                put_name(&mut body, name)?;
                body.extend(message.encode()?);
            }
        }
        if body.len() > MESSAGE_SIZE_MAX {
            return Err(Error::MessageSize(body.len()));
        }
        let len = u32::try_from(body.len()).map_err(|_| Error::MessageSize(body.len()))?;
        let mut out = len.to_be_bytes().to_vec();
        out.extend(body);
        Ok(out)
    }

    /// Parses a packet body (what follows the length prefix).
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut reader = Reader { data: body, pos: 0 };
        let kind = reader.next_byte().ok_or(Error::Truncated)?;
        let packet = match kind {
            CMD_REQUEST => Packet::CmdRequest {
                name: reader.name()?,
                message: Section::decode(reader.rest())?,
            },
            CMD_RESPONSE => Packet::CmdResponse(Section::decode(reader.rest())?),
            CMD_UNKNOWN => Packet::CmdUnknown,
            EVENT_REGISTER => Packet::EventRegister(reader.name()?),
            EVENT_UNREGISTER => Packet::EventUnregister(reader.name()?),
            EVENT_CONFIRM => Packet::EventConfirm,
            EVENT_UNKNOWN => Packet::EventUnknown,
            EVENT => Packet::Event {
                name: reader.name()?,
                message: Section::decode(reader.rest())?,
            },
            other => {
                return Err(Error::UnknownType {
                    kind: "packet",
                    value: other,
                });
            }
        };
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_kinds() {
        let message = Section::new().kv("k", "v");
        let packets = [
            Packet::CmdRequest {
                name: "version".into(),
                message: message.clone(),
            },
            Packet::CmdResponse(message.clone()),
            Packet::CmdUnknown,
            Packet::EventRegister("log".into()),
            Packet::EventUnregister("log".into()),
            Packet::EventConfirm,
            Packet::EventUnknown,
            Packet::Event {
                name: "log".into(),
                message,
            },
        ];
        for packet in packets {
            let bytes = packet.encode().expect("encode");
            let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            assert_eq!(len as usize, bytes.len() - 4);
            assert_eq!(Packet::decode(&bytes[4..]).expect("decode"), packet);
        }
    }

    #[test]
    fn rejects_bad_packets() {
        assert!(matches!(Packet::decode(&[]), Err(Error::Truncated)));
        assert!(matches!(
            Packet::decode(&[42]),
            Err(Error::UnknownType {
                kind: "packet",
                value: 42
            })
        ));
        assert!(matches!(
            Packet::decode(&[CMD_REQUEST, 5, b'a']),
            Err(Error::Truncated)
        ));
    }
}
