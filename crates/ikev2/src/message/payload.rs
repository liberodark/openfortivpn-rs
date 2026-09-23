//! RFC 7296 (payloads), RFC 7427 (SIGNATURE_HASH_ALGORITHMS), Cisco Unity
//! configuration attributes (draft-dukes-ike-mode-cfg).

use std::net::Ipv4Addr;

use super::bytes::{Reader, Writer, len16};
use super::proposal::{self, Proposal};
use crate::{Error, Result};

/// Payload type numbers.
pub mod types {
    pub const NONE: u8 = 0;
    pub const SA: u8 = 33;
    pub const KE: u8 = 34;
    pub const IDI: u8 = 35;
    pub const IDR: u8 = 36;
    pub const CERT: u8 = 37;
    pub const CERTREQ: u8 = 38;
    pub const AUTH: u8 = 39;
    pub const NONCE: u8 = 40;
    pub const NOTIFY: u8 = 41;
    pub const DELETE: u8 = 42;
    pub const VENDOR_ID: u8 = 43;
    pub const TSI: u8 = 44;
    pub const TSR: u8 = 45;
    pub const SK: u8 = 46;
    pub const CP: u8 = 47;
    pub const EAP: u8 = 48;
    pub const SKF: u8 = 53;
}

/// Notification message types.
pub mod notify {
    pub const UNSUPPORTED_CRITICAL_PAYLOAD: u16 = 1;
    pub const INVALID_IKE_SPI: u16 = 4;
    pub const INVALID_MAJOR_VERSION: u16 = 5;
    pub const INVALID_SYNTAX: u16 = 7;
    pub const INVALID_MESSAGE_ID: u16 = 9;
    pub const INVALID_SPI: u16 = 11;
    pub const NO_PROPOSAL_CHOSEN: u16 = 14;
    pub const INVALID_KE_PAYLOAD: u16 = 17;
    pub const AUTHENTICATION_FAILED: u16 = 24;
    pub const SINGLE_PAIR_REQUIRED: u16 = 34;
    pub const NO_ADDITIONAL_SAS: u16 = 35;
    pub const INTERNAL_ADDRESS_FAILURE: u16 = 36;
    pub const FAILED_CP_REQUIRED: u16 = 37;
    pub const TS_UNACCEPTABLE: u16 = 38;
    pub const INVALID_SELECTORS: u16 = 39;
    pub const TEMPORARY_FAILURE: u16 = 43;
    pub const CHILD_SA_NOT_FOUND: u16 = 44;
    pub const INITIAL_CONTACT: u16 = 16384;
    pub const NAT_DETECTION_SOURCE_IP: u16 = 16388;
    pub const NAT_DETECTION_DESTINATION_IP: u16 = 16389;
    pub const COOKIE: u16 = 16390;
    pub const REKEY_SA: u16 = 16393;
    pub const IKEV2_FRAGMENTATION_SUPPORTED: u16 = 16430;
    pub const SIGNATURE_HASH_ALGORITHMS: u16 = 16431;
    /// FortiClient's private status notification describing itself.
    pub const FORTICLIENT_CONNECT: u16 = 0xF100;

    /// A readable name for the error notifications.
    pub fn name(kind: u16) -> String {
        let name = match kind {
            UNSUPPORTED_CRITICAL_PAYLOAD => "UNSUPPORTED_CRITICAL_PAYLOAD",
            INVALID_IKE_SPI => "INVALID_IKE_SPI",
            INVALID_MAJOR_VERSION => "INVALID_MAJOR_VERSION",
            INVALID_SYNTAX => "INVALID_SYNTAX",
            INVALID_MESSAGE_ID => "INVALID_MESSAGE_ID",
            INVALID_SPI => "INVALID_SPI",
            NO_PROPOSAL_CHOSEN => "NO_PROPOSAL_CHOSEN",
            INVALID_KE_PAYLOAD => "INVALID_KE_PAYLOAD",
            AUTHENTICATION_FAILED => "AUTHENTICATION_FAILED",
            SINGLE_PAIR_REQUIRED => "SINGLE_PAIR_REQUIRED",
            NO_ADDITIONAL_SAS => "NO_ADDITIONAL_SAS",
            INTERNAL_ADDRESS_FAILURE => "INTERNAL_ADDRESS_FAILURE",
            FAILED_CP_REQUIRED => "FAILED_CP_REQUIRED",
            TS_UNACCEPTABLE => "TS_UNACCEPTABLE",
            INVALID_SELECTORS => "INVALID_SELECTORS",
            TEMPORARY_FAILURE => "TEMPORARY_FAILURE",
            CHILD_SA_NOT_FOUND => "CHILD_SA_NOT_FOUND",
            COOKIE => "COOKIE",
            _ => return format!("notification {kind}"),
        };
        name.to_owned()
    }

    /// Whether a notification type is an error (RFC 7296 section 3.10.1).
    pub fn is_error(kind: u16) -> bool {
        kind < 16384
    }
}

/// Identification types.
pub mod id_types {
    pub const IPV4_ADDR: u8 = 1;
    pub const FQDN: u8 = 2;
    pub const RFC822_ADDR: u8 = 3;
    pub const IPV6_ADDR: u8 = 5;
    pub const DER_ASN1_DN: u8 = 9;
    pub const KEY_ID: u8 = 11;
}

/// Configuration attribute types.
pub mod cp_attributes {
    pub const INTERNAL_IP4_ADDRESS: u16 = 1;
    pub const INTERNAL_IP4_NETMASK: u16 = 2;
    pub const INTERNAL_IP4_DNS: u16 = 3;
    pub const APPLICATION_VERSION: u16 = 7;
    pub const INTERNAL_IP4_SUBNET: u16 = 13;
    pub const INTERNAL_DNS_DOMAIN: u16 = 25;
    /// Cisco Unity attributes FortiOS pushes with `unity-support enable`
    /// (the default): the DNS domain, and the split networks as 14-byte
    /// entries (network, mask, protocol and ports).
    pub const UNITY_DEF_DOMAIN: u16 = 28674;
    pub const UNITY_SPLIT_INCLUDE: u16 = 28676;
}

/// Configuration payload types.
pub const CP_REQUEST: u8 = 1;
pub const CP_REPLY: u8 = 2;

/// X.509 certificate encoding in CERT and CERTREQ payloads.
pub const CERT_X509_SIGNATURE: u8 = 4;

/// A payload as received: its type and its data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPayload {
    pub kind: u8,
    pub data: Vec<u8>,
}

/// The first payload of a kind.
pub fn find(payloads: &[RawPayload], kind: u8) -> Option<&RawPayload> {
    payloads.iter().find(|payload| payload.kind == kind)
}

/// Parses a chain of payloads starting with type `first`.
pub fn parse_chain(first: u8, data: &[u8]) -> Result<Vec<RawPayload>> {
    let mut reader = Reader::new(data);
    let mut payloads = Vec::new();
    let mut kind = first;
    while kind != types::NONE {
        let next = reader.u8()?;
        reader.skip(1)?; // flags: the critical bit only matters to a responder
        let length = usize::from(reader.u16()?);
        if length < 4 {
            return Err(Error::Malformed("payload shorter than its header".into()));
        }
        payloads.push(RawPayload {
            kind,
            data: reader.take(length - 4)?.to_vec(),
        });
        kind = next;
    }
    if !reader.is_empty() {
        return Err(Error::Malformed(
            "trailing data after the last payload".into(),
        ));
    }
    Ok(payloads)
}

/// Encodes a chain of payloads; returns the type of the first one (each
/// payload's type is carried by the header before it).
pub fn encode_chain(payloads: &[(u8, Vec<u8>)], out: &mut Vec<u8>) -> Result<u8> {
    for (index, (_, data)) in payloads.iter().enumerate() {
        let next = payloads
            .get(index + 1)
            .map_or(types::NONE, |(kind, _)| *kind);
        out.put_u8(next);
        out.put_u8(0);
        out.put_u16(len16(data.len() + 4)?);
        out.extend_from_slice(data);
    }
    Ok(payloads.first().map_or(types::NONE, |(kind, _)| *kind))
}

/// An identity (IDi/IDr payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub kind: u8,
    pub data: Vec<u8>,
}

impl Identity {
    /// An identity from its text form, in strongSwan's syntax: an address,
    /// an e-mail address, `@name` or a name for an FQDN, `@@name` or
    /// `@#hex` for a KEY_ID; distinguished names are not supported.
    pub fn parse(text: &str) -> Self {
        if let Some(key_id) = text.strip_prefix("@@") {
            return Self {
                kind: id_types::KEY_ID,
                data: key_id.as_bytes().to_vec(),
            };
        }
        if let Some(hex) = text.strip_prefix("@#") {
            return Self {
                kind: id_types::KEY_ID,
                data: hex::decode(hex).unwrap_or_else(|_| hex.as_bytes().to_vec()),
            };
        }
        let text = text.strip_prefix('@').unwrap_or(text);
        if let Ok(address) = text.parse::<Ipv4Addr>() {
            return Self {
                kind: id_types::IPV4_ADDR,
                data: address.octets().to_vec(),
            };
        }
        if let Ok(address) = text.parse::<std::net::Ipv6Addr>() {
            return Self {
                kind: id_types::IPV6_ADDR,
                data: address.octets().to_vec(),
            };
        }
        if text.contains('@') {
            return Self {
                kind: id_types::RFC822_ADDR,
                data: text.as_bytes().to_vec(),
            };
        }
        Self {
            kind: id_types::FQDN,
            data: text.as_bytes().to_vec(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.data.len());
        out.put_u8(self.kind);
        out.extend_from_slice(&[0, 0, 0]);
        out.extend_from_slice(&self.data);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(data);
        let kind = reader.u8()?;
        reader.skip(3)?;
        Ok(Self {
            kind,
            data: reader.rest().to_vec(),
        })
    }

    /// A readable form.
    pub fn display(&self) -> String {
        match self.kind {
            id_types::IPV4_ADDR if self.data.len() == 4 => {
                Ipv4Addr::new(self.data[0], self.data[1], self.data[2], self.data[3]).to_string()
            }
            id_types::FQDN | id_types::RFC822_ADDR | id_types::KEY_ID => {
                match std::str::from_utf8(&self.data) {
                    Ok(text) if self.kind == id_types::KEY_ID => format!("@@{text}"),
                    Ok(text) => text.to_owned(),
                    Err(_) => hex::encode(&self.data),
                }
            }
            id_types::DER_ASN1_DN => "DN".to_owned(),
            _ => hex::encode(&self.data),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notify {
    pub protocol: u8,
    pub spi: Vec<u8>,
    pub kind: u16,
    pub data: Vec<u8>,
}

impl Notify {
    pub fn new(kind: u16, data: Vec<u8>) -> Self {
        Self {
            protocol: 0,
            spi: Vec::new(),
            kind,
            data,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.spi.len() + self.data.len());
        out.put_u8(self.protocol);
        out.put_u8(u8::try_from(self.spi.len()).expect("short SPI"));
        out.put_u16(self.kind);
        out.extend_from_slice(&self.spi);
        out.extend_from_slice(&self.data);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(data);
        let protocol = reader.u8()?;
        let spi_len = usize::from(reader.u8()?);
        let kind = reader.u16()?;
        let spi = reader.take(spi_len)?.to_vec();
        Ok(Self {
            protocol,
            spi,
            kind,
            data: reader.rest().to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delete {
    pub protocol: u8,
    pub spis: Vec<Vec<u8>>,
}

impl Delete {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.put_u8(self.protocol);
        let spi_len = self.spis.first().map_or(0, Vec::len);
        out.put_u8(u8::try_from(spi_len).expect("short SPI"));
        out.put_u16(u16::try_from(self.spis.len()).expect("few SPIs"));
        for spi in &self.spis {
            out.extend_from_slice(spi);
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(data);
        let protocol = reader.u8()?;
        let spi_len = usize::from(reader.u8()?);
        let count = usize::from(reader.u16()?);
        let mut spis = Vec::with_capacity(count);
        for _ in 0..count {
            spis.push(reader.take(spi_len)?.to_vec());
        }
        Ok(Self { protocol, spis })
    }
}

/// A traffic selector: an IPv4 address range, with ports and protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficSelector {
    pub protocol: u8,
    pub start_port: u16,
    pub end_port: u16,
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
}

impl TrafficSelector {
    const TYPE_IPV4_RANGE: u8 = 7;

    /// Everything.
    pub const ANY: TrafficSelector = TrafficSelector {
        protocol: 0,
        start_port: 0,
        end_port: 65535,
        start: Ipv4Addr::UNSPECIFIED,
        end: Ipv4Addr::BROADCAST,
    };

    /// A single address, any port and protocol.
    pub fn host(address: Ipv4Addr) -> Self {
        Self {
            protocol: 0,
            start_port: 0,
            end_port: 65535,
            start: address,
            end: address,
        }
    }

    /// A network, any port and protocol.
    pub fn network(address: Ipv4Addr, prefix: u8) -> Self {
        let bits = u32::from(address);
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(prefix.min(32)))
        };
        Self {
            protocol: 0,
            start_port: 0,
            end_port: 65535,
            start: Ipv4Addr::from(bits & mask),
            end: Ipv4Addr::from(bits | !mask),
        }
    }

    /// Whether this selector covers `other` entirely.
    pub fn covers(&self, other: &TrafficSelector) -> bool {
        (self.protocol == 0 || self.protocol == other.protocol)
            && self.start_port <= other.start_port
            && self.end_port >= other.end_port
            && self.start <= other.start
            && self.end >= other.end
    }

    /// Whether the selector is a single network: the CIDR blocks that
    /// cover the range exactly.
    pub fn networks(&self) -> Vec<(Ipv4Addr, u8)> {
        let mut blocks = Vec::new();
        let (mut start, end) = (
            u64::from(u32::from(self.start)),
            u64::from(u32::from(self.end)),
        );
        while start <= end {
            // The largest block aligned on `start` that does not go past `end`.
            let mut prefix = 32u8;
            while prefix > 0 {
                let size = 1u64 << (33 - u64::from(prefix));
                if start % size != 0 || start + size - 1 > end {
                    break;
                }
                prefix -= 1;
            }
            let size = 1u64 << (32 - u64::from(prefix));
            blocks.push((
                Ipv4Addr::from(u32::try_from(start).expect("an IPv4 address")),
                prefix,
            ));
            start += size;
        }
        blocks
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE_IPV4_RANGE);
        out.put_u8(self.protocol);
        out.put_u16(16);
        out.put_u16(self.start_port);
        out.put_u16(self.end_port);
        out.extend_from_slice(&self.start.octets());
        out.extend_from_slice(&self.end.octets());
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Option<Self>> {
        let kind = reader.u8()?;
        let protocol = reader.u8()?;
        let length = usize::from(reader.u16()?);
        if length < 4 {
            return Err(Error::Malformed("traffic selector too short".into()));
        }
        let mut body = Reader::new(reader.take(length - 4)?);
        if kind != Self::TYPE_IPV4_RANGE {
            // IPv6 and others: skipped.
            return Ok(None);
        }
        let start_port = body.u16()?;
        let end_port = body.u16()?;
        let start = Ipv4Addr::from(body.u32()?);
        let end = Ipv4Addr::from(body.u32()?);
        Ok(Some(Self {
            protocol,
            start_port,
            end_port,
            start,
            end,
        }))
    }
}

impl std::fmt::Display for TrafficSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let blocks = self.networks();
        if blocks.len() == 1 {
            write!(f, "{}/{}", blocks[0].0, blocks[0].1)?;
        } else {
            write!(f, "{}-{}", self.start, self.end)?;
        }
        if self.protocol != 0 {
            write!(f, "[{}]", self.protocol)?;
        }
        if self.start_port != 0 || self.end_port != 65535 {
            write!(f, ":{}-{}", self.start_port, self.end_port)?;
        }
        Ok(())
    }
}

pub fn encode_selectors(selectors: &[TrafficSelector]) -> Vec<u8> {
    let mut out = Vec::new();
    out.put_u8(u8::try_from(selectors.len()).expect("few selectors"));
    out.extend_from_slice(&[0, 0, 0]);
    for selector in selectors {
        selector.encode(&mut out);
    }
    out
}

/// Decodes a TS payload, keeping the IPv4 selectors.
pub fn decode_selectors(data: &[u8]) -> Result<Vec<TrafficSelector>> {
    let mut reader = Reader::new(data);
    let count = usize::from(reader.u8()?);
    reader.skip(3)?;
    let mut selectors = Vec::new();
    for _ in 0..count {
        if let Some(selector) = TrafficSelector::decode(&mut reader)? {
            selectors.push(selector);
        }
    }
    Ok(selectors)
}

/// The IPv4 selectors of the TSi and TSr payloads of a message, which
/// must both be there and name at least one IPv4 range.
pub fn selectors(payloads: &[RawPayload]) -> Result<(Vec<TrafficSelector>, Vec<TrafficSelector>)> {
    let decode = |kind: u8| {
        find(payloads, kind)
            .map(|payload| decode_selectors(&payload.data))
            .transpose()?
            .filter(|selectors| !selectors.is_empty())
            .ok_or_else(|| Error::Malformed("no IPv4 traffic selectors".into()))
    };
    Ok((decode(types::TSI)?, decode(types::TSR)?))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigAttribute {
    pub kind: u16,
    pub value: Vec<u8>,
}

impl ConfigAttribute {
    pub fn address(&self) -> Option<Ipv4Addr> {
        <[u8; 4]>::try_from(self.value.as_slice())
            .ok()
            .map(Ipv4Addr::from)
    }
}

/// A configuration payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub kind: u8,
    pub attributes: Vec<ConfigAttribute>,
}

impl Config {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.put_u8(self.kind);
        out.extend_from_slice(&[0, 0, 0]);
        for attribute in &self.attributes {
            out.put_u16(attribute.kind & 0x7fff);
            out.put_u16(len16(attribute.value.len())?);
            out.extend_from_slice(&attribute.value);
        }
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(data);
        let kind = reader.u8()?;
        reader.skip(3)?;
        let mut attributes = Vec::new();
        while !reader.is_empty() {
            let attribute_kind = reader.u16()? & 0x7fff;
            let length = usize::from(reader.u16()?);
            attributes.push(ConfigAttribute {
                kind: attribute_kind,
                value: reader.take(length)?.to_vec(),
            });
        }
        Ok(Self { kind, attributes })
    }
}

pub fn encode_ke(group: u16, public: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + public.len());
    out.put_u16(group);
    out.put_u16(0);
    out.extend_from_slice(public);
    out
}

/// The group and public value of a KE payload.
pub fn decode_ke(data: &[u8]) -> Result<(u16, &[u8])> {
    let mut reader = Reader::new(data);
    let group = reader.u16()?;
    reader.skip(2)?;
    Ok((group, reader.rest()))
}

pub fn encode_auth(method: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.put_u8(method);
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(data);
    out
}

/// The method and data of an AUTH payload.
pub fn decode_auth(data: &[u8]) -> Result<(u8, &[u8])> {
    let mut reader = Reader::new(data);
    let method = reader.u8()?;
    reader.skip(3)?;
    Ok((method, reader.rest()))
}

/// The CERT (or CERTREQ) payload.
pub fn encode_cert(encoding: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + data.len());
    out.put_u8(encoding);
    out.extend_from_slice(data);
    out
}

/// The encoding and data of a CERT (or CERTREQ) payload.
pub fn decode_cert(data: &[u8]) -> Result<(u8, &[u8])> {
    let mut reader = Reader::new(data);
    let encoding = reader.u8()?;
    Ok((encoding, reader.rest()))
}

pub fn encode_sa(proposals: &[Proposal]) -> Result<Vec<u8>> {
    proposal::encode(proposals)
}

/// The proposals of an SA payload.
pub fn decode_sa(data: &[u8]) -> Result<Vec<Proposal>> {
    proposal::decode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chains_round_trip() {
        let payloads = vec![
            (types::NONCE, vec![1, 2, 3]),
            (types::NOTIFY, Notify::new(notify::COOKIE, vec![9]).encode()),
        ];
        let mut out = Vec::new();
        let first = encode_chain(&payloads, &mut out).expect("encode");
        assert_eq!(first, types::NONCE);
        let parsed = parse_chain(first, &out).expect("parse");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].kind, types::NONCE);
        assert_eq!(parsed[0].data, [1, 2, 3]);
        let notify = Notify::decode(&parsed[1].data).expect("notify");
        assert_eq!(notify.kind, notify::COOKIE);
        assert_eq!(notify.data, [9]);
        assert!(parse_chain(first, &out[..out.len() - 1]).is_err());
        assert!(parse_chain(types::NONE, &[1]).is_err());
    }

    #[test]
    fn identities_are_typed() {
        assert_eq!(Identity::parse("10.0.0.1").kind, id_types::IPV4_ADDR);
        assert_eq!(
            Identity::parse("alice@example.com").kind,
            id_types::RFC822_ADDR
        );
        assert_eq!(Identity::parse("vpn.example.com").kind, id_types::FQDN);
        assert_eq!(Identity::parse("@my-peer-id").kind, id_types::FQDN);
        assert_eq!(Identity::parse("@@my-peer-id").kind, id_types::KEY_ID);
        assert_eq!(Identity::parse("@#0102").data, [1, 2]);
        let id = Identity::parse("vpn.example.com");
        assert_eq!(Identity::decode(&id.encode()).expect("decode"), id);
        assert_eq!(id.display(), "vpn.example.com");
        assert_eq!(Identity::parse("@@peer").display(), "@@peer");
        assert_eq!(Identity::parse("@peer").display(), "peer");
    }

    #[test]
    fn selectors_and_networks() {
        let any = TrafficSelector::ANY;
        assert_eq!(any.networks(), [(Ipv4Addr::UNSPECIFIED, 0)]);
        let net = TrafficSelector::network(Ipv4Addr::new(10, 1, 2, 3), 24);
        assert_eq!(net.start, Ipv4Addr::new(10, 1, 2, 0));
        assert_eq!(net.end, Ipv4Addr::new(10, 1, 2, 255));
        assert_eq!(net.to_string(), "10.1.2.0/24");
        assert!(any.covers(&net));
        assert!(!net.covers(&any));
        let range = TrafficSelector {
            start: Ipv4Addr::new(10, 0, 0, 1),
            end: Ipv4Addr::new(10, 0, 0, 6),
            ..TrafficSelector::ANY
        };
        assert_eq!(
            range.networks(),
            [
                (Ipv4Addr::new(10, 0, 0, 1), 32),
                (Ipv4Addr::new(10, 0, 0, 2), 31),
                (Ipv4Addr::new(10, 0, 0, 4), 31),
                (Ipv4Addr::new(10, 0, 0, 6), 32),
            ]
        );
        let encoded = encode_selectors(&[net, range]);
        assert_eq!(decode_selectors(&encoded).expect("decode"), [net, range]);
        assert_eq!(
            TrafficSelector::host(Ipv4Addr::new(1, 2, 3, 4)).to_string(),
            "1.2.3.4/32"
        );
    }

    #[test]
    fn config_payload_round_trips() {
        let config = Config {
            kind: CP_REQUEST,
            attributes: vec![
                ConfigAttribute {
                    kind: cp_attributes::INTERNAL_IP4_ADDRESS,
                    value: Vec::new(),
                },
                ConfigAttribute {
                    kind: cp_attributes::INTERNAL_IP4_DNS,
                    value: vec![10, 0, 0, 53],
                },
            ],
        };
        let decoded = Config::decode(&config.encode().expect("encode")).expect("decode");
        assert_eq!(decoded, config);
        assert_eq!(
            decoded.attributes[1].address(),
            Some(Ipv4Addr::new(10, 0, 0, 53))
        );
        let delete = Delete {
            protocol: 3,
            spis: vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]],
        };
        assert_eq!(Delete::decode(&delete.encode()).expect("decode"), delete);
        let ke = encode_ke(14, &[7; 4]);
        assert_eq!(decode_ke(&ke).expect("ke"), (14, &[7u8; 4][..]));
        let auth = encode_auth(2, b"x");
        assert_eq!(decode_auth(&auth).expect("auth"), (2, &b"x"[..]));
    }
}
