//! RFC 7296 (SA payload: proposals and transforms).

use super::bytes::{Reader, Writer, len16};
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Ike,
    Ah,
    Esp,
}

impl Protocol {
    fn id(self) -> u8 {
        match self {
            Protocol::Ike => 1,
            Protocol::Ah => 2,
            Protocol::Esp => 3,
        }
    }

    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            1 => Some(Protocol::Ike),
            2 => Some(Protocol::Ah),
            3 => Some(Protocol::Esp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransformType {
    Encryption,
    Prf,
    Integrity,
    DiffieHellman,
    Esn,
}

impl TransformType {
    fn id(self) -> u8 {
        match self {
            TransformType::Encryption => 1,
            TransformType::Prf => 2,
            TransformType::Integrity => 3,
            TransformType::DiffieHellman => 4,
            TransformType::Esn => 5,
        }
    }

    fn from_id(id: u8) -> Option<Self> {
        match id {
            1 => Some(TransformType::Encryption),
            2 => Some(TransformType::Prf),
            3 => Some(TransformType::Integrity),
            4 => Some(TransformType::DiffieHellman),
            5 => Some(TransformType::Esn),
            _ => None,
        }
    }
}

/// Attribute type of the key length.
const KEY_LENGTH: u16 = 14;

/// One algorithm of a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transform {
    pub kind: TransformType,
    pub id: u16,
    /// The key length attribute, for ciphers that take one.
    pub key_bits: Option<u16>,
}

impl Transform {
    pub fn new(kind: TransformType, id: u16) -> Self {
        Self {
            kind,
            id,
            key_bits: None,
        }
    }

    pub fn with_key_bits(kind: TransformType, id: u16, key_bits: Option<u16>) -> Self {
        Self { kind, id, key_bits }
    }

    fn encode(self, last: bool, out: &mut Vec<u8>) {
        out.put_u8(if last { 0 } else { 3 });
        out.put_u8(0);
        let length = 8 + if self.key_bits.is_some() { 4 } else { 0 };
        out.put_u16(length);
        out.put_u8(self.kind.id());
        out.put_u8(0);
        out.put_u16(self.id);
        if let Some(bits) = self.key_bits {
            out.put_u16(0x8000 | KEY_LENGTH);
            out.put_u16(bits);
        }
    }

    /// Decodes a transform; `None` for a type we do not know (RFC 7296
    /// section 3.3.6: the proposal is then skipped, not an error).
    fn decode(reader: &mut Reader<'_>) -> Result<(Option<Self>, bool)> {
        let more = reader.u8()?;
        reader.skip(1)?;
        let length = usize::from(reader.u16()?);
        if length < 8 {
            return Err(Error::Malformed("transform too short".into()));
        }
        let kind = reader.u8()?;
        reader.skip(1)?;
        let id = reader.u16()?;
        let mut attributes = Reader::new(reader.take(length - 8)?);
        let mut key_bits = None;
        while !attributes.is_empty() {
            let type_and_format = attributes.u16()?;
            let attribute_type = type_and_format & 0x7fff;
            if type_and_format & 0x8000 != 0 {
                let value = attributes.u16()?;
                if attribute_type == KEY_LENGTH {
                    key_bits = Some(value);
                }
            } else {
                let value_len = usize::from(attributes.u16()?);
                attributes.skip(value_len)?;
            }
        }
        let transform = TransformType::from_id(kind).map(|kind| Self { kind, id, key_bits });
        Ok((transform, more == 0))
    }
}

/// A proposal: one protocol, a set of transforms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub number: u8,
    pub protocol: Protocol,
    pub spi: Vec<u8>,
    pub transforms: Vec<Transform>,
    /// Some transforms are of a type we do not know: the proposal cannot
    /// be accepted.
    pub foreign: bool,
}

impl Proposal {
    fn encode(&self, last: bool, out: &mut Vec<u8>) -> Result<()> {
        let mut body = Vec::new();
        body.put_u8(self.number);
        body.put_u8(self.protocol.id());
        body.put_u8(u8::try_from(self.spi.len()).expect("short SPI"));
        body.put_u8(u8::try_from(self.transforms.len()).expect("few transforms"));
        body.extend_from_slice(&self.spi);
        let count = self.transforms.len();
        for (index, transform) in self.transforms.iter().enumerate() {
            transform.encode(index + 1 == count, &mut body);
        }
        out.put_u8(if last { 0 } else { 2 });
        out.put_u8(0);
        out.put_u16(len16(body.len() + 4)?);
        out.extend_from_slice(&body);
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> Result<(Self, bool)> {
        let more = reader.u8()?;
        reader.skip(1)?;
        let length = usize::from(reader.u16()?);
        if length < 8 {
            return Err(Error::Malformed("proposal too short".into()));
        }
        let mut body = Reader::new(reader.take(length - 4)?);
        let number = body.u8()?;
        let protocol = body.u8()?;
        let spi_len = usize::from(body.u8()?);
        let count = usize::from(body.u8()?);
        let spi = body.take(spi_len)?.to_vec();
        let mut transforms = Vec::with_capacity(count);
        let mut foreign = false;
        let mut decoded = 0;
        for _ in 0..count {
            let (transform, last) = Transform::decode(&mut body)?;
            decoded += 1;
            match transform {
                Some(transform) => transforms.push(transform),
                None => foreign = true,
            }
            if last {
                break;
            }
        }
        if decoded != count {
            return Err(Error::Malformed("transform count mismatch".into()));
        }
        let protocol = Protocol::from_id(protocol)
            .ok_or_else(|| Error::Malformed(format!("unknown protocol {protocol}")))?;
        Ok((
            Self {
                number,
                protocol,
                spi,
                transforms,
                foreign,
            },
            more == 0,
        ))
    }

    pub fn transforms_of(&self, kind: TransformType) -> impl Iterator<Item = &Transform> {
        self.transforms
            .iter()
            .filter(move |transform| transform.kind == kind)
    }
}

pub fn encode(proposals: &[Proposal]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let count = proposals.len();
    for (index, proposal) in proposals.iter().enumerate() {
        proposal.encode(index + 1 == count, &mut out)?;
    }
    Ok(out)
}

pub fn decode(data: &[u8]) -> Result<Vec<Proposal>> {
    let mut reader = Reader::new(data);
    let mut proposals = Vec::new();
    while !reader.is_empty() {
        let (proposal, last) = Proposal::decode(&mut reader)?;
        proposals.push(proposal);
        if last {
            break;
        }
    }
    if !reader.is_empty() {
        return Err(Error::Malformed("trailing data after the proposals".into()));
    }
    Ok(proposals)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposals_round_trip() {
        let proposals = vec![
            Proposal {
                number: 1,
                protocol: Protocol::Ike,
                spi: Vec::new(),
                transforms: vec![
                    Transform::with_key_bits(TransformType::Encryption, 12, Some(256)),
                    Transform::new(TransformType::Prf, 5),
                    Transform::new(TransformType::Integrity, 12),
                    Transform::new(TransformType::DiffieHellman, 14),
                ],
                foreign: false,
            },
            Proposal {
                number: 2,
                protocol: Protocol::Esp,
                spi: vec![1, 2, 3, 4],
                transforms: vec![
                    Transform::with_key_bits(TransformType::Encryption, 20, Some(128)),
                    Transform::new(TransformType::Esn, 0),
                ],
                foreign: false,
            },
        ];
        let encoded = encode(&proposals).expect("encode");
        assert_eq!(encoded[0], 2);
        assert_eq!(decode(&encoded).expect("decode"), proposals);
        assert!(decode(&encoded[..encoded.len() - 1]).is_err());
        assert_eq!(
            proposals[0]
                .transforms_of(TransformType::Encryption)
                .count(),
            1
        );
    }
}
