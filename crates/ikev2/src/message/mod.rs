//! RFC 7296 (IKEv2 header, Encrypted payload), RFC 7383 (fragmentation), RFC
//! 5282 (AEAD in IKEv2).

mod bytes;
pub mod payload;
pub mod proposal;

use std::collections::BTreeMap;

use rand_core::{OsRng, RngCore};

use crate::crypto::{Cipher, Integrity};
use crate::{Error, Result};
use bytes::{Reader, Writer};
pub use payload::{RawPayload, types};

/// Size of the IKE header.
pub const HEADER_LEN: usize = 28;
/// IKEv2 version byte: major 2, minor 0.
const VERSION: u8 = 0x20;
const FLAG_INITIATOR: u8 = 0x08;
const FLAG_RESPONSE: u8 = 0x20;

/// The exchange types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exchange {
    IkeSaInit,
    IkeAuth,
    CreateChildSa,
    Informational,
}

impl Exchange {
    fn id(self) -> u8 {
        match self {
            Exchange::IkeSaInit => 34,
            Exchange::IkeAuth => 35,
            Exchange::CreateChildSa => 36,
            Exchange::Informational => 37,
        }
    }

    fn from_id(id: u8) -> Option<Self> {
        match id {
            34 => Some(Exchange::IkeSaInit),
            35 => Some(Exchange::IkeAuth),
            36 => Some(Exchange::CreateChildSa),
            37 => Some(Exchange::Informational),
            _ => None,
        }
    }
}

/// The IKE header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub next_payload: u8,
    pub exchange: Exchange,
    pub from_initiator: bool,
    pub is_response: bool,
    pub message_id: u32,
    pub length: u32,
}

impl Header {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u64(self.initiator_spi);
        out.put_u64(self.responder_spi);
        out.put_u8(self.next_payload);
        out.put_u8(VERSION);
        out.put_u8(self.exchange.id());
        let mut flags = 0;
        if self.from_initiator {
            flags |= FLAG_INITIATOR;
        }
        if self.is_response {
            flags |= FLAG_RESPONSE;
        }
        out.put_u8(flags);
        out.put_u32(self.message_id);
        out.put_u32(self.length);
    }

    fn decode(data: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(data);
        let initiator_spi = reader.u64()?;
        let responder_spi = reader.u64()?;
        let next_payload = reader.u8()?;
        let version = reader.u8()?;
        if version >> 4 != 2 {
            return Err(Error::Malformed(format!(
                "IKE major version {}",
                version >> 4
            )));
        }
        let exchange = reader.u8()?;
        let flags = reader.u8()?;
        let message_id = reader.u32()?;
        let length = reader.u32()?;
        Ok(Self {
            initiator_spi,
            responder_spi,
            next_payload,
            exchange: Exchange::from_id(exchange)
                .ok_or_else(|| Error::Malformed(format!("unknown exchange type {exchange}")))?,
            from_initiator: flags & FLAG_INITIATOR != 0,
            is_response: flags & FLAG_RESPONSE != 0,
            message_id,
            length,
        })
    }
}

/// A message as received: the header and the payload chain, the
/// Encrypted payload still encrypted.
#[derive(Debug, Clone)]
pub struct Packet {
    pub header: Header,
    pub payloads: Vec<RawPayload>,
    /// The datagram, for the integrity check of the Encrypted payload.
    raw: Vec<u8>,
    /// Offset of the Encrypted (or Encrypted Fragment) payload header.
    encrypted_at: Option<usize>,
}

impl Packet {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let header = Header::decode(bytes)?;
        let length = usize::try_from(header.length).expect("u32 fits");
        if length != bytes.len() {
            return Err(Error::Malformed(format!(
                "header says {length} bytes, datagram has {}",
                bytes.len()
            )));
        }
        let mut payloads = Vec::new();
        let mut encrypted_at = None;
        let mut offset = HEADER_LEN;
        let mut kind = header.next_payload;
        while kind != types::NONE {
            if kind == types::SK || kind == types::SKF {
                // Whatever follows is inside it.
                encrypted_at = Some(offset);
                let mut reader = Reader::new(&bytes[offset..]);
                reader.skip(2)?;
                let payload_len = usize::from(reader.u16()?);
                if payload_len < 4 || offset + payload_len != bytes.len() {
                    return Err(Error::Malformed(
                        "the Encrypted payload does not end the message".into(),
                    ));
                }
                payloads.push(RawPayload {
                    kind,
                    data: bytes[offset + 4..].to_vec(),
                });
                break;
            }
            let mut reader = Reader::new(&bytes[offset..]);
            let next = reader.u8()?;
            reader.skip(1)?; // flags
            let payload_len = usize::from(reader.u16()?);
            if payload_len < 4 {
                return Err(Error::Malformed("payload shorter than its header".into()));
            }
            let data = reader.take(payload_len - 4)?.to_vec();
            payloads.push(RawPayload { kind, data });
            offset += payload_len;
            kind = next;
        }
        Ok(Self {
            header,
            payloads,
            raw: bytes.to_vec(),
            encrypted_at,
        })
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypted_at.is_some()
    }

    /// Decrypts the Encrypted payload: the inner payloads, or for a
    /// fragment, the fragment to reassemble.
    pub fn decrypt(&self, keys: &Keys) -> Result<Decrypted> {
        let offset = self
            .encrypted_at
            .ok_or_else(|| Error::Malformed("no Encrypted payload".into()))?;
        let raw = &self.raw;
        let next_payload = raw[offset];
        let fragmented = self
            .payloads
            .last()
            .is_some_and(|payload| payload.kind == types::SKF);
        let (fragment, iv_at) = if fragmented {
            let mut reader = Reader::new(&raw[offset + 4..]);
            let number = reader.u16()?;
            let total = reader.u16()?;
            (Some((number, total)), offset + 8)
        } else {
            (None, offset + 4)
        };
        let cipher = keys.cipher;
        let iv_len = cipher.iv_len();
        let tag_len = if cipher.is_aead() {
            cipher.icv_len()
        } else {
            keys.integrity.icv_len()
        };
        if raw.len() < iv_at + iv_len + tag_len {
            return Err(Error::Malformed("Encrypted payload too short".into()));
        }
        let iv = &raw[iv_at..iv_at + iv_len];
        let plaintext = if cipher.is_aead() {
            cipher.decrypt(&keys.encryption, iv, &raw[..iv_at], &raw[iv_at + iv_len..])?
        } else {
            let body_end = raw.len() - tag_len;
            if !keys
                .integrity
                .verify(&keys.integrity_key, &raw[..body_end], &raw[body_end..])
            {
                return Err(Error::Crypto("integrity check failed".into()));
            }
            cipher.decrypt(&keys.encryption, iv, &[], &raw[iv_at + iv_len..body_end])?
        };
        // Padding, then its length.
        let (&pad_len, padded) = plaintext
            .split_last()
            .ok_or_else(|| Error::Malformed("empty Encrypted payload".into()))?;
        let pad_len = usize::from(pad_len);
        if padded.len() < pad_len {
            return Err(Error::Malformed(
                "bad padding in the Encrypted payload".into(),
            ));
        }
        let inner = padded[..padded.len() - pad_len].to_vec();
        Ok(Decrypted {
            next_payload,
            inner,
            fragment,
        })
    }
}

/// What came out of an Encrypted payload.
#[derive(Debug)]
pub struct Decrypted {
    /// Type of the first inner payload (0 for a fragment after the first).
    pub next_payload: u8,
    /// The inner payload chain, or one fragment of it.
    pub inner: Vec<u8>,
    /// Fragment number and total, for a fragment.
    pub fragment: Option<(u16, u16)>,
}

impl Decrypted {
    /// The inner payloads of a whole message.
    pub fn payloads(&self) -> Result<Vec<RawPayload>> {
        payload::parse_chain(self.next_payload, &self.inner)
    }
}

/// The keys of one direction of an IKE SA.
pub struct Keys {
    pub cipher: Cipher,
    pub integrity: Integrity,
    pub encryption: Vec<u8>,
    pub integrity_key: Vec<u8>,
}

impl zeroize::Zeroize for Keys {
    fn zeroize(&mut self) {
        self.encryption.zeroize();
        self.integrity_key.zeroize();
    }
}

impl Drop for Keys {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

/// The most fragments a message may come in (RFC 7383 section 2.5.3
/// asks for a limit; 64 KiB of message in 1280-byte fragments is 52).
const MAX_FRAGMENTS: u16 = 64;

/// Puts fragments of one message back together.
#[derive(Debug, Default)]
pub struct Reassembler {
    message_id: Option<u32>,
    total: u16,
    next_payload: u8,
    fragments: BTreeMap<u16, Vec<u8>>,
}

impl Reassembler {
    /// Adds a fragment; the whole inner chain once complete.
    pub fn add(&mut self, message_id: u32, decrypted: Decrypted) -> Result<Option<Decrypted>> {
        let (number, total) = decrypted
            .fragment
            .ok_or_else(|| Error::Malformed("not a fragment".into()))?;
        if number == 0 || total == 0 || number > total || total > MAX_FRAGMENTS {
            return Err(Error::Malformed("bad fragment numbering".into()));
        }
        if self.message_id != Some(message_id) || self.total != total {
            self.message_id = Some(message_id);
            self.total = total;
            self.fragments.clear();
        }
        if number == 1 {
            self.next_payload = decrypted.next_payload;
        }
        self.fragments.insert(number, decrypted.inner);
        if self.fragments.len() < usize::from(total) {
            return Ok(None);
        }
        let inner = self.fragments.values().flatten().copied().collect();
        let next_payload = self.next_payload;
        *self = Self::default();
        Ok(Some(Decrypted {
            next_payload,
            inner,
            fragment: None,
        }))
    }
}

/// A message to send.
#[derive(Debug, Clone)]
pub struct Message {
    pub exchange: Exchange,
    pub is_response: bool,
    /// Whether we are the initiator of the IKE SA (not of the exchange):
    /// the gateway is, once it rekeyed the SA.
    pub from_initiator: bool,
    pub id: u32,
    pub initiator_spi: u64,
    pub responder_spi: u64,
    /// Payload type and data, in order.
    pub payloads: Vec<(u8, Vec<u8>)>,
}

impl Message {
    /// A request of ours, on an IKE SA we initiated.
    pub fn request(exchange: Exchange, id: u32, initiator_spi: u64, responder_spi: u64) -> Self {
        Self {
            exchange,
            is_response: false,
            from_initiator: true,
            id,
            initiator_spi,
            responder_spi,
            payloads: Vec::new(),
        }
    }

    /// Our response to a request of the gateway.
    pub fn response(exchange: Exchange, id: u32, initiator_spi: u64, responder_spi: u64) -> Self {
        Self {
            is_response: true,
            ..Self::request(exchange, id, initiator_spi, responder_spi)
        }
    }

    pub fn push(&mut self, kind: u8, data: Vec<u8>) -> &mut Self {
        self.payloads.push((kind, data));
        self
    }

    fn header(&self, next_payload: u8, length: usize) -> Header {
        Header {
            initiator_spi: self.initiator_spi,
            responder_spi: self.responder_spi,
            next_payload,
            exchange: self.exchange,
            from_initiator: self.from_initiator,
            is_response: self.is_response,
            message_id: self.id,
            length: u32::try_from(length).expect("a message fits a datagram"),
        }
    }

    /// The datagram of an unencrypted message.
    pub fn encode_plain(&self) -> Result<Vec<u8>> {
        let mut chain = Vec::new();
        let first = payload::encode_chain(&self.payloads, &mut chain)?;
        let mut out = Vec::with_capacity(HEADER_LEN + chain.len());
        self.header(first, HEADER_LEN + chain.len())
            .encode(&mut out);
        out.extend_from_slice(&chain);
        Ok(out)
    }

    /// The datagrams of an encrypted message: one, or several fragments
    /// when it would exceed `max_len` and the peer supports fragmentation.
    pub fn encode_encrypted(&self, keys: &Keys, max_len: Option<usize>) -> Result<Vec<Vec<u8>>> {
        let mut chain = Vec::new();
        let first = payload::encode_chain(&self.payloads, &mut chain)?;
        let overhead = HEADER_LEN
            + 8
            + keys.cipher.iv_len()
            + keys.cipher.block_len()
            + 1
            + keys.cipher.icv_len()
            + keys.integrity.icv_len();
        let whole_len = HEADER_LEN
            + 4
            + keys.cipher.iv_len()
            + padded_len(chain.len(), keys.cipher)
            + keys.cipher.icv_len()
            + keys.integrity.icv_len();
        match max_len {
            Some(max) if whole_len > max && max > overhead => {
                let chunk_len = max - overhead;
                let chunks: Vec<&[u8]> = chain.chunks(chunk_len).collect();
                let total = u16::try_from(chunks.len())
                    .map_err(|_| Error::Malformed("too many fragments".into()))?;
                chunks
                    .into_iter()
                    .enumerate()
                    .map(|(index, chunk)| {
                        let number = u16::try_from(index + 1).expect("few fragments");
                        let next = if number == 1 { first } else { types::NONE };
                        self.seal(keys, next, chunk, Some((number, total)))
                    })
                    .collect()
            }
            _ => Ok(vec![self.seal(keys, first, &chain, None)?]),
        }
    }

    /// One datagram carrying `plain` in an Encrypted (Fragment) payload.
    fn seal(
        &self,
        keys: &Keys,
        next: u8,
        plain: &[u8],
        fragment: Option<(u16, u16)>,
    ) -> Result<Vec<u8>> {
        let cipher = keys.cipher;
        let mut plaintext = plain.to_vec();
        let pad_len = padded_len(plain.len(), cipher) - plain.len() - 1;
        plaintext.extend(std::iter::repeat_n(0u8, pad_len));
        plaintext.push(u8::try_from(pad_len).expect("short padding"));

        // The AEAD nonce must never repeat under a key (RFC 5282 section
        // 3): the message id, fragment number and direction of the
        // message are unique per IKE SA. CBC takes a random IV.
        let iv = if cipher.is_aead() {
            let (number, _) = fragment.unwrap_or((0, 0));
            let mut iv = self.id.to_be_bytes().to_vec();
            iv.extend_from_slice(&number.to_be_bytes());
            iv.push(0);
            iv.push(u8::from(self.is_response));
            iv
        } else {
            let mut iv = vec![0u8; cipher.iv_len()];
            OsRng.fill_bytes(&mut iv);
            iv
        };
        let fragment_len = if fragment.is_some() { 4 } else { 0 };
        let payload_len = 4
            + fragment_len
            + iv.len()
            + plaintext.len()
            + cipher.icv_len()
            + keys.integrity.icv_len();
        let total_len = HEADER_LEN + payload_len;
        let kind = if fragment.is_some() {
            types::SKF
        } else {
            types::SK
        };

        let mut out = Vec::with_capacity(total_len);
        self.header(kind, total_len).encode(&mut out);
        out.put_u8(next);
        out.put_u8(0);
        out.put_u16(bytes::len16(payload_len)?);
        if let Some((number, total)) = fragment {
            out.put_u16(number);
            out.put_u16(total);
        }
        out.extend_from_slice(&iv);
        if cipher.is_aead() {
            let aad_len = out.len() - iv.len();
            let sealed = cipher.encrypt(&keys.encryption, &iv, &out[..aad_len], &plaintext)?;
            out.extend_from_slice(&sealed);
        } else {
            let sealed = cipher.encrypt(&keys.encryption, &iv, &[], &plaintext)?;
            out.extend_from_slice(&sealed);
            let icv = keys.integrity.mac(&keys.integrity_key, &out);
            out.extend_from_slice(&icv);
        }
        Ok(out)
    }
}

/// Size of `len` bytes of plaintext once padded for `cipher`, with the
/// pad length byte.
fn padded_len(len: usize, cipher: Cipher) -> usize {
    let block = cipher.block_len();
    (len + 1).div_ceil(block) * block
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Cipher, Integrity};

    fn keys(cipher: Cipher, integrity: Integrity) -> Keys {
        Keys {
            cipher,
            integrity,
            encryption: vec![1u8; cipher.key_len()],
            integrity_key: vec![2u8; integrity.key_len()],
        }
    }

    #[test]
    fn plain_messages_round_trip() {
        let mut message = Message::request(Exchange::IkeSaInit, 0, 0x1122, 0);
        message
            .push(types::NONCE, vec![7; 32])
            .push(types::VENDOR_ID, b"openfortivpn".to_vec());
        let bytes = message.encode_plain().expect("encode");
        let packet = Packet::parse(&bytes).expect("parse");
        assert_eq!(packet.header.initiator_spi, 0x1122);
        assert_eq!(packet.header.exchange, Exchange::IkeSaInit);
        assert!(packet.header.from_initiator && !packet.header.is_response);
        assert_eq!(packet.payloads.len(), 2);
        assert_eq!(
            payload::find(&packet.payloads, types::VENDOR_ID).map(|p| p.data.as_slice()),
            Some(&b"openfortivpn"[..])
        );
        assert!(!packet.is_encrypted());
        assert!(Packet::parse(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn encrypted_messages_round_trip() {
        for (cipher, integrity) in [
            (Cipher::AesCbc(256), Integrity::HmacSha256_128),
            (Cipher::AesCbc(128), Integrity::HmacSha1_96),
            (Cipher::AesGcm16(128), Integrity::None),
            (Cipher::ChaCha20Poly1305, Integrity::None),
        ] {
            let keys = keys(cipher, integrity);
            let mut message = Message::request(Exchange::IkeAuth, 1, 1, 2);
            message
                .push(types::IDI, vec![2, 0, 0, 0, b'a'])
                .push(types::NONCE, vec![9; 40]);
            let datagrams = message.encode_encrypted(&keys, None).expect("encode");
            assert_eq!(datagrams.len(), 1);
            let packet = Packet::parse(&datagrams[0]).expect("parse");
            assert!(packet.is_encrypted());
            let decrypted = packet.decrypt(&keys).expect("decrypt");
            let inner = decrypted.payloads().expect("payloads");
            assert_eq!(inner.len(), 2);
            assert_eq!(inner[0].kind, types::IDI);
            assert_eq!(inner[1].data, vec![9; 40]);

            let mut tampered = datagrams[0].clone();
            let last = tampered.len() - 1;
            tampered[last] ^= 1;
            let packet = Packet::parse(&tampered).expect("parse");
            assert!(packet.decrypt(&keys).is_err(), "{cipher:?}");
        }
    }

    #[test]
    fn fragments_reassemble() {
        let keys = keys(Cipher::AesCbc(128), Integrity::HmacSha256_128);
        let mut message = Message::request(Exchange::IkeAuth, 1, 1, 2);
        message
            .push(types::CERT, vec![5; 3000])
            .push(types::NONCE, vec![6; 10]);
        let datagrams = message.encode_encrypted(&keys, Some(1280)).expect("encode");
        assert!(datagrams.len() >= 3);
        assert!(datagrams.iter().all(|datagram| datagram.len() <= 1280));
        let mut reassembler = Reassembler::default();
        let mut whole = None;
        for datagram in datagrams.iter().rev() {
            let packet = Packet::parse(datagram).expect("parse");
            let decrypted = packet.decrypt(&keys).expect("decrypt");
            assert!(decrypted.fragment.is_some());
            whole = reassembler.add(1, decrypted).expect("add");
        }
        let inner = whole.expect("complete").payloads().expect("payloads");
        assert_eq!(inner[0].kind, types::CERT);
        assert_eq!(inner[0].data, vec![5; 3000]);
        assert_eq!(inner[1].data, vec![6; 10]);
    }
}
