//! RFC 4303 (ESP), RFC 3948 (ESP in UDP), RFC 4106 and RFC 7634 (AEAD in ESP).

use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::message::payload::TrafficSelector;
use crate::proposals::EspAlgorithms;
use crate::{Error, Result};

/// Next header value of an IPv4 packet inside ESP.
const NEXT_HEADER_IPV4: u8 = 4;
/// Next header value of a dummy packet (RFC 4303 section 2.6).
const NEXT_HEADER_NONE: u8 = 59;
/// Size of the anti-replay window.
const REPLAY_WINDOW: u32 = 64;
/// Sequence numbers do not wrap: the SA is rekeyed well before.
const SEQUENCE_LIMIT: u32 = u32::MAX - 1024;

/// The keys of one direction.
struct EspKeys {
    encryption: Zeroizing<Vec<u8>>,
    integrity: Zeroizing<Vec<u8>>,
}

/// Anti-replay window over the sequence numbers received.
#[derive(Debug, Default)]
struct Replay {
    highest: u32,
    /// Bit `n` set: `highest - n` was received.
    window: u64,
}

impl Replay {
    /// Whether `seq` is new; records it.
    fn accept(&mut self, seq: u32) -> bool {
        if seq == 0 {
            return false;
        }
        if seq > self.highest {
            let shift = seq - self.highest;
            self.window = if shift >= REPLAY_WINDOW {
                0
            } else {
                self.window << shift
            };
            self.window |= 1;
            self.highest = seq;
            return true;
        }
        let behind = self.highest - seq;
        if behind >= REPLAY_WINDOW {
            return false;
        }
        let bit = 1u64 << behind;
        if self.window & bit != 0 {
            return false;
        }
        self.window |= bit;
        true
    }
}

/// An established CHILD SA.
pub struct ChildSa {
    /// The SPI the gateway sends to (ours).
    pub spi_in: u32,
    /// The SPI we send to (the gateway's).
    pub spi_out: u32,
    pub algorithms: EspAlgorithms,
    pub ts_i: Vec<TrafficSelector>,
    pub ts_r: Vec<TrafficSelector>,
    /// Superseded by a rekey: kept to receive until the gateway deletes
    /// it, never rekeyed again.
    pub replaced: bool,
    outbound: EspKeys,
    inbound: EspKeys,
    seq_out: u32,
    replay: Replay,
    created: Instant,
    bytes_out: u64,
    bytes_in: u64,
}

impl ChildSa {
    /// Size of the keying material for these algorithms.
    pub fn keymat_len(algorithms: EspAlgorithms) -> usize {
        2 * (algorithms.cipher.key_len() + algorithms.integrity.key_len())
    }

    /// A random SPI for our side (never in the reserved range 0-255).
    pub fn random_spi() -> u32 {
        loop {
            let spi = OsRng.next_u32();
            if spi > 255 {
                return spi;
            }
        }
    }

    /// A CHILD SA from its keying material (RFC 7296 section 2.17: the
    /// initiator's encryption and integrity keys, then the responder's),
    /// `initiated` by us or by the gateway.
    pub fn new(
        algorithms: EspAlgorithms,
        (spi_in, spi_out): (u32, u32),
        keymat: &[u8],
        initiated: bool,
        (ts_i, ts_r): (Vec<TrafficSelector>, Vec<TrafficSelector>),
    ) -> Result<Self> {
        if keymat.len() != Self::keymat_len(algorithms) {
            return Err(Error::Crypto("keying material of the wrong size".into()));
        }
        let e_len = algorithms.cipher.key_len();
        let a_len = algorithms.integrity.key_len();
        let mut cursor = 0;
        let mut next = |len: usize| {
            let piece = Zeroizing::new(keymat[cursor..cursor + len].to_vec());
            cursor += len;
            piece
        };
        let first = EspKeys {
            encryption: next(e_len),
            integrity: next(a_len),
        };
        let second = EspKeys {
            encryption: next(e_len),
            integrity: next(a_len),
        };
        let (outbound, inbound) = if initiated {
            (first, second)
        } else {
            (second, first)
        };
        Ok(Self {
            spi_in,
            spi_out,
            algorithms,
            ts_i,
            ts_r,
            replaced: false,
            outbound,
            inbound,
            seq_out: 0,
            replay: Replay::default(),
            created: Instant::now(),
            bytes_out: 0,
            bytes_in: 0,
        })
    }

    /// The SPIs and the traffic carried, for the logs.
    pub fn summary(&self) -> String {
        format!(
            "{:#010x}/{:#010x} ({} bytes out, {} bytes in)",
            self.spi_in, self.spi_out, self.bytes_out, self.bytes_in
        )
    }

    /// When the SA is due for a rekey: after `lifetime`, or now if the
    /// sequence numbers are about to run out.
    pub fn rekey_at(&self, lifetime: Duration) -> Instant {
        if self.seq_out >= SEQUENCE_LIMIT {
            Instant::now()
        } else {
            self.created + lifetime
        }
    }

    pub fn is_due(&self, lifetime: Duration) -> bool {
        self.rekey_at(lifetime) <= Instant::now()
    }

    /// Wraps an IPv4 packet in ESP for the gateway.
    pub fn encapsulate(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        if self.seq_out == u32::MAX {
            return Err(Error::Crypto("ESP sequence numbers exhausted".into()));
        }
        self.seq_out += 1;
        let cipher = self.algorithms.cipher;
        // Payload, padding, pad length, next header: a multiple of the
        // cipher's block size and of 4.
        let align = cipher.block_len().max(4);
        let pad_len = (align - (packet.len() + 2) % align) % align;
        let mut plaintext = Vec::with_capacity(packet.len() + pad_len + 2);
        plaintext.extend_from_slice(packet);
        plaintext.extend((1..=pad_len).map(|pad| u8::try_from(pad).expect("short padding")));
        plaintext.push(u8::try_from(pad_len).expect("short padding"));
        plaintext.push(NEXT_HEADER_IPV4);

        // A counter IV for the AEAD ciphers (RFC 4106 section 3.1: it must
        // never repeat under a key), a random one for CBC.
        let iv = if cipher.is_aead() {
            u64::from(self.seq_out).to_be_bytes().to_vec()
        } else {
            let mut iv = vec![0u8; cipher.iv_len()];
            OsRng.fill_bytes(&mut iv);
            iv
        };
        let mut out = Vec::with_capacity(8 + iv.len() + plaintext.len() + 32);
        out.extend_from_slice(&self.spi_out.to_be_bytes());
        out.extend_from_slice(&self.seq_out.to_be_bytes());
        out.extend_from_slice(&iv);
        if cipher.is_aead() {
            let sealed = cipher.encrypt(&self.outbound.encryption, &iv, &out[..8], &plaintext)?;
            out.extend_from_slice(&sealed);
        } else {
            let sealed = cipher.encrypt(&self.outbound.encryption, &iv, &[], &plaintext)?;
            out.extend_from_slice(&sealed);
            let icv = self
                .algorithms
                .integrity
                .mac(&self.outbound.integrity, &out);
            out.extend_from_slice(&icv);
        }
        self.bytes_out += packet.len() as u64;
        Ok(out)
    }

    /// Unwraps an ESP packet from the gateway: the IPv4 packet inside,
    /// or nothing for a dummy packet.
    pub fn decapsulate(&mut self, esp: &[u8]) -> Result<Option<Vec<u8>>> {
        let cipher = self.algorithms.cipher;
        let iv_len = cipher.iv_len();
        let tag_len = cipher.icv_len() + self.algorithms.integrity.icv_len();
        if esp.len() < 8 + iv_len + tag_len {
            return Err(Error::Malformed("ESP packet too short".into()));
        }
        let spi = u32::from_be_bytes([esp[0], esp[1], esp[2], esp[3]]);
        if spi != self.spi_in {
            return Err(Error::Malformed(format!(
                "ESP packet for unknown SPI {spi:#010x}"
            )));
        }
        let seq = u32::from_be_bytes([esp[4], esp[5], esp[6], esp[7]]);
        let iv = &esp[8..8 + iv_len];
        let plaintext = if cipher.is_aead() {
            cipher.decrypt(&self.inbound.encryption, iv, &esp[..8], &esp[8 + iv_len..])?
        } else {
            let body_end = esp.len() - tag_len;
            if !self.algorithms.integrity.verify(
                &self.inbound.integrity,
                &esp[..body_end],
                &esp[body_end..],
            ) {
                return Err(Error::Crypto("ESP integrity check failed".into()));
            }
            cipher.decrypt(
                &self.inbound.encryption,
                iv,
                &[],
                &esp[8 + iv_len..body_end],
            )?
        };
        if !self.replay.accept(seq) {
            return Err(Error::Malformed(format!(
                "replayed ESP sequence number {seq}"
            )));
        }
        let Some((&next_header, rest)) = plaintext.split_last() else {
            return Err(Error::Malformed("empty ESP payload".into()));
        };
        let Some((&pad_len, padded)) = rest.split_last() else {
            return Err(Error::Malformed("empty ESP payload".into()));
        };
        let pad_len = usize::from(pad_len);
        if padded.len() < pad_len {
            return Err(Error::Malformed("bad ESP padding".into()));
        }
        let packet = &padded[..padded.len() - pad_len];
        self.bytes_in += packet.len() as u64;
        match next_header {
            NEXT_HEADER_IPV4 => Ok(Some(packet.to_vec())),
            NEXT_HEADER_NONE => Ok(None),
            other => {
                tracing::debug!("dropping an ESP packet with next header {other}");
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Cipher, Integrity};

    fn pair(algorithms: EspAlgorithms) -> (ChildSa, ChildSa) {
        let len = ChildSa::keymat_len(algorithms);
        let keymat: Vec<u8> = (0..len)
            .map(|i| u8::try_from(i % 251).expect("byte"))
            .collect();
        let initiator =
            ChildSa::new(algorithms, (1, 2), &keymat, true, (vec![], vec![])).expect("sa");
        let responder =
            ChildSa::new(algorithms, (2, 1), &keymat, false, (vec![], vec![])).expect("sa");
        (initiator, responder)
    }

    #[test]
    fn esp_round_trips() {
        for algorithms in [
            EspAlgorithms {
                cipher: Cipher::AesCbc(256),
                integrity: Integrity::HmacSha256_128,
                group: None,
            },
            EspAlgorithms {
                cipher: Cipher::AesGcm16(128),
                integrity: Integrity::None,
                group: None,
            },
            EspAlgorithms {
                cipher: Cipher::ChaCha20Poly1305,
                integrity: Integrity::None,
                group: None,
            },
        ] {
            let (mut initiator, mut responder) = pair(algorithms);
            let packet = [0x45u8; 61];
            let esp = initiator.encapsulate(&packet).expect("encapsulate");
            assert_eq!(&esp[..4], &2u32.to_be_bytes());
            assert_eq!(&esp[4..8], &1u32.to_be_bytes());
            assert_eq!(
                (esp.len()
                    - 8
                    - algorithms.cipher.iv_len()
                    - algorithms.cipher.icv_len()
                    - algorithms.integrity.icv_len())
                    % 4,
                0
            );
            let inner = responder.decapsulate(&esp).expect("decapsulate");
            assert_eq!(inner.as_deref(), Some(&packet[..]));
            assert!(responder.decapsulate(&esp).is_err(), "replay");
            let mut tampered = esp.clone();
            tampered[20] ^= 1;
            assert!(responder.decapsulate(&tampered).is_err());
            let back = responder.encapsulate(&packet).expect("encapsulate");
            assert_eq!(
                initiator
                    .decapsulate(&back)
                    .expect("decapsulate")
                    .as_deref(),
                Some(&packet[..])
            );
            assert_eq!(
                initiator.summary(),
                "0x00000001/0x00000002 (61 bytes out, 61 bytes in)"
            );
            if algorithms.cipher.is_aead() {
                assert_eq!(&esp[8..16], &1u64.to_be_bytes(), "counter IV");
            }
        }
    }

    #[test]
    fn replay_window_slides() {
        let mut replay = Replay::default();
        assert!(!replay.accept(0));
        assert!(replay.accept(5));
        assert!(replay.accept(3));
        assert!(!replay.accept(3));
        assert!(replay.accept(100));
        assert!(!replay.accept(5));
        assert!(replay.accept(99));
        assert!(!replay.accept(36));
        assert!(replay.accept(37));
    }
}
