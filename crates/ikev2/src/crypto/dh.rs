//! RFC 7296 (KE payload), RFC 2409 and RFC 3526 (MODP groups), RFC 5903 (ECP
//! groups), RFC 8031 (Curve25519).

use num_bigint_dig::BigUint;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use super::modp;
use crate::{Error, Result};

/// A Diffie-Hellman group, by its IKEv2 transform identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Group {
    Modp1024,
    Modp1536,
    Modp2048,
    Modp3072,
    Modp4096,
    Ecp256,
    Ecp384,
    Ecp521,
    Curve25519,
}

impl Group {
    /// Every group, strongest first.
    pub const ALL: [Group; 9] = [
        Group::Curve25519,
        Group::Ecp521,
        Group::Ecp384,
        Group::Ecp256,
        Group::Modp4096,
        Group::Modp3072,
        Group::Modp2048,
        Group::Modp1536,
        Group::Modp1024,
    ];

    /// The IKEv2 transform identifier.
    #[must_use]
    pub fn id(self) -> u16 {
        match self {
            Group::Modp1024 => 2,
            Group::Modp1536 => 5,
            Group::Modp2048 => 14,
            Group::Modp3072 => 15,
            Group::Modp4096 => 16,
            Group::Ecp256 => 19,
            Group::Ecp384 => 20,
            Group::Ecp521 => 21,
            Group::Curve25519 => 31,
        }
    }

    /// The group with this transform identifier.
    #[must_use]
    pub fn from_id(id: u16) -> Option<Self> {
        Group::ALL.into_iter().find(|group| group.id() == id)
    }

    /// The strongSwan name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Group::Modp1024 => "modp1024",
            Group::Modp1536 => "modp1536",
            Group::Modp2048 => "modp2048",
            Group::Modp3072 => "modp3072",
            Group::Modp4096 => "modp4096",
            Group::Ecp256 => "ecp256",
            Group::Ecp384 => "ecp384",
            Group::Ecp521 => "ecp521",
            Group::Curve25519 => "x25519",
        }
    }

    /// The group with this strongSwan name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "curve25519" => Some(Group::Curve25519),
            _ => Group::ALL.into_iter().find(|group| group.name() == name),
        }
    }

    /// Size of the public value in a KE payload.
    #[must_use]
    pub fn public_len(self) -> usize {
        match self {
            Group::Modp1024 => 128,
            Group::Modp1536 => 192,
            Group::Modp2048 => 256,
            Group::Modp3072 => 384,
            Group::Modp4096 => 512,
            Group::Ecp256 => 64,
            Group::Ecp384 => 96,
            Group::Ecp521 => 132,
            Group::Curve25519 => 32,
        }
    }

    /// Groups no longer considered strong enough.
    #[must_use]
    pub fn is_weak(self) -> bool {
        matches!(self, Group::Modp1024 | Group::Modp1536)
    }

    fn modp(self) -> Option<(&'static [u8], usize)> {
        match self {
            Group::Modp1024 => Some((&modp::MODP_1024, modp::MODP_1024_EXPONENT)),
            Group::Modp1536 => Some((&modp::MODP_1536, modp::MODP_1536_EXPONENT)),
            Group::Modp2048 => Some((&modp::MODP_2048, modp::MODP_2048_EXPONENT)),
            Group::Modp3072 => Some((&modp::MODP_3072, modp::MODP_3072_EXPONENT)),
            Group::Modp4096 => Some((&modp::MODP_4096, modp::MODP_4096_EXPONENT)),
            _ => None,
        }
    }
}

/// Our half of a key exchange.
pub struct KeyExchange {
    group: Group,
    secret: Secret,
    public: Vec<u8>,
}

enum Secret {
    Modp(BigUint),
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
    X25519(x25519_dalek::StaticSecret),
}

impl Drop for Secret {
    fn drop(&mut self) {
        if let Secret::Modp(exponent) = self {
            exponent.zeroize();
        }
    }
}

impl KeyExchange {
    /// A fresh key pair for `group`.
    #[must_use]
    pub fn generate(group: Group) -> Self {
        let (secret, public) = match group {
            Group::Ecp256 => {
                let secret = p256::SecretKey::random(&mut OsRng);
                let public = secret.public_key().to_encoded_point(false);
                (Secret::P256(secret), public.as_bytes()[1..].to_vec())
            }
            Group::Ecp384 => {
                let secret = p384::SecretKey::random(&mut OsRng);
                let public = secret.public_key().to_encoded_point(false);
                (Secret::P384(secret), public.as_bytes()[1..].to_vec())
            }
            Group::Ecp521 => {
                let secret = p521::SecretKey::random(&mut OsRng);
                let public = secret.public_key().to_encoded_point(false);
                (Secret::P521(secret), public.as_bytes()[1..].to_vec())
            }
            Group::Curve25519 => {
                let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
                let public = x25519_dalek::PublicKey::from(&secret);
                (Secret::X25519(secret), public.as_bytes().to_vec())
            }
            modp => {
                let (prime, exponent_len) = modp.modp().expect("a MODP group");
                let mut bytes = Zeroizing::new(vec![0u8; exponent_len]);
                OsRng.fill_bytes(&mut bytes);
                let exponent = BigUint::from_bytes_be(&bytes);
                let prime = BigUint::from_bytes_be(prime);
                let public = BigUint::from(2u8).modpow(&exponent, &prime);
                (Secret::Modp(exponent), fixed(&public, modp.public_len()))
            }
        };
        Self {
            group,
            secret,
            public,
        }
    }

    #[must_use]
    pub fn group(&self) -> Group {
        self.group
    }

    /// Our public value, as sent in the KE payload.
    #[must_use]
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    /// The shared secret with the peer's public value.
    pub fn shared(&self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let invalid = || Error::Crypto(format!("invalid {} public value", self.group.name()));
        if peer.len() != self.group.public_len() {
            return Err(invalid());
        }
        let shared = match &self.secret {
            Secret::Modp(exponent) => {
                let (prime, _) = self.group.modp().expect("a MODP group");
                let prime = BigUint::from_bytes_be(prime);
                let peer = BigUint::from_bytes_be(peer);
                if peer <= BigUint::from(1u8) || peer >= &prime - BigUint::from(1u8) {
                    return Err(invalid());
                }
                let shared = peer.modpow(exponent, &prime);
                fixed(&shared, self.group.public_len())
            }
            Secret::P256(secret) => {
                let point = p256::PublicKey::from_sec1_bytes(&sec1(peer)).map_err(|_| invalid())?;
                p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), point.as_affine())
                    .raw_secret_bytes()
                    .to_vec()
            }
            Secret::P384(secret) => {
                let point = p384::PublicKey::from_sec1_bytes(&sec1(peer)).map_err(|_| invalid())?;
                p384::ecdh::diffie_hellman(secret.to_nonzero_scalar(), point.as_affine())
                    .raw_secret_bytes()
                    .to_vec()
            }
            Secret::P521(secret) => {
                let point = p521::PublicKey::from_sec1_bytes(&sec1(peer)).map_err(|_| invalid())?;
                p521::ecdh::diffie_hellman(secret.to_nonzero_scalar(), point.as_affine())
                    .raw_secret_bytes()
                    .to_vec()
            }
            Secret::X25519(secret) => {
                let peer: [u8; 32] = peer.try_into().map_err(|_| invalid())?;
                let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
                if !shared.was_contributory() {
                    return Err(invalid());
                }
                shared.as_bytes().to_vec()
            }
        };
        Ok(Zeroizing::new(shared))
    }
}

/// The uncompressed SEC 1 encoding of a KE public value (x || y).
fn sec1(point: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(point.len() + 1);
    encoded.push(0x04);
    encoded.extend_from_slice(point);
    encoded
}

/// A big number as a fixed-size big-endian byte string.
fn fixed(value: &BigUint, len: usize) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    let mut out = vec![0u8; len.saturating_sub(bytes.len())];
    out.extend_from_slice(&bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_agree() {
        for group in Group::ALL {
            let alice = KeyExchange::generate(group);
            let bob = KeyExchange::generate(group);
            assert_eq!(alice.public().len(), group.public_len(), "{group:?}");
            let shared_a = alice.shared(bob.public()).expect("shared");
            let shared_b = bob.shared(alice.public()).expect("shared");
            assert_eq!(*shared_a, *shared_b, "{group:?}");
            assert_ne!(alice.public(), bob.public());
        }
    }

    #[test]
    fn rejects_bad_public_values() {
        let alice = KeyExchange::generate(Group::Modp2048);
        assert!(alice.shared(&[0u8; 256]).is_err());
        let mut one = vec![0u8; 256];
        one[255] = 1;
        assert!(alice.shared(&one).is_err());
        assert!(alice.shared(&[0xff; 256]).is_err());
        assert!(alice.shared(&[1u8; 255]).is_err());
        let ec = KeyExchange::generate(Group::Ecp256);
        assert!(ec.shared(&[0u8; 64]).is_err());
        let x = KeyExchange::generate(Group::Curve25519);
        assert!(x.shared(&[0u8; 32]).is_err());
    }

    #[test]
    fn names_and_ids_round_trip() {
        for group in Group::ALL {
            assert_eq!(Group::from_id(group.id()), Some(group));
            assert_eq!(Group::from_name(group.name()), Some(group));
        }
        assert_eq!(Group::from_name("curve25519"), Some(Group::Curve25519));
        assert_eq!(Group::from_id(1), None);
    }
}
