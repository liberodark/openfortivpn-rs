//! RFC 7296 (PRF and integrity transforms, prf+), RFC 2403, RFC 2404 and RFC
//! 4868 (HMAC truncations).

use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// The hash under an HMAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Hash {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn output_len(self) -> usize {
        match self {
            Hash::Md5 => 16,
            Hash::Sha1 => 20,
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
        }
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        macro_rules! compute {
            ($digest:ty) => {{
                let mut mac =
                    Hmac::<$digest>::new_from_slice(key).expect("HMAC takes any key size");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }};
        }
        match self {
            Hash::Md5 => compute!(Md5),
            Hash::Sha1 => compute!(Sha1),
            Hash::Sha256 => compute!(Sha256),
            Hash::Sha384 => compute!(Sha384),
            Hash::Sha512 => compute!(Sha512),
        }
    }
}

/// A pseudo-random function (IKEv2 transform type 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Prf {
    HmacMd5,
    HmacSha1,
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl Prf {
    /// Every function, strongest first.
    pub const ALL: [Prf; 5] = [
        Prf::HmacSha512,
        Prf::HmacSha384,
        Prf::HmacSha256,
        Prf::HmacSha1,
        Prf::HmacMd5,
    ];

    fn hash(self) -> Hash {
        match self {
            Prf::HmacMd5 => Hash::Md5,
            Prf::HmacSha1 => Hash::Sha1,
            Prf::HmacSha256 => Hash::Sha256,
            Prf::HmacSha384 => Hash::Sha384,
            Prf::HmacSha512 => Hash::Sha512,
        }
    }

    /// The IKEv2 transform identifier.
    #[must_use]
    pub fn id(self) -> u16 {
        match self {
            Prf::HmacMd5 => 1,
            Prf::HmacSha1 => 2,
            Prf::HmacSha256 => 5,
            Prf::HmacSha384 => 6,
            Prf::HmacSha512 => 7,
        }
    }

    /// The strongSwan name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Prf::HmacMd5 => "prfmd5",
            Prf::HmacSha1 => "prfsha1",
            Prf::HmacSha256 => "prfsha256",
            Prf::HmacSha384 => "prfsha384",
            Prf::HmacSha512 => "prfsha512",
        }
    }

    /// The function with this strongSwan name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Prf::ALL.into_iter().find(|prf| prf.name() == name)
    }

    /// The PRF that goes with an integrity algorithm, when none is named.
    #[must_use]
    pub fn for_integrity(integrity: Integrity) -> Option<Self> {
        match integrity {
            Integrity::None => None,
            Integrity::HmacMd5_96 => Some(Prf::HmacMd5),
            Integrity::HmacSha1_96 => Some(Prf::HmacSha1),
            Integrity::HmacSha256_128 => Some(Prf::HmacSha256),
            Integrity::HmacSha384_192 => Some(Prf::HmacSha384),
            Integrity::HmacSha512_256 => Some(Prf::HmacSha512),
        }
    }

    /// The preferred key size, which is also the output size.
    #[must_use]
    pub fn key_len(self) -> usize {
        self.hash().output_len()
    }

    /// `prf(K, S)`.
    #[must_use]
    pub fn prf(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        self.hash().hmac(key, data)
    }

    /// `prf+(K, S)`: `len` bytes of keying material.
    #[must_use]
    pub fn prf_plus(self, key: &[u8], seed: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
        let mut output = Zeroizing::new(Vec::with_capacity(len + self.key_len()));
        let mut previous: Vec<u8> = Vec::new();
        let mut counter: u8 = 1;
        while output.len() < len {
            let mut data = previous.clone();
            data.extend_from_slice(seed);
            data.push(counter);
            previous = self.prf(key, &data);
            output.extend_from_slice(&previous);
            counter = counter
                .checked_add(1)
                .expect("prf+ is never asked for more than 255 blocks");
        }
        output.truncate(len);
        output
    }
}

/// An integrity algorithm (IKEv2 transform type 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Integrity {
    /// For AEAD ciphers.
    None,
    HmacMd5_96,
    HmacSha1_96,
    HmacSha256_128,
    HmacSha384_192,
    HmacSha512_256,
}

impl Integrity {
    /// Every algorithm, strongest first.
    pub const ALL: [Integrity; 6] = [
        Integrity::HmacSha512_256,
        Integrity::HmacSha384_192,
        Integrity::HmacSha256_128,
        Integrity::HmacSha1_96,
        Integrity::HmacMd5_96,
        Integrity::None,
    ];

    fn hash(self) -> Option<Hash> {
        match self {
            Integrity::None => None,
            Integrity::HmacMd5_96 => Some(Hash::Md5),
            Integrity::HmacSha1_96 => Some(Hash::Sha1),
            Integrity::HmacSha256_128 => Some(Hash::Sha256),
            Integrity::HmacSha384_192 => Some(Hash::Sha384),
            Integrity::HmacSha512_256 => Some(Hash::Sha512),
        }
    }

    /// The IKEv2 transform identifier.
    #[must_use]
    pub fn id(self) -> u16 {
        match self {
            Integrity::None => 0,
            Integrity::HmacMd5_96 => 1,
            Integrity::HmacSha1_96 => 2,
            Integrity::HmacSha256_128 => 12,
            Integrity::HmacSha384_192 => 13,
            Integrity::HmacSha512_256 => 14,
        }
    }

    /// The strongSwan name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Integrity::None => "none",
            Integrity::HmacMd5_96 => "md5",
            Integrity::HmacSha1_96 => "sha1",
            Integrity::HmacSha256_128 => "sha256",
            Integrity::HmacSha384_192 => "sha384",
            Integrity::HmacSha512_256 => "sha512",
        }
    }

    /// The algorithm with this strongSwan name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "sha2_256" | "sha256_128" => Some(Integrity::HmacSha256_128),
            "sha2_384" | "sha384_192" => Some(Integrity::HmacSha384_192),
            "sha2_512" | "sha512_256" => Some(Integrity::HmacSha512_256),
            "sha1_96" => Some(Integrity::HmacSha1_96),
            "md5_96" => Some(Integrity::HmacMd5_96),
            _ => Integrity::ALL
                .into_iter()
                .filter(|integ| *integ != Integrity::None)
                .find(|integ| integ.name() == name),
        }
    }

    #[must_use]
    pub fn key_len(self) -> usize {
        self.hash().map_or(0, Hash::output_len)
    }

    /// Size of the integrity checksum value.
    #[must_use]
    pub fn icv_len(self) -> usize {
        match self {
            Integrity::None => 0,
            Integrity::HmacMd5_96 | Integrity::HmacSha1_96 => 12,
            Integrity::HmacSha256_128 => 16,
            Integrity::HmacSha384_192 => 24,
            Integrity::HmacSha512_256 => 32,
        }
    }

    /// The truncated checksum of `data`.
    #[must_use]
    pub fn mac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let Some(hash) = self.hash() else {
            return Vec::new();
        };
        let mut mac = hash.hmac(key, data);
        mac.truncate(self.icv_len());
        mac
    }

    /// Whether `icv` is the checksum of `data`, in constant time.
    #[must_use]
    pub fn verify(self, key: &[u8], data: &[u8], icv: &[u8]) -> bool {
        let expected = self.mac(key, data);
        expected.len() == icv.len() && bool::from(expected.ct_eq(icv))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_matches_rfc_4231() {
        // Test case 2 of RFC 4231.
        let mac = Prf::HmacSha256.prf(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let mac = Prf::HmacSha1.prf(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(hex::encode(mac), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
    }

    #[test]
    fn prf_plus_chains_blocks() {
        let key = b"key";
        let seed = b"seed";
        let out = Prf::HmacSha256.prf_plus(key, seed, 70);
        assert_eq!(out.len(), 70);
        let t1 = Prf::HmacSha256.prf(key, &[seed.as_slice(), &[1]].concat());
        let t2 = Prf::HmacSha256.prf(key, &[t1.as_slice(), seed, &[2]].concat());
        let t3 = Prf::HmacSha256.prf(key, &[t2.as_slice(), seed, &[3]].concat());
        assert_eq!(&out[..32], &t1[..]);
        assert_eq!(&out[32..64], &t2[..]);
        assert_eq!(&out[64..], &t3[..6]);
    }

    #[test]
    fn integrity_truncates_and_verifies() {
        let key = [7u8; 32];
        let icv = Integrity::HmacSha256_128.mac(&key, b"data");
        assert_eq!(icv.len(), 16);
        assert!(Integrity::HmacSha256_128.verify(&key, b"data", &icv));
        assert!(!Integrity::HmacSha256_128.verify(&key, b"datb", &icv));
        assert!(!Integrity::HmacSha256_128.verify(&key, b"data", &icv[..15]));
        assert_eq!(Integrity::HmacSha1_96.mac(&key, b"x").len(), 12);
        assert!(Integrity::None.mac(&key, b"x").is_empty());
        for integ in Integrity::ALL {
            if integ != Integrity::None {
                assert_eq!(Integrity::from_name(integ.name()), Some(integ));
            }
        }
        for prf in Prf::ALL {
            assert_eq!(Prf::from_name(prf.name()), Some(prf));
        }
        assert_eq!(
            Integrity::from_name("sha256"),
            Some(Integrity::HmacSha256_128)
        );
        assert_eq!(
            Prf::for_integrity(Integrity::HmacSha1_96),
            Some(Prf::HmacSha1)
        );
    }
}
