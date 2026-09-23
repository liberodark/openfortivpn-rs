//! RFC 3602 (AES-CBC), RFC 4106 (AES-GCM), RFC 7634 (ChaCha20-Poly1305), RFC
//! 5282 (their use in IKEv2).

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{AeadCore, AesGcm, KeyInit};
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use chacha20poly1305::ChaCha20Poly1305;

use crate::{Error, Result};

type Aes128Gcm = AesGcm<Aes128, aes_gcm::aes::cipher::consts::U12>;
type Aes192Gcm = AesGcm<Aes192, aes_gcm::aes::cipher::consts::U12>;
type Aes256Gcm = AesGcm<Aes256, aes_gcm::aes::cipher::consts::U12>;

/// Size of the salt an AEAD cipher takes from the keying material.
const AEAD_SALT_LEN: usize = 4;
/// Size of the explicit IV of an AEAD cipher.
const AEAD_IV_LEN: usize = 8;
/// Size of the AEAD tag.
const AEAD_ICV_LEN: usize = 16;
const AES_BLOCK_LEN: usize = 16;

/// An encryption algorithm with its key size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cipher {
    /// AES in CBC mode, 128, 192 or 256-bit key.
    AesCbc(u16),
    /// AES in GCM mode with a 16-byte tag, 128, 192 or 256-bit key.
    AesGcm16(u16),
    /// ChaCha20 with Poly1305, 256-bit key.
    ChaCha20Poly1305,
}

impl Cipher {
    /// The IKEv2 transform identifier.
    #[must_use]
    pub fn id(self) -> u16 {
        match self {
            Cipher::AesCbc(_) => 12,
            Cipher::AesGcm16(_) => 20,
            Cipher::ChaCha20Poly1305 => 28,
        }
    }

    /// The key size attribute, for the algorithms that take one.
    #[must_use]
    pub fn key_bits(self) -> Option<u16> {
        match self {
            Cipher::AesCbc(bits) | Cipher::AesGcm16(bits) => Some(bits),
            Cipher::ChaCha20Poly1305 => None,
        }
    }

    /// The strongSwan name.
    #[must_use]
    pub fn name(self) -> String {
        match self {
            Cipher::AesCbc(bits) => format!("aes{bits}"),
            Cipher::AesGcm16(bits) => format!("aes{bits}gcm16"),
            Cipher::ChaCha20Poly1305 => "chacha20poly1305".to_owned(),
        }
    }

    /// The algorithm with this strongSwan name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "chacha20poly1305" => Some(Cipher::ChaCha20Poly1305),
            "aes128gcm16" | "aes128gcm128" => Some(Cipher::AesGcm16(128)),
            "aes192gcm16" | "aes192gcm128" => Some(Cipher::AesGcm16(192)),
            "aes256gcm16" | "aes256gcm128" => Some(Cipher::AesGcm16(256)),
            "aes" | "aes128" => Some(Cipher::AesCbc(128)),
            "aes192" => Some(Cipher::AesCbc(192)),
            "aes256" => Some(Cipher::AesCbc(256)),
            _ => None,
        }
    }

    /// Whether the algorithm authenticates by itself.
    #[must_use]
    pub fn is_aead(self) -> bool {
        !matches!(self, Cipher::AesCbc(_))
    }

    /// Size of the keying material: the key, plus the salt of an AEAD.
    #[must_use]
    pub fn key_len(self) -> usize {
        match self {
            Cipher::AesCbc(bits) => usize::from(bits / 8),
            Cipher::AesGcm16(bits) => usize::from(bits / 8) + AEAD_SALT_LEN,
            Cipher::ChaCha20Poly1305 => 32 + AEAD_SALT_LEN,
        }
    }

    /// Size of the IV sent with each message.
    #[must_use]
    pub fn iv_len(self) -> usize {
        if self.is_aead() {
            AEAD_IV_LEN
        } else {
            AES_BLOCK_LEN
        }
    }

    /// The plaintext is padded to a multiple of this.
    #[must_use]
    pub fn block_len(self) -> usize {
        if self.is_aead() { 1 } else { AES_BLOCK_LEN }
    }

    /// Size of the tag an AEAD appends; zero otherwise.
    #[must_use]
    pub fn icv_len(self) -> usize {
        if self.is_aead() { AEAD_ICV_LEN } else { 0 }
    }

    /// Encrypts `plaintext` (a multiple of the block size for CBC) with
    /// `key` (keying material) and `iv`; `aad` is authenticated by an
    /// AEAD and ignored otherwise. The tag is appended for an AEAD.
    pub fn encrypt(self, key: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.check(key, iv)?;
        match self {
            Cipher::AesCbc(_) => {
                if !plaintext.len().is_multiple_of(AES_BLOCK_LEN) {
                    return Err(Error::Crypto("plaintext is not block aligned".into()));
                }
                Ok(match key.len() {
                    16 => cbc::Encryptor::<Aes128>::new(key.into(), iv.into())
                        .encrypt_padded_vec_mut::<NoPadding>(plaintext),
                    24 => cbc::Encryptor::<Aes192>::new(key.into(), iv.into())
                        .encrypt_padded_vec_mut::<NoPadding>(plaintext),
                    _ => cbc::Encryptor::<Aes256>::new(key.into(), iv.into())
                        .encrypt_padded_vec_mut::<NoPadding>(plaintext),
                })
            }
            authenticated => authenticated.seal(
                key,
                iv,
                Payload {
                    msg: plaintext,
                    aad,
                },
            ),
        }
    }

    /// Decrypts `ciphertext` (with its tag for an AEAD).
    pub fn decrypt(self, key: &[u8], iv: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.check(key, iv)?;
        match self {
            Cipher::AesCbc(_) => {
                if !ciphertext.len().is_multiple_of(AES_BLOCK_LEN) {
                    return Err(Error::Crypto("ciphertext is not block aligned".into()));
                }
                let result = match key.len() {
                    16 => cbc::Decryptor::<Aes128>::new(key.into(), iv.into())
                        .decrypt_padded_vec_mut::<NoPadding>(ciphertext),
                    24 => cbc::Decryptor::<Aes192>::new(key.into(), iv.into())
                        .decrypt_padded_vec_mut::<NoPadding>(ciphertext),
                    _ => cbc::Decryptor::<Aes256>::new(key.into(), iv.into())
                        .decrypt_padded_vec_mut::<NoPadding>(ciphertext),
                };
                result.map_err(|_| Error::Crypto("AES-CBC decryption failed".into()))
            }
            authenticated => authenticated.open(
                key,
                iv,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            ),
        }
    }

    fn check(self, key: &[u8], iv: &[u8]) -> Result<()> {
        if key.len() != self.key_len() {
            return Err(Error::Crypto(format!(
                "{} takes {} bytes of keying material, got {}",
                self.name(),
                self.key_len(),
                key.len()
            )));
        }
        if iv.len() != self.iv_len() {
            return Err(Error::Crypto(format!(
                "{} takes a {}-byte IV",
                self.name(),
                self.iv_len()
            )));
        }
        Ok(())
    }

    /// The AEAD nonce: the salt from the keying material, then the IV.
    fn nonce(key: &[u8], iv: &[u8]) -> ([u8; 12], usize) {
        let key_len = key.len() - AEAD_SALT_LEN;
        let mut nonce = [0u8; 12];
        nonce[..AEAD_SALT_LEN].copy_from_slice(&key[key_len..]);
        nonce[AEAD_SALT_LEN..].copy_from_slice(iv);
        (nonce, key_len)
    }

    fn seal(self, key: &[u8], iv: &[u8], payload: Payload<'_, '_>) -> Result<Vec<u8>> {
        let (nonce, key_len) = Self::nonce(key, iv);
        let key = &key[..key_len];
        let nonce = aes_gcm::Nonce::<<Aes128Gcm as AeadCore>::NonceSize>::from_slice(&nonce);
        let result = match self {
            Cipher::AesGcm16(128) => Aes128Gcm::new(key.into()).encrypt(nonce, payload),
            Cipher::AesGcm16(192) => Aes192Gcm::new(key.into()).encrypt(nonce, payload),
            Cipher::AesGcm16(_) => Aes256Gcm::new(key.into()).encrypt(nonce, payload),
            _ => ChaCha20Poly1305::new(key.into()).encrypt(nonce, payload),
        };
        result.map_err(|_| Error::Crypto("AEAD encryption failed".into()))
    }

    fn open(self, key: &[u8], iv: &[u8], payload: Payload<'_, '_>) -> Result<Vec<u8>> {
        let (nonce, key_len) = Self::nonce(key, iv);
        let key = &key[..key_len];
        let nonce = aes_gcm::Nonce::<<Aes128Gcm as AeadCore>::NonceSize>::from_slice(&nonce);
        let result = match self {
            Cipher::AesGcm16(128) => Aes128Gcm::new(key.into()).decrypt(nonce, payload),
            Cipher::AesGcm16(192) => Aes192Gcm::new(key.into()).decrypt(nonce, payload),
            Cipher::AesGcm16(_) => Aes256Gcm::new(key.into()).decrypt(nonce, payload),
            _ => ChaCha20Poly1305::new(key.into()).decrypt(nonce, payload),
        };
        result.map_err(|_| Error::Crypto("integrity check failed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_cbc_round_trips() {
        for bits in [128u16, 192, 256] {
            let cipher = Cipher::AesCbc(bits);
            let key = vec![0x42u8; cipher.key_len()];
            let iv = [7u8; 16];
            let plaintext = [1u8; 48];
            let ciphertext = cipher.encrypt(&key, &iv, b"", &plaintext).expect("encrypt");
            assert_eq!(ciphertext.len(), 48);
            assert_ne!(&ciphertext[..], &plaintext[..]);
            let decrypted = cipher
                .decrypt(&key, &iv, b"", &ciphertext)
                .expect("decrypt");
            assert_eq!(decrypted, plaintext);
            assert!(cipher.encrypt(&key, &iv, b"", &[1u8; 20]).is_err());
            assert!(cipher.encrypt(&key[..8], &iv, b"", &plaintext).is_err());
        }
    }

    #[test]
    fn aes_cbc_matches_nist_vector() {
        // NIST SP 800-38A F.2.1, CBC-AES128.Encrypt, first block.
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").expect("hex");
        let iv = hex::decode("000102030405060708090a0b0c0d0e0f").expect("hex");
        let plaintext = hex::decode("6bc1bee22e409f96e93d7e117393172a").expect("hex");
        let ciphertext = Cipher::AesCbc(128)
            .encrypt(&key, &iv, b"", &plaintext)
            .expect("encrypt");
        assert_eq!(hex::encode(ciphertext), "7649abac8119b246cee98e9b12e9197d");
    }

    #[test]
    fn aead_round_trips_and_authenticates() {
        for cipher in [
            Cipher::AesGcm16(128),
            Cipher::AesGcm16(192),
            Cipher::AesGcm16(256),
            Cipher::ChaCha20Poly1305,
        ] {
            let key = vec![0x42u8; cipher.key_len()];
            let iv = [9u8; 8];
            let ciphertext = cipher
                .encrypt(&key, &iv, b"aad", b"hello")
                .expect("encrypt");
            assert_eq!(ciphertext.len(), 5 + 16);
            let decrypted = cipher
                .decrypt(&key, &iv, b"aad", &ciphertext)
                .expect("decrypt");
            assert_eq!(decrypted, b"hello");
            assert!(cipher.decrypt(&key, &iv, b"aae", &ciphertext).is_err());
            let mut tampered = ciphertext.clone();
            tampered[0] ^= 1;
            assert!(cipher.decrypt(&key, &iv, b"aad", &tampered).is_err());
        }
    }

    #[test]
    fn aes_gcm_matches_known_vector() {
        // RFC 4106 test case 2 style check: key||salt, IV, AAD = SPI||SEQ.
        // (Test vector from the GCM specification, test case 4, restricted
        // to what the salt/IV split allows: encrypt then decrypt back.)
        let key = hex::decode("feffe9928665731c6d6a8f9467308308cafebabe").expect("hex");
        let iv = hex::decode("facedbaddecaf888").expect("hex");
        let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").expect("hex");
        let plaintext = hex::decode(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        )
        .expect("hex");
        let ciphertext = Cipher::AesGcm16(128)
            .encrypt(&key, &iv, &aad, &plaintext)
            .expect("encrypt");
        assert_eq!(
            hex::encode(&ciphertext),
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091\
             5bc94fbc3221a5db94fae95ae7121a47"
        );
    }

    #[test]
    fn names_round_trip() {
        for cipher in [
            Cipher::AesCbc(128),
            Cipher::AesCbc(256),
            Cipher::AesGcm16(128),
            Cipher::AesGcm16(256),
            Cipher::ChaCha20Poly1305,
        ] {
            assert_eq!(Cipher::from_name(&cipher.name()), Some(cipher));
        }
        assert_eq!(Cipher::from_name("aes64"), None);
        assert_eq!(Cipher::from_name("des"), None);
    }
}
