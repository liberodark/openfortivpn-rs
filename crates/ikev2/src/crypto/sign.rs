//! RFC 7296 and RFC 4754 (classic signature methods), RFC 7427 (digital
//! signature method), RFC 8017 (RSA PKCS#1 v1.5).

use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ring::rand::SystemRandom;
use ring::signature::{RsaEncoding, RsaKeyPair, RsaParameters, UnparsedPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_parser::oid_registry::{
    OID_PKCS1_RSAENCRYPTION, OID_PKCS1_SHA1WITHRSA, OID_PKCS1_SHA256WITHRSA,
    OID_PKCS1_SHA384WITHRSA, OID_PKCS1_SHA512WITHRSA, OID_SIG_ECDSA_WITH_SHA256,
    OID_SIG_ECDSA_WITH_SHA384, OID_SIG_ECDSA_WITH_SHA512,
};
use x509_parser::prelude::{AlgorithmIdentifier, FromDer, SubjectPublicKeyInfo, X509Certificate};

use crate::{Error, Result};

/// Hash algorithms of the SIGNATURE_HASH_ALGORITHMS notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    /// Every algorithm, strongest first.
    pub const ALL: [HashAlgorithm; 4] = [
        HashAlgorithm::Sha512,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha1,
    ];

    /// The identifier of RFC 7427 section 7.
    #[must_use]
    pub fn id(self) -> u16 {
        match self {
            HashAlgorithm::Sha1 => 1,
            HashAlgorithm::Sha256 => 2,
            HashAlgorithm::Sha384 => 3,
            HashAlgorithm::Sha512 => 4,
        }
    }

    /// The algorithm with this identifier.
    #[must_use]
    pub fn from_id(id: u16) -> Option<Self> {
        HashAlgorithm::ALL.into_iter().find(|hash| hash.id() == id)
    }

    fn digest(self, message: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha1 => Sha1::digest(message).to_vec(),
            HashAlgorithm::Sha256 => Sha256::digest(message).to_vec(),
            HashAlgorithm::Sha384 => Sha384::digest(message).to_vec(),
            HashAlgorithm::Sha512 => Sha512::digest(message).to_vec(),
        }
    }

    /// How RSA PKCS#1 v1.5 signatures with this hash are checked: keys
    /// of 2048 bits and more, as `webpki` wants of the certificates too.
    fn rsa_verification(self) -> &'static RsaParameters {
        match self {
            HashAlgorithm::Sha1 => &ring::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
            HashAlgorithm::Sha256 => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            HashAlgorithm::Sha384 => &ring::signature::RSA_PKCS1_2048_8192_SHA384,
            HashAlgorithm::Sha512 => &ring::signature::RSA_PKCS1_2048_8192_SHA512,
        }
    }

    /// How RSA PKCS#1 v1.5 signatures with this hash are made: not at
    /// all with SHA-1.
    fn rsa_signing(self) -> Option<&'static dyn RsaEncoding> {
        match self {
            HashAlgorithm::Sha1 => None,
            HashAlgorithm::Sha256 => Some(&ring::signature::RSA_PKCS1_SHA256),
            HashAlgorithm::Sha384 => Some(&ring::signature::RSA_PKCS1_SHA384),
            HashAlgorithm::Sha512 => Some(&ring::signature::RSA_PKCS1_SHA512),
        }
    }

    /// The DER `AlgorithmIdentifier` of RSA PKCS#1 v1.5 with this hash.
    fn rsa_identifier(self) -> Vec<u8> {
        let last = match self {
            HashAlgorithm::Sha1 => 0x05,
            HashAlgorithm::Sha256 => 0x0b,
            HashAlgorithm::Sha384 => 0x0c,
            HashAlgorithm::Sha512 => 0x0d,
        };
        vec![
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, last, 0x05,
            0x00,
        ]
    }

    /// The DER `AlgorithmIdentifier` of ECDSA with this hash.
    fn ecdsa_identifier(self) -> Vec<u8> {
        let last = match self {
            HashAlgorithm::Sha256 => 0x02,
            HashAlgorithm::Sha384 => 0x03,
            _ => 0x04,
        };
        vec![
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, last,
        ]
    }
}

/// The public key of a certificate.
pub enum PublicKey {
    /// The DER `RSAPublicKey` of PKCS#1.
    Rsa(Vec<u8>),
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
}

impl PublicKey {
    /// The public key of a DER certificate.
    pub fn from_certificate(der: &[u8]) -> Result<Self> {
        let (_, certificate) = X509Certificate::from_der(der)
            .map_err(|error| Error::Crypto(format!("bad certificate: {error}")))?;
        Self::from_spki(certificate.public_key().raw)
    }

    /// The key of a DER `SubjectPublicKeyInfo`.
    fn from_spki(spki: &[u8]) -> Result<Self> {
        if let Ok((_, info)) = SubjectPublicKeyInfo::from_der(spki)
            && info.algorithm.algorithm == OID_PKCS1_RSAENCRYPTION
        {
            return Ok(PublicKey::Rsa(info.subject_public_key.data.to_vec()));
        }
        if let Ok(key) = p256::ecdsa::VerifyingKey::from_public_key_der(spki) {
            return Ok(PublicKey::P256(key));
        }
        if let Ok(key) = p384::ecdsa::VerifyingKey::from_public_key_der(spki) {
            return Ok(PublicKey::P384(key));
        }
        Err(Error::Crypto(
            "unsupported public key algorithm in the certificate (RSA, P-256 and P-384 are)".into(),
        ))
    }

    fn verify_rsa(&self, hash: HashAlgorithm, message: &[u8], signature: &[u8]) -> bool {
        match self {
            PublicKey::Rsa(key) => UnparsedPublicKey::new(hash.rsa_verification(), key)
                .verify(message, signature)
                .is_ok(),
            _ => false,
        }
    }

    /// Checks an ECDSA signature, raw `r || s` or DER as `der` says.
    fn verify_ecdsa(
        &self,
        hash: HashAlgorithm,
        message: &[u8],
        signature: &[u8],
        der: bool,
    ) -> bool {
        let digest = hash.digest(message);
        macro_rules! check {
            ($curve:ident, $key:expr) => {{
                let parsed = if der {
                    $curve::ecdsa::Signature::from_der(signature)
                } else {
                    $curve::ecdsa::Signature::from_slice(signature)
                };
                parsed.is_ok_and(|parsed| $key.verify_prehash(&digest, &parsed).is_ok())
            }};
        }
        match self {
            PublicKey::Rsa(_) => false,
            PublicKey::P256(key) => check!(p256, key),
            PublicKey::P384(key) => check!(p384, key),
        }
    }

    /// Checks the signature of an AUTH payload with the given
    /// authentication method (1 for RSA, 9 to 11 for ECDSA, 14 for the
    /// digital signature form), `data` being the payload data.
    #[must_use]
    pub fn verify_auth(&self, method: u8, message: &[u8], data: &[u8]) -> bool {
        match method {
            1 => self.verify_rsa(HashAlgorithm::Sha1, message, data),
            9 => self.verify_ecdsa(HashAlgorithm::Sha256, message, data, false),
            10 => self.verify_ecdsa(HashAlgorithm::Sha384, message, data, false),
            11 => self.verify_ecdsa(HashAlgorithm::Sha512, message, data, false),
            14 => self.verify_digital_signature(message, data),
            _ => false,
        }
    }

    /// RFC 7427: a length, the DER `AlgorithmIdentifier`, the signature.
    fn verify_digital_signature(&self, message: &[u8], data: &[u8]) -> bool {
        let Some((&length, rest)) = data.split_first() else {
            return false;
        };
        let length = usize::from(length);
        if rest.len() < length {
            return false;
        }
        let (identifier, signature) = rest.split_at(length);
        let Ok((_, algorithm)) = AlgorithmIdentifier::from_der(identifier) else {
            return false;
        };
        let oid = &algorithm.algorithm;
        if *oid == OID_PKCS1_SHA256WITHRSA {
            self.verify_rsa(HashAlgorithm::Sha256, message, signature)
        } else if *oid == OID_PKCS1_SHA384WITHRSA {
            self.verify_rsa(HashAlgorithm::Sha384, message, signature)
        } else if *oid == OID_PKCS1_SHA512WITHRSA {
            self.verify_rsa(HashAlgorithm::Sha512, message, signature)
        } else if *oid == OID_PKCS1_SHA1WITHRSA {
            self.verify_rsa(HashAlgorithm::Sha1, message, signature)
        } else if *oid == OID_SIG_ECDSA_WITH_SHA256 {
            self.verify_ecdsa(HashAlgorithm::Sha256, message, signature, true)
        } else if *oid == OID_SIG_ECDSA_WITH_SHA384 {
            self.verify_ecdsa(HashAlgorithm::Sha384, message, signature, true)
        } else if *oid == OID_SIG_ECDSA_WITH_SHA512 {
            self.verify_ecdsa(HashAlgorithm::Sha512, message, signature, true)
        } else {
            tracing::warn!("Unsupported signature algorithm {oid} in the AUTH payload.");
            false
        }
    }
}

/// Our private key, for certificate authentication.
pub enum PrivateKey {
    Rsa(RsaKeyPair),
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
}

impl PrivateKey {
    /// Loads a key read by `ofv-pki`: RSA keys of 2048 bits and more,
    /// P-256 and P-384.
    pub fn from_pki(key: &ofv_pki::PrivateKey) -> Result<Self> {
        let der = key.der();
        let unsupported = || Error::Crypto("unsupported private key algorithm or size".into());
        match key.format() {
            ofv_pki::KeyFormat::Pkcs1 => RsaKeyPair::from_der(der)
                .map(PrivateKey::Rsa)
                .map_err(|_| unsupported()),
            ofv_pki::KeyFormat::Pkcs8 => {
                if let Ok(key) = RsaKeyPair::from_pkcs8(der) {
                    return Ok(PrivateKey::Rsa(key));
                }
                if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_der(der) {
                    return Ok(PrivateKey::P256(key));
                }
                if let Ok(key) = p384::ecdsa::SigningKey::from_pkcs8_der(der) {
                    return Ok(PrivateKey::P384(key));
                }
                Err(unsupported())
            }
            ofv_pki::KeyFormat::Sec1 => {
                if let Ok(key) = p256::SecretKey::from_sec1_der(der) {
                    return Ok(PrivateKey::P256(key.into()));
                }
                if let Ok(key) = p384::SecretKey::from_sec1_der(der) {
                    return Ok(PrivateKey::P384(key.into()));
                }
                Err(unsupported())
            }
        }
    }

    /// The hash the classic authentication method of this key uses.
    fn classic_hash(&self) -> HashAlgorithm {
        match self {
            PrivateKey::Rsa(_) => HashAlgorithm::Sha1,
            PrivateKey::P256(_) => HashAlgorithm::Sha256,
            PrivateKey::P384(_) => HashAlgorithm::Sha384,
        }
    }

    fn sign_rsa(key: &RsaKeyPair, hash: HashAlgorithm, message: &[u8]) -> Result<Vec<u8>> {
        let padding = hash.rsa_signing().ok_or_else(|| {
            Error::Crypto(
                "RSA signatures with SHA-1 are not made: the gateway must take RFC 7427 \
                 signatures with SHA-2"
                    .into(),
            )
        })?;
        let mut signature = vec![0; key.public().modulus_len()];
        key.sign(padding, &SystemRandom::new(), message, &mut signature)
            .map_err(|_| Error::Crypto("RSA signature failed".into()))?;
        Ok(signature)
    }

    fn sign_ecdsa(&self, hash: HashAlgorithm, message: &[u8], der: bool) -> Result<Vec<u8>> {
        let digest = hash.digest(message);
        macro_rules! sign {
            ($curve:ident, $key:expr) => {{
                let signature: $curve::ecdsa::Signature = $key
                    .sign_prehash(&digest)
                    .map_err(|error| Error::Crypto(format!("ECDSA signature failed: {error}")))?;
                Ok(if der {
                    signature.to_der().as_bytes().to_vec()
                } else {
                    signature.to_bytes().to_vec()
                })
            }};
        }
        match self {
            PrivateKey::Rsa(_) => Err(Error::Crypto("not an EC key".into())),
            PrivateKey::P256(key) => sign!(p256, key),
            PrivateKey::P384(key) => sign!(p384, key),
        }
    }

    /// Signs `message` the classic way: the authentication method and
    /// the AUTH payload data.
    pub fn sign_classic(&self, message: &[u8]) -> Result<(u8, Vec<u8>)> {
        let hash = self.classic_hash();
        match self {
            PrivateKey::Rsa(key) => Ok((1, Self::sign_rsa(key, hash, message)?)),
            PrivateKey::P256(_) => Ok((9, self.sign_ecdsa(hash, message, false)?)),
            PrivateKey::P384(_) => Ok((10, self.sign_ecdsa(hash, message, false)?)),
        }
    }

    /// Signs `message` the RFC 7427 way with `hash` (method 14): the AUTH
    /// payload data with its algorithm identifier.
    pub fn sign_digital_signature(&self, hash: HashAlgorithm, message: &[u8]) -> Result<Vec<u8>> {
        let (identifier, signature) = match self {
            PrivateKey::Rsa(key) => (hash.rsa_identifier(), Self::sign_rsa(key, hash, message)?),
            _ => (
                hash.ecdsa_identifier(),
                self.sign_ecdsa(hash, message, true)?,
            ),
        };
        let mut data = Vec::with_capacity(1 + identifier.len() + signature.len());
        data.push(u8::try_from(identifier.len()).expect("short identifier"));
        data.extend_from_slice(&identifier);
        data.extend_from_slice(&signature);
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use p256::pkcs8::EncodePublicKey;

    use super::*;

    /// A 2048-bit RSA key made with `openssl genpkey`.
    const RSA_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDDltMjHZytvOVw\n\
TYHTXdzp3p+HAsxMELTlprYRJIDshnb+BEEX/AzWFhTIwZXw8HML0cg3bGjlQ1d2\n\
sleZXNKPekLF/GCEdTE3mG976NqbwaEUa5H5AUyyOjg0y+691zAKKzmM3VxVoMJ+\n\
8Ly/jZkdn06fm9vK/tBH5RvcB4BfUAuNWks3c70qunOrVvbiMX1JIGvu1nxQzhhb\n\
VbqaNFLnfbSDczqZEOb68W6F/0TGVT0TIGuVQA8M1z5tlzdQObS8f7hE/raTqp3d\n\
0wXBiLbz/femi1dZTyHY7fvcCt5r2CBjTWPGLsag5Uk8YRU5aIy2yCOKvz4rdAyg\n\
bhHN/J1TAgMBAAECggEAUeJ7q7hyh4RNdGpmn4Ss/9ad6CrCOFhIO9tDX0LunNeg\n\
yrEiRXXXM+wTsIbnjPNF3x1pWtbOxakfXYjFxuXHG51+hiAmkl30CIgPqIswtsPm\n\
ecOdXefu4bEhJe15Gs6UBLXbBsAIL6s5smZ8Rx/ziiTPiF/6sW5j6a2gL8qOMph2\n\
S3NVC9/enYh5X0rK/a5dUq2USmLVqwi5ijwlLG8vb00FJKQ8Pqd8TXph/9NDH/BO\n\
GkF0X4x3x0pQL8IrS3/p2xsipckwWWZHN2qxDg3m5gv35m00Aq3+Rz4yRTfDuUuq\n\
Y8g9hVx5IwB4jOxpz+K8VRBx0gVrkolESdIBmz/qwQKBgQD7urFlj2pvRwwC2esc\n\
uFLu29jw15cVNOx7pKPqFH/3pA0kA2bsZ67LWWp33O8FfARQ+9wdnwgYaLVQycnV\n\
e4+qKROW/CZV+wn6t9/sdMr/SV047b1czom49lWp2fDyhwBMDH9KAELF/mAQbSBu\n\
dBgOqBdnoZLu6eUcSNL4VXSKkwKBgQDG6E4LGgLojwDjhH8CYv7VoD8zUo8nKQiJ\n\
l3IZSw47Vwdx+E6xCgHaMqwWxyt9/iAkn2GdTUuKPngBURhfuHKM/Dho6fnutuYA\n\
lt7Qpanzn5wtpph3IW/Myq+05Dh88TAnKPIJxByi/KU4PJvOZf2yr9E8uHZHgMXJ\n\
4vcPQHOaQQKBgQDgy8axeFJHDz41qZ9hJWXCMofYA97CrGFmxQ8v8aCZaGHnwDYA\n\
dVLN+4qtgZnd3vMH0vKtbSBQk+kfPSRFxbL09PuugHxHmgg+YkfQpDfHpB9gwEWz\n\
hCnPCARVyu911YM5ZouhbPw0TcZBxQIKQRhetlM4UzygqDTWfl4QMFgDiwKBgD/Z\n\
5uOtb+2Tqmde6x6rBL8y99bT09xwUatJkHkKHQFziJJPcYNngPy4c4HEYfPKFitr\n\
dnx2iZ9ROljB3Z8sqKkVdk5HfdHhqKfbxp8X7xyjyhDlf+AOPcNx9UGOWYvSKPEJ\n\
NdlouQChNbB91E5Hc09fHT3uwRlm/xc14rVkrTeBAoGAVtqANzLVdTbG6Ar/5liO\n\
sB29hnW9ZVSc7zLfFP3RlNfTU7l57/d482dK3Pctb6uwni0nb1Dplv9uhEeSWegi\n\
TdzOmY3nLG2Atfsn4XVOtrKMY+yoIvAD9IfAM1UughD+4BMW985JaQv3zakCm2NN\n\
fDFTAmLVEeByILsPFotRXGI=\n\
-----END PRIVATE KEY-----";
    /// `openssl dgst -sha1 -sign` of "message" with that key.
    const RSA_SHA1_SIGNATURE: &str = "7f76d609416e91ba0bc7102deddfe01e73e8c6884234eaf667ca84723f4288017ecd372697bc295ba71caf8f541da268e8758d611f996e17b08b089933599dae4592405306853934f967dbc0b44cc5cf769a67df0015e0af866c4b153711c10284a1e48d3b5543694e14c023d767c200250856d33fcd84873eb788213d701084d9108a0d0e13b9289c4e56d1386e41e5255439697519cbabe38fea3c2fb616f0e9f6d4faf6bd670a30f2f6cb5ad3c738befa3d303f47713e28b1f8be91cb21ea5ba31cc886671c640fe974f4043d6d3c72238b4f223e22d860aefd52d3eedf1e5423a5acf159f98fcd2414b07662e07ab6da4e211333a49339fd57157ab39b60";

    #[test]
    fn rsa_signatures_verify() {
        let pkcs8 = pem::parse(RSA_KEY).expect("pem");
        let key = RsaKeyPair::from_pkcs8(pkcs8.contents()).expect("key");
        let public = PublicKey::Rsa(key.public().as_ref().to_vec());
        let private = PrivateKey::Rsa(key);
        let data = private
            .sign_digital_signature(HashAlgorithm::Sha256, b"message")
            .expect("sign");
        assert_eq!(data[0], 15);
        assert!(public.verify_auth(14, b"message", &data));
        assert!(!public.verify_auth(14, b"messagf", &data));
        assert!(!public.verify_auth(9, b"message", &data));
        // The classic method signs with SHA-1, which ring only verifies.
        assert!(private.sign_classic(b"message").is_err());
        let classic = hex::decode(RSA_SHA1_SIGNATURE).expect("hex");
        assert!(public.verify_auth(1, b"message", &classic));
        assert!(!public.verify_auth(1, b"messagf", &classic));
    }

    #[test]
    fn ecdsa_signatures_verify() {
        let key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let spki = key.verifying_key().to_public_key_der().expect("spki");
        let public = PublicKey::from_spki(spki.as_bytes()).expect("key");
        let private = PrivateKey::P256(key);
        let (method, data) = private.sign_classic(b"message").expect("sign");
        assert_eq!((method, data.len()), (9, 64));
        assert!(public.verify_auth(9, b"message", &data));
        assert!(!public.verify_auth(9, b"messagf", &data));
        let data = private
            .sign_digital_signature(HashAlgorithm::Sha256, b"message")
            .expect("sign");
        assert!(public.verify_auth(14, b"message", &data));
        assert!(!public.verify_auth(14, b"messagf", &data));

        let key = p384::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let spki = key.verifying_key().to_public_key_der().expect("spki");
        let public = PublicKey::from_spki(spki.as_bytes()).expect("key");
        let (method, data) = PrivateKey::P384(key).sign_classic(b"m").expect("sign");
        assert_eq!((method, data.len()), (10, 96));
        assert!(public.verify_auth(10, b"m", &data));
    }

    #[test]
    fn loads_keys_from_pki_formats() {
        let key = p256::SecretKey::random(&mut rand_core::OsRng);
        let sec1 = key.to_sec1_der().expect("sec1");
        let dir = std::env::temp_dir().join(format!("ofv-ikev2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("ec.pem");
        let config = pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF);
        std::fs::write(
            &path,
            pem::encode_config(&pem::Pem::new("EC PRIVATE KEY", sec1.to_vec()), config),
        )
        .expect("write");
        let loaded = ofv_pki::private_key(&path, None).expect("key");
        assert!(matches!(
            PrivateKey::from_pki(&loaded),
            Ok(PrivateKey::P256(_))
        ));
        std::fs::remove_dir_all(&dir).ok();
    }
}
