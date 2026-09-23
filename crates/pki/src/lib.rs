//! RFC 7468 (PEM), RFC 5958 (PKCS#8), RFC 8017 (PKCS#1), RFC 5915 (SEC 1 EC
//! private keys).

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use pkcs8::{EncryptedPrivateKeyInfo, SecretDocument};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

const CERTIFICATE: &str = "CERTIFICATE";
const ENCRYPTED_KEY: &str = "ENCRYPTED PRIVATE KEY";

/// What went wrong with a credential file.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Could not read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path} is not PEM: {source}")]
    NotPem {
        path: PathBuf,
        source: pem::PemError,
    },
    #[error("no certificate found in {0}")]
    NoCertificate(PathBuf),
    #[error("no private key found in {0}")]
    NoKey(PathBuf),
    #[error("{0} is encrypted, a passphrase is needed")]
    PassphraseNeeded(PathBuf),
    #[error("Could not read private key {path}: {source}")]
    Decrypt { path: PathBuf, source: pkcs8::Error },
}

pub type Result<T> = std::result::Result<T, Error>;

/// An X.509 certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    der: Vec<u8>,
}

impl Certificate {
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The PEM encoding, with Unix line endings.
    #[must_use]
    pub fn to_pem(&self) -> String {
        encode_pem(CERTIFICATE, &self.der)
    }
}

/// The ASN.1 structure of a private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    /// `PRIVATE KEY` (RFC 5958), any algorithm.
    Pkcs8,
    /// `RSA PRIVATE KEY` (RFC 8017).
    Pkcs1,
    /// `EC PRIVATE KEY` (RFC 5915).
    Sec1,
}

impl KeyFormat {
    fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "PRIVATE KEY" => Some(KeyFormat::Pkcs8),
            "RSA PRIVATE KEY" => Some(KeyFormat::Pkcs1),
            "EC PRIVATE KEY" => Some(KeyFormat::Sec1),
            _ => None,
        }
    }

    fn tag(self) -> &'static str {
        match self {
            KeyFormat::Pkcs8 => "PRIVATE KEY",
            KeyFormat::Pkcs1 => "RSA PRIVATE KEY",
            KeyFormat::Sec1 => "EC PRIVATE KEY",
        }
    }
}

/// An unencrypted private key, wiped when dropped.
pub struct PrivateKey {
    format: KeyFormat,
    der: Zeroizing<Vec<u8>>,
}

impl PrivateKey {
    /// The ASN.1 structure of the key.
    #[must_use]
    pub fn format(&self) -> KeyFormat {
        self.format
    }

    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The PEM encoding, with Unix line endings.
    #[must_use]
    pub fn to_pem(&self) -> Zeroizing<String> {
        Zeroizing::new(encode_pem(self.format.tag(), &self.der))
    }
}

fn encode_pem(tag: &str, der: &[u8]) -> String {
    let config = pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF);
    pem::encode_config(&pem::Pem::new(tag, der), config)
}

fn read_pem(path: &Path) -> Result<Vec<pem::Pem>> {
    // The file may hold a key: wipe the buffer afterwards.
    let text = std::fs::read_to_string(path)
        .map(Zeroizing::new)
        .map_err(|source| Error::Read {
            path: path.to_path_buf(),
            source,
        })?;
    pem::parse_many(text.as_str()).map_err(|source| Error::NotPem {
        path: path.to_path_buf(),
        source,
    })
}

/// Every certificate of a PEM file, in order.
pub fn certificates(path: &Path) -> Result<Vec<Certificate>> {
    let certs: Vec<Certificate> = read_pem(path)?
        .into_iter()
        .filter(|block| block.tag() == CERTIFICATE)
        .map(|block| Certificate {
            der: block.into_contents(),
        })
        .collect();
    if certs.is_empty() {
        return Err(Error::NoCertificate(path.to_path_buf()));
    }
    Ok(certs)
}

fn key_block(path: &Path) -> Result<pem::Pem> {
    read_pem(path)?
        .into_iter()
        .find(|block| block.tag() == ENCRYPTED_KEY || KeyFormat::from_tag(block.tag()).is_some())
        .ok_or_else(|| Error::NoKey(path.to_path_buf()))
}

/// Whether the private key at `path` is an encrypted PKCS#8 key.
pub fn key_needs_passphrase(path: &Path) -> Result<bool> {
    Ok(key_block(path)?.tag() == ENCRYPTED_KEY)
}

/// The private key at `path`, decrypted with `passphrase` if needed.
pub fn private_key(path: &Path, passphrase: Option<&SecretString>) -> Result<PrivateKey> {
    let block = key_block(path)?;
    if let Some(format) = KeyFormat::from_tag(block.tag()) {
        return Ok(PrivateKey {
            format,
            der: Zeroizing::new(block.into_contents()),
        });
    }
    let passphrase = passphrase.ok_or_else(|| Error::PassphraseNeeded(path.to_path_buf()))?;
    let decrypt_error = |source| Error::Decrypt {
        path: path.to_path_buf(),
        source,
    };
    let info = EncryptedPrivateKeyInfo::try_from(block.contents()).map_err(decrypt_error)?;
    let document: SecretDocument = info
        .decrypt(passphrase.expose_secret().as_bytes())
        .map_err(decrypt_error)?;
    Ok(PrivateKey {
        format: KeyFormat::Pkcs8,
        der: Zeroizing::new(document.as_bytes().to_vec()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str, content: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ofv-pki-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join(name);
        std::fs::write(&path, content).expect("write");
        path
    }

    const CERT_A: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    const CERT_B: &str = "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n";
    const KEY: &str = "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n";

    #[test]
    fn splits_certificate_bundles() {
        let path = temp_file("bundle.pem", &format!("{CERT_A}garbage\n{KEY}{CERT_B}"));
        let certs = certificates(&path).expect("certificates");
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].der(), [0, 0, 0]);
        assert_eq!(certs[0].to_pem(), CERT_A);
        assert_eq!(certs[1].to_pem(), CERT_B);
        let key = private_key(&path, None).expect("key");
        assert_eq!(key.format(), KeyFormat::Sec1);
        assert_eq!(key.to_pem().as_str(), KEY);
        assert!(!key_needs_passphrase(&path).expect("key"));
    }

    #[test]
    fn reports_missing_items() {
        let path = temp_file("key-only.pem", KEY);
        assert!(matches!(certificates(&path), Err(Error::NoCertificate(_))));
        let path = temp_file("cert-only.pem", CERT_A);
        assert!(matches!(private_key(&path, None), Err(Error::NoKey(_))));
        assert!(matches!(
            certificates(Path::new("/nonexistent")),
            Err(Error::Read { .. })
        ));
    }

    #[test]
    fn encrypted_key_needs_a_passphrase() {
        let path = temp_file(
            "enc.pem",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
        );
        assert!(key_needs_passphrase(&path).expect("key"));
        assert!(matches!(
            private_key(&path, None),
            Err(Error::PassphraseNeeded(_))
        ));
        let wrong = SecretString::from("nope");
        assert!(matches!(
            private_key(&path, Some(&wrong)),
            Err(Error::Decrypt { .. })
        ));
    }
}
