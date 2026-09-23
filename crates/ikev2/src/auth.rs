//! RFC 7296 (CERTREQ, IDr against the certificate), RFC 5280 (X.509 chains,
//! through webpki).

use rustls_pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use sha1::{Digest, Sha1};
use webpki::{EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

use crate::config::Config;
use crate::crypto::PublicKey;
use crate::message::payload::{CERT_X509_SIGNATURE, Identity, id_types};
use crate::{Error, Result};

/// Any extended key usage is fine: the roots are the user's own.
struct AnyUsage;

impl ExtendedKeyUsageValidator for AnyUsage {
    fn validate(&self, iter: KeyPurposeIdIter<'_, '_>) -> std::result::Result<(), webpki::Error> {
        for purpose in iter {
            purpose?;
        }
        Ok(())
    }
}

/// What the gateway's certificate is checked against.
pub struct GatewayVerifier {
    anchors: Vec<TrustAnchor<'static>>,
    /// The certificates of `ca-file` themselves, accepted as the
    /// gateway's own when given directly.
    pinned: Vec<Vec<u8>>,
    /// The identity the gateway must claim.
    expected: String,
}

impl GatewayVerifier {
    /// Loads `ca-file`, or the system roots without it.
    pub fn new(config: &Config) -> Result<Self> {
        let expected = config
            .remote_id
            .clone()
            .unwrap_or_else(|| config.gateway.clone());
        let ders: Vec<Vec<u8>> = if let Some(path) = &config.ca_file {
            ofv_pki::certificates(path)?
                .into_iter()
                .map(|cert| cert.der().to_vec())
                .collect()
        } else {
            let native = rustls_native_certs::load_native_certs();
            for error in &native.errors {
                tracing::debug!("loading the system certificates: {error}");
            }
            native.certs.into_iter().map(|cert| cert.to_vec()).collect()
        };
        let mut anchors = Vec::new();
        for der in &ders {
            match webpki::anchor_from_trusted_cert(&CertificateDer::from(der.as_slice())) {
                Ok(anchor) => anchors.push(anchor.to_owned()),
                Err(error) => tracing::debug!("skipping a root certificate: {error}"),
            }
        }
        if anchors.is_empty() {
            return Err(Error::Config(
                "no trusted certificate to authenticate the gateway: give a --ca-file".into(),
            ));
        }
        tracing::debug!("{} trusted root certificates", anchors.len());
        Ok(Self {
            anchors,
            pinned: if config.ca_file.is_some() {
                ders
            } else {
                Vec::new()
            },
            expected,
        })
    }

    /// The CERTREQ payload data: the SHA-1 of each `ca-file` certificate's
    /// public key info, so that the gateway sends a certificate we can
    /// chain; nothing with the system roots.
    pub fn certreq(&self) -> Option<Vec<u8>> {
        if self.pinned.is_empty() {
            return None;
        }
        let mut data = vec![CERT_X509_SIGNATURE];
        for der in &self.pinned {
            if let Ok((_, cert)) = X509Certificate::from_der(der) {
                data.extend_from_slice(&Sha1::digest(cert.public_key().raw));
            }
        }
        Some(data)
    }

    /// Checks the gateway's certificate chain (`certs`, the gateway's
    /// first), that it is for the expected identity (or `idr` is), and
    /// the AUTH payload signature over `signed_octets`.
    pub fn verify(
        &self,
        certs: &[Vec<u8>],
        idr: &Identity,
        method: u8,
        signed_octets: &[u8],
        auth: &[u8],
    ) -> Result<()> {
        let failed = |what: String| Error::Authentication(format!("gateway certificate: {what}"));
        let (end_entity, intermediates) = certs
            .split_first()
            .ok_or_else(|| failed("the gateway sent no certificate".into()))?;
        let public =
            PublicKey::from_certificate(end_entity).map_err(|error| failed(error.to_string()))?;
        if !public.verify_auth(method, signed_octets, auth) {
            return Err(failed(
                "the AUTH signature does not verify with the certificate's key".into(),
            ));
        }
        if self.pinned.iter().any(|pinned| pinned == end_entity) {
            tracing::debug!("the gateway certificate is one of the trusted certificates");
        } else {
            let end_entity_der = CertificateDer::from(end_entity.as_slice());
            let parsed = EndEntityCert::try_from(&end_entity_der)
                .map_err(|error| failed(format!("cannot parse it: {error}")))?;
            let intermediates: Vec<CertificateDer<'_>> = intermediates
                .iter()
                .map(|der| CertificateDer::from(der.as_slice()))
                .collect();
            parsed
                .verify_for_usage(
                    webpki::ALL_VERIFICATION_ALGS,
                    &self.anchors,
                    &intermediates,
                    UnixTime::now(),
                    AnyUsage,
                    None,
                    None,
                )
                .map_err(|error| failed(format!("not trusted ({error})")))?;
            tracing::debug!("the gateway certificate chains to a trusted root");
        }
        // The certificate must be for the expected identity, and the
        // gateway must claim an identity the certificate asserts (RFC
        // 7296 section 3.5): the signature proves only the latter.
        let Ok((_, cert)) = X509Certificate::from_der(end_entity) else {
            return Err(failed("cannot parse it".into()));
        };
        let expected = self.expected.strip_prefix('@').unwrap_or(&self.expected);
        if !asserts(&cert, expected) && !valid_for_host(end_entity, expected) {
            return Err(failed(format!(
                "it is not for \"{}\"; check --ipsec-remote-id",
                self.expected
            )));
        }
        let claimed = if idr.kind == id_types::DER_ASN1_DN {
            idr.data == cert.subject().as_raw()
        } else {
            asserts(&cert, &idr.display())
        };
        if !claimed {
            return Err(failed(format!(
                "it does not name \"{}\", which the gateway claims to be",
                idr.display()
            )));
        }
        Ok(())
    }
}

/// Whether a certificate names `name` as its subject common name or in
/// its subject alternative names (DNS, e-mail or IP address).
fn asserts(cert: &X509Certificate<'_>, name: &str) -> bool {
    let same = |candidate: &str| candidate.eq_ignore_ascii_case(name);
    let in_subject = cert
        .subject()
        .iter_common_name()
        .any(|cn| cn.as_str().is_ok_and(same));
    let in_san = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .is_some_and(|san| {
            san.value.general_names.iter().any(|general| match general {
                GeneralName::RFC822Name(mail) => same(mail),
                GeneralName::DNSName(dns) => same(dns),
                GeneralName::IPAddress(octets) => <[u8; 4]>::try_from(*octets)
                    .is_ok_and(|octets| same(&std::net::Ipv4Addr::from(octets).to_string())),
                _ => false,
            })
        });
    in_subject || in_san
}

/// Whether a certificate is valid for a host name or address by the TLS
/// rules (wildcards included).
fn valid_for_host(end_entity: &[u8], name: &str) -> bool {
    let Ok(name) = ServerName::try_from(name.to_owned()) else {
        return false;
    };
    let der = CertificateDer::from(end_entity);
    EndEntityCert::try_from(&der)
        .is_ok_and(|cert| cert.verify_is_valid_for_subject_name(&name).is_ok())
}
