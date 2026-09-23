use crate::crypto::{Cipher, Group, Integrity, Prf};
use crate::message::proposal::{Proposal, Protocol, Transform, TransformType};
use crate::{Error, Result};

/// The FortiOS 7.x defaults (AES-CBC/GCM, SHA-256/384, ChaCha20, DH
/// group 14) plus SHA-1 for older gateways.
pub const DEFAULT_IKE: &str = "aes256-sha256-modp2048,aes128-sha256-modp2048,\
aes256gcm16-prfsha384-modp2048,aes128gcm16-prfsha256-modp2048,\
chacha20poly1305-prfsha256-modp2048,aes256-sha384-modp2048,\
aes256-sha1-modp2048,aes128-sha1-modp2048,\
aes256-sha256-ecp256,aes256gcm16-prfsha384-ecp384";
/// ESP proposals without PFS come last, for gateways with PFS disabled.
pub const DEFAULT_ESP: &str = "aes256-sha256-modp2048,aes128-sha256-modp2048,\
aes256gcm16-modp2048,aes128gcm16-modp2048,\
chacha20poly1305-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048,\
aes256-sha256,aes128-sha256,aes256gcm16,aes128gcm16,aes256-sha1,aes128-sha1";

/// The algorithms of an IKE SA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IkeAlgorithms {
    pub cipher: Cipher,
    pub prf: Prf,
    pub integrity: Integrity,
    pub group: Group,
}

impl std::fmt::Display for IkeAlgorithms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-", self.cipher.name())?;
        if self.cipher.is_aead() {
            write!(f, "{}", self.prf.name())?;
        } else {
            write!(f, "{}", self.integrity.name())?;
        }
        write!(f, "-{}", self.group.name())
    }
}

/// The algorithms of a CHILD SA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EspAlgorithms {
    pub cipher: Cipher,
    pub integrity: Integrity,
    /// The group for perfect forward secrecy on rekeys, if any.
    pub group: Option<Group>,
}

impl std::fmt::Display for EspAlgorithms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.cipher.name())?;
        if !self.cipher.is_aead() {
            write!(f, "-{}", self.integrity.name())?;
        }
        if let Some(group) = self.group {
            write!(f, "-{}", group.name())?;
        }
        Ok(())
    }
}

/// The parts of one `a-b-c` proposal string.
#[derive(Default)]
struct Parts {
    cipher: Option<Cipher>,
    prf: Option<Prf>,
    integrity: Option<Integrity>,
    group: Option<Group>,
}

fn parts(spec: &str) -> Result<Parts> {
    let mut parts = Parts::default();
    for word in spec.split('-').filter(|word| !word.is_empty()) {
        if let Some(cipher) = Cipher::from_name(word) {
            parts.cipher = Some(cipher);
        } else if let Some(prf) = Prf::from_name(word) {
            parts.prf = Some(prf);
        } else if let Some(integrity) = Integrity::from_name(word) {
            parts.integrity = Some(integrity);
        } else if let Some(group) = Group::from_name(word) {
            parts.group = Some(group);
        } else {
            return Err(Error::Config(format!(
                "unknown algorithm \"{word}\" in proposal \"{spec}\""
            )));
        }
    }
    Ok(parts)
}

fn specs(list: &str) -> impl Iterator<Item = &str> {
    list.split([',', ' ', '\t']).filter(|spec| !spec.is_empty())
}

/// Parses a comma separated list of IKE proposals.
pub fn parse_ike(list: &str) -> Result<Vec<IkeAlgorithms>> {
    let mut sets = Vec::new();
    for spec in specs(list) {
        let parts = parts(spec)?;
        let invalid = |what: &str| Error::Config(format!("IKE proposal \"{spec}\": {what}"));
        let cipher = parts.cipher.ok_or_else(|| invalid("no cipher"))?;
        let group = parts
            .group
            .ok_or_else(|| invalid("no Diffie-Hellman group"))?;
        let (prf, integrity) = if cipher.is_aead() {
            let prf = parts
                .prf
                .or_else(|| parts.integrity.and_then(Prf::for_integrity))
                .ok_or_else(|| invalid("an AEAD cipher needs a PRF (prfsha256...)"))?;
            (prf, Integrity::None)
        } else {
            let integrity = parts
                .integrity
                .ok_or_else(|| invalid("no integrity algorithm"))?;
            let prf = parts
                .prf
                .or_else(|| Prf::for_integrity(integrity))
                .ok_or_else(|| invalid("no PRF"))?;
            (prf, integrity)
        };
        sets.push(IkeAlgorithms {
            cipher,
            prf,
            integrity,
            group,
        });
    }
    if sets.is_empty() {
        return Err(Error::Config("no IKE proposal".into()));
    }
    Ok(sets)
}

/// Parses a comma separated list of ESP proposals.
pub fn parse_esp(list: &str) -> Result<Vec<EspAlgorithms>> {
    let mut sets = Vec::new();
    for spec in specs(list) {
        let parts = parts(spec)?;
        let invalid = |what: &str| Error::Config(format!("ESP proposal \"{spec}\": {what}"));
        let cipher = parts.cipher.ok_or_else(|| invalid("no cipher"))?;
        let integrity = if cipher.is_aead() {
            Integrity::None
        } else {
            parts
                .integrity
                .ok_or_else(|| invalid("no integrity algorithm"))?
        };
        sets.push(EspAlgorithms {
            cipher,
            integrity,
            group: parts.group,
        });
    }
    if sets.is_empty() {
        return Err(Error::Config("no ESP proposal".into()));
    }
    Ok(sets)
}

fn cipher_transform(cipher: Cipher) -> Transform {
    Transform::with_key_bits(TransformType::Encryption, cipher.id(), cipher.key_bits())
}

/// The SA payload proposals for IKE algorithm sets.
pub fn ike_proposals(sets: &[IkeAlgorithms]) -> Vec<Proposal> {
    sets.iter()
        .enumerate()
        .map(|(index, set)| {
            let mut transforms = vec![
                cipher_transform(set.cipher),
                Transform::new(TransformType::Prf, set.prf.id()),
            ];
            if !set.cipher.is_aead() {
                transforms.push(Transform::new(TransformType::Integrity, set.integrity.id()));
            }
            transforms.push(Transform::new(TransformType::DiffieHellman, set.group.id()));
            Proposal {
                number: u8::try_from(index + 1).expect("few proposals"),
                protocol: Protocol::Ike,
                spi: Vec::new(),
                transforms,
                foreign: false,
            }
        })
        .collect()
}

/// The SA payload proposals for ESP algorithm sets, with our SPI. Groups
/// are proposed only `with_groups` (on a rekey with PFS).
pub fn esp_proposals(sets: &[EspAlgorithms], spi: u32, with_groups: bool) -> Vec<Proposal> {
    sets.iter()
        .enumerate()
        .map(|(index, set)| {
            let mut transforms = vec![cipher_transform(set.cipher)];
            if !set.cipher.is_aead() {
                transforms.push(Transform::new(TransformType::Integrity, set.integrity.id()));
            }
            if let Some(group) = set.group.filter(|_| with_groups) {
                transforms.push(Transform::new(TransformType::DiffieHellman, group.id()));
            }
            transforms.push(Transform::new(TransformType::Esn, 0));
            Proposal {
                number: u8::try_from(index + 1).expect("few proposals"),
                protocol: Protocol::Esp,
                spi: spi.to_be_bytes().to_vec(),
                transforms,
                foreign: false,
            }
        })
        .collect()
}

/// Whether a proposal offers a transform.
fn offers(proposal: &Proposal, kind: TransformType, id: u16, key_bits: Option<u16>) -> bool {
    proposal.transforms_of(kind).any(|transform| {
        transform.id == id && (key_bits.is_none() || transform.key_bits == key_bits)
    })
}

/// Whether a proposal offers a cipher, with its integrity algorithm when
/// it needs one.
fn offers_cipher(proposal: &Proposal, cipher: Cipher, integrity: Integrity) -> bool {
    offers(
        proposal,
        TransformType::Encryption,
        cipher.id(),
        cipher.key_bits(),
    ) && (cipher.is_aead() || offers(proposal, TransformType::Integrity, integrity.id(), None))
}

/// The first of our IKE algorithm sets that a proposal offers: the one
/// the responder chose from ours, or, as the responder of an IKE SA
/// rekey, our pick among the gateway's, restricted to `group` (the group
/// of its KE payload) when given.
pub fn select_ike(
    proposal: &Proposal,
    offered: &[IkeAlgorithms],
    group: Option<Group>,
) -> Result<IkeAlgorithms> {
    if proposal.protocol != Protocol::Ike || proposal.foreign {
        return Err(Error::Malformed(
            "the IKE proposal is not for IKE, or has unknown transforms".into(),
        ));
    }
    offered
        .iter()
        .copied()
        .find(|set| {
            group.is_none_or(|group| set.group == group)
                && offers_cipher(proposal, set.cipher, set.integrity)
                && offers(proposal, TransformType::Prf, set.prf.id(), None)
                && offers(proposal, TransformType::DiffieHellman, set.group.id(), None)
        })
        .ok_or_else(|| Error::Malformed("the IKE proposal offers none of our algorithms".into()))
}

/// The first of our ESP algorithm sets that a proposal offers, with the
/// SPI of the proposal, as [`select_ike`]. A proposal without a group
/// (the first CHILD SA, or a rekey without PFS) matches a set with one;
/// the group returned is the negotiated one.
pub fn select_esp(
    proposal: &Proposal,
    offered: &[EspAlgorithms],
    group: Option<Group>,
) -> Result<(EspAlgorithms, u32)> {
    let bad = |what: &str| Error::Malformed(format!("the ESP proposal {what}"));
    if proposal.protocol != Protocol::Esp || proposal.foreign {
        return Err(bad("is not for ESP, or has unknown transforms"));
    }
    let spi = <[u8; 4]>::try_from(proposal.spi.as_slice())
        .map(u32::from_be_bytes)
        .map_err(|_| bad("has no 4-byte SPI"))?;
    if proposal.transforms_of(TransformType::Esn).next().is_some()
        && !offers(proposal, TransformType::Esn, 0, None)
    {
        return Err(bad("requires extended sequence numbers"));
    }
    let with_pfs = proposal
        .transforms_of(TransformType::DiffieHellman)
        .next()
        .is_some();
    offered
        .iter()
        .find_map(|set| {
            if !offers_cipher(proposal, set.cipher, set.integrity) {
                return None;
            }
            let negotiated = if with_pfs {
                let candidate = set
                    .group
                    .filter(|candidate| group.is_none_or(|group| *candidate == group))?;
                offers(proposal, TransformType::DiffieHellman, candidate.id(), None)
                    .then_some(candidate)?;
                Some(candidate)
            } else {
                None
            };
            Some(EspAlgorithms {
                cipher: set.cipher,
                integrity: set.integrity,
                group: negotiated,
            })
        })
        .map(|set| (set, spi))
        .ok_or_else(|| bad("offers none of our algorithms"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_defaults() {
        let ike = parse_ike(DEFAULT_IKE).expect("ike");
        assert_eq!(ike.len(), 10);
        assert_eq!(ike[0].to_string(), "aes256-sha256-modp2048");
        assert_eq!(ike[2].to_string(), "aes256gcm16-prfsha384-modp2048");
        assert_eq!(ike[2].integrity, Integrity::None);
        assert_eq!(ike[0].prf, Prf::HmacSha256);
        let esp = parse_esp(DEFAULT_ESP).expect("esp");
        assert_eq!(esp.len(), 13);
        assert_eq!(esp[2].to_string(), "aes256gcm16-modp2048");
        assert_eq!(esp[7].to_string(), "aes256-sha256");
        assert!(esp[7].group.is_none());
        assert!(parse_ike("aes256-sha256").is_err());
        assert!(parse_ike("aes128gcm16-modp2048").is_err());
        assert!(parse_ike("des-sha1-modp2048").is_err());
        assert!(parse_esp("").is_err());
    }

    #[test]
    fn proposals_select_back() {
        let ike = parse_ike("aes128-sha1-modp2048,aes256gcm16-prfsha256-ecp256").expect("ike");
        let proposals = ike_proposals(&ike);
        assert_eq!(proposals.len(), 2);
        assert_eq!(proposals[1].transforms.len(), 3);
        assert_eq!(
            select_ike(&proposals[1], &ike, None).expect("select"),
            ike[1]
        );
        assert!(select_ike(&proposals[0], &ike[1..], None).is_err());
        assert!(select_ike(&proposals[1], &ike, Some(Group::Modp2048)).is_err());
        // A responder's view: one proposal with every transform of the peer.
        let everything = Proposal {
            number: 1,
            protocol: Protocol::Ike,
            spi: Vec::new(),
            transforms: proposals
                .iter()
                .flat_map(|proposal| proposal.transforms.clone())
                .collect(),
            foreign: false,
        };
        assert_eq!(
            select_ike(&everything, &ike, Some(Group::Ecp256)).expect("select"),
            ike[1]
        );
        assert_eq!(select_ike(&everything, &ike, None).expect("select"), ike[0]);

        let esp = parse_esp("aes256-sha256-modp2048,aes128gcm16").expect("esp");
        let proposals = esp_proposals(&esp, 0x0102_0304, true);
        assert_eq!(proposals[0].spi, [1, 2, 3, 4]);
        assert_eq!(proposals[0].transforms.len(), 4);
        assert_eq!(proposals[1].transforms.len(), 2);
        let (set, spi) = select_esp(&proposals[0], &esp, None).expect("select");
        assert_eq!((set, spi), (esp[0], 0x0102_0304));
        // Without the group in the answer: accepted for the same cipher.
        let without = esp_proposals(&esp, 9, false);
        assert_eq!(
            select_esp(&without[0], &esp, None).expect("select").0.group,
            None
        );
        // The peer's KE group must be the set's.
        assert!(select_esp(&proposals[0], &esp, Some(Group::Ecp256)).is_err());
        assert_eq!(
            select_esp(&proposals[1], &esp, Some(Group::Ecp256))
                .expect("select")
                .0,
            esp[1]
        );
    }
}
