//! RFC 7296 (IKE SA keys, CHILD SA keying material, signed octets of the AUTH
//! payload).

use zeroize::Zeroizing;

use crate::message::Keys;
use crate::message::payload::Identity;
use crate::proposals::IkeAlgorithms;

const KEY_PAD: &[u8] = b"Key Pad for IKEv2";

/// The keys of an IKE SA, from our side as the initiator.
pub struct IkeKeys {
    pub algorithms: IkeAlgorithms,
    /// For deriving the CHILD SA keys and the next IKE SA.
    pub sk_d: Zeroizing<Vec<u8>>,
    /// For what we send.
    pub outbound: Keys,
    /// For what we receive.
    pub inbound: Keys,
    /// For our AUTH payload.
    pub sk_pi: Zeroizing<Vec<u8>>,
    /// For the gateway's AUTH payload.
    pub sk_pr: Zeroizing<Vec<u8>>,
}

impl IkeKeys {
    /// Derives the keys of a new IKE SA. `old_sk_d` is the SK_d of the
    /// SA being rekeyed, for a CREATE_CHILD_SA rekey.
    pub fn derive(
        algorithms: IkeAlgorithms,
        spi_i: u64,
        spi_r: u64,
        nonce_i: &[u8],
        nonce_r: &[u8],
        shared: &[u8],
        old_sk_d: Option<&[u8]>,
    ) -> Self {
        let prf = algorithms.prf;
        let nonces = [nonce_i, nonce_r].concat();
        let skeyseed = match old_sk_d {
            None => Zeroizing::new(prf.prf(&nonces, shared)),
            Some(old) => Zeroizing::new(prf.prf(old, &[shared, &nonces].concat())),
        };
        let mut seed = nonces;
        seed.extend_from_slice(&spi_i.to_be_bytes());
        seed.extend_from_slice(&spi_r.to_be_bytes());
        let d_len = prf.key_len();
        let a_len = algorithms.integrity.key_len();
        let e_len = algorithms.cipher.key_len();
        let p_len = prf.key_len();
        let material = prf.prf_plus(&skeyseed, &seed, d_len + 2 * a_len + 2 * e_len + 2 * p_len);
        let mut cursor = 0;
        let mut next = |len: usize| {
            let piece = material[cursor..cursor + len].to_vec();
            cursor += len;
            piece
        };
        // SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr
        let sk_d = Zeroizing::new(next(d_len));
        let integrity_keys = (next(a_len), next(a_len));
        let encryption_keys = (next(e_len), next(e_len));
        let prf_keys = (next(p_len), next(p_len));
        Self {
            algorithms,
            sk_d,
            outbound: Keys {
                cipher: algorithms.cipher,
                integrity: algorithms.integrity,
                encryption: encryption_keys.0,
                integrity_key: integrity_keys.0,
            },
            inbound: Keys {
                cipher: algorithms.cipher,
                integrity: algorithms.integrity,
                encryption: encryption_keys.1,
                integrity_key: integrity_keys.1,
            },
            sk_pi: Zeroizing::new(prf_keys.0),
            sk_pr: Zeroizing::new(prf_keys.1),
        }
    }

    /// The keying material of a CHILD SA: `prf+(SK_d, [g^ir |] Ni | Nr)`.
    pub fn child_keymat(
        &self,
        shared: Option<&[u8]>,
        nonce_i: &[u8],
        nonce_r: &[u8],
        len: usize,
    ) -> Zeroizing<Vec<u8>> {
        let mut seed = shared.map(<[u8]>::to_vec).unwrap_or_default();
        seed.extend_from_slice(nonce_i);
        seed.extend_from_slice(nonce_r);
        self.algorithms.prf.prf_plus(&self.sk_d, &seed, len)
    }

    /// The octets each side signs: its IKE_SA_INIT message, the other's
    /// nonce and its identity under its SK_p.
    pub fn signed_octets(
        &self,
        message: &[u8],
        peer_nonce: &[u8],
        sk_p: &[u8],
        identity: &Identity,
    ) -> Vec<u8> {
        let mut octets = message.to_vec();
        octets.extend_from_slice(peer_nonce);
        octets.extend_from_slice(&self.algorithms.prf.prf(sk_p, &identity.encode()));
        octets
    }

    /// The AUTH data for a shared secret (a pre-shared key or an EAP MSK).
    pub fn shared_secret_auth(&self, secret: &[u8], signed_octets: &[u8]) -> Vec<u8> {
        let prf = self.algorithms.prf;
        let key = Zeroizing::new(prf.prf(secret, KEY_PAD));
        prf.prf(&key, signed_octets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Cipher, Group, Integrity, Prf};

    #[test]
    fn keys_are_derived_deterministically() {
        let algorithms = IkeAlgorithms {
            cipher: Cipher::AesCbc(128),
            prf: Prf::HmacSha256,
            integrity: Integrity::HmacSha256_128,
            group: Group::Modp2048,
        };
        let a = IkeKeys::derive(algorithms, 1, 2, &[3; 32], &[4; 32], &[5; 256], None);
        let b = IkeKeys::derive(algorithms, 1, 2, &[3; 32], &[4; 32], &[5; 256], None);
        assert_eq!(a.sk_d, b.sk_d);
        assert_eq!(a.outbound.encryption, b.outbound.encryption);
        assert_ne!(a.outbound.encryption, a.inbound.encryption);
        assert_eq!(a.outbound.encryption.len(), 16);
        assert_eq!(a.outbound.integrity_key.len(), 32);
        assert_eq!(a.sk_pi.len(), 32);
        let rekeyed = IkeKeys::derive(
            algorithms,
            7,
            8,
            &[3; 32],
            &[4; 32],
            &[5; 256],
            Some(&a.sk_d),
        );
        assert_ne!(rekeyed.sk_d, a.sk_d);
        let keymat = a.child_keymat(None, &[3; 32], &[4; 32], 100);
        assert_eq!(keymat.len(), 100);
        let auth = a.shared_secret_auth(b"psk", b"octets");
        assert_eq!(auth.len(), 32);
    }
}
