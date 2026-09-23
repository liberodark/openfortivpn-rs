//! RFC 2759 (MS-CHAPv2), RFC 3079 (its master session key).

use des::Des;
use des::cipher::{BlockEncrypt, KeyInit};
use md4::{Digest, Md4};
use sha1::Sha1;
use zeroize::Zeroizing;

/// Size of the challenges.
pub const CHALLENGE_LEN: usize = 16;
/// Size of the NT-Response.
pub const RESPONSE_LEN: usize = 24;
/// Size of the EAP master session key.
pub const MSK_LEN: usize = 64;

const MAGIC1: &[u8] = b"Magic server to client signing constant";
const MAGIC2: &[u8] = b"Pad to make it do more than one iteration";
const MASTER_KEY_MAGIC: &[u8] = b"This is the MPPE Master Key";
const SEND_KEY_MAGIC: &[u8] =
    b"On the client side, this is the send key; on the server side, it is the receive key.";
const RECEIVE_KEY_MAGIC: &[u8] =
    b"On the client side, this is the receive key; on the server side, it is the send key.";
const SHA_PAD1: [u8; 40] = [0x00; 40];
const SHA_PAD2: [u8; 40] = [0xf2; 40];

/// `NtPasswordHash`: MD4 of the password in UTF-16LE.
fn nt_password_hash(password: &str) -> Zeroizing<[u8; 16]> {
    let mut utf16 = Zeroizing::new(Vec::with_capacity(password.len() * 2));
    for unit in password.encode_utf16() {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }
    Zeroizing::new(Md4::digest(&*utf16).into())
}

/// `ChallengeHash`: the first 8 bytes of SHA-1 over both challenges and
/// the user name.
fn challenge_hash(
    peer_challenge: &[u8],
    authenticator_challenge: &[u8],
    username: &str,
) -> [u8; 8] {
    let mut hasher = Sha1::new();
    hasher.update(peer_challenge);
    hasher.update(authenticator_challenge);
    hasher.update(username.as_bytes());
    let digest = hasher.finalize();
    digest[..8].try_into().expect("8 bytes")
}

/// A 56-bit key spread over 8 bytes with room for the parity bits.
fn des_key(key: &[u8]) -> [u8; 8] {
    let k = |index: usize| key.get(index).copied().unwrap_or(0);
    [
        k(0),
        (k(0) << 7) | (k(1) >> 1),
        (k(1) << 6) | (k(2) >> 2),
        (k(2) << 5) | (k(3) >> 3),
        (k(3) << 4) | (k(4) >> 4),
        (k(4) << 3) | (k(5) >> 5),
        (k(5) << 2) | (k(6) >> 6),
        k(6) << 1,
    ]
}

/// `ChallengeResponse`: the challenge hash encrypted with the three DES
/// keys cut out of the password hash.
fn challenge_response(challenge: [u8; 8], password_hash: &[u8; 16]) -> [u8; RESPONSE_LEN] {
    let mut response = [0u8; RESPONSE_LEN];
    for (index, key) in [
        &password_hash[0..7],
        &password_hash[7..14],
        &password_hash[14..16],
    ]
    .into_iter()
    .enumerate()
    {
        let mut block: des::cipher::Block<Des> = challenge.into();
        Des::new(&des_key(key).into()).encrypt_block(&mut block);
        response[index * 8..index * 8 + 8].copy_from_slice(&block);
    }
    response
}

/// `GenerateNTResponse`.
#[must_use]
pub fn nt_response(
    username: &str,
    password: &str,
    authenticator_challenge: &[u8],
    peer_challenge: &[u8],
) -> [u8; RESPONSE_LEN] {
    let challenge = challenge_hash(peer_challenge, authenticator_challenge, username);
    let hash = nt_password_hash(password);
    challenge_response(challenge, &hash)
}

/// `GenerateAuthenticatorResponse`: the `S=...` string the server must
/// send back to prove it knows the password too.
#[must_use]
pub fn authenticator_response(
    username: &str,
    password: &str,
    nt_response: &[u8; RESPONSE_LEN],
    authenticator_challenge: &[u8],
    peer_challenge: &[u8],
) -> String {
    let hash = nt_password_hash(password);
    let hash_hash = Zeroizing::new(Md4::digest(*hash));
    let mut hasher = Sha1::new();
    hasher.update(*hash_hash);
    hasher.update(nt_response);
    hasher.update(MAGIC1);
    let digest = hasher.finalize();
    let challenge = challenge_hash(peer_challenge, authenticator_challenge, username);
    let mut hasher = Sha1::new();
    hasher.update(digest);
    hasher.update(challenge);
    hasher.update(MAGIC2);
    format!("S={}", hex::encode_upper(hasher.finalize()))
}

/// `GetMasterKey` then `GetAsymmetricStartKey` both ways: the EAP master
/// session key, our send key first, then our receive key, then zeros.
#[must_use]
pub fn master_session_key(
    password: &str,
    nt_response: &[u8; RESPONSE_LEN],
) -> Zeroizing<[u8; MSK_LEN]> {
    let hash = nt_password_hash(password);
    let hash_hash = Zeroizing::new(Md4::digest(*hash));
    let mut hasher = Sha1::new();
    hasher.update(*hash_hash);
    hasher.update(nt_response);
    hasher.update(MASTER_KEY_MAGIC);
    let master_key = Zeroizing::new(hasher.finalize());
    let start_key = |magic: &[u8]| {
        let mut hasher = Sha1::new();
        hasher.update(&master_key[..16]);
        hasher.update(SHA_PAD1);
        hasher.update(magic);
        hasher.update(SHA_PAD2);
        hasher.finalize()
    };
    let mut msk = Zeroizing::new([0u8; MSK_LEN]);
    msk[..16].copy_from_slice(&start_key(SEND_KEY_MAGIC)[..16]);
    msk[16..32].copy_from_slice(&start_key(RECEIVE_KEY_MAGIC)[..16]);
    msk
}

#[cfg(test)]
mod tests {
    use super::*;

    // The vectors of RFC 2759 section 9.2 and RFC 3079 section 3.5.3.
    const USER: &str = "User";
    const PASSWORD: &str = "clientPass";
    const AUTHENTICATOR_CHALLENGE: &str = "5B5D7C7D7B3F2F3E3C2C602132262628";
    const PEER_CHALLENGE: &str = "21402324255E262A28295F2B3A337C7E";
    const NT_RESPONSE: &str = "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF";

    #[test]
    fn matches_rfc_2759() {
        let auth = hex::decode(AUTHENTICATOR_CHALLENGE).expect("hex");
        let peer = hex::decode(PEER_CHALLENGE).expect("hex");
        assert_eq!(
            hex::encode_upper(*nt_password_hash(PASSWORD)),
            "44EBBA8D5312B8D611474411F56989AE"
        );
        assert_eq!(
            hex::encode_upper(challenge_hash(&peer, &auth, USER)),
            "D02E4386BCE91226"
        );
        let response = nt_response(USER, PASSWORD, &auth, &peer);
        assert_eq!(hex::encode_upper(response), NT_RESPONSE);
        assert_eq!(
            authenticator_response(USER, PASSWORD, &response, &auth, &peer),
            "S=407A5589115FD0D6209F510FE9C04566932CDA56"
        );
    }

    #[test]
    fn matches_rfc_3079() {
        let response: [u8; 24] = hex::decode(NT_RESPONSE)
            .expect("hex")
            .try_into()
            .expect("24 bytes");
        // The RFC example computes the keys from the server's side: its
        // send key (Magic3) is our receive key.
        let msk = master_session_key(PASSWORD, &response);
        assert_eq!(
            hex::encode_upper(&msk[..16]),
            "D5F0E9521E3EA9589645E86051C82226"
        );
        assert_eq!(
            hex::encode_upper(&msk[16..32]),
            "8B7CDC149B993A1BA118CB153F56DCCB"
        );
        assert_eq!(msk[32..], [0u8; 32]);
    }
}
