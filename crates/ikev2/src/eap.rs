//! RFC 3748 (EAP: Identity, Notification, Nak, MD5-Challenge, GTC), draft-
//! kamath-pppext-eap-mschapv2 (EAP-MSCHAPv2), RFC 2759 (MS-CHAPv2 failure
//! codes).

use md5::{Digest, Md5};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::config::Auth;
use crate::crypto::mschapv2;
use crate::{Error, Result};

const CODE_REQUEST: u8 = 1;
const CODE_RESPONSE: u8 = 2;
const CODE_SUCCESS: u8 = 3;
const CODE_FAILURE: u8 = 4;

const TYPE_IDENTITY: u8 = 1;
const TYPE_NOTIFICATION: u8 = 2;
const TYPE_NAK: u8 = 3;
const TYPE_MD5_CHALLENGE: u8 = 4;
const TYPE_GTC: u8 = 6;
const TYPE_MSCHAPV2: u8 = 26;

const MSCHAPV2_CHALLENGE: u8 = 1;
const MSCHAPV2_RESPONSE: u8 = 2;
const MSCHAPV2_SUCCESS: u8 = 3;
const MSCHAPV2_FAILURE: u8 = 4;

/// What to do with an EAP message from the gateway.
pub enum Step {
    /// Send this EAP packet back.
    Reply(Vec<u8>),
    /// Authentication succeeded, with the master session key of the
    /// method when it has one.
    Success(Option<Zeroizing<Vec<u8>>>),
}

/// The state of an MSCHAPv2 conversation.
struct Mschapv2 {
    authenticator_challenge: Vec<u8>,
    peer_challenge: [u8; mschapv2::CHALLENGE_LEN],
    nt_response: [u8; mschapv2::RESPONSE_LEN],
}

/// The EAP peer for one user.
pub struct Peer {
    /// The method we insist on; any the gateway asks for when `None`
    /// (a SAML token works with all of them).
    method: Option<Auth>,
    username: String,
    password: SecretString,
    mschapv2: Option<Mschapv2>,
    msk: Option<Zeroizing<Vec<u8>>>,
}

impl Peer {
    /// A peer authenticating `username` with `method`, or with whatever
    /// the gateway asks for.
    pub fn new(method: Option<Auth>, username: &str, password: SecretString) -> Self {
        Self {
            method,
            username: username.to_owned(),
            password,
            mschapv2: None,
            msk: None,
        }
    }

    /// Whether we do `method` when the gateway asks for it.
    fn accepts(&self, method: Auth) -> bool {
        self.method.is_none_or(|ours| ours == method)
    }

    /// The type we propose in a Nak.
    fn method_type(&self) -> u8 {
        match self.method {
            Some(Auth::EapGtc) => TYPE_GTC,
            Some(Auth::EapMd5) => TYPE_MD5_CHALLENGE,
            _ => TYPE_MSCHAPV2,
        }
    }

    fn packet(code: u8, id: u8, kind: Option<u8>, data: &[u8]) -> Vec<u8> {
        let length = 4 + usize::from(kind.is_some()) + data.len();
        let mut out = Vec::with_capacity(length);
        out.push(code);
        out.push(id);
        out.extend_from_slice(
            &u16::try_from(length)
                .expect("short EAP packet")
                .to_be_bytes(),
        );
        if let Some(kind) = kind {
            out.push(kind);
        }
        out.extend_from_slice(data);
        out
    }

    pub fn handle(&mut self, packet: &[u8]) -> Result<Step> {
        let malformed = |what: &str| Error::Malformed(format!("EAP: {what}"));
        if packet.len() < 4 {
            return Err(malformed("packet too short"));
        }
        let code = packet[0];
        let id = packet[1];
        let length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        if length < 4 || length > packet.len() {
            return Err(malformed("bad length"));
        }
        let packet = &packet[..length];
        match code {
            CODE_SUCCESS => {
                // MSCHAPv2 proves the gateway knows the password before
                // this; a success without that proof is no success.
                let mschapv2 = self.method == Some(Auth::EapMschapv2) || self.mschapv2.is_some();
                if mschapv2 && self.msk.is_none() {
                    return Err(Error::Authentication(
                        "EAP success before the gateway proved it knows the password".into(),
                    ));
                }
                tracing::debug!("EAP success");
                Ok(Step::Success(self.msk.take()))
            }
            CODE_FAILURE => Err(Error::Authentication(
                "the gateway rejected the EAP authentication (wrong user name or password?)".into(),
            )),
            CODE_REQUEST => {
                let kind = *packet
                    .get(4)
                    .ok_or_else(|| malformed("request without a type"))?;
                let data = &packet[5..];
                self.request(id, kind, data)
            }
            _ => Err(malformed("unexpected code")),
        }
    }

    fn request(&mut self, id: u8, kind: u8, data: &[u8]) -> Result<Step> {
        let reply =
            |kind: u8, data: &[u8]| Step::Reply(Self::packet(CODE_RESPONSE, id, Some(kind), data));
        match kind {
            TYPE_IDENTITY => {
                tracing::debug!("EAP identity requested");
                Ok(reply(TYPE_IDENTITY, self.username.as_bytes()))
            }
            TYPE_NOTIFICATION => {
                tracing::info!("Gateway says: {}", String::from_utf8_lossy(data).trim());
                Ok(reply(TYPE_NOTIFICATION, &[]))
            }
            TYPE_MSCHAPV2 if self.accepts(Auth::EapMschapv2) => self.mschapv2(id, data),
            TYPE_MD5_CHALLENGE if self.accepts(Auth::EapMd5) => {
                let (&size, rest) = data
                    .split_first()
                    .ok_or_else(|| Error::Malformed("EAP-MD5: empty challenge".into()))?;
                let challenge = rest
                    .get(..usize::from(size))
                    .ok_or_else(|| Error::Malformed("EAP-MD5: short challenge".into()))?;
                let mut hasher = Md5::new();
                hasher.update([id]);
                hasher.update(self.password.expose_secret().as_bytes());
                hasher.update(challenge);
                let digest = hasher.finalize();
                let mut response = vec![16u8];
                response.extend_from_slice(&digest);
                response.extend_from_slice(self.username.as_bytes());
                Ok(reply(TYPE_MD5_CHALLENGE, &response))
            }
            TYPE_GTC if self.accepts(Auth::EapGtc) => {
                let prompt = String::from_utf8_lossy(data);
                tracing::debug!("EAP-GTC prompt: {}", prompt.trim());
                Ok(reply(TYPE_GTC, self.password.expose_secret().as_bytes()))
            }
            TYPE_MSCHAPV2 | TYPE_MD5_CHALLENGE | TYPE_GTC => {
                tracing::debug!(
                    "EAP method {kind} requested, proposing {}",
                    self.method_type()
                );
                Ok(reply(TYPE_NAK, &[self.method_type()]))
            }
            other => Err(Error::Authentication(format!(
                "the gateway requires an unsupported EAP method ({other})"
            ))),
        }
    }

    fn mschapv2(&mut self, id: u8, data: &[u8]) -> Result<Step> {
        let malformed = |what: &str| Error::Malformed(format!("EAP-MSCHAPv2: {what}"));
        if data.len() < 4 {
            return Err(malformed("packet too short"));
        }
        let opcode = data[0];
        let ms_id = data[1];
        let ms_length = usize::from(u16::from_be_bytes([data[2], data[3]]));
        if ms_length > data.len() {
            return Err(malformed("bad length"));
        }
        let body = &data[4..ms_length.max(4)];
        match opcode {
            MSCHAPV2_CHALLENGE => {
                let (&size, rest) = body
                    .split_first()
                    .ok_or_else(|| malformed("empty challenge"))?;
                let challenge = rest
                    .get(..usize::from(size))
                    .ok_or_else(|| malformed("short challenge"))?;
                if challenge.len() != mschapv2::CHALLENGE_LEN {
                    return Err(malformed("challenge is not 16 bytes"));
                }
                let mut peer_challenge = [0u8; mschapv2::CHALLENGE_LEN];
                OsRng.fill_bytes(&mut peer_challenge);
                let nt_response = mschapv2::nt_response(
                    &self.username,
                    self.password.expose_secret(),
                    challenge,
                    &peer_challenge,
                );
                self.mschapv2 = Some(Mschapv2 {
                    authenticator_challenge: challenge.to_vec(),
                    peer_challenge,
                    nt_response,
                });
                // Value-Size, Peer-Challenge, Reserved, NT-Response, Flags, Name.
                let mut response = vec![49u8];
                response.extend_from_slice(&peer_challenge);
                response.extend_from_slice(&[0u8; 8]);
                response.extend_from_slice(&nt_response);
                response.push(0);
                response.extend_from_slice(self.username.as_bytes());
                let mut ms = vec![MSCHAPV2_RESPONSE, ms_id];
                ms.extend_from_slice(
                    &u16::try_from(4 + response.len())
                        .expect("short")
                        .to_be_bytes(),
                );
                ms.extend_from_slice(&response);
                tracing::debug!("EAP-MSCHAPv2 challenge answered");
                Ok(Step::Reply(Self::packet(
                    CODE_RESPONSE,
                    id,
                    Some(TYPE_MSCHAPV2),
                    &ms,
                )))
            }
            MSCHAPV2_SUCCESS => {
                let state = self
                    .mschapv2
                    .as_ref()
                    .ok_or_else(|| malformed("success before the challenge"))?;
                let message = String::from_utf8_lossy(body);
                let expected = mschapv2::authenticator_response(
                    &self.username,
                    self.password.expose_secret(),
                    &state.nt_response,
                    &state.authenticator_challenge,
                    &state.peer_challenge,
                );
                let proof = message.as_bytes().get(..expected.len());
                if !proof.is_some_and(|proof| bool::from(proof.ct_eq(expected.as_bytes()))) {
                    return Err(Error::Authentication(
                        "the gateway did not prove it knows the password (EAP-MSCHAPv2 authenticator response mismatch)".into(),
                    ));
                }
                let msk =
                    mschapv2::master_session_key(self.password.expose_secret(), &state.nt_response);
                self.msk = Some(Zeroizing::new(msk.to_vec()));
                tracing::debug!("EAP-MSCHAPv2 success acknowledged");
                Ok(Step::Reply(Self::packet(
                    CODE_RESPONSE,
                    id,
                    Some(TYPE_MSCHAPV2),
                    &[MSCHAPV2_SUCCESS],
                )))
            }
            MSCHAPV2_FAILURE => {
                let message = String::from_utf8_lossy(body);
                tracing::debug!("EAP-MSCHAPv2 failure: {}", message.trim());
                Err(Error::Authentication(format!(
                    "EAP-MSCHAPv2: {}",
                    failure_reason(&message)
                )))
            }
            other => Err(malformed(&format!("unexpected opcode {other}"))),
        }
    }
}

/// The reason of an MSCHAPv2 failure message (RFC 2759 section 6).
fn failure_reason(message: &str) -> &'static str {
    match message
        .split_whitespace()
        .find_map(|field| field.strip_prefix("E="))
    {
        Some("691") => "wrong user name or password",
        Some("646") => "restricted logon hours",
        Some("647") => "account disabled",
        Some("648") => "password expired",
        Some("649") => "no dial-in permission",
        Some("709") => "error changing the password",
        _ => "authentication failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A gateway running EAP-MSCHAPv2 for RFC 2759's user.
    #[test]
    fn mschapv2_conversation() {
        let mut peer = Peer::new(
            Some(Auth::EapMschapv2),
            "User",
            SecretString::from("clientPass"),
        );
        let identity = [CODE_REQUEST, 1, 0, 5, TYPE_IDENTITY];
        let Step::Reply(reply) = peer.handle(&identity).expect("identity") else {
            panic!("expected a reply");
        };
        assert_eq!(
            reply,
            [
                CODE_RESPONSE,
                1,
                0,
                9,
                TYPE_IDENTITY,
                b'U',
                b's',
                b'e',
                b'r'
            ]
        );

        let challenge = hex::decode("5B5D7C7D7B3F2F3E3C2C602132262628").expect("hex");
        let mut ms = vec![MSCHAPV2_CHALLENGE, 7, 0, 0, 16];
        ms.extend_from_slice(&challenge);
        ms.extend_from_slice(b"gateway");
        let length = u16::try_from(ms.len()).expect("short");
        ms[2..4].copy_from_slice(&length.to_be_bytes());
        let request = Peer::packet(CODE_REQUEST, 2, Some(TYPE_MSCHAPV2), &ms);
        let Step::Reply(reply) = peer.handle(&request).expect("challenge") else {
            panic!("expected a reply");
        };
        assert_eq!(reply[4], TYPE_MSCHAPV2);
        assert_eq!(reply[5], MSCHAPV2_RESPONSE);
        assert_eq!(reply[6], 7);
        assert_eq!(reply[9], 49);
        let peer_challenge = &reply[10..26];
        let nt_response = &reply[34..58];
        assert_eq!(&reply[59..], b"User");
        let expected = mschapv2::nt_response("User", "clientPass", &challenge, peer_challenge);
        assert_eq!(nt_response, expected);

        // The gateway proves it knows the password too.
        let nt_response: [u8; 24] = nt_response.try_into().expect("24 bytes");
        let success_message = mschapv2::authenticator_response(
            "User",
            "clientPass",
            &nt_response,
            &challenge,
            peer_challenge,
        ) + " M=Welcome";
        let mut ms = vec![MSCHAPV2_SUCCESS, 7, 0, 0];
        ms.extend_from_slice(success_message.as_bytes());
        let length = u16::try_from(ms.len()).expect("short");
        ms[2..4].copy_from_slice(&length.to_be_bytes());
        let request = Peer::packet(CODE_REQUEST, 3, Some(TYPE_MSCHAPV2), &ms);
        let Step::Reply(reply) = peer.handle(&request).expect("success") else {
            panic!("expected a reply");
        };
        assert_eq!(reply[5], MSCHAPV2_SUCCESS);
        let Step::Success(msk) = peer.handle(&[CODE_SUCCESS, 4, 0, 4]).expect("eap success") else {
            panic!("expected success");
        };
        assert_eq!(msk.expect("msk").len(), 64);

        // A wrong authenticator response is refused.
        let mut peer = Peer::new(
            Some(Auth::EapMschapv2),
            "User",
            SecretString::from("clientPass"),
        );
        let request = Peer::packet(CODE_REQUEST, 2, Some(TYPE_MSCHAPV2), &{
            let mut ms = vec![MSCHAPV2_CHALLENGE, 7, 0, 21, 16];
            ms.extend_from_slice(&challenge);
            ms
        });
        peer.handle(&request).expect("challenge");
        let bogus = Peer::packet(
            CODE_REQUEST,
            3,
            Some(TYPE_MSCHAPV2),
            b"\x03\x07\x00\x08S=00",
        );
        assert!(matches!(peer.handle(&bogus), Err(Error::Authentication(_))));
    }

    #[test]
    fn other_methods_and_failures() {
        let mut peer = Peer::new(Some(Auth::EapGtc), "alice", SecretString::from("pw"));
        let Step::Reply(reply) = peer
            .handle(&Peer::packet(CODE_REQUEST, 1, Some(TYPE_GTC), b"Password:"))
            .expect("gtc")
        else {
            panic!("expected a reply");
        };
        assert_eq!(&reply[5..], b"pw");
        // A method we do not do: Nak with ours.
        let Step::Reply(reply) = peer
            .handle(&Peer::packet(
                CODE_REQUEST,
                2,
                Some(TYPE_MSCHAPV2),
                &[1, 1, 0, 4],
            ))
            .expect("nak")
        else {
            panic!("expected a reply");
        };
        assert_eq!(&reply[4..], [TYPE_NAK, TYPE_GTC]);
        assert!(matches!(
            peer.handle(&[CODE_FAILURE, 3, 0, 4]),
            Err(Error::Authentication(_))
        ));
        let Step::Success(msk) = peer.handle(&[CODE_SUCCESS, 4, 0, 4]).expect("success") else {
            panic!("expected success");
        };
        assert!(msk.is_none());

        let mut peer = Peer::new(None, "alice", SecretString::from("pw"));
        let mut data = vec![4u8];
        data.extend_from_slice(&[9, 9, 9, 9]);
        let Step::Reply(reply) = peer
            .handle(&Peer::packet(
                CODE_REQUEST,
                5,
                Some(TYPE_MD5_CHALLENGE),
                &data,
            ))
            .expect("md5")
        else {
            panic!("expected a reply");
        };
        let mut hasher = Md5::new();
        hasher.update([5u8]);
        hasher.update(b"pw");
        hasher.update([9u8, 9, 9, 9]);
        assert_eq!(&reply[6..22], &hasher.finalize()[..]);
        assert!(peer.handle(&[CODE_REQUEST, 1]).is_err());
    }
}
