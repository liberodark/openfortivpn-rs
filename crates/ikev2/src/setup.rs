//! RFC 7296 (IKE_SA_INIT, NAT detection, IKE_AUTH, configuration payload), RFC
//! 7427 (signature authentication).

use std::net::Ipv4Addr;

use ofv_net::{Dns, DnsTool, Routes, Tun};
use secrecy::ExposeSecret;
use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::auth::GatewayVerifier;
use crate::child::ChildSa;
use crate::config::Auth;
use crate::crypto::{Group, HashAlgorithm, KeyExchange, PrivateKey};
use crate::eap;
use crate::forticlient;
use crate::message::payload::{
    self, CERT_X509_SIGNATURE, CP_REPLY, CP_REQUEST, Config as ConfigPayload, ConfigAttribute,
    Identity, Notify, RawPayload, TrafficSelector, cp_attributes, notify,
};
use crate::message::{Exchange, Message, types};
use crate::proposals::{self, esp_proposals, ike_proposals};
use crate::sa::IkeKeys;
use crate::session::{Assigned, Host, Reply, Session, Stage, nonce};
use crate::{Error, Result};

/// AUTH method of a shared key MIC.
const AUTH_SHARED_KEY: u8 = 2;
/// AUTH method of RFC 7427 digital signatures.
const AUTH_DIGITAL_SIGNATURE: u8 = 14;
/// How many times IKE_SA_INIT is retried on a COOKIE or INVALID_KE_PAYLOAD.
const INIT_RETRIES: usize = 3;

/// Sets everything up, from the sockets to the routes.
pub async fn establish(session: &mut Session<'_>, cancel: &CancellationToken) -> Result<()> {
    let config = session.config;
    session.ike_algorithms = proposals::parse_ike(
        config
            .ike_proposals
            .as_deref()
            .unwrap_or(proposals::DEFAULT_IKE),
    )?;
    session.esp_algorithms = proposals::parse_esp(
        config
            .esp_proposals
            .as_deref()
            .unwrap_or(proposals::DEFAULT_ESP),
    )?;
    if config.auth == Auth::Pubkey {
        let cert_path = config.user_cert.as_ref().ok_or_else(|| {
            Error::Config("certificate authentication needs a certificate".into())
        })?;
        let key_path = config
            .user_key
            .as_ref()
            .ok_or_else(|| Error::Config("certificate authentication needs a key".into()))?;
        session.certificates = ofv_pki::certificates(cert_path)?
            .into_iter()
            .map(|cert| cert.der().to_vec())
            .collect();
        let key = ofv_pki::private_key(key_path, config.pem_passphrase.as_ref())?;
        session.private_key = Some(PrivateKey::from_pki(&key)?);
    }
    if config.gateway_uses_cert() {
        session.verifier = Some(GatewayVerifier::new(config)?);
    }

    tracing::info!(
        "Establishing IKEv2 tunnel to {}:{} as {} ({})...",
        config.gateway,
        config.port,
        if config.username.is_empty() {
            "certificate"
        } else {
            &config.username
        },
        if session.forticlient.is_some() {
            "saml"
        } else {
            config.auth.charon_name()
        }
    );
    ike_sa_init(session, cancel).await?;
    session.stage = Stage::Auth;
    ike_auth(session, cancel).await?;

    // One CHILD SA per network the first one does not cover: the split
    // networks, or else those the gateway pushed.
    let networks = if config.split_include.is_empty() {
        session.assigned.subnets.clone()
    } else {
        config.split_networks()?
    };
    for (address, prefix) in networks {
        let selector = TrafficSelector::network(address, prefix);
        let covered = session
            .children
            .iter()
            .any(|child| child.ts_r.iter().any(|ts| ts.covers(&selector)));
        if !covered {
            crate::rekey::create_child(
                session,
                vec![TrafficSelector::ANY],
                vec![selector],
                None,
                cancel,
            )
            .await?;
        }
    }
    bring_up(session).await?;
    Ok(())
}

/// The NAT_DETECTION hash: SHA-1 of the SPIs, an address and a port.
fn nat_detection(spi_i: u64, spi_r: u64, address: Ipv4Addr, port: u16) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(spi_i.to_be_bytes());
    hasher.update(spi_r.to_be_bytes());
    hasher.update(address.octets());
    hasher.update(port.to_be_bytes());
    hasher.finalize().to_vec()
}

/// The IKE_SA_INIT exchange, retried on a cookie request or a group
/// change.
async fn ike_sa_init(session: &mut Session<'_>, cancel: &CancellationToken) -> Result<()> {
    // The nonce and the key exchange stay the same across a cookie retry
    // (RFC 7296 section 2.6 computes the cookie over the nonce).
    let mut exchange = KeyExchange::generate(session.ike_algorithms[0].group);
    session.nonce_i = nonce();
    let mut cookie: Option<Vec<u8>> = None;
    for _ in 0..INIT_RETRIES {
        let message = init_request(session, &exchange, cookie.as_deref())?;
        tracing::debug!("IKE_SA_INIT with {}", exchange.group().name());
        let reply = session.request(message, cancel).await?;
        session.init_request.clone_from(&session.last_request);

        if let Some(request) = reply
            .notifies()
            .find(|notify| notify.kind == notify::COOKIE)
        {
            tracing::debug!("the gateway wants a cookie");
            cookie = Some(request.data);
            session.message_id = 0;
            continue;
        }
        if let Some(invalid) = reply
            .notifies()
            .find(|notify| notify.kind == notify::INVALID_KE_PAYLOAD)
        {
            let offered = session.ike_algorithms.iter().map(|set| set.group);
            let wanted = wanted_group(&invalid.data, offered)?;
            tracing::debug!("the gateway wants {}", wanted.name());
            exchange = KeyExchange::generate(wanted);
            session.message_id = 0;
            continue;
        }
        reply.check()?;
        return accept_init(session, &reply, &exchange);
    }
    Err(Error::Notify("IKE_SA_INIT kept being redirected".into()))
}

/// The group an INVALID_KE_PAYLOAD notification asks for, if we offer it.
pub fn wanted_group(data: &[u8], mut offered: impl Iterator<Item = Group>) -> Result<Group> {
    let wanted = <[u8; 2]>::try_from(data)
        .map(u16::from_be_bytes)
        .map_err(|_| Error::Malformed("INVALID_KE_PAYLOAD without a group".into()))?;
    Group::from_id(wanted)
        .filter(|wanted| offered.any(|group| group == *wanted))
        .ok_or_else(|| {
            Error::Notify(format!(
                "INVALID_KE_PAYLOAD for group {wanted}, which we do not offer"
            ))
        })
}

/// Our IKE_SA_INIT request.
fn init_request(
    session: &Session<'_>,
    exchange: &KeyExchange,
    cookie: Option<&[u8]>,
) -> Result<Message> {
    let group = exchange.group();
    let mut message = session.new_request(Exchange::IkeSaInit);
    if let Some(cookie) = cookie {
        message.push(
            types::NOTIFY,
            Notify::new(notify::COOKIE, cookie.to_vec()).encode(),
        );
    }
    // Proposals first with the group we do the exchange for.
    let mut ordered = session.ike_algorithms.clone();
    ordered.sort_by_key(|set| set.group != group);
    message.push(types::SA, payload::encode_sa(&ike_proposals(&ordered))?);
    message.push(types::KE, payload::encode_ke(group.id(), exchange.public()));
    message.push(types::NONCE, session.nonce_i.clone());
    if session.forticlient.is_some() {
        for vendor_id in forticlient::Device::VENDOR_IDS {
            message.push(types::VENDOR_ID, vendor_id.to_vec());
        }
    }
    // A wrong source hash makes the gateway see a NAT and encapsulate
    // ESP in UDP, which is how we carry it.
    message.push(
        types::NOTIFY,
        Notify::new(notify::NAT_DETECTION_SOURCE_IP, nonce()[..20].to_vec()).encode(),
    );
    message.push(
        types::NOTIFY,
        Notify::new(
            notify::NAT_DETECTION_DESTINATION_IP,
            nat_detection(session.spi_i, 0, session.gateway, session.config.port),
        )
        .encode(),
    );
    message.push(
        types::NOTIFY,
        Notify::new(notify::IKEV2_FRAGMENTATION_SUPPORTED, Vec::new()).encode(),
    );
    let hashes: Vec<u8> = HashAlgorithm::ALL
        .iter()
        .flat_map(|hash| hash.id().to_be_bytes())
        .collect();
    message.push(
        types::NOTIFY,
        Notify::new(notify::SIGNATURE_HASH_ALGORITHMS, hashes).encode(),
    );
    Ok(message)
}

/// The IKE_SA_INIT response: the algorithms, the shared secret, the keys.
fn accept_init(session: &mut Session<'_>, reply: &Reply, exchange: &KeyExchange) -> Result<()> {
    let group = exchange.group();
    let sa = reply
        .payload(types::SA)
        .ok_or_else(|| Error::Malformed("IKE_SA_INIT response without SA".into()))?;
    let chosen = payload::decode_sa(&sa.data)?;
    let chosen = chosen
        .first()
        .ok_or_else(|| Error::Malformed("empty SA payload".into()))?;
    let algorithms = proposals::select_ike(chosen, &session.ike_algorithms, Some(group))?;
    if algorithms.group != group {
        return Err(Error::Malformed(
            "the gateway chose a group other than the KE payload's".into(),
        ));
    }
    let ke = reply
        .payload(types::KE)
        .ok_or_else(|| Error::Malformed("IKE_SA_INIT response without KE".into()))?;
    let (peer_group, peer_public) = payload::decode_ke(&ke.data)?;
    if peer_group != group.id() {
        return Err(Error::Malformed("KE payload for another group".into()));
    }
    let shared = exchange.shared(peer_public)?;
    session.nonce_r.clone_from(
        &reply
            .payload(types::NONCE)
            .ok_or_else(|| Error::Malformed("IKE_SA_INIT response without a nonce".into()))?
            .data,
    );
    session.spi_r = reply.header.responder_spi;
    if !reply
        .notifies()
        .any(|notify| notify.kind == notify::NAT_DETECTION_SOURCE_IP)
    {
        return Err(Error::Notify(
            "the gateway does not do NAT traversal (RFC 3948), which this client needs to carry \
             ESP over UDP; enable it on the gateway (nattraversal enable)"
                .into(),
        ));
    }
    session.peer_fragments = reply
        .notifies()
        .any(|notify| notify.kind == notify::IKEV2_FRAGMENTATION_SUPPORTED);
    session.peer_hash_algorithms = reply
        .notifies()
        .filter(|notify| notify.kind == notify::SIGNATURE_HASH_ALGORITHMS)
        .flat_map(|notify| {
            notify
                .data
                .chunks_exact(2)
                .filter_map(|id| HashAlgorithm::from_id(u16::from_be_bytes([id[0], id[1]])))
                .collect::<Vec<_>>()
        })
        .collect();
    session.init_response.clone_from(&reply.raw);
    session.keys = Some(IkeKeys::derive(
        algorithms,
        session.spi_i,
        session.spi_r,
        &session.nonce_i,
        &session.nonce_r,
        &shared,
        None,
    ));
    tracing::info!(
        "IKE_SA_INIT done with {algorithms}{}{}.",
        if session.peer_fragments {
            ", fragmentation"
        } else {
            ""
        },
        if algorithms.group.is_weak() {
            " (weak group!)"
        } else {
            ""
        }
    );
    Ok(())
}

/// Our AUTH payload for a shared secret.
fn shared_key_auth(session: &Session<'_>, secret: &[u8], identity: &Identity) -> Vec<u8> {
    let keys = session.keys.as_ref().expect("keys");
    let octets = keys.signed_octets(
        &session.init_request,
        &session.nonce_r,
        &keys.sk_pi,
        identity,
    );
    payload::encode_auth(AUTH_SHARED_KEY, &keys.shared_secret_auth(secret, &octets))
}

/// Our AUTH payload with our private key.
fn signature_auth(session: &Session<'_>, identity: &Identity) -> Result<Vec<u8>> {
    let keys = session.keys.as_ref().expect("keys");
    let key = session.private_key.as_ref().expect("a private key");
    let octets = keys.signed_octets(
        &session.init_request,
        &session.nonce_r,
        &keys.sk_pi,
        identity,
    );
    let hash = [
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
    ]
    .into_iter()
    .find(|hash| session.peer_hash_algorithms.contains(hash));
    if let Some(hash) = hash {
        Ok(payload::encode_auth(
            AUTH_DIGITAL_SIGNATURE,
            &key.sign_digital_signature(hash, &octets)?,
        ))
    } else {
        let (method, data) = key.sign_classic(&octets)?;
        Ok(payload::encode_auth(method, &data))
    }
}

/// Checks the gateway's AUTH payload of `reply` with `secret` (the PSK
/// or the EAP key) or its certificate.
fn verify_gateway(session: &Session<'_>, reply: &Reply, secret: Option<&[u8]>) -> Result<Identity> {
    let keys = session.keys.as_ref().expect("keys");
    let idr = reply
        .payload(types::IDR)
        .map(|payload| Identity::decode(&payload.data))
        .transpose()?
        .ok_or_else(|| Error::Authentication("the gateway sent no identity".into()))?;
    let auth = reply
        .payload(types::AUTH)
        .ok_or_else(|| Error::Authentication("the gateway sent no AUTH payload".into()))?;
    let (method, data) = payload::decode_auth(&auth.data)?;
    let octets = keys.signed_octets(&session.init_response, &session.nonce_i, &keys.sk_pr, &idr);
    if let Some(secret) = secret {
        if let Some(expected) = &session.config.remote_id
            && idr != Identity::parse(expected)
        {
            return Err(Error::Authentication(format!(
                "the gateway claims to be \"{}\", not \"{expected}\"",
                idr.display()
            )));
        }
        verify_shared_auth(session, reply, secret, &idr).map_err(|_| {
            Error::Authentication(
                "the gateway's AUTH payload does not match the pre-shared key".into(),
            )
        })?;
    } else {
        let verifier = session.verifier.as_ref().expect("a verifier");
        let certs: Vec<Vec<u8>> = reply
            .payloads
            .iter()
            .filter(|payload| payload.kind == types::CERT)
            .filter_map(|payload| payload::decode_cert(&payload.data).ok())
            .filter(|(encoding, _)| *encoding == CERT_X509_SIGNATURE)
            .map(|(_, der)| der.to_vec())
            .collect();
        verifier.verify(&certs, &idr, method, &octets, data)?;
    }
    tracing::info!("Gateway {} authenticated.", idr.display());
    Ok(idr)
}

/// The IKE_AUTH exchange(s): our identity and credentials, the gateway's,
/// the first CHILD SA and the configuration.
async fn ike_auth(session: &mut Session<'_>, cancel: &CancellationToken) -> Result<()> {
    let config = session.config;
    let identity = session.local_identity();
    let our_spi = ChildSa::random_spi();
    let message = auth_request(session, &identity, our_spi)?;
    let mut reply = session.request(message, cancel).await?;
    let psk = config
        .psk
        .as_ref()
        .filter(|_| !config.gateway_uses_cert())
        .map(|psk| psk.expose_secret().as_bytes().to_vec());
    if config.auth.is_eap() {
        // The gateway proves itself first, then runs EAP with us, then
        // proves itself again with the EAP key (SK_pr for a method
        // without one).
        reply.check()?;
        let idr = verify_gateway(session, &reply, psk.as_deref())?;
        let (final_reply, msk) = eap_rounds(session, reply, &identity, cancel).await?;
        reply = final_reply;
        let keys = session.keys.as_ref().expect("keys");
        let secret = msk.as_deref().unwrap_or(&keys.sk_pr);
        verify_shared_auth(session, &reply, secret, &idr)?;
    } else {
        gateway_committed(session, &reply);
        reply.check()?;
        verify_gateway(session, &reply, psk.as_deref())?;
    }
    if reply.payload(types::SA).is_none() {
        return Err(Error::Notify("the gateway created no CHILD_SA".into()));
    }
    session.assigned = assigned_from(&reply.payloads);
    let child = child_from(
        session,
        &reply,
        our_spi,
        None,
        &session.nonce_i.clone(),
        &session.nonce_r.clone(),
    )?;
    tracing::info!(
        "CHILD_SA {:#010x}/{:#010x} established with {}: {} === {}",
        child.spi_in,
        child.spi_out,
        child.algorithms,
        selectors_text(&child.ts_i),
        selectors_text(&child.ts_r)
    );
    session.children.push(child);
    Ok(())
}

/// The gateway proving itself in its last IKE_AUTH response means it
/// created the IKE SA, even when it refuses the CHILD SA (RFC 7296
/// section 1.2): it will want it deleted.
fn gateway_committed(session: &mut Session<'_>, reply: &Reply) {
    if reply.payload(types::AUTH).is_some() {
        session.stage = Stage::Established;
    }
}

/// Our first IKE_AUTH request.
fn auth_request(session: &Session<'_>, identity: &Identity, our_spi: u32) -> Result<Message> {
    let config = session.config;
    let first_selector = session
        .config
        .split_networks()?
        .first()
        .map_or(TrafficSelector::ANY, |&(address, prefix)| {
            TrafficSelector::network(address, prefix)
        });
    let mut message = session.new_request(Exchange::IkeAuth);
    message.push(types::IDI, identity.encode());
    if config.auth == Auth::Pubkey {
        for cert in &session.certificates {
            message.push(types::CERT, payload::encode_cert(CERT_X509_SIGNATURE, cert));
        }
    }
    if let Some(certreq) = session.verifier.as_ref().and_then(GatewayVerifier::certreq) {
        message.push(types::CERTREQ, certreq);
    }
    if let Some(remote_id) = &config.remote_id {
        message.push(types::IDR, Identity::parse(remote_id).encode());
    }
    message.push(
        types::NOTIFY,
        Notify::new(notify::INITIAL_CONTACT, Vec::new()).encode(),
    );
    if let Some(device) = &session.forticlient {
        message.push(
            types::NOTIFY,
            device.connect_notify(session.local_address).encode(),
        );
    }
    match config.auth {
        Auth::Psk => {
            let psk = config
                .psk
                .as_ref()
                .ok_or_else(|| Error::Config("a pre-shared key is needed".into()))?;
            message.push(
                types::AUTH,
                shared_key_auth(session, psk.expose_secret().as_bytes(), identity),
            );
        }
        Auth::Pubkey => {
            message.push(types::AUTH, signature_auth(session, identity)?);
        }
        _ => {} // EAP: no AUTH yet
    }
    let request = ConfigPayload {
        kind: CP_REQUEST,
        attributes: [
            cp_attributes::INTERNAL_IP4_ADDRESS,
            cp_attributes::INTERNAL_IP4_NETMASK,
            cp_attributes::INTERNAL_IP4_DNS,
            cp_attributes::INTERNAL_IP4_SUBNET,
            cp_attributes::INTERNAL_DNS_DOMAIN,
            cp_attributes::APPLICATION_VERSION,
            cp_attributes::UNITY_DEF_DOMAIN,
            cp_attributes::UNITY_SPLIT_INCLUDE,
        ]
        .into_iter()
        .map(|kind| ConfigAttribute {
            kind,
            value: Vec::new(),
        })
        .collect(),
    };
    message.push(types::CP, request.encode()?);
    message.push(
        types::SA,
        payload::encode_sa(&esp_proposals(&session.esp_algorithms, our_spi, false))?,
    );
    message.push(
        types::TSI,
        payload::encode_selectors(&[TrafficSelector::ANY]),
    );
    message.push(types::TSR, payload::encode_selectors(&[first_selector]));
    Ok(message)
}

/// The EAP conversation, then our final AUTH payload with its key (or
/// SK_pi for a method without one). Returns the last reply and the key.
async fn eap_rounds(
    session: &mut Session<'_>,
    mut reply: Reply,
    identity: &Identity,
    cancel: &CancellationToken,
) -> Result<(Reply, Option<Zeroizing<Vec<u8>>>)> {
    let config = session.config;
    let password = config
        .password
        .clone()
        .ok_or_else(|| Error::Config("EAP authentication needs a password".into()))?;
    // With a SAML login, the device identifier is the EAP identity, the
    // token the password, and the method whatever the gateway asks for.
    let (method, username) = match &session.forticlient {
        Some(device) => (None, device.uid.as_str()),
        None => (Some(config.auth), config.username.as_str()),
    };
    let mut peer = eap::Peer::new(method, username, password);
    let msk = loop {
        let eap_payload = reply
            .payload(types::EAP)
            .ok_or_else(|| Error::Authentication("the gateway sent no EAP payload".into()))?;
        match peer.handle(&eap_payload.data)? {
            eap::Step::Reply(packet) => {
                let mut message = session.new_request(Exchange::IkeAuth);
                message.push(types::EAP, packet);
                reply = session.request(message, cancel).await?;
                reply.check()?;
            }
            eap::Step::Success(msk) => break msk,
        }
    };
    let keys = session.keys.as_ref().expect("keys");
    if msk.is_none() {
        tracing::debug!("EAP method without a key: authenticating with SK_p");
    }
    let secret = msk.as_deref().unwrap_or(&keys.sk_pi);
    let mut message = session.new_request(Exchange::IkeAuth);
    message.push(types::AUTH, shared_key_auth(session, secret, identity));
    reply = session.request(message, cancel).await?;
    gateway_committed(session, &reply);
    reply.check()?;
    Ok((reply, msk))
}

/// Checks a shared-secret AUTH payload of the gateway (the pre-shared
/// key, or the EAP key of its second AUTH) for the identity `idr`.
fn verify_shared_auth(
    session: &Session<'_>,
    reply: &Reply,
    secret: &[u8],
    idr: &Identity,
) -> Result<()> {
    let keys = session.keys.as_ref().expect("keys");
    let auth = reply
        .payload(types::AUTH)
        .ok_or_else(|| Error::Authentication("the gateway sent no final AUTH payload".into()))?;
    let (method, data) = payload::decode_auth(&auth.data)?;
    let octets = keys.signed_octets(&session.init_response, &session.nonce_i, &keys.sk_pr, idr);
    let expected = keys.shared_secret_auth(secret, &octets);
    if method != AUTH_SHARED_KEY
        || expected.len() != data.len()
        || !bool::from(expected.ct_eq(data))
    {
        return Err(Error::Authentication(
            "the gateway's AUTH payload does not match the EAP key".into(),
        ));
    }
    Ok(())
}

/// A network from its address and mask, when the mask is one.
fn subnet(bytes: &[u8]) -> Option<(Ipv4Addr, u8)> {
    let bytes = <[u8; 8]>::try_from(bytes).ok()?;
    let address = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
    let mask = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    (mask.count_ones() == mask.leading_ones()).then(|| {
        (
            address,
            u8::try_from(mask.leading_ones()).expect("at most 32"),
        )
    })
}

/// The configuration reply among the payloads of an IKE_AUTH response.
fn assigned_from(payloads: &[RawPayload]) -> Assigned {
    let mut assigned = Assigned::default();
    let Some(cp) = payload::find(payloads, types::CP)
        .and_then(|payload| ConfigPayload::decode(&payload.data).ok())
        .filter(|cp| cp.kind == CP_REPLY)
    else {
        return assigned;
    };
    for attribute in &cp.attributes {
        match attribute.kind {
            cp_attributes::INTERNAL_IP4_ADDRESS => {
                if let Some(address) = attribute.address() {
                    assigned.address = Some(address);
                }
            }
            cp_attributes::INTERNAL_IP4_DNS => {
                if let Some(server) = attribute
                    .address()
                    .filter(|server| !server.is_unspecified())
                {
                    assigned.dns.push(server);
                }
            }
            cp_attributes::INTERNAL_IP4_SUBNET => assigned.subnets.extend(subnet(&attribute.value)),
            cp_attributes::UNITY_SPLIT_INCLUDE => assigned.subnets.extend(
                attribute
                    .value
                    .chunks_exact(14)
                    .filter_map(|entry| subnet(&entry[..8])),
            ),
            cp_attributes::INTERNAL_DNS_DOMAIN | cp_attributes::UNITY_DEF_DOMAIN => {
                if let Ok(domain) = std::str::from_utf8(&attribute.value)
                    && !domain.is_empty()
                    && !assigned.domains.contains(&domain.to_owned())
                {
                    assigned.domains.push(domain.to_owned());
                }
            }
            _ => {}
        }
    }
    assigned.subnets.dedup();
    assigned
}

/// A CHILD SA from the SA, TS and nonce payloads of a response.
pub fn child_from(
    session: &Session<'_>,
    reply: &Reply,
    our_spi: u32,
    shared: Option<(Group, &[u8])>,
    nonce_i: &[u8],
    nonce_r: &[u8],
) -> Result<ChildSa> {
    let shared_group = shared.map(|(group, _)| group);
    let sa = reply
        .payload(types::SA)
        .ok_or_else(|| Error::Malformed("response without SA".into()))?;
    let chosen = payload::decode_sa(&sa.data)?;
    let chosen = chosen
        .first()
        .ok_or_else(|| Error::Malformed("empty SA payload".into()))?;
    let (algorithms, peer_spi) =
        proposals::select_esp(chosen, &session.esp_algorithms, shared_group)?;
    let selectors = payload::selectors(&reply.payloads)?;
    let keys = session.keys.as_ref().expect("keys");
    let keymat = keys.child_keymat(
        shared.map(|(_, secret)| secret),
        nonce_i,
        nonce_r,
        ChildSa::keymat_len(algorithms),
    );
    ChildSa::new(algorithms, (our_spi, peer_spi), &keymat, true, selectors)
}

/// Traffic selectors for the logs.
pub fn selectors_text(selectors: &[TrafficSelector]) -> String {
    selectors
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

/// The TUN device, the routes and the DNS settings.
async fn bring_up(session: &mut Session<'_>) -> Result<()> {
    let config = session.config;
    let address = session
        .assigned
        .address
        .or_else(|| session.children.first().map(|child| child.ts_i[0].start))
        .ok_or_else(|| Error::Notify("the gateway assigned no address".into()))?;
    tracing::info!(
        "Virtual IP address {address} assigned by the gateway{}.",
        if session.assigned.dns.is_empty() {
            String::new()
        } else {
            format!(
                ", nameservers {}",
                session
                    .assigned
                    .dns
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        }
    );
    let tun = Tun::create(
        config.tun_name.as_deref(),
        address,
        None,
        crate::session::MTU,
    )?;
    tracing::info!("Interface {} is UP.", tun.name());
    let mut host = Host {
        tun,
        routes: None,
        dns: None,
    };
    if config.set_routes {
        tracing::info!("Setting new routes...");
        host.routes = Some(set_routes(session, host.tun.name()).await?);
    }
    if config.set_dns {
        if session.assigned.dns.is_empty() && session.assigned.domains.is_empty() {
            tracing::info!("No VPN nameservers to add.");
        } else {
            tracing::info!("Adding VPN nameservers...");
            match Dns::install(
                host.tun.name(),
                &session.assigned.dns,
                &session.assigned.domains,
                DnsTool::Auto,
            )
            .await
            {
                Ok(dns) => host.dns = Some(dns),
                Err(error) => tracing::warn!("Could not add the VPN nameservers ({error})."),
            }
        }
    }
    session.host = Some(host);
    tracing::info!("Tunnel is up and running.");
    sd_notify::notify(false, &[sd_notify::NotifyState::Ready]).ok();
    Ok(())
}

/// The routes through `interface`: the split networks, else what the
/// gateway pushed, else what the traffic selectors cover; the default
/// route only once the gateway itself is routed around the tunnel.
async fn set_routes(session: &Session<'_>, interface: &str) -> Result<Routes> {
    let mut routes = Routes::new(interface);
    let protected = routes.protect_gateway(session.gateway).await;
    let mut networks: Vec<(Ipv4Addr, u8)> = session.config.split_networks()?;
    if networks.is_empty() {
        networks.clone_from(&session.assigned.subnets);
    }
    if networks.is_empty() {
        for child in &session.children {
            for selector in &child.ts_r {
                networks.extend(selector.networks());
            }
        }
    }
    let everything = networks.iter().any(|(_, prefix)| *prefix == 0);
    if everything {
        match protected {
            Ok(()) => {
                if let Err(error) = routes.set_default(false).await {
                    tracing::warn!("Could not set the default route ({error}).");
                }
            }
            Err(error) => tracing::warn!(
                "Not setting the default route: the route to the gateway could not be protected ({error})."
            ),
        }
    } else {
        if let Err(error) = protected {
            tracing::warn!("Could not protect the route to the gateway ({error}).");
        }
        for (network, prefix) in networks {
            if network == session.gateway {
                continue;
            }
            if let Err(error) = routes.add(network, prefix).await {
                tracing::warn!("Could not add route {network}/{prefix} ({error}).");
            }
        }
    }
    Ok(routes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_replies_are_read() {
        let reply = ConfigPayload {
            kind: CP_REPLY,
            attributes: vec![
                ConfigAttribute {
                    kind: cp_attributes::INTERNAL_IP4_ADDRESS,
                    value: vec![10, 98, 0, 7],
                },
                ConfigAttribute {
                    kind: cp_attributes::INTERNAL_IP4_DNS,
                    value: vec![10, 97, 0, 53],
                },
                ConfigAttribute {
                    kind: cp_attributes::INTERNAL_IP4_DNS,
                    value: vec![0, 0, 0, 0],
                },
                ConfigAttribute {
                    kind: cp_attributes::INTERNAL_IP4_SUBNET,
                    value: vec![10, 97, 0, 0, 255, 255, 255, 0],
                },
                ConfigAttribute {
                    kind: cp_attributes::UNITY_SPLIT_INCLUDE,
                    value: [
                        [10, 97, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0],
                        [192, 168, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0],
                        [172, 16, 0, 0, 255, 0, 255, 0, 0, 0, 0, 0, 0, 0],
                    ]
                    .concat(),
                },
                ConfigAttribute {
                    kind: cp_attributes::UNITY_DEF_DOMAIN,
                    value: b"corp.example".to_vec(),
                },
                ConfigAttribute {
                    kind: cp_attributes::INTERNAL_DNS_DOMAIN,
                    value: b"corp.example".to_vec(),
                },
            ],
        };
        let payloads = vec![RawPayload {
            kind: types::CP,
            data: reply.encode().expect("encode"),
        }];
        let assigned = assigned_from(&payloads);
        assert_eq!(assigned.address, Some(Ipv4Addr::new(10, 98, 0, 7)));
        assert_eq!(assigned.dns, vec![Ipv4Addr::new(10, 97, 0, 53)]);
        assert_eq!(
            assigned.subnets,
            vec![
                (Ipv4Addr::new(10, 97, 0, 0), 24),
                (Ipv4Addr::new(192, 168, 0, 0), 16)
            ]
        );
        assert_eq!(assigned.domains, vec!["corp.example".to_owned()]);
        assert_eq!(assigned_from(&[]).address, None);
    }

    #[test]
    fn invalid_ke_payload_names_a_group_we_offer() {
        let offered = [Group::Modp2048, Group::Ecp256];
        assert_eq!(
            wanted_group(&19u16.to_be_bytes(), offered.into_iter()).expect("group"),
            Group::Ecp256
        );
        assert!(wanted_group(&31u16.to_be_bytes(), offered.into_iter()).is_err());
        assert!(wanted_group(&[1], offered.into_iter()).is_err());
    }
}
