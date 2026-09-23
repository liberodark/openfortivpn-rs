//! RFC 7296 (CREATE_CHILD_SA: CHILD SA creation and rekey, DELETE).

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::child::ChildSa;
use crate::crypto::KeyExchange;
use crate::message::payload::{self, Delete, Notify, TrafficSelector, notify};
use crate::message::{Exchange, Message, types};
use crate::proposals::esp_proposals;
use crate::session::{Session, nonce};
use crate::setup::{child_from, selectors_text, wanted_group};
use crate::{Error, Result};

/// How long a CHILD SA is used before being rekeyed (the gateway usually
/// rekeys earlier, on its own lifetime).
pub const CHILD_LIFETIME: Duration = Duration::from_secs(3600);
/// How many times the exchange is retried when the gateway wants another
/// group.
const GROUP_RETRIES: usize = 2;

/// Creates a CHILD SA for `ts_i` === `ts_r`; `rekey` is the inbound SPI of
/// the CHILD SA it replaces, which is deleted afterwards.
pub async fn create_child(
    session: &mut Session<'_>,
    ts_i: Vec<TrafficSelector>,
    ts_r: Vec<TrafficSelector>,
    rekey: Option<u32>,
    cancel: &CancellationToken,
) -> Result<()> {
    let our_spi = ChildSa::random_spi();
    let mut group = session.esp_algorithms.iter().find_map(|set| set.group);
    for _ in 0..GROUP_RETRIES {
        let exchange = group.map(KeyExchange::generate);
        let nonce_i = nonce();
        let message = child_request(
            session,
            (&ts_i, &ts_r),
            rekey,
            our_spi,
            exchange.as_ref(),
            &nonce_i,
        )?;
        let reply = session.request(message, cancel).await?;

        if let Some(invalid) = reply
            .notifies()
            .find(|notify| notify.kind == notify::INVALID_KE_PAYLOAD)
        {
            let offered = session.esp_algorithms.iter().filter_map(|set| set.group);
            let wanted = wanted_group(&invalid.data, offered)?;
            tracing::debug!("the gateway wants {} for the CHILD_SA", wanted.name());
            group = Some(wanted);
            continue;
        }
        if rekey.is_some()
            && reply
                .notifies()
                .any(|notify| notify.kind == notify::CHILD_SA_NOT_FOUND)
        {
            // The gateway already dropped it: so do we.
            tracing::debug!("the gateway no longer has the CHILD_SA to rekey");
            session.children.retain(|child| Some(child.spi_in) != rekey);
            return Ok(());
        }
        reply.check()?;

        let shared = match (&exchange, reply.payload(types::KE)) {
            (Some(exchange), Some(ke)) => {
                let (peer_group, peer_public) = payload::decode_ke(&ke.data)?;
                if peer_group != exchange.group().id() {
                    return Err(Error::Malformed("KE payload for another group".into()));
                }
                Some((exchange.group(), exchange.shared(peer_public)?))
            }
            (_, None) => None,
            (None, Some(_)) => return Err(Error::Malformed("unexpected KE payload".into())),
        };
        let nonce_r = reply
            .payload(types::NONCE)
            .ok_or_else(|| Error::Malformed("CREATE_CHILD_SA response without a nonce".into()))?
            .data
            .clone();
        let child = child_from(
            session,
            &reply,
            our_spi,
            shared
                .as_ref()
                .map(|(group, secret)| (*group, secret.as_slice())),
            &nonce_i,
            &nonce_r,
        )?;
        tracing::info!(
            "CHILD_SA {:#010x}/{:#010x} {} with {}: {} === {}",
            child.spi_in,
            child.spi_out,
            if rekey.is_some() {
                "rekeyed"
            } else {
                "established"
            },
            child.algorithms,
            selectors_text(&child.ts_i),
            selectors_text(&child.ts_r)
        );
        // The newest CHILD SA carries the traffic from now on.
        session.children.insert(0, child);
        if let Some(old_spi) = rekey {
            delete_child(session, old_spi, cancel).await?;
        }
        return Ok(());
    }
    Err(Error::Notify(
        "CREATE_CHILD_SA kept being redirected".into(),
    ))
}

/// Our CREATE_CHILD_SA request.
fn child_request(
    session: &Session<'_>,
    (ts_i, ts_r): (&[TrafficSelector], &[TrafficSelector]),
    rekey: Option<u32>,
    our_spi: u32,
    exchange: Option<&KeyExchange>,
    nonce_i: &[u8],
) -> Result<Message> {
    let mut message = session.new_request(Exchange::CreateChildSa);
    if let Some(old_spi) = rekey {
        message.push(
            types::NOTIFY,
            Notify {
                protocol: 3,
                spi: old_spi.to_be_bytes().to_vec(),
                kind: notify::REKEY_SA,
                data: Vec::new(),
            }
            .encode(),
        );
    }
    // The proposals with the group we do the exchange for first.
    let group = exchange.map(KeyExchange::group);
    let mut ordered = session.esp_algorithms.clone();
    ordered.sort_by_key(|set| set.group != group);
    message.push(
        types::SA,
        payload::encode_sa(&esp_proposals(&ordered, our_spi, true))?,
    );
    message.push(types::NONCE, nonce_i.to_vec());
    if let Some(exchange) = exchange {
        message.push(
            types::KE,
            payload::encode_ke(exchange.group().id(), exchange.public()),
        );
    }
    message.push(types::TSI, payload::encode_selectors(ts_i));
    message.push(types::TSR, payload::encode_selectors(ts_r));
    Ok(message)
}

/// Deletes the CHILD SA with inbound SPI `spi`, on both sides.
async fn delete_child(
    session: &mut Session<'_>,
    spi: u32,
    cancel: &CancellationToken,
) -> Result<()> {
    let Some(index) = session
        .children
        .iter()
        .position(|child| child.spi_in == spi)
    else {
        return Ok(());
    };
    let old = session.children.remove(index);
    let mut request = session.new_request(Exchange::Informational);
    request.push(
        types::DELETE,
        Delete {
            protocol: 3,
            spis: vec![spi.to_be_bytes().to_vec()],
        }
        .encode(),
    );
    session.request(request, cancel).await?;
    tracing::debug!("deleted CHILD_SA {}", old.summary());
    Ok(())
}

/// Rekeys the CHILD SA that is due for it.
pub async fn rekey_child(session: &mut Session<'_>, cancel: &CancellationToken) -> Result<()> {
    let Some(child) = session
        .children
        .iter()
        .find(|child| !child.replaced && child.is_due(CHILD_LIFETIME))
    else {
        return Ok(());
    };
    tracing::info!("Rekeying CHILD_SA {}...", child.summary());
    let (spi, ts_i, ts_r) = (child.spi_in, child.ts_i.clone(), child.ts_r.clone());
    create_child(session, ts_i, ts_r, Some(spi), cancel).await
}
