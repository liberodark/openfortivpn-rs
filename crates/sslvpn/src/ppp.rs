//! RFC 1661 (PPP, LCP), RFC 1332 (IPCP), RFC 1877 (nameservers over IPCP).

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Protocol number of IPv4 packets.
pub const PROTOCOL_IP: u16 = 0x0021;
const PROTOCOL_IPCP: u16 = 0x8021;
const PROTOCOL_LCP: u16 = 0xc021;

const CONF_REQ: u8 = 1;
const CONF_ACK: u8 = 2;
const CONF_NAK: u8 = 3;
const CONF_REJ: u8 = 4;
const TERM_REQ: u8 = 5;
const TERM_ACK: u8 = 6;
const CODE_REJ: u8 = 7;
const PROTO_REJ: u8 = 8;
const ECHO_REQ: u8 = 9;
const ECHO_REPLY: u8 = 10;
const DISCARD_REQ: u8 = 11;

const LCP_MRU: u8 = 1;
const LCP_ACCM: u8 = 2;
const LCP_MAGIC: u8 = 5;

const IPCP_ADDRESS: u8 = 3;
const IPCP_DNS1: u8 = 129;
const IPCP_DNS2: u8 = 131;

/// pppd's defaults: `lcp-restart 3`, `lcp-max-terminate 2`, and
/// openfortivpn's `lcp-max-configure 40`.
const RESTART_TIMER: Duration = Duration::from_secs(3);
const MAX_TERMINATE: u32 = 2;
const LCP_MAX_CONFIGURE: u32 = 40;
const IPCP_MAX_CONFIGURE: u32 = 10;
/// Configure-Naks we take before treating them as rejects (pppd's
/// `maxnakloops`), and twice that many negative answers before giving up
/// on a peer that never agrees.
const MAX_NAK_LOOPS: u32 = 5;
/// The MRU a peer that does not negotiate one is assumed to have, and the
/// largest one we take from a Nak.
const DEFAULT_MRU: u16 = 1500;
/// Codes 1 to 7 are those the automaton cannot do without.
const LAST_ESSENTIAL_CODE: u8 = CODE_REJ;
/// pppd's fallback when the peer does not tell its address.
const DEFAULT_PEER: Ipv4Addr = Ipv4Addr::new(10, 64, 64, 64);

/// What the tunnel has to do after feeding the state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send this PPP packet to the gateway.
    Send(Vec<u8>),
    /// Hand this IP packet to the TUN device.
    Deliver(Vec<u8>),
    /// IPCP is open: configure the interface.
    Up(Addresses),
    /// The link is finished, for the given reason.
    Down(String),
}

/// What IPCP negotiated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addresses {
    pub local: Ipv4Addr,
    /// The gateway's address.
    pub peer: Ipv4Addr,
    /// Nameservers the gateway gave, in order.
    pub dns: Vec<Ipv4Addr>,
    /// Largest packet the gateway accepts.
    pub mtu: u16,
}

/// A configuration option: type, then data.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Opt {
    kind: u8,
    data: Vec<u8>,
}

impl Opt {
    fn new(kind: u8, data: impl Into<Vec<u8>>) -> Self {
        Self {
            kind,
            data: data.into(),
        }
    }

    fn u16(&self) -> Option<u16> {
        <[u8; 2]>::try_from(self.data.as_slice())
            .ok()
            .map(u16::from_be_bytes)
    }

    fn u32(&self) -> Option<u32> {
        <[u8; 4]>::try_from(self.data.as_slice())
            .ok()
            .map(u32::from_be_bytes)
    }

    fn address(&self) -> Option<Ipv4Addr> {
        self.u32().map(Ipv4Addr::from)
    }

    fn parse_all(mut data: &[u8]) -> Option<Vec<Self>> {
        let mut options = Vec::new();
        while !data.is_empty() {
            let (&kind, &length) = (data.first()?, data.get(1)?);
            let length = usize::from(length);
            if length < 2 || length > data.len() {
                return None;
            }
            options.push(Opt::new(kind, &data[2..length]));
            data = &data[length..];
        }
        Some(options)
    }

    fn encode_all(options: &[Self]) -> Vec<u8> {
        let mut encoded = Vec::new();
        for option in options {
            encoded.push(option.kind);
            encoded.push(u8::try_from(option.data.len() + 2).expect("short option"));
            encoded.extend_from_slice(&option.data);
        }
        encoded
    }
}

/// Our answer to one option of the peer's Configure-Request.
enum Verdict {
    Ack,
    Nak(Opt),
    Rej,
}

/// What differs between LCP and IPCP: the options.
trait Layer {
    const PROTOCOL: u16;
    const NAME: &'static str;
    const MAX_CONFIGURE: u32;

    /// The options of our Configure-Request.
    fn request(&self) -> Vec<Opt>;
    /// The peer suggests another value for one of our options.
    fn accept_nak(&mut self, option: &Opt);
    /// The peer refuses one of our options.
    fn accept_rej(&mut self, option: &Opt);
    /// What to answer to one option the peer requests.
    fn review(&self, option: &Opt) -> Verdict;
    /// The peer's request was acknowledged: remember its values.
    fn peer_configured(&mut self, options: &[Opt]);
    /// The largest packet the peer accepts.
    fn peer_mru(&self) -> u16;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Initial,
    ReqSent,
    AckRcvd,
    AckSent,
    Opened,
    Closing,
    Closed,
}

/// Why a layer left the Opened state, or never reached it.
enum Outcome {
    Up,
    Down(String),
}

/// The option negotiation automaton of one layer.
struct Fsm<L> {
    layer: L,
    state: State,
    /// Identifier of our outstanding request.
    id: u8,
    retransmits: u32,
    /// Configure-Naks received for the current negotiation.
    nak_loops: u32,
    timer: Option<Instant>,
    /// The peer's options we acknowledged, to recognise a retransmission.
    peer_options: Vec<Opt>,
}

impl<L: Layer> Fsm<L> {
    fn new(layer: L) -> Self {
        Self {
            layer,
            state: State::Initial,
            id: 0,
            retransmits: 0,
            nak_loops: 0,
            timer: None,
            peer_options: Vec::new(),
        }
    }

    fn packet(code: u8, id: u8, payload: &[u8]) -> Vec<u8> {
        let length = u16::try_from(payload.len() + 4).expect("short packet");
        let mut packet = Vec::with_capacity(payload.len() + 6);
        packet.extend_from_slice(&L::PROTOCOL.to_be_bytes());
        packet.push(code);
        packet.push(id);
        packet.extend_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    fn open(&mut self, now: Instant, actions: &mut Vec<Action>) {
        self.state = State::ReqSent;
        self.retransmits = L::MAX_CONFIGURE;
        self.nak_loops = 0;
        self.id = self.id.wrapping_add(1);
        self.send_request(now, actions);
    }

    fn send_request(&mut self, now: Instant, actions: &mut Vec<Action>) {
        let options = Opt::encode_all(&self.layer.request());
        tracing::debug!("{}: sending Configure-Request id {}", L::NAME, self.id);
        actions.push(Action::Send(Self::packet(CONF_REQ, self.id, &options)));
        self.timer = Some(now + RESTART_TIMER);
    }

    /// Starts closing the layer: the caller learns from the returned
    /// value whether a Terminate-Ack is to be waited for.
    fn close(&mut self, now: Instant, actions: &mut Vec<Action>) -> bool {
        match self.state {
            State::Initial | State::Closed => false,
            State::Closing => true,
            _ => {
                self.state = State::Closing;
                self.retransmits = MAX_TERMINATE;
                self.send_terminate(now, actions);
                true
            }
        }
    }

    fn send_terminate(&mut self, now: Instant, actions: &mut Vec<Action>) {
        self.id = self.id.wrapping_add(1);
        tracing::debug!("{}: sending Terminate-Request id {}", L::NAME, self.id);
        actions.push(Action::Send(Self::packet(TERM_REQ, self.id, &[])));
        self.timer = Some(now + RESTART_TIMER);
    }

    fn finish(&mut self, reason: String) -> Outcome {
        self.state = State::Closed;
        self.timer = None;
        Outcome::Down(reason)
    }

    /// The restart timer fired.
    fn timeout(&mut self, now: Instant, actions: &mut Vec<Action>) -> Option<Outcome> {
        if self.timer.is_none_or(|deadline| deadline > now) {
            return None;
        }
        if self.retransmits == 0 {
            return Some(match self.state {
                State::Closing => self.finish(format!("{}: no Terminate-Ack", L::NAME)),
                _ => self.finish(format!("{}: no answer from the gateway", L::NAME)),
            });
        }
        self.retransmits -= 1;
        match self.state {
            State::Closing => self.send_terminate(now, actions),
            State::ReqSent | State::AckRcvd | State::AckSent => {
                self.send_request(now, actions);
                if self.state == State::AckRcvd {
                    self.state = State::ReqSent;
                }
            }
            State::Initial | State::Opened | State::Closed => self.timer = None,
        }
        None
    }

    /// One packet of this layer's protocol.
    fn input(
        &mut self,
        code: u8,
        id: u8,
        data: &[u8],
        now: Instant,
        actions: &mut Vec<Action>,
    ) -> Option<Outcome> {
        if self.state == State::Closing && code != TERM_ACK && code != TERM_REQ {
            return None;
        }
        match code {
            CONF_REQ => self.on_request(id, data, actions),
            CONF_ACK => self.on_ack(id),
            CONF_NAK | CONF_REJ => self.on_nak_or_rej(code, id, data, now, actions),
            TERM_REQ => {
                tracing::debug!("{}: Terminate-Request received", L::NAME);
                actions.push(Action::Send(Self::packet(TERM_ACK, id, &[])));
                Some(self.finish(format!("{}: terminated by the gateway", L::NAME)))
            }
            TERM_ACK => match self.state {
                State::Closing => Some(self.finish(format!("{} closed", L::NAME))),
                State::Opened => {
                    Some(self.finish(format!("{}: unexpected Terminate-Ack", L::NAME)))
                }
                _ => None,
            },
            CODE_REJ => self.on_code_reject(data),
            _ => {
                tracing::debug!("{}: unknown code {code}, rejecting", L::NAME);
                let mut rejected = vec![code, id];
                rejected
                    .extend_from_slice(&(u16::try_from(data.len() + 4).unwrap_or(4)).to_be_bytes());
                rejected.extend_from_slice(data);
                rejected.truncate(self.reject_limit());
                self.id = self.id.wrapping_add(1);
                actions.push(Action::Send(Self::packet(CODE_REJ, self.id, &rejected)));
                None
            }
        }
    }

    /// How much of a rejected packet fits in a Code-Reject or
    /// Protocol-Reject the peer accepts (RFC 1661, 5.6 and 5.7).
    fn reject_limit(&self) -> usize {
        usize::from(self.layer.peer_mru().saturating_sub(6))
    }

    /// A Code-Reject is fatal when it rejects a code the automaton needs
    /// (RFC 1661, RXJ-); other ones are shrugged off.
    fn on_code_reject(&mut self, data: &[u8]) -> Option<Outcome> {
        let rejected = data.first().copied().unwrap_or(0);
        tracing::debug!("{}: the gateway rejected our code {rejected}", L::NAME);
        if (CONF_REQ..=LAST_ESSENTIAL_CODE).contains(&rejected) {
            return Some(self.finish(format!(
                "{}: the gateway rejected our code {rejected}",
                L::NAME
            )));
        }
        if self.state == State::AckRcvd {
            self.state = State::ReqSent;
        }
        None
    }

    fn on_request(&mut self, id: u8, data: &[u8], actions: &mut Vec<Action>) -> Option<Outcome> {
        let Some(options) = Opt::parse_all(data) else {
            tracing::warn!("{}: malformed Configure-Request", L::NAME);
            return None;
        };
        if self.state == State::Opened {
            // A retransmission of the request we acknowledged is answered
            // again; anything else is the gateway renegotiating, which
            // would need the link down and up again.
            if options == self.peer_options {
                tracing::debug!("{}: acknowledging a repeated Configure-Request", L::NAME);
                actions.push(Action::Send(Self::packet(CONF_ACK, id, data)));
                return None;
            }
            return Some(self.finish(format!(
                "{}: the gateway restarted the negotiation",
                L::NAME
            )));
        }
        if self.state == State::Initial || self.state == State::Closed {
            return None;
        }
        let mut naks = Vec::new();
        let mut rejs = Vec::new();
        for option in &options {
            match self.layer.review(option) {
                Verdict::Ack => {}
                Verdict::Nak(better) => naks.push(better),
                Verdict::Rej => rejs.push(option.clone()),
            }
        }
        let (code, answer) = if !rejs.is_empty() {
            (CONF_REJ, rejs)
        } else if !naks.is_empty() {
            (CONF_NAK, naks)
        } else {
            (CONF_ACK, options.clone())
        };
        tracing::debug!(
            "{}: Configure-Request id {id} received, answering code {code}",
            L::NAME
        );
        actions.push(Action::Send(Self::packet(
            code,
            id,
            &Opt::encode_all(&answer),
        )));
        if code == CONF_ACK {
            self.layer.peer_configured(&options);
            self.peer_options = options;
            match self.state {
                State::AckRcvd => {
                    self.state = State::Opened;
                    self.timer = None;
                    return Some(Outcome::Up);
                }
                _ => self.state = State::AckSent,
            }
        } else if self.state == State::AckSent {
            self.state = State::ReqSent;
        }
        None
    }

    fn on_ack(&mut self, id: u8) -> Option<Outcome> {
        if id != self.id {
            tracing::debug!("{}: Configure-Ack with unexpected id {id}", L::NAME);
            return None;
        }
        tracing::debug!("{}: Configure-Ack id {id} received", L::NAME);
        match self.state {
            State::ReqSent => {
                self.state = State::AckRcvd;
                None
            }
            State::AckSent => {
                self.state = State::Opened;
                self.timer = None;
                Some(Outcome::Up)
            }
            _ => None,
        }
    }

    fn on_nak_or_rej(
        &mut self,
        code: u8,
        id: u8,
        data: &[u8],
        now: Instant,
        actions: &mut Vec<Action>,
    ) -> Option<Outcome> {
        if id != self.id {
            tracing::debug!("{}: answer with unexpected id {id}", L::NAME);
            return None;
        }
        let Some(options) = Opt::parse_all(data) else {
            tracing::warn!("{}: malformed Configure-Nak/Reject", L::NAME);
            return None;
        };
        if self.state == State::Opened {
            tracing::debug!("{}: ignoring a late Configure-Nak/Reject", L::NAME);
            return None;
        }
        // A peer that keeps naking is told nothing new: after a few rounds
        // its Naks are taken as rejects, like pppd does, and a peer that
        // still does not agree is given up on.
        self.nak_loops += 1;
        if self.nak_loops > 2 * MAX_NAK_LOOPS {
            return Some(self.finish(format!(
                "{}: the gateway keeps refusing our configuration",
                L::NAME
            )));
        }
        let as_reject = code == CONF_REJ || self.nak_loops > MAX_NAK_LOOPS;
        for option in &options {
            if as_reject {
                tracing::debug!("{}: option {} rejected", L::NAME, option.kind);
                self.layer.accept_rej(option);
            } else {
                tracing::debug!("{}: option {} naked", L::NAME, option.kind);
                self.layer.accept_nak(option);
            }
        }
        if self.state == State::AckRcvd {
            self.state = State::ReqSent;
        }
        self.id = self.id.wrapping_add(1);
        self.send_request(now, actions);
        None
    }
}

/// LCP: MRU and magic number.
struct Lcp {
    mru: u16,
    magic: u32,
    ask_mru: bool,
    ask_magic: bool,
    peer_mru: u16,
}

impl Layer for Lcp {
    const PROTOCOL: u16 = PROTOCOL_LCP;
    const NAME: &'static str = "LCP";
    const MAX_CONFIGURE: u32 = LCP_MAX_CONFIGURE;

    fn request(&self) -> Vec<Opt> {
        let mut options = Vec::new();
        if self.ask_mru {
            options.push(Opt::new(LCP_MRU, self.mru.to_be_bytes()));
        }
        if self.ask_magic {
            options.push(Opt::new(LCP_MAGIC, self.magic.to_be_bytes()));
        }
        options
    }

    fn accept_nak(&mut self, option: &Opt) {
        match (option.kind, option.u16(), option.u32()) {
            (LCP_MRU, Some(mru), _) if mru <= DEFAULT_MRU => self.mru = mru,
            (LCP_MAGIC, _, Some(magic)) => self.magic = magic,
            _ => {}
        }
    }

    fn accept_rej(&mut self, option: &Opt) {
        match option.kind {
            LCP_MRU => self.ask_mru = false,
            LCP_MAGIC => self.ask_magic = false,
            _ => {}
        }
    }

    fn review(&self, option: &Opt) -> Verdict {
        match option.kind {
            LCP_MRU if option.u16().is_some() => Verdict::Ack,
            LCP_MAGIC if option.u32() == Some(self.magic) => {
                Verdict::Nak(Opt::new(LCP_MAGIC, rand::random::<u32>().to_be_bytes()))
            }
            // No async framing here: whatever the gateway wants escaped is
            // fine, as is any other magic number.
            LCP_ACCM | LCP_MAGIC if option.u32().is_some() => Verdict::Ack,
            // Authentication, protocol and address/control field
            // compression and anything else: not with pppd's options.
            _ => Verdict::Rej,
        }
    }

    fn peer_configured(&mut self, options: &[Opt]) {
        self.peer_mru = options
            .iter()
            .find(|option| option.kind == LCP_MRU)
            .and_then(Opt::u16)
            .unwrap_or(DEFAULT_MRU);
    }

    fn peer_mru(&self) -> u16 {
        self.peer_mru
    }
}

/// IPCP: our address and nameservers come from the gateway's Naks.
struct Ipcp {
    local: Ipv4Addr,
    peer: Option<Ipv4Addr>,
    dns: [Option<Ipv4Addr>; 2],
    ask_address: bool,
    ask_dns: [bool; 2],
    /// What LCP negotiated, for the size of the packets we reject.
    peer_mru: u16,
}

impl Ipcp {
    fn dns_kind(index: usize) -> u8 {
        if index == 0 { IPCP_DNS1 } else { IPCP_DNS2 }
    }

    fn dns_index(kind: u8) -> Option<usize> {
        match kind {
            IPCP_DNS1 => Some(0),
            IPCP_DNS2 => Some(1),
            _ => None,
        }
    }
}

impl Layer for Ipcp {
    const PROTOCOL: u16 = PROTOCOL_IPCP;
    const NAME: &'static str = "IPCP";
    const MAX_CONFIGURE: u32 = IPCP_MAX_CONFIGURE;

    fn request(&self) -> Vec<Opt> {
        let mut options = Vec::new();
        if self.ask_address {
            options.push(Opt::new(IPCP_ADDRESS, self.local.octets()));
        }
        for (index, ask) in self.ask_dns.iter().enumerate() {
            if *ask {
                let server = self.dns[index].unwrap_or(Ipv4Addr::UNSPECIFIED);
                options.push(Opt::new(Self::dns_kind(index), server.octets()));
            }
        }
        options
    }

    fn accept_nak(&mut self, option: &Opt) {
        // An unspecified address is no suggestion at all.
        let Some(address) = option.address().filter(|address| !address.is_unspecified()) else {
            return;
        };
        match (option.kind, Self::dns_index(option.kind)) {
            (IPCP_ADDRESS, _) => self.local = address,
            (_, Some(index)) => self.dns[index] = Some(address),
            _ => {}
        }
    }

    fn accept_rej(&mut self, option: &Opt) {
        match (option.kind, Self::dns_index(option.kind)) {
            (IPCP_ADDRESS, _) => self.ask_address = false,
            (_, Some(index)) => self.ask_dns[index] = false,
            _ => {}
        }
    }

    fn review(&self, option: &Opt) -> Verdict {
        match (option.kind, option.address()) {
            (IPCP_ADDRESS, Some(address)) if !address.is_unspecified() => Verdict::Ack,
            // Van Jacobson compression and the rest: not with pppd's options.
            _ => Verdict::Rej,
        }
    }

    fn peer_configured(&mut self, options: &[Opt]) {
        self.peer = options
            .iter()
            .find(|option| option.kind == IPCP_ADDRESS)
            .and_then(Opt::address);
    }

    fn peer_mru(&self) -> u16 {
        self.peer_mru
    }
}

/// The PPP link: LCP, then IPCP, then IP.
pub struct Ppp {
    lcp: Fsm<Lcp>,
    ipcp: Fsm<Ipcp>,
    /// A Down was already reported.
    down: bool,
}

impl Ppp {
    /// A link asking for `mru`, and for nameservers if `ask_dns`.
    #[must_use]
    pub fn new(mru: u16, ask_dns: bool) -> Self {
        Self {
            lcp: Fsm::new(Lcp {
                mru,
                magic: rand::random(),
                ask_mru: true,
                ask_magic: true,
                peer_mru: DEFAULT_MRU,
            }),
            ipcp: Fsm::new(Ipcp {
                local: Ipv4Addr::UNSPECIFIED,
                peer: None,
                dns: [None; 2],
                ask_address: true,
                ask_dns: [ask_dns; 2],
                peer_mru: DEFAULT_MRU,
            }),
            down: false,
        }
    }

    /// Whether IP packets can flow.
    #[must_use]
    pub fn is_up(&self) -> bool {
        self.ipcp.state == State::Opened
    }

    /// Whether a Terminate-Ack is still awaited after [`Ppp::close`].
    #[must_use]
    pub fn is_closing(&self) -> bool {
        self.lcp.state == State::Closing
    }

    pub fn open(&mut self, now: Instant) -> Vec<Action> {
        let mut actions = Vec::new();
        self.lcp.open(now, &mut actions);
        actions
    }

    /// Closes the link gracefully; the [`Action::Down`] follows when the
    /// gateway acknowledges or the retries are exhausted.
    pub fn close(&mut self, now: Instant) -> Vec<Action> {
        let mut actions = Vec::new();
        self.ipcp.state = State::Closed;
        self.ipcp.timer = None;
        if !self.lcp.close(now, &mut actions) {
            self.report_down("link closed".into(), &mut actions);
        }
        actions
    }

    #[must_use]
    pub fn next_timeout(&self) -> Option<Instant> {
        match (self.lcp.timer, self.ipcp.timer) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    pub fn timeout(&mut self, now: Instant) -> Vec<Action> {
        let mut actions = Vec::new();
        if let Some(outcome) = self.lcp.timeout(now, &mut actions) {
            self.on_lcp(outcome, now, &mut actions);
        }
        if let Some(outcome) = self.ipcp.timeout(now, &mut actions) {
            self.on_ipcp(outcome, now, &mut actions);
        }
        actions
    }

    /// Wraps an IP packet from the TUN device.
    #[must_use]
    pub fn encode_ip(packet: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(packet.len() + 2);
        encoded.extend_from_slice(&PROTOCOL_IP.to_be_bytes());
        encoded.extend_from_slice(packet);
        encoded
    }

    pub fn input(&mut self, packet: &[u8], now: Instant) -> Vec<Action> {
        let mut actions = Vec::new();
        let Some((protocol, payload)) = packet.split_first_chunk::<2>() else {
            tracing::debug!("dropping a truncated PPP packet");
            return actions;
        };
        let protocol = u16::from_be_bytes(*protocol);
        match protocol {
            PROTOCOL_IP if self.is_up() => actions.push(Action::Deliver(payload.to_vec())),
            PROTOCOL_LCP => self.control(Which::Lcp, payload, now, &mut actions),
            PROTOCOL_IPCP if self.lcp.state == State::Opened => {
                self.control(Which::Ipcp, payload, now, &mut actions);
            }
            PROTOCOL_IP | PROTOCOL_IPCP => {
                tracing::debug!("dropping a packet of protocol {protocol:#06x}: not open yet");
            }
            _ if self.lcp.state == State::Opened => {
                tracing::debug!("rejecting protocol {protocol:#06x}");
                self.lcp.id = self.lcp.id.wrapping_add(1);
                let limit = self.lcp.reject_limit();
                actions.push(Action::Send(Fsm::<Lcp>::packet(
                    PROTO_REJ,
                    self.lcp.id,
                    &packet[..packet.len().min(limit)],
                )));
            }
            _ => tracing::debug!("dropping a packet of protocol {protocol:#06x}"),
        }
        actions
    }

    fn control(&mut self, which: Which, payload: &[u8], now: Instant, actions: &mut Vec<Action>) {
        let Some((header, rest)) = payload.split_first_chunk::<4>() else {
            tracing::debug!("dropping a truncated control packet");
            return;
        };
        let (code, id) = (header[0], header[1]);
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if length < 4 || length > payload.len() {
            tracing::debug!("dropping a control packet with a bad length");
            return;
        }
        let data = &rest[..length - 4];
        match which {
            Which::Lcp => {
                if let Some(outcome) = self.lcp_input(code, id, data, now, actions) {
                    self.on_lcp(outcome, now, actions);
                }
            }
            Which::Ipcp => {
                if let Some(outcome) = self.ipcp.input(code, id, data, now, actions) {
                    self.on_ipcp(outcome, now, actions);
                }
            }
        }
    }

    /// LCP has a few more codes than the generic automaton.
    fn lcp_input(
        &mut self,
        code: u8,
        id: u8,
        data: &[u8],
        now: Instant,
        actions: &mut Vec<Action>,
    ) -> Option<Outcome> {
        match code {
            ECHO_REQ => {
                if self.lcp.state == State::Opened {
                    let mut reply = self.lcp.layer.magic.to_be_bytes().to_vec();
                    reply.extend_from_slice(data.get(4..).unwrap_or_default());
                    actions.push(Action::Send(Fsm::<Lcp>::packet(ECHO_REPLY, id, &reply)));
                }
                None
            }
            // Echo-Reply, Discard-Request, Identification, Time-Remaining
            ECHO_REPLY | DISCARD_REQ | 12 | 13 => None,
            PROTO_REJ => {
                let rejected = data
                    .split_first_chunk::<2>()
                    .map(|(protocol, _)| u16::from_be_bytes(*protocol));
                tracing::debug!("the gateway rejected protocol {rejected:#06x?}");
                if rejected == Some(PROTOCOL_IPCP) {
                    return Some(Outcome::Down("the gateway rejected IPCP".into()));
                }
                None
            }
            _ => self.lcp.input(code, id, data, now, actions),
        }
    }

    fn on_lcp(&mut self, outcome: Outcome, now: Instant, actions: &mut Vec<Action>) {
        match outcome {
            Outcome::Up => {
                tracing::debug!("LCP is open, starting IPCP");
                self.ipcp.layer.peer_mru = self.lcp.layer.peer_mru;
                self.ipcp.open(now, actions);
            }
            Outcome::Down(reason) => self.report_down(reason, actions),
        }
    }

    fn on_ipcp(&mut self, outcome: Outcome, now: Instant, actions: &mut Vec<Action>) {
        match outcome {
            Outcome::Up => {
                let ipcp = &self.ipcp.layer;
                if ipcp.local.is_unspecified() {
                    self.ipcp.state = State::Closed;
                    self.lcp.close(now, actions);
                    self.report_down("the gateway did not assign an address".into(), actions);
                    return;
                }
                let peer = ipcp.peer.unwrap_or_else(|| {
                    tracing::warn!(
                        "Could not determine remote IP address: defaulting to {DEFAULT_PEER}"
                    );
                    DEFAULT_PEER
                });
                actions.push(Action::Up(Addresses {
                    local: ipcp.local,
                    peer,
                    dns: ipcp
                        .dns
                        .iter()
                        .flatten()
                        .copied()
                        .filter(|server| !server.is_unspecified())
                        .collect(),
                    mtu: self.lcp.layer.peer_mru.min(self.lcp.layer.mru),
                }));
            }
            Outcome::Down(reason) => {
                // No IP, no point keeping the link.
                if self.lcp.state == State::Opened {
                    self.lcp.close(now, actions);
                }
                self.report_down(reason, actions);
            }
        }
    }

    fn report_down(&mut self, reason: String, actions: &mut Vec<Action>) {
        if !self.down {
            self.down = true;
            actions.push(Action::Down(reason));
        }
    }
}

#[derive(Clone, Copy)]
enum Which {
    Lcp,
    Ipcp,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A gateway-like peer: acknowledges what we ask (after naking the
    /// addresses) and requests its own MRU, magic and address.
    struct Peer {
        mru: u16,
        local: Ipv4Addr,
        remote: Ipv4Addr,
        dns: Ipv4Addr,
        seen_request: bool,
        reject_dns2: bool,
    }

    fn control(protocol: u16, code: u8, id: u8, options: &[Opt]) -> Vec<u8> {
        let payload = Opt::encode_all(options);
        let length = u16::try_from(payload.len() + 4).expect("short");
        let mut packet = protocol.to_be_bytes().to_vec();
        packet.extend([code, id]);
        packet.extend(length.to_be_bytes());
        packet.extend(payload);
        packet
    }

    /// Splits a control packet into protocol, code, identifier and data.
    fn parse(packet: &[u8]) -> (u16, u8, u8, &[u8]) {
        let protocol = u16::from_be_bytes([packet[0], packet[1]]);
        let length = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
        (protocol, packet[2], packet[3], &packet[6..2 + length])
    }

    impl Peer {
        /// Answers one packet of ours, as the peer would.
        fn answer(&mut self, packet: &[u8]) -> Vec<Vec<u8>> {
            let (protocol, code, id, data) = parse(packet);
            let options = Opt::parse_all(data).expect("options");
            let mut replies = Vec::new();
            match (protocol, code) {
                (PROTOCOL_LCP, CONF_REQ) => {
                    replies.push(control(protocol, CONF_ACK, id, &options));
                    if !self.seen_request {
                        self.seen_request = true;
                        replies.push(control(
                            PROTOCOL_LCP,
                            CONF_REQ,
                            7,
                            &[
                                Opt::new(LCP_MRU, self.mru.to_be_bytes()),
                                Opt::new(LCP_ACCM, [0, 0, 0, 0]),
                                Opt::new(LCP_MAGIC, [1, 2, 3, 4]),
                            ],
                        ));
                    }
                }
                // Our side is configured; nothing to do.
                (PROTOCOL_LCP | PROTOCOL_IPCP, CONF_ACK) => {}
                (PROTOCOL_LCP, TERM_REQ) => {
                    replies.push(control(protocol, TERM_ACK, id, &[]));
                }
                (PROTOCOL_IPCP, CONF_REQ) => {
                    let mut naks = Vec::new();
                    let mut rejs = Vec::new();
                    for option in &options {
                        match option.kind {
                            IPCP_ADDRESS if option.address() != Some(self.local) => {
                                naks.push(Opt::new(IPCP_ADDRESS, self.local.octets()));
                            }
                            IPCP_DNS1 if option.address() != Some(self.dns) => {
                                naks.push(Opt::new(IPCP_DNS1, self.dns.octets()));
                            }
                            IPCP_DNS2 if self.reject_dns2 => rejs.push(option.clone()),
                            IPCP_DNS2 if option.address() != Some(self.dns) => {
                                naks.push(Opt::new(IPCP_DNS2, self.dns.octets()));
                            }
                            _ => {}
                        }
                    }
                    if !rejs.is_empty() {
                        replies.push(control(protocol, CONF_REJ, id, &rejs));
                    } else if !naks.is_empty() {
                        replies.push(control(protocol, CONF_NAK, id, &naks));
                    } else {
                        replies.push(control(protocol, CONF_ACK, id, &options));
                        replies.push(control(
                            PROTOCOL_IPCP,
                            CONF_REQ,
                            9,
                            &[Opt::new(IPCP_ADDRESS, self.remote.octets())],
                        ));
                    }
                }
                other => panic!("unexpected packet {other:?}"),
            }
            replies
        }
    }

    /// Runs the negotiation to completion and returns the addresses.
    fn negotiate(ppp: &mut Ppp, peer: &mut Peer) -> Addresses {
        let now = Instant::now();
        let mut pending = ppp.open(now);
        let mut up = None;
        let mut rounds = 0;
        while let Some(action) = pending.pop() {
            rounds += 1;
            assert!(rounds < 100, "negotiation does not converge");
            match action {
                Action::Send(packet) => {
                    for reply in peer.answer(&packet) {
                        pending.extend(ppp.input(&reply, now));
                    }
                }
                Action::Up(addresses) => up = Some(addresses),
                other => panic!("unexpected action {other:?}"),
            }
        }
        up.expect("IPCP open")
    }

    fn peer() -> Peer {
        Peer {
            mru: 1400,
            local: Ipv4Addr::new(10, 0, 0, 2),
            remote: Ipv4Addr::new(10, 0, 0, 1),
            dns: Ipv4Addr::new(10, 0, 0, 53),
            seen_request: false,
            reject_dns2: false,
        }
    }

    #[test]
    fn negotiates_lcp_and_ipcp() {
        let mut ppp = Ppp::new(1354, true);
        let addresses = negotiate(&mut ppp, &mut peer());
        assert_eq!(
            addresses,
            Addresses {
                local: Ipv4Addr::new(10, 0, 0, 2),
                peer: Ipv4Addr::new(10, 0, 0, 1),
                dns: vec![Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(10, 0, 0, 53)],
                mtu: 1354,
            }
        );
        assert!(ppp.is_up());

        // IP packets flow both ways.
        let ip = [0x45, 0, 0, 20];
        assert_eq!(Ppp::encode_ip(&ip), [0, 0x21, 0x45, 0, 0, 20]);
        assert_eq!(
            ppp.input(&Ppp::encode_ip(&ip), Instant::now()),
            [Action::Deliver(ip.to_vec())]
        );

        // Echo requests are answered with our magic.
        let echo = control(PROTOCOL_LCP, ECHO_REQ, 3, &[]);
        let actions = ppp.input(&echo, Instant::now());
        let Action::Send(reply) = &actions[0] else {
            panic!("no echo reply");
        };
        assert_eq!(parse(reply).1, ECHO_REPLY);
        assert_eq!(parse(reply).3, ppp.lcp.layer.magic.to_be_bytes());

        // Unknown protocols are rejected.
        let ccp = [0x80, 0xfd, 1, 1, 0, 4];
        let actions = ppp.input(&ccp, Instant::now());
        assert!(matches!(&actions[0], Action::Send(packet) if packet[2] == PROTO_REJ));

        // Closing waits for the Terminate-Ack.
        let now = Instant::now();
        let actions = ppp.close(now);
        let Action::Send(request) = &actions[0] else {
            panic!("no terminate request");
        };
        assert_eq!(parse(request).1, TERM_REQ);
        assert_eq!(actions.len(), 1);
        let ack = control(PROTOCOL_LCP, TERM_ACK, parse(request).2, &[]);
        assert_eq!(ppp.input(&ack, now), [Action::Down("LCP closed".into())]);
        assert!(!ppp.is_up());
    }

    #[test]
    fn survives_rejected_options() {
        let mut ppp = Ppp::new(1354, true);
        let mut rejecting = peer();
        rejecting.reject_dns2 = true;
        let addresses = negotiate(&mut ppp, &mut rejecting);
        assert_eq!(addresses.dns, [Ipv4Addr::new(10, 0, 0, 53)]);
        let mut ppp = Ppp::new(1354, false);
        let addresses = negotiate(&mut ppp, &mut peer());
        assert!(addresses.dns.is_empty());
    }

    #[test]
    fn gives_up_after_the_retries() {
        let mut ppp = Ppp::new(1354, false);
        let start = Instant::now();
        let actions = ppp.open(start);
        assert_eq!(actions.len(), 1);
        let mut now = start;
        let mut sent = 0;
        loop {
            now += RESTART_TIMER;
            let actions = ppp.timeout(now);
            if let Some(Action::Down(reason)) = actions.last() {
                assert!(reason.contains("no answer"));
                break;
            }
            sent += 1;
            assert!(matches!(actions.as_slice(), [Action::Send(_)]));
        }
        assert_eq!(sent, LCP_MAX_CONFIGURE);
        assert_eq!(ppp.next_timeout(), None);
    }

    #[test]
    fn terminate_request_takes_the_link_down() {
        let mut ppp = Ppp::new(1354, false);
        negotiate(&mut ppp, &mut peer());
        let request = control(PROTOCOL_LCP, TERM_REQ, 5, &[]);
        let actions = ppp.input(&request, Instant::now());
        assert!(matches!(&actions[0], Action::Send(packet) if parse(packet).1 == TERM_ACK));
        assert!(matches!(&actions[1], Action::Down(_)));
        // Nothing more is reported afterwards.
        assert!(ppp.close(Instant::now()).is_empty());
    }

    #[test]
    fn repeated_requests_are_acknowledged_again() {
        let mut ppp = Ppp::new(1354, false);
        negotiate(&mut ppp, &mut peer());
        let repeat = control(
            PROTOCOL_IPCP,
            CONF_REQ,
            9,
            &[Opt::new(IPCP_ADDRESS, Ipv4Addr::new(10, 0, 0, 1).octets())],
        );
        let actions = ppp.input(&repeat, Instant::now());
        assert!(matches!(&actions[..], [Action::Send(packet)] if parse(packet).1 == CONF_ACK));
        assert!(ppp.is_up());
        // A different request is a renegotiation: the link goes down.
        let other = control(
            PROTOCOL_IPCP,
            CONF_REQ,
            10,
            &[Opt::new(IPCP_ADDRESS, Ipv4Addr::new(10, 0, 0, 7).octets())],
        );
        let actions = ppp.input(&other, Instant::now());
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, Action::Down(_)))
        );
    }

    #[test]
    fn endless_naks_are_taken_as_rejects() {
        let mut ppp = Ppp::new(1354, false);
        let now = Instant::now();
        let mut pending = ppp.open(now);
        let mut peer = peer();
        let mut naks = 0;
        let mut down = None;
        while let Some(action) = pending.pop() {
            match action {
                Action::Send(packet) => {
                    let (protocol, code, id, _) = parse(&packet);
                    if protocol == PROTOCOL_IPCP && code == CONF_REQ {
                        // Always suggest the unusable address.
                        naks += 1;
                        assert!(naks < 20, "the Nak loop does not end");
                        let nak = control(
                            PROTOCOL_IPCP,
                            CONF_NAK,
                            id,
                            &[Opt::new(IPCP_ADDRESS, [0, 0, 0, 0])],
                        );
                        pending.extend(ppp.input(&nak, now));
                    } else {
                        for reply in peer.answer(&packet) {
                            pending.extend(ppp.input(&reply, now));
                        }
                    }
                }
                Action::Down(reason) => down = Some(reason),
                other => panic!("unexpected action {other:?}"),
            }
        }
        assert_eq!(naks, 2 * MAX_NAK_LOOPS + 1);
        assert!(down.is_some_and(|reason| reason.contains("keeps refusing")));
    }

    #[test]
    fn parses_options_strictly() {
        assert!(Opt::parse_all(&[1, 4, 5, 0x4a]).is_some());
        assert!(Opt::parse_all(&[1, 1]).is_none());
        assert!(Opt::parse_all(&[1, 5, 0]).is_none());
        assert_eq!(Opt::parse_all(&[]), Some(Vec::new()));
    }
}
