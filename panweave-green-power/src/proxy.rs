//! The GP Basic Proxy (GP Basic 1.1.2 §A.3.5.2.3, §A.3.7.3.1.3, §A.3.9):
//! a sans-I/O machine that consumes received GPDFs and Green Power cluster
//! commands and produces the GP Notification / GP Commissioning
//! Notification / GP Proxy Table Response frames to tunnel through the
//! Zigbee network, with the delay, destination and NWK alias each of them
//! must be sent with. Time, keys and the radio belong to the caller.

use heapless::{Deque, Vec};
use panweave_codec::Encode;
use panweave_security::cipher::BlockCipher;
use panweave_types::time::{Duration, Instant};
use panweave_types::{CommandId, ExtendedAddress, Key128, ShortAddress};

use crate::cluster::{
    self, CommissioningNotification, CommunicationMode, GppGpdLink, Notification, Pairing,
    ProxyCommissioningMode, ProxyTableRequest, ProxyTableResponse, SinkAddress, TableStatus,
};
use crate::command;
use crate::gpdf::{FrameType, GpdId, Gpdf, SRC_ID_UNSPECIFIED, SecurityLevel};
use crate::proxy_table::{ALIAS_DERIVED, ProxyEntry, ProxyTable, SecurityOptions, derived_alias};
use crate::security::{self, Direction, KeyType};

/// gppCommissioningWindow default (§A.3.6.3.2).
pub const DEFAULT_COMMISSIONING_WINDOW: Duration = Duration::from_secs(180);
/// gpDuplicateTimeout default (§A.3.6.1.2.1).
pub const DUPLICATE_TIMEOUT: Duration = Duration::from_secs(2);
/// Dmin_u (§A.3.6.3.1).
pub const DMIN_UNIDIRECTIONAL: Duration = Duration::from_millis(5);
/// Dmin_b (§A.3.6.3.1).
pub const DMIN_BIDIRECTIONAL: Duration = Duration::from_millis(32);
/// Largest tunnelled command payload.
pub const MAX_PAYLOAD: usize = 80;
/// Outgoing action queue capacity.
pub const QUEUE_CAPACITY: usize = 8;
/// Duplicate filter capacity.
pub const DUPLICATE_ENTRIES: usize = 8;

/// The proxy's own addresses and the keys it may use (§A.3.3.3).
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// NWK address of this proxy (proxy info in notifications).
    pub short: ShortAddress,
    /// IEEE address of this proxy.
    pub ieee: ExtendedAddress,
    /// `gpSharedSecurityKeyType`.
    pub shared_key_type: KeyType,
    /// `gpSharedSecurityKey` (the group key for GroupKey /
    /// DerivedIndividual).
    pub shared_key: Option<Key128>,
    /// The current NWK key (for NwkKey / NwkDerivedGroupKey).
    pub nwk_key: Option<Key128>,
    /// gppCommissioningWindow.
    pub commissioning_window: Duration,
}

impl ProxyConfig {
    /// A proxy with no shared key.
    pub const fn new(short: ShortAddress, ieee: ExtendedAddress) -> Self {
        ProxyConfig {
            short,
            ieee,
            shared_key_type: KeyType::None,
            shared_key: None,
            nwk_key: None,
            commissioning_window: DEFAULT_COMMISSIONING_WINDOW,
        }
    }
}

/// Where a tunnelled frame goes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Destination {
    /// Unicast to a sink (Green Power EndPoint to Green Power EndPoint).
    Unicast(ShortAddress),
    /// APS groupcast to the group (NWK broadcast to 0xfffd).
    Group(u16),
    /// NWK broadcast to 0xfffd.
    Broadcast,
}

/// NWK source aliasing of a tunnelled frame (§A.3.6.3.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Alias {
    /// Alias NWK source address.
    pub address: ShortAddress,
    /// Alias NWK sequence number, also used as the APS counter.
    pub sequence: u8,
}

/// An outgoing Green Power cluster command.
#[derive(Clone, Debug)]
pub struct Outgoing {
    /// Destination.
    pub destination: Destination,
    /// Alias, when the frame is sent on behalf of the GPD.
    pub alias: Option<Alias>,
    /// Earliest transmission time (gppTunnelingDelay / Dmin).
    pub not_before: Instant,
    /// Groupcast radius (0 = default).
    pub radius: u8,
    /// Cluster-specific command (client → server direction).
    pub command: CommandId,
    /// Encoded payload.
    pub payload: Vec<u8, MAX_PAYLOAD>,
}

/// Events for the application / runtime.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ProxyEvent {
    /// The Proxy Table changed: persist it.
    TableChanged,
    /// Commissioning mode entered (`Some(window end)`) or left (`None`).
    CommissioningMode(Option<Instant>),
    /// A unicast GP Pairing could not be honoured: send a ZCL Default
    /// Response with this status.
    PairingRejected(PairingError),
}

/// Why a unicast GP Pairing was refused (§A.3.5.2.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PairingError {
    /// Unsupported communication mode: INVALID_FIELD.
    InvalidField,
    /// No free Proxy Table entry: INSUFFICIENT_SPACE.
    InsufficientSpace,
}

/// Result of the security processing of a GPDF (GP-DATA.indication
/// Status, §A.1.5.2.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SecurityStatus {
    /// Unprotected frame.
    NoSecurity,
    /// Verified (and decrypted).
    Success,
    /// The MIC did not verify.
    AuthFailed,
    /// No key to process the frame with.
    Unprocessed,
}

#[derive(Clone, Copy, Debug)]
struct Commissioning {
    until: Instant,
    unicast_to: Option<ShortAddress>,
    exit_on_first_pairing: bool,
}

#[derive(Clone, Copy, Debug)]
struct Duplicate {
    gpd: GpdId,
    counter: u32,
    until: Instant,
}

/// The Basic Proxy.
pub struct Proxy<const N: usize> {
    /// Configuration.
    pub config: ProxyConfig,
    /// The Proxy Table.
    pub table: ProxyTable<N>,
    commissioning: Option<Commissioning>,
    duplicates: Vec<Duplicate, DUPLICATE_ENTRIES>,
    outgoing: Deque<Outgoing, QUEUE_CAPACITY>,
    events: Deque<ProxyEvent, QUEUE_CAPACITY>,
    now: Instant,
}

impl<const N: usize> Proxy<N> {
    /// A proxy in operational mode with an empty table.
    pub fn new(config: ProxyConfig) -> Self {
        Proxy {
            config,
            table: ProxyTable::new(),
            commissioning: None,
            duplicates: Vec::new(),
            outgoing: Deque::new(),
            events: Deque::new(),
            now: Instant::from_millis(0),
        }
    }

    /// Next frame to transmit.
    pub fn next_outgoing(&mut self) -> Option<Outgoing> {
        self.outgoing.pop_front()
    }

    /// Next event.
    pub fn next_event(&mut self) -> Option<ProxyEvent> {
        self.events.pop_front()
    }

    /// True while in commissioning mode.
    pub fn in_commissioning_mode(&self) -> bool {
        self.commissioning.is_some()
    }

    /// Earliest timer.
    pub fn next_deadline(&self) -> Option<Instant> {
        let c = self.commissioning.map(|c| c.until);
        let d = self
            .duplicates
            .iter()
            .map(|d| d.until)
            .min_by_key(|t| t.as_millis());
        match (c, d) {
            (Some(a), Some(b)) => Some(if a.as_millis() < b.as_millis() { a } else { b }),
            (a, None) => a,
            (None, b) => b,
        }
    }

    /// Advances time: expires the commissioning window and the duplicate
    /// filter.
    pub fn poll(&mut self, now: Instant) {
        self.now = now;
        self.duplicates.retain(|d| !now.has_reached(d.until));
        if let Some(c) = self.commissioning
            && now.has_reached(c.until)
        {
            self.commissioning = None;
            let _ = self.events.push_back(ProxyEvent::CommissioningMode(None));
        }
    }

    fn push(&mut self, o: Outgoing) {
        let _ = self.outgoing.push_back(o);
    }

    // ---------------------------------------------------------------
    // GP Proxy Commissioning Mode (§A.3.3.5.3, §A.3.5.2.3)
    // ---------------------------------------------------------------

    /// GP Proxy Commissioning Mode received from `src`.
    pub fn on_commissioning_mode(&mut self, cmd: &ProxyCommissioningMode, src: ShortAddress) {
        if cmd.enter {
            let window = cmd
                .window_secs
                .map_or(self.config.commissioning_window, |s| {
                    Duration::from_secs(u64::from(s))
                });
            let until = self.now + window;
            self.commissioning = Some(Commissioning {
                until,
                unicast_to: cmd.unicast.then_some(src),
                exit_on_first_pairing: cmd.exit_on_first_pairing,
            });
            let _ = self
                .events
                .push_back(ProxyEvent::CommissioningMode(Some(until)));
        } else if self.commissioning.take().is_some() {
            let _ = self.events.push_back(ProxyEvent::CommissioningMode(None));
        }
    }

    // ---------------------------------------------------------------
    // GP Pairing (§A.3.5.2.3)
    // ---------------------------------------------------------------

    /// GP Pairing received (`unicast` selects the error reporting).
    pub fn on_pairing(&mut self, p: &Pairing, unicast: bool) {
        let gpd = p.gpd;
        // SrcID / IEEE 0: dropped. AddSink + RemoveGPD: dropped.
        let zero = match gpd {
            GpdId::SrcId(s) => s == SRC_ID_UNSPECIFIED,
            GpdId::Ieee { address, .. } => address.0 == 0,
        };
        if zero || (p.add_sink && p.remove_gpd) {
            return;
        }
        if let Some(c) = self.commissioning
            && c.exit_on_first_pairing
        {
            self.commissioning = None;
            let _ = self.events.push_back(ProxyEvent::CommissioningMode(None));
        }
        if p.remove_gpd {
            let removed = match gpd {
                GpdId::Ieee { endpoint: 0xff, .. } => self.table.remove_device(&gpd) > 0,
                _ => self.table.remove(&gpd),
            };
            if removed {
                let _ = self.events.push_back(ProxyEvent::TableChanged);
            }
            return;
        }
        // Reserved SecurityLevel 0b01: no update, no creation.
        let Some(level) = p.security_level() else {
            return;
        };
        if !p.add_sink {
            // Remove the sink from the entry; drop empty entries.
            let mut changed = false;
            let mut remove_entry = false;
            if let Some(e) = self.table.get_exact_mut(&gpd) {
                match (p.mode, p.sink) {
                    (
                        CommunicationMode::LightweightUnicast,
                        Some(SinkAddress::Unicast(ieee, _)),
                    ) => {
                        let before = e.lightweight_sinks.len();
                        e.lightweight_sinks.retain(|(i, _)| *i != ieee);
                        changed = e.lightweight_sinks.len() != before;
                    }
                    (CommunicationMode::DerivedGroupcast, _) => {
                        changed = e.derived_group;
                        e.derived_group = false;
                    }
                    (CommunicationMode::CommissionedGroupcast, Some(SinkAddress::Group(g))) => {
                        let before = e.groups.len();
                        e.groups.retain(|(gr, _)| *gr != g);
                        changed = e.groups.len() != before;
                    }
                    _ => {}
                }
                remove_entry = e.is_empty();
            }
            if remove_entry {
                self.table.remove(&gpd);
                changed = true;
            }
            if changed {
                let _ = self.events.push_back(ProxyEvent::TableChanged);
            }
            return;
        }
        // AddSink.
        if p.mode == CommunicationMode::FullUnicast {
            // Not supported by a Basic Proxy.
            if unicast {
                let _ = self
                    .events
                    .push_back(ProxyEvent::PairingRejected(PairingError::InvalidField));
            }
            return;
        }
        let existing = self.table.iter().position(|e| e.gpd == gpd);
        let index = match existing {
            Some(i) => i,
            None => match self.table.insert(ProxyEntry::new(gpd)) {
                Ok(i) => i,
                Err(_) => {
                    if unicast {
                        let _ = self.events.push_back(ProxyEvent::PairingRejected(
                            PairingError::InsufficientSpace,
                        ));
                    }
                    return;
                }
            },
        };
        let Some(e) = self.table.at_mut(index) else {
            return;
        };
        e.active = true;
        e.valid = true;
        e.gpd_fixed = p.gpd_fixed;
        e.sequence_number_capable = p.sequence_number_capable;
        match (p.mode, p.sink) {
            (CommunicationMode::LightweightUnicast, Some(SinkAddress::Unicast(ieee, short))) => {
                if let Some(s) = e.lightweight_sinks.iter_mut().find(|(i, _)| *i == ieee) {
                    s.1 = short;
                } else {
                    let _ = e.lightweight_sinks.push((ieee, short));
                }
            }
            (CommunicationMode::DerivedGroupcast, _) => e.derived_group = true,
            (CommunicationMode::CommissionedGroupcast, Some(SinkAddress::Group(g))) => {
                let alias = p.assigned_alias.unwrap_or(ALIAS_DERIVED);
                if let Some(s) = e.groups.iter_mut().find(|(gr, _)| *gr == g) {
                    s.1 = alias;
                } else {
                    let _ = e.groups.push((g, alias));
                }
            }
            _ => {}
        }
        if p.mode != CommunicationMode::CommissionedGroupcast
            && let Some(a) = p.assigned_alias
        {
            e.assigned_alias = Some(a);
        }
        if let Some(r) = p.groupcast_radius {
            // §A.3.4.2.2.2.7: keep the higher value.
            e.groupcast_radius = if e.groupcast_radius == 0 {
                r
            } else {
                e.groupcast_radius.max(r)
            };
        }
        // Security: the pairing's level / key type always apply; the key
        // and counter when included.
        if level.is_protected() || p.key_type != KeyType::None {
            let key = p
                .key
                .clone()
                .or_else(|| e.security.as_ref().and_then(|s| s.key.clone()));
            e.security = Some(SecurityOptions {
                level,
                key_type: p.key_type,
                key,
            });
        } else {
            e.security = None;
        }
        if let Some(c) = p.frame_counter {
            e.frame_counter = c;
        }
        // §A.3.5.2.3: other entries of the same IEEE device share the
        // security fields.
        let sec = e.security.clone();
        let counter = e.frame_counter;
        for other in self.table.for_device_mut(&gpd) {
            if other.gpd != gpd {
                other.security.clone_from(&sec);
                other.frame_counter = counter;
            }
        }
        let _ = self.events.push_back(ProxyEvent::TableChanged);
    }

    // ---------------------------------------------------------------
    // GP Proxy Table Request (§A.3.4.4.2)
    // ---------------------------------------------------------------

    /// GP Proxy Table Request from `src`; answers with a GP Proxy Table
    /// Response (only for a hit when the request was not unicast).
    pub fn on_proxy_table_request(
        &mut self,
        req: &ProxyTableRequest,
        src: ShortAddress,
        unicast: bool,
    ) {
        let total = u8::try_from(self.table.len()).unwrap_or(u8::MAX);
        let mut entries = [0u8; MAX_PAYLOAD];
        let (status, start_index, count, len) = match req {
            ProxyTableRequest::ByIndex(i) => {
                let start = usize::from(*i);
                if start < self.table.len() {
                    let (count, len) = self.table.encode_from(start, &mut entries);
                    (TableStatus::Success, *i, count, len)
                } else {
                    (TableStatus::NotFound, *i, 0, 0)
                }
            }
            ProxyTableRequest::ByGpd(gpd) => match self.table.iter().position(|e| e.gpd == *gpd) {
                Some(i) => {
                    let mut w = panweave_codec::Writer::new(&mut entries);
                    let ok = self.table.at(i).is_some_and(|e| e.encode(&mut w).is_ok());
                    let len = w.position();
                    if ok {
                        (TableStatus::Success, 0xff, 1, len)
                    } else {
                        (TableStatus::NotFound, 0xff, 0, 0)
                    }
                }
                None => (TableStatus::NotFound, 0xff, 0, 0),
            },
        };
        if status == TableStatus::NotFound && !unicast {
            return;
        }
        let rsp = ProxyTableResponse {
            status,
            total,
            start_index,
            count,
            entries: entries.get(..len).unwrap_or(&[]),
        };
        let mut payload = Vec::new();
        if payload.resize(rsp.encoded_len(), 0).is_err() {
            return;
        }
        if rsp.encode_to_slice(&mut payload).is_err() {
            return;
        }
        self.push(Outgoing {
            destination: Destination::Unicast(src),
            alias: None,
            not_before: self.now,
            radius: 0,
            command: cluster::client_cmd::PROXY_TABLE_RESPONSE,
            payload,
        });
    }

    // ---------------------------------------------------------------
    // GPDF reception (§A.1.5.2.2, §A.3.7.3.1.3, §A.3.5.2.3, §A.3.9.1)
    // ---------------------------------------------------------------

    /// A GPDF received by the GP stub. `link` describes the reception
    /// quality. The application payload is copied so that it can be
    /// decrypted in place.
    pub fn on_gpdf<C: BlockCipher>(&mut self, gpdf: &Gpdf<'_>, link: GppGpdLink) {
        // §A.1.5.1.1: frames from proxies are not for us.
        if gpdf.extended.from_proxy {
            return;
        }
        let Some(command_id) = gpdf.command_id() else {
            return;
        };
        if gpdf.frame_control.frame_type == FrameType::Maintenance {
            self.on_maintenance(gpdf, command_id, link);
            return;
        }
        let Some(gpd) = gpdf.gpd else {
            return;
        };
        if !gpd.is_valid() {
            return;
        }
        let level = gpdf.extended.security_level;
        // Commands reserved for the direction to the GPD never arrive in
        // the clear from a GPD (§A.1.5.2.2).
        if !matches!(level, SecurityLevel::EncryptedMic) && command::is_to_gpd(command_id) {
            return;
        }
        let counter = gpdf.frame_counter.unwrap_or(u32::from(gpdf.mac_sequence));
        if self.is_duplicate(&gpd, counter) {
            return;
        }
        // Security processing.
        let mut payload: Vec<u8, MAX_PAYLOAD> = Vec::new();
        if payload.extend_from_slice(gpdf.application_payload).is_err() {
            return;
        }
        let (status, key_type) = self.security_process::<C>(gpdf, &gpd, &mut payload);
        let command_id = payload.first().copied().unwrap_or(command_id);
        if status == SecurityStatus::Success && command::is_to_gpd(command_id) {
            return;
        }
        let in_commissioning = self.commissioning.is_some();
        let entry = self.table.find(&gpd).filter(|e| e.active);
        let has_entry = entry.is_some();
        let entry_protected = entry.is_some_and(|e| e.security_level().is_protected());
        let commissioning_cmd = command::is_commissioning(command_id)
            || gpdf.frame_control.auto_commissioning
            || command::is_manufacturer_defined(command_id);
        // §A.3.7.3.1.3: an unprotected frame from a GPD paired with
        // security fails the level check; §A.3.9.1 step 12b.ii accepts
        // unprotected commissioning frames in commissioning mode.
        if !level.is_protected() && entry_protected && !(in_commissioning && commissioning_cmd) {
            return;
        }
        match status {
            SecurityStatus::AuthFailed | SecurityStatus::Unprocessed => {
                // Operational mode: dropped. Commissioning mode: forwarded
                // with SecurityProcessingFailed for commissioning frames
                // (§A.3.9.2.1.1, §A.3.9.1 step 12b/17b).
                if in_commissioning && commissioning_cmd {
                    let _ = payload.clear();
                    let _ = payload.extend_from_slice(gpdf.application_payload);
                    self.remember(&gpd, counter);
                    self.commissioning_notification(gpdf, &gpd, key_type, true, &payload, link);
                }
                return;
            }
            SecurityStatus::NoSecurity | SecurityStatus::Success => {}
        }
        self.remember(&gpd, counter);
        if commissioning_cmd {
            if command_id == command::COMMISSIONING && gpdf.frame_control.auto_commissioning {
                return;
            }
            if gpdf.frame_control.auto_commissioning && gpdf.extended.rx_after_tx {
                return;
            }
            if in_commissioning {
                if status == SecurityStatus::Success {
                    self.store_counter(&gpd, counter);
                }
                self.commissioning_notification(gpdf, &gpd, key_type, false, &payload, link);
                return;
            }
            // Operational mode: a correctly protected Commissioning /
            // Decommissioning from a known GPD is tunnelled without
            // RxAfterTx; Success and 0xE4–0xEF are not forwarded; the
            // rest is dropped (§A.3.5.2.3).
            if has_entry
                && matches!(
                    command_id,
                    command::COMMISSIONING | command::DECOMMISSIONING
                )
                && !gpdf.frame_control.auto_commissioning
            {
                self.store_counter(&gpd, counter);
                self.notify(gpdf, &gpd, key_type, false, &payload, link, counter);
            }
            return;
        }
        if !has_entry {
            return;
        }
        self.store_counter(&gpd, counter);
        self.notify(
            gpdf,
            &gpd,
            key_type,
            gpdf.extended.rx_after_tx,
            &payload,
            link,
            counter,
        );
    }

    fn on_maintenance(&mut self, gpdf: &Gpdf<'_>, command_id: u8, link: GppGpdLink) {
        // §A.1.5.2.2: commands to the GPD are dropped; §A.3.9.1 step 6:
        // only a proxy in commissioning mode forwards a Channel Request.
        if command::is_to_gpd(command_id) || self.commissioning.is_none() {
            return;
        }
        let gpd = GpdId::SrcId(SRC_ID_UNSPECIFIED);
        let counter = u32::from(gpdf.mac_sequence);
        if self.is_duplicate(&gpd, counter) {
            return;
        }
        self.remember(&gpd, counter);
        let mut payload: Vec<u8, MAX_PAYLOAD> = Vec::new();
        if payload.extend_from_slice(gpdf.application_payload).is_err() {
            return;
        }
        // Channel Request: RxAfterTx set in the notification (step 6b).
        let rx_after_tx = command_id == command::CHANNEL_REQUEST;
        let n = CommissioningNotification {
            gpd,
            rx_after_tx,
            security_level: SecurityLevel::None,
            key_type: KeyType::None,
            security_failed: false,
            bidirectional: false,
            frame_counter: counter,
            command_id,
            payload: payload.get(1..).unwrap_or(&[]),
            proxy: Some((self.config.short, link)),
            mic: None,
        };
        let delay = if rx_after_tx {
            DMIN_BIDIRECTIONAL
        } else {
            DMIN_UNIDIRECTIONAL
        };
        self.send_commissioning_notification(&n, &gpd, gpdf.mac_sequence, delay);
    }

    fn is_duplicate(&self, gpd: &GpdId, counter: u32) -> bool {
        self.duplicates
            .iter()
            .any(|d| d.gpd.same_device(gpd) && d.counter == counter)
    }

    fn remember(&mut self, gpd: &GpdId, counter: u32) {
        let d = Duplicate {
            gpd: *gpd,
            counter,
            until: self.now + DUPLICATE_TIMEOUT,
        };
        if self.duplicates.push(d).is_err() {
            self.duplicates.remove(0);
            let _ = self.duplicates.push(d);
        }
    }

    fn store_counter(&mut self, gpd: &GpdId, counter: u32) {
        let mut changed = false;
        for e in self.table.for_device_mut(gpd) {
            if e.matches(gpd) && e.frame_counter != counter {
                e.frame_counter = counter;
                changed = true;
            }
            if !e.in_range {
                e.in_range = true;
            }
        }
        if changed {
            let _ = self.events.push_back(ProxyEvent::TableChanged);
        }
    }

    /// GP-SEC processing (§A.3.7.3.1.3): returns the status and the key
    /// type used (or mapped from the SecurityKey bit on failure).
    fn security_process<C: BlockCipher>(
        &mut self,
        gpdf: &Gpdf<'_>,
        gpd: &GpdId,
        payload: &mut Vec<u8, MAX_PAYLOAD>,
    ) -> (SecurityStatus, KeyType) {
        let level = gpdf.extended.security_level;
        let individual = gpdf.extended.individual_key;
        let failed_type = if individual {
            KeyType::Individual
        } else {
            KeyType::None
        };
        if !level.is_protected() {
            return (SecurityStatus::NoSecurity, KeyType::None);
        }
        let (Some(counter), Some(mic)) = (gpdf.frame_counter, gpdf.mic) else {
            return (SecurityStatus::Unprocessed, failed_type);
        };
        let entry = self.table.find(gpd).filter(|e| e.active).cloned();
        if let Some(e) = &entry {
            // Level and key type must match; the counter must be fresh.
            if e.security_level() != level
                || e.key_type().is_individual() != individual
                || (e.security_level().is_protected() && counter <= e.frame_counter)
            {
                return (SecurityStatus::Unprocessed, failed_type);
            }
        }
        let Some((key, key_type)) = self.resolve_key::<C>(entry.as_ref(), gpd, individual) else {
            return (SecurityStatus::Unprocessed, failed_type);
        };
        let ok = security::unprotect::<C>(
            &key,
            level,
            gpd,
            counter,
            Direction::FromGpd,
            gpdf.header,
            payload,
            &mic,
        );
        match ok {
            Ok(()) => (SecurityStatus::Success, key_type),
            Err(_) => (SecurityStatus::AuthFailed, failed_type),
        }
    }

    /// Key recovery (§A.3.7.3.1.4) with the cipher for derivations.
    fn resolve_key<C: BlockCipher>(
        &self,
        entry: Option<&ProxyEntry>,
        gpd: &GpdId,
        individual: bool,
    ) -> Option<(Key128, KeyType)> {
        let stored = entry.and_then(|e| e.security.as_ref().and_then(|s| s.key.clone()));
        let entry_type = entry.map(ProxyEntry::key_type);
        let shared_type = self.config.shared_key_type;
        let derived_group = || {
            self.config
                .nwk_key
                .as_ref()
                .map(security::derive_group_key::<C>)
        };
        let derived_individual = || {
            self.config
                .shared_key
                .as_ref()
                .map(|k| security::derive_individual_key::<C>(k, gpd))
        };
        if individual {
            return match entry_type {
                Some(KeyType::Individual) => stored.map(|k| (k, KeyType::Individual)),
                Some(KeyType::DerivedIndividual) => stored
                    .or_else(derived_individual)
                    .map(|k| (k, KeyType::DerivedIndividual)),
                // No entry: an individual key cannot be known.
                _ => None,
            };
        }
        let wanted = match entry_type {
            Some(t) if t != KeyType::None => t,
            _ => shared_type,
        };
        match wanted {
            KeyType::NwkKey => self.config.nwk_key.clone().map(|k| (k, KeyType::NwkKey)),
            KeyType::GroupKey => stored
                .or_else(|| self.config.shared_key.clone())
                .map(|k| (k, KeyType::GroupKey)),
            KeyType::NwkDerivedGroupKey => stored
                .or_else(derived_group)
                .map(|k| (k, KeyType::NwkDerivedGroupKey)),
            _ => None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn notify(
        &mut self,
        gpdf: &Gpdf<'_>,
        gpd: &GpdId,
        key_type: KeyType,
        rx_after_tx: bool,
        payload: &[u8],
        link: GppGpdLink,
        counter: u32,
    ) {
        let Some(entry) = self.table.find(gpd).cloned() else {
            return;
        };
        let command_id = payload.first().copied().unwrap_or(0);
        let n = Notification {
            gpd: *gpd,
            also_unicast: !entry.lightweight_sinks.is_empty(),
            also_derived_group: entry.derived_group,
            also_commissioned_group: !entry.groups.is_empty(),
            security_level: gpdf.extended.security_level,
            key_type,
            rx_after_tx,
            tx_queue_full: true,
            bidirectional: false,
            frame_counter: counter,
            command_id,
            payload: payload.get(1..).unwrap_or(&[]),
            proxy: Some((self.config.short, link)),
        };
        let mut encoded: Vec<u8, MAX_PAYLOAD> = Vec::new();
        if encoded.resize(n.encoded_len(), 0).is_err() || n.encode_to_slice(&mut encoded).is_err() {
            return;
        }
        let dmin = if gpdf.extended.rx_after_tx {
            DMIN_BIDIRECTIONAL
        } else {
            DMIN_UNIDIRECTIONAL
        };
        // Lightweight unicast: no alias, after Dmin.
        for (_, short) in &entry.lightweight_sinks {
            self.push(Outgoing {
                destination: Destination::Unicast(*short),
                alias: None,
                not_before: self.now + dmin,
                radius: 0,
                command: cluster::client_cmd::NOTIFICATION,
                payload: encoded.clone(),
            });
        }
        // Derived groupcast: DGroupID = derived alias, alias = entry alias,
        // sequence = MAC sequence.
        if entry.derived_group {
            self.push(Outgoing {
                destination: Destination::Group(derived_alias(gpd).0),
                alias: Some(Alias {
                    address: entry.alias(),
                    sequence: gpdf.mac_sequence,
                }),
                not_before: self.now + dmin,
                radius: entry.groupcast_radius,
                command: cluster::client_cmd::NOTIFICATION,
                payload: encoded.clone(),
            });
        }
        // Commissioned groupcast: the group's alias (or the derived one),
        // sequence = MAC sequence − 9.
        for (group, alias) in &entry.groups {
            let address = if *alias == ALIAS_DERIVED {
                derived_alias(gpd)
            } else {
                *alias
            };
            self.push(Outgoing {
                destination: Destination::Group(*group),
                alias: Some(Alias {
                    address,
                    sequence: gpdf.mac_sequence.wrapping_sub(9),
                }),
                not_before: self.now + dmin,
                radius: entry.groupcast_radius,
                command: cluster::client_cmd::NOTIFICATION,
                payload: encoded.clone(),
            });
        }
    }

    fn commissioning_notification(
        &mut self,
        gpdf: &Gpdf<'_>,
        gpd: &GpdId,
        key_type: KeyType,
        failed: bool,
        payload: &[u8],
        link: GppGpdLink,
    ) {
        let command_id = payload.first().copied().unwrap_or(0);
        let counter = gpdf.frame_counter.unwrap_or(u32::from(gpdf.mac_sequence));
        let n = CommissioningNotification {
            gpd: *gpd,
            rx_after_tx: gpdf.extended.rx_after_tx,
            security_level: gpdf.extended.security_level,
            key_type,
            security_failed: failed,
            bidirectional: false,
            frame_counter: counter,
            command_id,
            payload: payload.get(1..).unwrap_or(&[]),
            proxy: Some((self.config.short, link)),
            mic: if failed { gpdf.mic } else { None },
        };
        let delay = if gpdf.extended.rx_after_tx {
            DMIN_BIDIRECTIONAL
        } else {
            DMIN_UNIDIRECTIONAL
        };
        self.send_commissioning_notification(&n, gpd, gpdf.mac_sequence, delay);
    }

    /// Broadcast with the derived alias (sequence − 12), or unicast to
    /// the originator of the commissioning mode without alias (§A.3.9.1
    /// step 12).
    fn send_commissioning_notification(
        &mut self,
        n: &CommissioningNotification<'_>,
        gpd: &GpdId,
        mac_sequence: u8,
        delay: Duration,
    ) {
        let mut encoded: Vec<u8, MAX_PAYLOAD> = Vec::new();
        if encoded.resize(n.encoded_len(), 0).is_err() || n.encode_to_slice(&mut encoded).is_err() {
            return;
        }
        let unicast_to = self.commissioning.and_then(|c| c.unicast_to);
        let (destination, alias) = match unicast_to {
            Some(sink) => (Destination::Unicast(sink), None),
            None => (
                Destination::Broadcast,
                Some(Alias {
                    address: derived_alias(gpd),
                    sequence: mac_sequence.wrapping_sub(12),
                }),
            ),
        };
        self.push(Outgoing {
            destination,
            alias,
            not_before: self.now + delay,
            radius: 0,
            command: cluster::client_cmd::COMMISSIONING_NOTIFICATION,
            payload: encoded,
        });
    }
}
