//! Smart Energy profile security policies (SE 1.4a §5.4) as pure,
//! testable pieces the runtime or application drives:
//!
//! * [`PermitJoinSchedule`] — the coordinator's permit-join broadcasts
//!   (§5.4.1.2: never 255, at most 254 s, repeated every 240 s or on a
//!   device announce).
//! * [`JoinScanBackoff`] — the autonomous joiner's scan pacing (§5.4.1
//!   step 5: three scans in succession, then exponential back-off to
//!   once per hour, reset by user action).
//! * [`Registry`] — the Trust Center's list of registered devices
//!   (§5.4.1.1) with the per-device key authorization state of §5.4.7
//!   and the stale-key rule of §5.4.5; [`Registry::incoming_data`]
//!   and [`Registry::may_send_secured`] give the verdicts of §5.4.6 /
//!   §5.4.7.2; [`Registry::on_device_left`] keeps the key (§5.4.3);
//!   [`Registry::overdue`] lists joiners that never ran CBKE within the
//!   20-minute recommendation (§5.4.7.1); [`Registry::backup`] yields the
//!   Table 5-10 swap-out records with hashed keys.
//! * [`link_key_hash`] — the AES-MMO hash of a Trust Center link key
//!   backed up for swap-out (§5.4.2.2.3.6, Table 5-11 vector).
//! * [`SwapOut`] — the device-side Trust Center swap-out procedure
//!   (§5.4.2.2.3.5 steps 9–16) as a state machine emitting the actions
//!   the application performs.
//! * [`partner_key`] — the Trust Center brokered partner link keys of
//!   §5.4.7.4.

use heapless::Vec;
use panweave_security::cipher::BlockCipher;
use panweave_security::mmo;
use panweave_types::time::{Duration, Instant};
use panweave_types::{ClusterId, ExtendedAddress, InstallCode, Key128, PanId};

use crate::key_establishment::Status as KeStatus;
use crate::link_key_required;

/// Longest permit-join broadcast (§5.4.1.2; 255 is forbidden).
pub const MAX_PERMIT_JOIN_SECONDS: u8 = 254;
/// Permit-join broadcast repetition interval.
pub const PERMIT_JOIN_REPEAT: Duration = Duration::from_secs(240);
/// Scans an autonomous joiner may run back to back (§5.4.1 step 5).
pub const IMMEDIATE_SCANS: u8 = 3;
/// Slowest autonomous scan rate.
pub const MAX_SCAN_INTERVAL: Duration = Duration::from_secs(3600);
/// Recommended limit for a joiner to start CBKE (§5.4.7.1).
pub const KEY_ESTABLISHMENT_DEADLINE: Duration = Duration::from_mins(20);
/// Keep-alive failures before the Trust Center counts as lost
/// (§5.4.2.2.3.4).
pub const KEEP_ALIVE_FAILURES: u8 = 3;
/// Request Key / partner link key timeout (§5.4.7.4).
pub const PARTNER_KEY_TIMEOUT: Duration = Duration::from_secs(5);

/// Permit-join broadcasting for the network coordinator (§5.4.1.2).
#[derive(Clone, Copy, Debug)]
pub struct PermitJoinSchedule {
    ends: Instant,
    next: Instant,
}

impl PermitJoinSchedule {
    /// Opens the network for `period` from `now`; the first broadcast
    /// is due immediately.
    pub const fn open(now: Instant, period: Duration) -> Self {
        PermitJoinSchedule {
            ends: now.saturating_add(period),
            next: now,
        }
    }

    /// The duration to broadcast now, when a broadcast is due (at the
    /// start, every 240 s, or whenever a device announced itself):
    /// the lesser of the remaining period and 254 s. `None` when the
    /// period is over or nothing is due yet.
    pub fn broadcast(&mut self, now: Instant, device_announced: bool) -> Option<u8> {
        if now.as_millis() >= self.ends.as_millis() {
            return None;
        }
        if !device_announced && now.as_millis() < self.next.as_millis() {
            return None;
        }
        let remaining = now
            .saturating_duration_until(self.ends)
            .as_millis()
            .div_ceil(1000);
        let seconds = u8::try_from(remaining.min(u64::from(MAX_PERMIT_JOIN_SECONDS)))
            .unwrap_or(MAX_PERMIT_JOIN_SECONDS);
        self.next = now.saturating_add(PERMIT_JOIN_REPEAT);
        Some(seconds.max(1))
    }

    /// Whether the joining period is still open.
    pub fn is_open(&self, now: Instant) -> bool {
        now.as_millis() < self.ends.as_millis()
    }

    /// When the next broadcast is due while open.
    pub fn next_broadcast(&self, now: Instant) -> Option<Instant> {
        self.is_open(now).then_some(self.next)
    }
}

/// Scan pacing of an autonomous joiner (§5.4.1 step 5).
#[derive(Clone, Copy, Debug)]
pub struct JoinScanBackoff {
    attempts: u32,
    initial: Duration,
}

impl JoinScanBackoff {
    /// Starts fresh: `initial` is the first pause after the immediate
    /// scans, doubled on every further failure up to one hour.
    pub const fn new(initial: Duration) -> Self {
        JoinScanBackoff {
            attempts: 0,
            initial,
        }
    }

    /// A scan failed; returns the pause before the next one (zero for
    /// the first three).
    pub fn failed(&mut self) -> Duration {
        self.attempts = self.attempts.saturating_add(1);
        if self.attempts < u32::from(IMMEDIATE_SCANS) {
            return Duration::from_millis(0);
        }
        let exp = self.attempts - u32::from(IMMEDIATE_SCANS);
        let ms = self.initial.as_millis().saturating_mul(1u64 << exp.min(24));
        Duration::from_millis(ms.min(MAX_SCAN_INTERVAL.as_millis()))
    }

    /// User input (button, power cycle): scanning may speed up again.
    pub fn user_triggered(&mut self) {
        self.attempts = 0;
    }

    /// Scans attempted since the last reset.
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }
}

/// Registration status of a device known to the Trust Center
/// (§5.4.1.1 item 3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Registration {
    /// Provisioned out of band; not yet on the network.
    Provisioned,
    /// Joined with the preconfigured key; CBKE not yet completed.
    Joined,
    /// Authenticated: a CBKE link key is in use.
    Authenticated,
    /// Announced as having left; the key is kept (§5.4.3).
    Left,
    /// De-registered out of band; no longer authorized.
    Deregistered,
}

/// Which Trust Center link key a device currently holds (§5.4.7.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum KeyState {
    /// Only the install-code-derived (or hashed, after a swap-out)
    /// preconfigured key: unauthorized for application data.
    Preconfigured,
    /// A CBKE-negotiated key.
    Cbke,
    /// A CBKE key the Trust Center retired (§5.4.5): commands still
    /// pass, data does not, and a fresh CBKE is due.
    Stale,
}

/// Verdict for an incoming APS data frame at the Trust Center (§5.4.6,
/// §5.4.7.2, §5.4.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Verdict {
    /// Deliver to the application.
    Accept,
    /// Discard silently, without an APS acknowledgement.
    DropNoAck,
    /// Answer with a network-key-secured Default Response FAILURE.
    DefaultResponseFailure,
    /// Discard and initiate Key Establishment with the sender.
    DropAndRenegotiate,
}

/// Why a device could not be added to the registry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RegistryError {
    /// The install code's CRC does not match.
    BadInstallCode,
    /// The registry is full.
    Full,
}

/// A registered device.
#[derive(Clone, Debug)]
pub struct Registered {
    /// Client EUI64.
    pub ieee: ExtendedAddress,
    /// Install code hash (the preconfigured key), when kept.
    pub install_code_key: Option<Key128>,
    /// Registration status.
    pub status: Registration,
    /// Link key state.
    pub key: KeyState,
    /// When the device joined (for the CBKE deadline).
    pub joined_at: Option<Instant>,
    /// When the status last changed.
    pub updated_at: Instant,
    /// Supported cryptographic suites (KeyEstablishmentSuite bitmap).
    pub suites: u16,
    /// Hash of the current CBKE Trust Center link key, for backup.
    pub key_hash: Option<Key128>,
}

/// Trust Center registration list (§5.4.1.1) applying the §5.4.7
/// key-usage policies.
#[derive(Clone, Debug, Default)]
pub struct Registry<const N: usize> {
    devices: Vec<Registered, N>,
}

/// A Table 5-10 backup record.
#[derive(Clone, Debug)]
pub struct BackupRecord {
    /// Registered device EUI64.
    pub ieee: ExtendedAddress,
    /// Hashed Trust Center link key.
    pub hashed_key: Key128,
    /// Install code hash, when kept.
    pub install_code_key: Option<Key128>,
}

impl<const N: usize> Registry<N> {
    /// An empty registry.
    pub const fn new() -> Self {
        Registry {
            devices: Vec::new(),
        }
    }

    /// Provisions a device from its install code (§5.4.1 steps 1–2): the
    /// preconfigured key is derived here so the code itself need not be
    /// kept. `Err` when the code's CRC fails or the list is full.
    pub fn provision<C: BlockCipher>(
        &mut self,
        ieee: ExtendedAddress,
        code: &InstallCode,
        now: Instant,
    ) -> Result<Key128, RegistryError> {
        if !code.crc_valid() {
            return Err(RegistryError::BadInstallCode);
        }
        let key = panweave_security::key_hierarchy::link_key_from_install_code::<C>(code);
        if let Some(d) = self.get_mut(ieee) {
            d.install_code_key = Some(key.clone());
            d.status = Registration::Provisioned;
            d.key = KeyState::Preconfigured;
            d.updated_at = now;
            return Ok(key);
        }
        self.devices
            .push(Registered {
                ieee,
                install_code_key: Some(key.clone()),
                status: Registration::Provisioned,
                key: KeyState::Preconfigured,
                joined_at: None,
                updated_at: now,
                suites: 0,
                key_hash: None,
            })
            .map_err(|_| RegistryError::Full)?;
        Ok(key)
    }

    /// Restores a device from a swap-out backup (§5.4.2.2.3.5 step 7):
    /// its hashed key is the new preconfigured, unauthorized key.
    pub fn restore(&mut self, record: &BackupRecord, now: Instant) -> Result<(), RegistryError> {
        self.devices
            .push(Registered {
                ieee: record.ieee,
                install_code_key: record.install_code_key.clone(),
                status: Registration::Provisioned,
                key: KeyState::Preconfigured,
                joined_at: None,
                updated_at: now,
                suites: 0,
                key_hash: Some(record.hashed_key.clone()),
            })
            .map_err(|_| RegistryError::Full)
    }

    /// The device, when registered.
    pub fn get(&self, ieee: ExtendedAddress) -> Option<&Registered> {
        self.devices.iter().find(|d| d.ieee == ieee)
    }

    fn get_mut(&mut self, ieee: ExtendedAddress) -> Option<&mut Registered> {
        self.devices.iter_mut().find(|d| d.ieee == ieee)
    }

    /// Every registered device.
    pub fn devices(&self) -> &[Registered] {
        &self.devices
    }

    /// Whether a join / Trust Center rejoin by `ieee` is authorized
    /// (§5.4.2.2 step 2): registered and not de-registered.
    pub fn is_authorized(&self, ieee: ExtendedAddress) -> bool {
        self.get(ieee)
            .is_some_and(|d| d.status != Registration::Deregistered)
    }

    /// The device joined (or rejoined) and received the network key.
    pub fn on_joined(&mut self, ieee: ExtendedAddress, now: Instant) {
        if let Some(d) = self.get_mut(ieee) {
            if d.key != KeyState::Cbke {
                d.status = Registration::Joined;
                d.joined_at = Some(now);
            } else {
                d.status = Registration::Authenticated;
            }
            d.updated_at = now;
        }
    }

    /// CBKE completed with the device: the new key is authorized and
    /// its hash recorded for backup (§5.4.2.2.3.5 steps 4–5).
    pub fn on_key_established<C: BlockCipher>(
        &mut self,
        ieee: ExtendedAddress,
        key: &Key128,
        suites: u16,
        now: Instant,
    ) {
        if let Some(d) = self.get_mut(ieee) {
            d.status = Registration::Authenticated;
            d.key = KeyState::Cbke;
            d.key_hash = Some(link_key_hash::<C>(key));
            d.suites = suites;
            d.joined_at = None;
            d.updated_at = now;
        }
    }

    /// The Trust Center retires the device's link key (§5.4.5).
    pub fn mark_stale(&mut self, ieee: ExtendedAddress, now: Instant) {
        if let Some(d) = self.get_mut(ieee)
            && d.key == KeyState::Cbke
        {
            d.key = KeyState::Stale;
            d.updated_at = now;
        }
    }

    /// An Update Device reported the device left: the key is kept
    /// (§5.4.3); removal happens out of band.
    pub fn on_device_left(&mut self, ieee: ExtendedAddress, now: Instant) {
        if let Some(d) = self.get_mut(ieee) {
            d.status = Registration::Left;
            d.updated_at = now;
        }
    }

    /// De-registration (§5.4.2.2.2): the key is invalidated; the caller
    /// sends the leave, the Remove Device and the unbinds.
    pub fn deregister(&mut self, ieee: ExtendedAddress, now: Instant) -> bool {
        match self.get_mut(ieee) {
            Some(d) => {
                d.status = Registration::Deregistered;
                d.key = KeyState::Preconfigured;
                d.key_hash = None;
                d.updated_at = now;
                true
            }
            None => false,
        }
    }

    /// Forgets a device entirely.
    pub fn remove(&mut self, ieee: ExtendedAddress) -> bool {
        let before = self.devices.len();
        self.devices.retain(|d| d.ieee != ieee);
        self.devices.len() != before
    }

    /// Verdict for an APS data frame from `ieee` on `cluster`
    /// (`aps_secured` says whether it carried link-key security).
    pub fn incoming_data(
        &self,
        ieee: ExtendedAddress,
        cluster: ClusterId,
        aps_secured: bool,
    ) -> Verdict {
        let Some(d) = self.get(ieee) else {
            return if aps_secured {
                Verdict::DropNoAck
            } else if link_key_required(cluster) {
                Verdict::DefaultResponseFailure
            } else {
                Verdict::Accept
            };
        };
        match (d.key, aps_secured) {
            // A frame secured with the preconfigured key is discarded
            // without an acknowledgement (§5.4.7.2).
            (KeyState::Preconfigured, true) => Verdict::DropNoAck,
            // A stale key: discard, no ACK, renegotiate (§5.4.5).
            (KeyState::Stale, true) => Verdict::DropAndRenegotiate,
            (KeyState::Cbke, true) => Verdict::Accept,
            // Unsecured: fine for clusters that need only the network
            // key, FAILURE otherwise (§5.4.6).
            (_, false) => {
                if link_key_required(cluster) {
                    Verdict::DefaultResponseFailure
                } else {
                    Verdict::Accept
                }
            }
        }
    }

    /// Whether the Trust Center may send an APS-secured data frame to
    /// the device (§5.4.7.2, §5.4.5: only with a CBKE key that is not
    /// stale).
    pub fn may_send_secured(&self, ieee: ExtendedAddress) -> bool {
        self.get(ieee).is_some_and(|d| d.key == KeyState::Cbke)
    }

    /// Joined devices that have not completed CBKE within `limit` of
    /// joining (§5.4.7.1) and may be told to leave.
    pub fn overdue(
        &self,
        now: Instant,
        limit: Duration,
    ) -> impl Iterator<Item = ExtendedAddress> + '_ {
        self.devices.iter().filter_map(move |d| {
            let joined = d.joined_at?;
            (d.status == Registration::Joined
                && d.key != KeyState::Cbke
                && now.saturating_duration_since(joined).as_millis() >= limit.as_millis())
            .then_some(d.ieee)
        })
    }

    /// The Table 5-10 records: every authenticated device with its
    /// hashed link key.
    pub fn backup(&self, out: &mut Vec<BackupRecord, N>) {
        for d in &self.devices {
            if let Some(h) = &d.key_hash
                && d.status != Registration::Deregistered
            {
                let _ = out.push(BackupRecord {
                    ieee: d.ieee,
                    hashed_key: h.clone(),
                    install_code_key: d.install_code_key.clone(),
                });
            }
        }
    }
}

/// AES-MMO hash of a Trust Center link key (§5.4.2.2.3.6).
pub fn link_key_hash<C: BlockCipher>(key: &Key128) -> Key128 {
    Key128::from_bytes(mmo::hash::<C>(key.as_bytes()))
}

/// What a joining device must do after a Key Establishment result
/// (§5.4.7.1, §5.4.7.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AfterKeyEstablishment {
    /// The new key is authorized: clusters needing APS security may be
    /// used.
    Authorized,
    /// Leave the network (UNKNOWN_ISSUER).
    Leave,
    /// Retry (any other failure).
    Retry,
}

/// Applies §5.4.7.1 to a Key Establishment outcome on the joiner.
pub const fn after_key_establishment(result: Result<(), KeStatus>) -> AfterKeyEstablishment {
    match result {
        Ok(()) => AfterKeyEstablishment::Authorized,
        Err(KeStatus::UnknownIssuer) => AfterKeyEstablishment::Leave,
        Err(_) => AfterKeyEstablishment::Retry,
    }
}

/// Partner link keys brokered by the Trust Center (§5.4.7.4).
pub mod partner_key {
    use super::{KeStatus, KeyState};

    /// Whether the Trust Center issues a partner link key to two
    /// devices: both must hold CBKE keys.
    pub const fn may_issue(initiator: KeyState, partner: KeyState) -> bool {
        matches!(initiator, KeyState::Cbke) && matches!(partner, KeyState::Cbke)
    }

    /// How a non-Trust-Center device answers an Initiate Key
    /// Establishment from another non-TC device: `None` to proceed
    /// (an existing partner key is refreshed over network security),
    /// or the Terminate status to send.
    pub const fn on_initiate_from_peer(
        shares_partner_key: bool,
        peer_cbke_enabled: bool,
    ) -> Option<KeStatus> {
        if shares_partner_key && peer_cbke_enabled {
            None
        } else {
            Some(KeStatus::NoResources)
        }
    }
}

/// A network instance found while searching for the Trust Center
/// (§5.4.2.2.3.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetworkInstance {
    /// PAN identifier.
    pub pan_id: PanId,
    /// Channel number.
    pub channel: u8,
    /// `nwkUpdateId` from the beacon.
    pub update_id: u8,
}

/// Which key the replacement Trust Center used for the Transport Key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TransportKeyUnder {
    /// The device's existing Trust Center link key.
    ExistingKey,
    /// The AES-MMO hash of it (a swapped-out Trust Center).
    HashedKey,
}

/// Actions the device performs during a swap-out search.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SwapOutAction {
    /// Save the current security material (TC link key and its
    /// authorization, network key, frame counters) before rejoining
    /// (step 11).
    BackupState,
    /// Scan for the extended PAN (step 10).
    Scan,
    /// Attempt a Trust Center rejoin to the instance, accepting a
    /// Transport Key under either the existing or the hashed key
    /// (steps 12–13).
    Rejoin(NetworkInstance),
    /// Install the hashed key as the unauthorized Trust Center link key,
    /// ignoring the frame counter check, and take `new_tc` as the Trust
    /// Center (step 13).
    AdoptHashedKey {
        /// The replacement Trust Center.
        new_tc: ExtendedAddress,
    },
    /// Run Key Establishment with the new Trust Center (step 13).
    StartKeyEstablishment,
    /// Back in business: discard the backup, announce, rediscover
    /// services (step 15).
    Resume,
    /// Leave the candidate network and go on with the next one.
    LeaveCandidate,
    /// Restore the backed-up state and continue on the previous
    /// network (steps 14, 16).
    RestorePrevious,
}

/// Device-side Trust Center swap-out procedure (§5.4.2.2.3.5).
#[derive(Clone, Debug)]
pub struct SwapOut<const N: usize> {
    current: NetworkInstance,
    stage: Stage,
    candidates: Vec<NetworkInstance, N>,
    ke_attempts: u8,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stage {
    Idle,
    Scanning,
    Rejoining(NetworkInstance),
    KeyEstablishment(NetworkInstance),
    Done,
}

impl<const N: usize> SwapOut<N> {
    /// Retries of Key Establishment before giving a candidate up
    /// (step 14 allows an immediate retry).
    pub const KEY_ESTABLISHMENT_RETRIES: u8 = 1;

    /// A procedure for a device on `current`.
    pub const fn new(current: NetworkInstance) -> Self {
        SwapOut {
            current,
            stage: Stage::Idle,
            candidates: Vec::new(),
            ke_attempts: 0,
        }
    }

    /// The Trust Center was found unreachable (three keep-alive
    /// failures): back the state up and scan.
    pub fn on_trust_center_lost(&mut self) -> [SwapOutAction; 2] {
        self.stage = Stage::Scanning;
        self.candidates.clear();
        [SwapOutAction::BackupState, SwapOutAction::Scan]
    }

    /// The scan finished with the instances of the extended PAN heard.
    /// Instances identical to the current one are filtered out in
    /// preference of a changed one (§5.4.2.2.3.1); the next action is
    /// a rejoin, or a restore when nothing new was found.
    pub fn on_scan_result(&mut self, found: &[NetworkInstance]) -> SwapOutAction {
        if self.stage != Stage::Scanning {
            return SwapOutAction::RestorePrevious;
        }
        self.candidates.clear();
        for n in found {
            if *n != self.current && !self.candidates.contains(n) {
                let _ = self.candidates.push(*n);
            }
        }
        self.next_candidate()
    }

    fn next_candidate(&mut self) -> SwapOutAction {
        if self.candidates.is_empty() {
            self.stage = Stage::Idle;
            return SwapOutAction::RestorePrevious;
        }
        let n = self.candidates.remove(0);
        self.stage = Stage::Rejoining(n);
        self.ke_attempts = 0;
        SwapOutAction::Rejoin(n)
    }

    /// The rejoin failed (no Transport Key, or one that could not be
    /// decrypted).
    pub fn on_rejoin_failed(&mut self) -> SwapOutAction {
        match self.stage {
            Stage::Rejoining(_) => self.next_candidate(),
            _ => SwapOutAction::RestorePrevious,
        }
    }

    /// The rejoin delivered a network key under `key` from `tc`.
    pub fn on_transport_key(
        &mut self,
        key: TransportKeyUnder,
        tc: ExtendedAddress,
    ) -> SwapOutAction {
        let Stage::Rejoining(n) = self.stage else {
            return SwapOutAction::RestorePrevious;
        };
        match key {
            // Step 12: the same Trust Center; nothing more to do.
            TransportKeyUnder::ExistingKey => {
                self.stage = Stage::Done;
                self.current = n;
                SwapOutAction::Resume
            }
            // Step 13: a replacement Trust Center.
            TransportKeyUnder::HashedKey => {
                self.stage = Stage::KeyEstablishment(n);
                SwapOutAction::AdoptHashedKey { new_tc: tc }
            }
        }
    }

    /// After the hashed key was adopted: start CBKE.
    pub fn on_hashed_key_adopted(&mut self) -> SwapOutAction {
        match self.stage {
            Stage::KeyEstablishment(_) => SwapOutAction::StartKeyEstablishment,
            _ => SwapOutAction::RestorePrevious,
        }
    }

    /// Key Establishment finished (steps 14–15).
    pub fn on_key_establishment(&mut self, success: bool) -> SwapOutAction {
        let Stage::KeyEstablishment(n) = self.stage else {
            return SwapOutAction::RestorePrevious;
        };
        if success {
            self.stage = Stage::Done;
            self.current = n;
            return SwapOutAction::Resume;
        }
        if self.ke_attempts < Self::KEY_ESTABLISHMENT_RETRIES {
            self.ke_attempts += 1;
            return SwapOutAction::StartKeyEstablishment;
        }
        // Leave that network; the caller then calls `after_leave`.
        SwapOutAction::LeaveCandidate
    }

    /// After leaving a failed candidate: the next one or the restore.
    pub fn after_leave(&mut self) -> SwapOutAction {
        match self.stage {
            Stage::KeyEstablishment(_) | Stage::Rejoining(_) => self.next_candidate(),
            _ => SwapOutAction::RestorePrevious,
        }
    }

    /// The network the device now considers current.
    pub const fn current(&self) -> NetworkInstance {
        self.current
    }

    /// Whether the procedure is running.
    pub const fn is_active(&self) -> bool {
        !matches!(self.stage, Stage::Idle | Stage::Done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_security::cipher::SoftwareAes;

    fn at(secs: u64) -> Instant {
        Instant::from_millis(secs * 1000)
    }

    #[test]
    fn link_key_hash_matches_table_5_11() {
        let key = Key128::from_bytes([
            0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD,
            0xCE, 0xCF,
        ]);
        assert_eq!(
            link_key_hash::<SoftwareAes>(&key).as_bytes(),
            &[
                0xA7, 0x97, 0x7E, 0x88, 0xBC, 0x0B, 0x61, 0xE8, 0x21, 0x08, 0x27, 0x10, 0x9A, 0x22,
                0x8F, 0x2D
            ]
        );
    }

    #[test]
    fn permit_join_broadcasts_are_bounded_and_repeated() {
        let mut p = PermitJoinSchedule::open(at(0), Duration::from_secs(600));
        assert_eq!(p.broadcast(at(0), false), Some(254));
        assert_eq!(p.broadcast(at(100), false), None);
        assert_eq!(p.broadcast(at(100), true), Some(254));
        assert_eq!(p.next_broadcast(at(100)), Some(at(340)));
        assert_eq!(p.broadcast(at(340), false), Some(254));
        // 20 s left: the lesser of the remainder and 254.
        assert_eq!(p.broadcast(at(580), true), Some(20));
        assert_eq!(p.broadcast(at(600), true), None);
        assert!(!p.is_open(at(600)));
        assert_eq!(p.next_broadcast(at(600)), None);
    }

    #[test]
    fn scan_backoff_grows_to_an_hour_and_resets_on_user_action() {
        let mut b = JoinScanBackoff::new(Duration::from_secs(60));
        assert_eq!(b.failed().as_millis(), 0);
        assert_eq!(b.failed().as_millis(), 0);
        assert_eq!(b.failed().as_millis(), 60_000);
        assert_eq!(b.failed().as_millis(), 120_000);
        assert_eq!(b.failed().as_millis(), 240_000);
        for _ in 0..10 {
            b.failed();
        }
        assert_eq!(b.failed().as_millis(), 3_600_000);
        b.user_triggered();
        assert_eq!(b.failed().as_millis(), 0);
    }

    #[test]
    fn registry_applies_key_usage_policies() {
        const D: ExtendedAddress = ExtendedAddress(0x1122);
        let mut r: Registry<4> = Registry::new();
        let code = InstallCode::new(&[0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x2B, 0x70]).unwrap();
        let key = r.provision::<SoftwareAes>(D, &code, at(0)).unwrap();
        assert_eq!(
            key.as_bytes(),
            &[
                0xCD, 0x4F, 0xA0, 0x64, 0x77, 0x3F, 0x46, 0x94, 0x1E, 0xC9, 0x86, 0xC0, 0x99, 0x63,
                0xD1, 0xA8
            ]
        );
        let mut bad = [0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x2B, 0x71];
        bad[7] = 0x71;
        assert!(
            r.provision::<SoftwareAes>(ExtendedAddress(9), &InstallCode::new(&bad).unwrap(), at(0))
                .is_err()
        );
        assert!(r.is_authorized(D) && !r.is_authorized(ExtendedAddress(9)));
        r.on_joined(D, at(10));
        // Preconfigured key: secured data dropped without ACK, unsecured
        // data fine for network-key clusters, FAILURE for the rest.
        assert_eq!(
            r.incoming_data(D, crate::cluster::PRICE, true),
            Verdict::DropNoAck
        );
        assert_eq!(
            r.incoming_data(D, crate::cluster::BASIC, false),
            Verdict::Accept
        );
        assert_eq!(
            r.incoming_data(D, crate::cluster::PRICE, false),
            Verdict::DefaultResponseFailure
        );
        assert!(!r.may_send_secured(D));
        // Overdue after 20 minutes without CBKE.
        assert_eq!(
            r.overdue(at(10 + 19 * 60), KEY_ESTABLISHMENT_DEADLINE)
                .count(),
            0
        );
        assert_eq!(
            r.overdue(at(10 + 20 * 60), KEY_ESTABLISHMENT_DEADLINE)
                .count(),
            1
        );
        r.on_key_established::<SoftwareAes>(D, &Key128::from_bytes([1; 16]), 0x0003, at(100));
        assert_eq!(
            r.incoming_data(D, crate::cluster::PRICE, true),
            Verdict::Accept
        );
        assert!(r.may_send_secured(D));
        assert_eq!(r.overdue(at(10_000), KEY_ESTABLISHMENT_DEADLINE).count(), 0);
        assert_eq!(r.get(D).unwrap().status, Registration::Authenticated);
        // Stale key: data dropped and renegotiated, not sent to.
        r.mark_stale(D, at(200));
        assert_eq!(
            r.incoming_data(D, crate::cluster::PRICE, true),
            Verdict::DropAndRenegotiate
        );
        assert!(!r.may_send_secured(D));
        r.on_key_established::<SoftwareAes>(D, &Key128::from_bytes([2; 16]), 0x0003, at(300));
        assert!(r.may_send_secured(D));
        // A leave keeps the key; the backup carries the hash.
        r.on_device_left(D, at(400));
        assert_eq!(r.get(D).unwrap().key, KeyState::Cbke);
        let mut out = Vec::new();
        r.backup(&mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].hashed_key,
            link_key_hash::<SoftwareAes>(&Key128::from_bytes([2; 16]))
        );
        // Unknown devices: secured frames dropped.
        assert_eq!(
            r.incoming_data(ExtendedAddress(7), crate::cluster::PRICE, true),
            Verdict::DropNoAck
        );
        // De-registration invalidates the key.
        assert!(r.deregister(D, at(500)));
        assert!(!r.is_authorized(D));
        let mut out = Vec::new();
        r.backup(&mut out);
        assert!(out.is_empty());
        // Restore from backup on a replacement Trust Center.
        let mut fresh: Registry<4> = Registry::new();
        fresh
            .restore(
                &BackupRecord {
                    ieee: D,
                    hashed_key: Key128::from_bytes([3; 16]),
                    install_code_key: None,
                },
                at(0),
            )
            .unwrap();
        assert_eq!(fresh.get(D).unwrap().key, KeyState::Preconfigured);
        assert!(fresh.is_authorized(D));
        assert_eq!(
            after_key_establishment(Ok(())),
            AfterKeyEstablishment::Authorized
        );
        assert_eq!(
            after_key_establishment(Err(KeStatus::UnknownIssuer)),
            AfterKeyEstablishment::Leave
        );
        assert_eq!(
            after_key_establishment(Err(KeStatus::NoResources)),
            AfterKeyEstablishment::Retry
        );
        assert!(partner_key::may_issue(KeyState::Cbke, KeyState::Cbke));
        assert!(!partner_key::may_issue(
            KeyState::Cbke,
            KeyState::Preconfigured
        ));
        assert_eq!(
            partner_key::on_initiate_from_peer(false, true),
            Some(KeStatus::NoResources)
        );
        assert_eq!(partner_key::on_initiate_from_peer(true, true), None);
    }

    #[test]
    fn swap_out_procedure_walks_the_candidates() {
        let current = NetworkInstance {
            pan_id: PanId(0x1234),
            channel: 15,
            update_id: 0,
        };
        let newer = NetworkInstance {
            pan_id: PanId(0x5678),
            channel: 20,
            update_id: 0,
        };
        let other = NetworkInstance {
            pan_id: PanId(0x9abc),
            channel: 25,
            update_id: 1,
        };
        let mut s: SwapOut<4> = SwapOut::new(current);
        assert!(!s.is_active());
        assert_eq!(
            s.on_trust_center_lost(),
            [SwapOutAction::BackupState, SwapOutAction::Scan]
        );
        // Only the current instance found: restore.
        assert_eq!(s.on_scan_result(&[current]), SwapOutAction::RestorePrevious);
        assert!(!s.is_active());
        // Two new instances: the first fails to rejoin, the second is a
        // swapped-out TC with the hashed key.
        s.on_trust_center_lost();
        assert_eq!(
            s.on_scan_result(&[current, newer, other, newer]),
            SwapOutAction::Rejoin(newer)
        );
        assert_eq!(s.on_rejoin_failed(), SwapOutAction::Rejoin(other));
        let tc = ExtendedAddress(0xdead);
        assert_eq!(
            s.on_transport_key(TransportKeyUnder::HashedKey, tc),
            SwapOutAction::AdoptHashedKey { new_tc: tc }
        );
        assert_eq!(
            s.on_hashed_key_adopted(),
            SwapOutAction::StartKeyEstablishment
        );
        // One retry, then leave and, with no candidates left, restore.
        assert_eq!(
            s.on_key_establishment(false),
            SwapOutAction::StartKeyEstablishment
        );
        assert_eq!(s.on_key_establishment(false), SwapOutAction::LeaveCandidate);
        assert_eq!(s.after_leave(), SwapOutAction::RestorePrevious);
        assert_eq!(s.current(), current);
        // Success path.
        s.on_trust_center_lost();
        assert_eq!(s.on_scan_result(&[other]), SwapOutAction::Rejoin(other));
        s.on_transport_key(TransportKeyUnder::HashedKey, tc);
        s.on_hashed_key_adopted();
        assert_eq!(s.on_key_establishment(true), SwapOutAction::Resume);
        assert_eq!(s.current(), other);
        assert!(!s.is_active());
        // The same TC on new parameters: resume at once.
        s.on_trust_center_lost();
        assert_eq!(s.on_scan_result(&[newer]), SwapOutAction::Rejoin(newer));
        assert_eq!(
            s.on_transport_key(TransportKeyUnder::ExistingKey, tc),
            SwapOutAction::Resume
        );
        assert_eq!(s.current(), newer);
    }
}
