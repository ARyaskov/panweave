//! The Smart Energy Trust Center (SE 1.4a §5.4.1, §5.4.2, §5.4.7, §5.5.5.5)
//! over a [`Stack`]: devices provisioned with install codes get their
//! preconfigured link keys installed, the network is opened on the
//! §5.4.1.2 broadcast rule (never 255, at most 254 s, repeated every
//! 240 s and on every device announce), the registry follows the joins,
//! Key Establishment results and leaves, devices that never establish a
//! key are removed after the §5.5.5.5 grace period, and the Table 5-10
//! backup is available at any time.

use heapless::Vec;
use panweave_runtime::{Stack, StackEvent};
use panweave_security::cipher::BlockCipher;
use panweave_security::material::{InitialJoinAuthentication, LinkKeyEntry, LinkKeyKind};
use panweave_smart_energy::commissioning::TRUST_CENTER_REMOVAL_AFTER;
use panweave_smart_energy::security::{
    BackupRecord, PermitJoinSchedule, Registered, Registration, Registry, RegistryError,
};
use panweave_storage::Storage;
use panweave_types::time::{Duration, Instant};
use panweave_types::{CryptoRng, ExtendedAddress, InstallCode, Key128};

use crate::cbke::CbkeOutcome;

/// What the driver reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SeTrustCenterEvent {
    /// A provisioned device joined with the network key; Key
    /// Establishment is expected within the grace period.
    Joined(ExtendedAddress),
    /// A device completed Key Establishment.
    Authenticated(ExtendedAddress),
    /// A device left.
    Left(ExtendedAddress),
    /// A device that never completed Key Establishment was removed.
    Removed(ExtendedAddress),
    /// Permit joining was (re)broadcast for `seconds`.
    PermitJoin(u8),
}

/// The driver, tracking up to `N` devices.
pub struct SeTrustCenter<const N: usize = 16> {
    /// The device registry.
    pub registry: Registry<N>,
    /// Grace period after a join without Key Establishment before the
    /// device is removed (§5.5.5.5 item 6).
    pub removal_after: Duration,
    permit: Option<PermitJoinSchedule>,
}

impl<const N: usize> Default for SeTrustCenter<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> SeTrustCenter<N> {
    /// An empty registry, the network closed.
    pub const fn new() -> Self {
        SeTrustCenter {
            registry: Registry::new(),
            removal_after: TRUST_CENTER_REMOVAL_AFTER,
            permit: None,
        }
    }

    /// Registers `ieee` with its install code (§5.4.1.1): the derived
    /// link key is installed as the device's provisional unique key.
    pub fn provision<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        ieee: ExtendedAddress,
        code: &InstallCode,
    ) -> Result<Key128, RegistryError> {
        let key = self.registry.provision::<C>(ieee, code, stack.now())?;
        let mut entry = LinkKeyEntry::provisional(ieee, key.clone(), LinkKeyKind::Unique);
        entry.initial_join_authentication = InitialJoinAuthentication::InstallCodeKey;
        let _ = stack.aps.install_link_key(entry);
        stack.flush();
        Ok(key)
    }

    /// Opens the network for `period` (§5.4.1.2): the first permit-join
    /// broadcast goes out now, the following ones every 240 s and on
    /// every device announce, each for at most 254 s.
    pub fn permit_join<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        period: Duration,
    ) -> Option<SeTrustCenterEvent> {
        let now = stack.now();
        let mut schedule = PermitJoinSchedule::open(now, period);
        let seconds = schedule.broadcast(now, false);
        self.permit = Some(schedule);
        Self::broadcast(stack, seconds)
    }

    /// Closes the network.
    pub fn close<C: BlockCipher, R: CryptoRng, S: Storage>(&mut self, stack: &mut Stack<C, R, S>) {
        self.permit = None;
        let _ = stack.permit_join_network(0);
        stack.flush();
    }

    fn broadcast<C: BlockCipher, R: CryptoRng, S: Storage>(
        stack: &mut Stack<C, R, S>,
        seconds: Option<u8>,
    ) -> Option<SeTrustCenterEvent> {
        let s = seconds?;
        stack.permit_join_network(s).ok()?;
        stack.flush();
        Some(SeTrustCenterEvent::PermitJoin(s))
    }

    /// The Trust Center's own Key Establishment driver finished with
    /// `partner`: an established key authorizes the device and records
    /// its hash for the backup.
    pub fn on_key_establishment<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &Stack<C, R, S>,
        outcome: &CbkeOutcome,
        suites: u16,
    ) -> Option<SeTrustCenterEvent> {
        let CbkeOutcome::Established { partner } = outcome else {
            return None;
        };
        let key = stack.aps.security.entry(*partner)?.key.clone();
        self.registry
            .on_key_established::<C>(*partner, &key, suites, stack.now());
        Some(SeTrustCenterEvent::Authenticated(*partner))
    }

    /// Retires a device's link key (§5.4.5): its secured frames are
    /// dropped until it establishes a new one.
    pub fn retire_key<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &Stack<C, R, S>,
        ieee: ExtendedAddress,
    ) {
        self.registry.mark_stale(ieee, stack.now());
    }

    /// De-registers a device (§5.4.2.2.2): it is told to leave and its
    /// key invalidated.
    pub fn deregister<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        ieee: ExtendedAddress,
        parent: Option<ExtendedAddress>,
    ) -> bool {
        if !self.registry.deregister(ieee, stack.now()) {
            return false;
        }
        let _ = stack.remove_device(ieee, parent);
        true
    }

    /// The registered devices.
    pub fn devices(&self) -> &[Registered] {
        self.registry.devices()
    }

    /// The Table 5-10 backup records.
    pub fn backup(&self, out: &mut Vec<BackupRecord, N>) {
        self.registry.backup(out);
    }

    /// Feeds a stack event.
    pub fn on_event<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        event: &StackEvent,
    ) -> Option<SeTrustCenterEvent> {
        let now = stack.now();
        match event {
            StackEvent::DeviceAuthorized { ieee, .. } => {
                self.registry.get(*ieee)?;
                self.registry.on_joined(*ieee, now);
                Some(SeTrustCenterEvent::Joined(*ieee))
            }
            StackEvent::DeviceAnnounce { .. } => {
                let seconds = self.permit.as_mut()?.broadcast(now, true);
                Self::broadcast(stack, seconds)
            }
            StackEvent::DeviceLeft { ieee, .. } => {
                self.registry.get(*ieee)?;
                self.registry.on_device_left(*ieee, now);
                Some(SeTrustCenterEvent::Left(*ieee))
            }
            _ => None,
        }
    }

    /// Runs the permit-join schedule and removes devices that never
    /// completed Key Establishment.
    pub fn poll<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        now: Instant,
    ) -> Option<SeTrustCenterEvent> {
        if let Some(p) = self.permit.as_mut() {
            if !p.is_open(now) {
                self.permit = None;
            } else if let Some(s) = p.broadcast(now, false) {
                return Self::broadcast(stack, Some(s));
            }
        }
        let overdue: Vec<ExtendedAddress, 4> = self
            .registry
            .overdue(now, self.removal_after)
            .take(4)
            .collect();
        for ieee in overdue {
            if stack.remove_device(ieee, None).is_ok()
                || self
                    .registry
                    .get(ieee)
                    .is_some_and(|d| d.status == Registration::Joined)
            {
                self.registry.on_device_left(ieee, now);
                return Some(SeTrustCenterEvent::Removed(ieee));
            }
        }
        None
    }

    /// The next instant [`Self::poll`] has something to do.
    pub fn deadline(&self, now: Instant) -> Option<Instant> {
        let permit = self.permit.and_then(|p| p.next_broadcast(now));
        let overdue = self
            .registry
            .devices()
            .iter()
            .filter(|d| d.status == Registration::Joined)
            .filter_map(|d| d.joined_at)
            .map(|j| j + self.removal_after)
            .min_by_key(|t| t.as_millis());
        match (permit, overdue) {
            (Some(a), Some(b)) => Some(if a.as_millis() < b.as_millis() { a } else { b }),
            (a, None) => a,
            (None, b) => b,
        }
    }
}
