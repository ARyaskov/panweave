//! Persistent stack state (R23.2 §2.2.8.1 APS persistent data, §3.6.1
//! NIB items retained across resets, §4.3.4 / §4.4.12 security material)
//! serialized into [`Storage`] records, and the warm-start restore.
//!
//! Layout is versioned; every record starts with a format octet so that
//! a later layout can migrate or reject old data instead of misreading
//! it. Keys are stored as raw octets: the storage backend is expected to
//! be the device's protected non-volatile memory (`docs/storage-model.md`).

use heapless::Vec;
use panweave_aps::layer::DeviceState;
use panweave_aps::tables::{BindingDestination, BindingEntry};
use panweave_codec::{Reader, Writer};
use panweave_nwk::neighbor::{NeighborEntry, Relationship};
use panweave_security::cipher::BlockCipher;
use panweave_security::material::{
    InitialJoinAuthentication, KeyNegotiationState, LinkKeyEntry, LinkKeyKind, PostJoinKeyUpdate,
};
use panweave_storage::{Key, Kind, Storage, StorageError};
use panweave_types::{
    Channel, ChannelMask, ChannelPage, ClusterId, CryptoRng, Endpoint, ExtendedAddress,
    GroupAddress, Key128, KeyAttributes, KeySequenceNumber, LogicalDeviceType, NwkStatus, PanId,
    ShortAddress,
};

use panweave_zcl::Role;

use panweave_types::capacity::{Capacity, VecOf};

use crate::profile::StackProfile;
use crate::stack::{Phase, Stack};

/// Format version of the NIB record.
const NIB_FORMAT: u8 = 1;
/// Format version of the network keys record.
const KEYS_FORMAT: u8 = 1;
/// Format version of link key records.
const LINK_KEY_FORMAT: u8 = 2;
const LINK_KEY_BYTES: usize = 64;
/// V1 cannot prove whether a verified key came from a stronger negotiation.
const LEGACY_NEGOTIATION_UNKNOWN: u8 = 0xff;
/// Format version of the binding record.
const BINDINGS_FORMAT: u8 = 1;
/// Format version of the group record.
const GROUPS_FORMAT: u8 = 1;
/// Format version of the AIB record.
const AIB_FORMAT: u8 = 3;
/// Format version of the children record.
const CHILDREN_FORMAT: u8 = 1;
const PENDING_LINK_KEYS: Key = Key::with_id(Kind::Aib, 1);

#[derive(Default)]
pub(crate) struct PersistenceState {
    dirty: u16,
    startup: [u8; 32],
    erase_pending: bool,
    pub(crate) retry_at: Option<panweave_types::Instant>,
    errors: [Option<StorageError>; 16],
}

fn key_partners<K: Capacity>(bytes: &[u8], aib: bool) -> Result<VecOf<u64, K>, StorageError> {
    let mut r = Reader::new(bytes);
    let mut partners = K::vec();
    let parsed = (|| -> Result<(), panweave_codec::CodecError> {
        let format = r.u8()?;
        if (aib && !matches!(format, 1..=AIB_FORMAT)) || (!aib && format != 1) {
            return Err(panweave_codec::CodecError::Unsupported {
                what: "link-key index",
            });
        }
        if aib {
            let _ = r.u64_le()?;
        }
        for _ in 0..r.u8()? {
            partners
                .push(r.u64_le()?)
                .map_err(|_| panweave_codec::CodecError::LengthMismatch {
                    field: "link-key index",
                })?;
        }
        if !aib && r.remaining() != 0 {
            return Err(panweave_codec::CodecError::LengthMismatch {
                field: "pending link keys",
            });
        }
        Ok(())
    })();
    parsed.map_err(|_| StorageError::Corrupt)?;
    Ok(partners)
}

fn boolean(r: &mut Reader<'_>, field: &'static str) -> Result<bool, panweave_codec::CodecError> {
    match r.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(panweave_codec::CodecError::InvalidField {
            field,
            value: u32::from(value),
        }),
    }
}

fn decode_link_key(
    bytes: &[u8],
    expected: ExtendedAddress,
) -> Result<LinkKeyEntry, panweave_codec::CodecError> {
    use panweave_codec::CodecError;
    let invalid = |field, value| CodecError::InvalidField {
        field,
        value: u32::from(value),
    };
    let mut r = Reader::new(bytes);
    let format = r.u8()?;
    if !matches!(format, 1..=LINK_KEY_FORMAT) {
        return Err(CodecError::Unsupported {
            what: "link key format",
        });
    }
    let partner = ExtendedAddress(r.u64_le()?);
    if partner != expected {
        return Err(CodecError::InvalidField {
            field: "link key partner",
            value: 0,
        });
    }
    let key = Key128::from_bytes(r.array::<16>()?);
    let kind = if boolean(&mut r, "link key kind")? {
        LinkKeyKind::Global
    } else {
        LinkKeyKind::Unique
    };
    let mut e = LinkKeyEntry::provisional(partner, key, kind);
    e.verified_frame_counter = false;
    e.attributes = KeyAttributes::from_raw(r.u8()?);
    e.incoming = r.u32_le()?;
    e.outgoing = panweave_security::frame_counter::OutgoingCounter::restore(r.u32_le()?);
    e.frame_counter_sync = boolean(&mut r, "frame counter sync")?;
    if format == LINK_KEY_FORMAT {
        e.initial_join_authentication = match r.u8()? {
            0 => InitialJoinAuthentication::None,
            1 => InitialJoinAuthentication::InstallCodeKey,
            2 => InitialJoinAuthentication::AnonymousKeyNegotiation,
            3 => InitialJoinAuthentication::KeyNegotiationWithAuthentication,
            value => return Err(invalid("initial join authentication", value)),
        };
        e.negotiation_state = match r.u8()? {
            0 => KeyNegotiationState::None,
            1 => KeyNegotiationState::Started,
            2 => KeyNegotiationState::Complete,
            value => return Err(invalid("key negotiation state", value)),
        };
        e.negotiation_method = r.u8()?;
        e.post_join_key_update = match r.u8()? {
            0 => PostJoinKeyUpdate::NotUpdated,
            1 => PostJoinKeyUpdate::KeyRequest,
            2 => PostJoinKeyUpdate::UnauthenticatedNegotiation,
            3 => PostJoinKeyUpdate::AuthenticatedNegotiation,
            4 => PostJoinKeyUpdate::CertificateBased,
            value => return Err(invalid("post-join key update", value)),
        };
        e.passphrase_update_allowed = boolean(&mut r, "passphrase update allowed")?;
        if boolean(&mut r, "passphrase present")? {
            e.passphrase = Some(Key128::from_bytes(r.array::<16>()?));
        }
    } else {
        // Old records omitted the token and its lock. Do not reissue a token
        // or permit downgrading a possibly negotiated established key.
        e.passphrase_update_allowed = false;
        if e.kind == LinkKeyKind::Unique && e.attributes != KeyAttributes::ProvisionalKey {
            e.negotiation_method = LEGACY_NEGOTIATION_UNKNOWN;
        }
    }
    if r.remaining() != 0 {
        return Err(CodecError::LengthMismatch {
            field: "link key record",
        });
    }
    Ok(e)
}

/// Outcome of [`Stack::restore`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Restored {
    /// No usable network data was found: the device is factory new, or
    /// what was stored cannot be used ([`Stack::restore_detail`] tells
    /// which — a caller that forms a network must check it).
    FactoryNew,
    /// Network parameters and keys were restored; the runtime should
    /// rejoin (end devices) or resume (routers / coordinator).
    OnNetwork,
}

/// Why [`Stack::restore`] returned what it did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RestoreDetail {
    /// `restore` has not run (or failed with a storage error).
    NotRun,
    /// A network was restored.
    Restored,
    /// Neither the NIB nor the network keys are stored: factory new.
    Empty,
    /// Only one of the NIB and the network-key records is stored (an
    /// interrupted formation, factory reset or write).
    Incomplete,
    /// A record is in a format this firmware does not know (written by a
    /// newer one). It is left untouched.
    UnknownFormat,
    /// A record could not be decoded, or holds no active network key.
    Malformed,
}

impl RestoreDetail {
    /// Whether the storage genuinely holds no network: the only case in
    /// which forming a new one cannot replace an existing one.
    pub const fn is_empty(self) -> bool {
        matches!(self, RestoreDetail::Empty)
    }

    /// A stable code (diagnostics).
    pub const fn code(self) -> u8 {
        match self {
            RestoreDetail::NotRun => 0,
            RestoreDetail::Restored => 1,
            RestoreDetail::Empty => 2,
            RestoreDetail::Incomplete => 3,
            RestoreDetail::UnknownFormat => 4,
            RestoreDetail::Malformed => 5,
        }
    }

    /// A short name.
    pub const fn name(self) -> &'static str {
        match self {
            RestoreDetail::NotRun => "not-run",
            RestoreDetail::Restored => "restored",
            RestoreDetail::Empty => "empty",
            RestoreDetail::Incomplete => "incomplete",
            RestoreDetail::UnknownFormat => "unknown-format",
            RestoreDetail::Malformed => "malformed",
        }
    }
}

fn record<S: Storage, K: Capacity>(
    storage: &mut S,
    key: Key,
) -> Result<Option<VecOf<u8, K>>, StorageError> {
    // Loaded straight into the returned buffer: one record-sized buffer
    // on the stack, not two.
    let mut buf = K::vec();
    let _ = buf.resize_default(K::N);
    let Some(n) = storage.load(key, &mut buf)? else {
        return Ok(None);
    };
    buf.truncate(n);
    Ok(Some(buf))
}

pub(crate) fn store_if_changed<S: Storage>(
    storage: &mut S,
    key: Key,
    bytes: &[u8],
    previous: &mut [u8],
) -> Result<(), StorageError> {
    if let Some(n) = storage.load(key, previous)?
        && previous.get(..n) == Some(bytes)
    {
        return Ok(());
    }
    storage.store(key, bytes)
}

impl<
    C: BlockCipher,
    R: CryptoRng,
    S: Storage,
    P: StackProfile,
    const E: usize,
    const CL: usize,
    const A: usize,
> Stack<C, R, S, P, E, CL, A>
{
    /// Whether a failed stack-state save is waiting for its timed retry.
    /// Green Power has its own durable effects gate.
    pub fn persistence_pending(&self) -> bool {
        self.persistence.dirty != 0 || self.persistence.erase_pending
    }

    pub(crate) fn persistence_reset_pending(&self) -> bool {
        self.persistence.erase_pending
    }

    /// Last write error for a record kind, cleared when that write recovers.
    pub fn persistence_error(&self, kind: Kind) -> Option<StorageError> {
        self.persistence.errors[usize::from(kind.code())]
    }

    pub(crate) fn note_persistence_result(
        &mut self,
        kind: Kind,
        result: Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        let slot = usize::from(kind.code());
        if let Err(error) = result {
            if self.persistence.errors[slot] != Some(error) {
                self.push_event(crate::StackEvent::PersistenceFailed { kind, error });
            }
            self.persistence.errors[slot] = Some(error);
        } else {
            self.persistence.errors[slot] = None;
        }
        result
    }

    fn finish_persistence(
        &mut self,
        kind: Kind,
        result: Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        let bit = 1u16 << kind.code();
        if result.is_err() {
            self.persistence.dirty |= bit;
            self.persistence
                .retry_at
                .get_or_insert(self.now + panweave_types::Duration::from_millis(100));
        } else {
            self.persistence.dirty &= !bit;
            if self.persistence.dirty == 0 && !self.persistence.erase_pending {
                self.persistence.retry_at = None;
            }
        }
        self.note_persistence_result(kind, result)
    }

    pub(crate) fn poll_persistence(&mut self) {
        if self
            .persistence
            .retry_at
            .is_none_or(|at| !self.now.has_reached(at))
        {
            return;
        }
        self.persistence.retry_at = None;
        if self.persistence.erase_pending {
            let _ = self.erase_persisted();
            return;
        }
        let dirty = self.persistence.dirty;
        for kind in [
            Kind::Nib,
            Kind::Children,
            Kind::NetworkKeys,
            Kind::LinkKey,
            Kind::Bindings,
            Kind::Groups,
            Kind::StartupSets,
        ] {
            if dirty & (1u16 << kind.code()) == 0 {
                continue;
            }
            // Each public save retains its own error and schedules the next
            // bounded retry; no failed write is requeued into the pump loop.
            let _ = match kind {
                Kind::Nib => self.persist_nib(),
                Kind::Children => self.persist_children(),
                Kind::NetworkKeys => self.persist_network_keys(),
                Kind::LinkKey => self.persist_link_keys(),
                Kind::Bindings => self.persist_bindings(),
                Kind::Groups => self.persist_groups(),
                Kind::StartupSets => {
                    for endpoint in 0..=u8::MAX {
                        if self.persistence.startup[usize::from(endpoint / 8)]
                            & (1 << (endpoint % 8))
                            != 0
                        {
                            let _ = self.persist_startup_sets(Endpoint(endpoint));
                        }
                    }
                    Ok(())
                }
                _ => Ok(()),
            };
        }
    }

    pub(crate) fn ensure_link_key_indexed(
        &mut self,
        partner: ExtendedAddress,
    ) -> Result<(), StorageError> {
        if self.aps.security.entry(partner).is_none() {
            return Err(StorageError::Corrupt);
        }
        if let Some(bytes) = record::<S, P::Record>(&mut self.storage, Key::single(Kind::Aib))?
            && key_partners::<<P::Aps as panweave_aps::layer::ApsDims>::Keys>(&bytes, true)?
                .contains(&partner.0)
        {
            return Ok(());
        }
        self.persist_link_keys()
    }

    /// Stores the saved startup sets of the Commissioning server on
    /// `endpoint` (ZCL8 §13.2.2.3.2: non-volatile).
    pub fn persist_startup_sets(&mut self, endpoint: Endpoint) -> Result<(), StorageError> {
        let result = self.persist_startup_sets_inner(endpoint);
        let slot = usize::from(endpoint.0 / 8);
        let bit = 1 << (endpoint.0 % 8);
        if result.is_err() {
            self.persistence.startup[slot] |= bit;
        } else {
            self.persistence.startup[slot] &= !bit;
            if self.persistence.startup.iter().any(|bits| *bits != 0) {
                return result;
            }
        }
        self.finish_persistence(Kind::StartupSets, result)
    }

    fn persist_startup_sets_inner(&mut self, endpoint: Endpoint) -> Result<(), StorageError> {
        use panweave_zcl::clusters::commissioning;
        let Some(state) = self
            .zcl
            .cluster(endpoint, commissioning::ID, Role::Server)
            .and_then(commissioning::saved_state)
        else {
            return Ok(());
        };
        let mut buf = [0u8; commissioning::State::ENCODED_LEN];
        let n = state.encode(&mut buf).unwrap_or(0);
        self.storage.store(
            Key::with_id(Kind::StartupSets, u64::from(endpoint.0)),
            buf.get(..n).unwrap_or(&[]),
        )
    }

    /// Restores the saved startup sets of every Commissioning server
    /// (part of [`Self::restore`]).
    pub fn restore_startup_sets(&mut self) -> Result<(), StorageError> {
        use panweave_zcl::clusters::commissioning;
        let endpoints: Vec<Endpoint, 8> = self
            .zcl
            .endpoints()
            .iter()
            .filter(|e| e.cluster(commissioning::ID, Role::Server).is_some())
            .map(|e| e.endpoint)
            .collect();
        for endpoint in endpoints {
            let mut buf = [0u8; commissioning::State::ENCODED_LEN];
            let Some(n) = self.storage.load(
                Key::with_id(Kind::StartupSets, u64::from(endpoint.0)),
                &mut buf,
            )?
            else {
                continue;
            };
            let saved = commissioning::State::decode(buf.get(..n).unwrap_or(&[]));
            if let Some(c) = self
                .zcl
                .cluster_mut(endpoint, commissioning::ID, Role::Server)
            {
                commissioning::restore_saved(c, saved);
            }
        }
        Ok(())
    }

    /// Persists the NIB items needed to resume the network.
    pub fn persist_nib(&mut self) -> Result<(), StorageError> {
        let result = self.persist_nib_inner();
        self.finish_persistence(Kind::Nib, result)
    }

    fn persist_nib_inner(&mut self) -> Result<(), StorageError> {
        let nib = &self.nwk.nib;
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        let r = (|| -> Result<(), panweave_codec::CodecError> {
            w.u8(NIB_FORMAT)?;
            w.u16_le(nib.pan_id.0)?;
            w.u64_le(nib.extended_pan_id.0)?;
            w.u16_le(nib.network_address.0)?;
            w.u8(nib.channel_page.raw())?;
            w.u8(nib.channel.raw())?;
            w.u8(nib.update_id)?;
            w.u8(nib.depth)?;
            w.u16_le(nib.parent_address.0)?;
            w.u64_le(nib.parent_ieee.0)?;
            w.u16_le(nib.manager_addr.0)?;
            w.u8(match nib.device_type {
                LogicalDeviceType::Coordinator => 0,
                LogicalDeviceType::Router => 1,
                LogicalDeviceType::EndDevice => 2,
            })?;
            w.u8(u8::from(nib.router_started))?;
            w.u8(u8::from(self.aps.aib.is_distributed()))?;
            w.u8(nib.parent_information.0)?;
            w.u8(nib.stack_profile)?;
            Ok(())
        })();
        if r.is_err() {
            return Err(StorageError::Full);
        }
        let n = w.position();
        self.storage.store(Key::single(Kind::Nib), &buf[..n])
    }

    /// Persists the end-device children (R23.2 §3.6.9: IEEE and network
    /// address, End Device Configuration and Device Timeout of every
    /// end-device neighbor).
    pub fn persist_children(&mut self) -> Result<(), StorageError> {
        let result = self.persist_children_inner();
        self.finish_persistence(Kind::Children, result)
    }

    fn persist_children_inner(&mut self) -> Result<(), StorageError> {
        let mut buf = P::Record::vec();
        let _ = buf.resize_default(<P::Record as Capacity>::N);
        let mut w = Writer::new(&mut buf);
        let _ = w.u8(CHILDREN_FORMAT);
        for e in self.nwk.neighbors.end_device_children() {
            let r = (|| -> Result<(), panweave_codec::CodecError> {
                w.u64_le(e.extended.0)?;
                w.u16_le(e.short.0)?;
                w.u8(e.end_device_configuration)?;
                w.u32_le(e.device_timeout_secs)?;
                w.u8(u8::from(e.rx_on_when_idle))
            })();
            if r.is_err() {
                return Err(StorageError::Full);
            }
        }
        let n = w.position();
        self.storage.store(Key::single(Kind::Children), &buf[..n])
    }

    /// Persists the network keys and the active sequence number.
    pub fn persist_network_keys(&mut self) -> Result<(), StorageError> {
        let result = self.persist_network_keys_inner();
        self.finish_persistence(Kind::NetworkKeys, result)
    }

    fn persist_network_keys_inner(&mut self) -> Result<(), StorageError> {
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        let keys = &self.nwk.security.keys;
        let r = (|| -> Result<(), panweave_codec::CodecError> {
            w.u8(KEYS_FORMAT)?;
            w.u8(keys.active_sequence().map_or(0xff, |s| s.0))?;
            let n = keys.iter().count();
            #[allow(clippy::cast_possible_truncation)]
            w.u8(n as u8)?;
            for slot in keys.iter() {
                w.u8(slot.sequence.0)?;
                w.bytes(slot.key.as_bytes())?;
            }
            Ok(())
        })();
        if r.is_err() {
            return Err(StorageError::Full);
        }
        let n = w.position();
        self.storage
            .store(Key::single(Kind::NetworkKeys), &buf[..n])
    }

    /// Persists every link-key entry (one record per partner) and the
    /// scalar AIB attributes.
    pub fn persist_link_keys(&mut self) -> Result<(), StorageError> {
        let result = self.persist_link_keys_inner();
        self.finish_persistence(Kind::LinkKey, result)
    }

    fn persist_link_keys_inner(&mut self) -> Result<(), StorageError> {
        let previous = record::<S, P::Record>(&mut self.storage, Key::single(Kind::Aib))?;
        let partners = match &previous {
            Some(bytes) => {
                key_partners::<<P::Aps as panweave_aps::layer::ApsDims>::Keys>(bytes, true)?
            }
            None => <P::Aps as panweave_aps::layer::ApsDims>::Keys::vec(),
        };
        let pending = record::<S, P::Record>(&mut self.storage, PENDING_LINK_KEYS)?;
        if let Some(bytes) = &pending {
            for partner in
                key_partners::<<P::Aps as panweave_aps::layer::ApsDims>::Keys>(bytes, false)?
                    .iter()
                    .copied()
            {
                if !partners.contains(&partner) {
                    self.storage.erase(Key::with_id(Kind::LinkKey, partner))?;
                    self.storage
                        .erase(Key::with_id(Kind::ApsFrameCounter, partner))?;
                }
            }
        }
        let mut additions: VecOf<u64, <P::Aps as panweave_aps::layer::ApsDims>::Keys> =
            <P::Aps as panweave_aps::layer::ApsDims>::Keys::vec();
        for e in self.aps.security.keys().iter() {
            if !partners.contains(&e.partner.0) {
                additions
                    .push(e.partner.0)
                    .map_err(|_| StorageError::Full)?;
            }
        }
        // Journal new identifiers before creating records that the committed
        // AIB does not yet own. Recovery can reclaim every interrupted addition.
        if !additions.is_empty() {
            let mut buf = P::Record::vec();
            buf.resize_default(P::Record::N)
                .map_err(|_| StorageError::Full)?;
            let mut w = Writer::new(&mut buf);
            w.u8(1).map_err(|_| StorageError::Full)?;
            w.u8(u8::try_from(additions.len()).map_err(|_| StorageError::Full)?)
                .map_err(|_| StorageError::Full)?;
            for partner in additions.iter() {
                w.u64_le(*partner).map_err(|_| StorageError::Full)?;
            }
            let n = w.position();
            if pending.as_ref().map(|bytes| bytes.as_slice()) != Some(&buf[..n]) {
                self.storage.store(PENDING_LINK_KEYS, &buf[..n])?;
            }
        } else if pending.is_some() {
            self.storage.erase(PENDING_LINK_KEYS)?;
        }
        // Each record is stored as soon as it is encoded.
        let mut count = 0u8;
        for e in self.aps.security.keys().iter() {
            let mut buf = [0u8; LINK_KEY_BYTES];
            let mut w = Writer::new(&mut buf);
            let r = (|| -> Result<(), panweave_codec::CodecError> {
                w.u8(LINK_KEY_FORMAT)?;
                w.u64_le(e.partner.0)?;
                w.bytes(e.key.as_bytes())?;
                w.u8(u8::from(e.kind == LinkKeyKind::Global))?;
                w.u8(e.attributes.raw())?;
                w.u32_le(e.incoming)?;
                w.u32_le(e.outgoing.reserved_until())?;
                w.u8(u8::from(e.frame_counter_sync))?;
                w.u8(e.initial_join_authentication.raw())?;
                w.u8(match e.negotiation_state {
                    KeyNegotiationState::None => 0,
                    KeyNegotiationState::Started => 1,
                    KeyNegotiationState::Complete => 2,
                })?;
                w.u8(e.negotiation_method)?;
                w.u8(e.post_join_key_update.raw())?;
                w.u8(u8::from(e.passphrase_update_allowed))?;
                w.u8(u8::from(e.passphrase.is_some()))?;
                if let Some(passphrase) = &e.passphrase {
                    w.bytes(passphrase.as_bytes())?;
                }
                Ok(())
            })();
            if r.is_err() {
                return Err(StorageError::Full);
            }
            let n = w.position();
            store_if_changed(
                &mut self.storage,
                Key::with_id(Kind::LinkKey, e.partner.0),
                &buf[..n],
                &mut [0u8; LINK_KEY_BYTES],
            )?;
            count = count.saturating_add(1);
        }
        // Remove only departed partners. The old index may temporarily
        // reference an absent entry after a cut, which restore denies;
        // untouched partners retain their own atomic records.
        for partner in partners.iter().copied() {
            if self.aps.security.entry(ExtendedAddress(partner)).is_none() {
                self.storage.erase(Key::with_id(Kind::LinkKey, partner))?;
                self.storage
                    .erase(Key::with_id(Kind::ApsFrameCounter, partner))?;
            }
        }
        // The AIB record doubles as the index of link-key records: the
        // storage trait has no enumeration. Format 2 appends the startup
        // attributes of Table 2-24 (apsDesignatedCoordinator,
        // apsChannelMaskList, apsUseExtendedPANID, apsUseInsecureJoin).
        let mut buf = [0u8; 16 + 8 * crate::stack::LINK_KEYS + 16 + 16];
        let mut w = Writer::new(&mut buf);
        let _ = w.u8(AIB_FORMAT);
        let _ = w.u64_le(self.aps.aib.trust_center_address.0);
        let _ = w.u8(count);
        for e in self.aps.security.keys().iter().take(usize::from(count)) {
            let _ = w.u64_le(e.partner.0);
        }
        let aib = &self.aps.aib;
        let _ = w.u8(u8::from(aib.designated_coordinator));
        let _ = w.u32_le(aib.channel_mask.0);
        let _ = w.u64_le(aib.use_extended_pan_id.0);
        let _ = w.u8(u8::from(aib.use_insecure_join));
        // Format 3: the other channel pages of apsChannelMaskList.
        #[allow(clippy::cast_possible_truncation)]
        let _ = w.u8(aib.channel_mask_pages.len() as u8);
        for m in &aib.channel_mask_pages {
            let _ = w.u32_le(m.0);
        }
        let n = w.position();
        if previous.as_ref().map(|bytes| bytes.as_slice()) != Some(&buf[..n]) {
            self.storage.store(Key::single(Kind::Aib), &buf[..n])?;
        }
        if !additions.is_empty() {
            self.storage.erase(PENDING_LINK_KEYS)?;
        }
        Ok(())
    }

    /// Persists the binding table.
    pub fn persist_bindings(&mut self) -> Result<(), StorageError> {
        let result = self.persist_bindings_inner();
        self.finish_persistence(Kind::Bindings, result)
    }

    fn persist_bindings_inner(&mut self) -> Result<(), StorageError> {
        let mut buf = P::Record::vec();
        let _ = buf.resize_default(<P::Record as Capacity>::N);
        let mut w = Writer::new(&mut buf);
        let _ = w.u8(BINDINGS_FORMAT);
        for b in self.aps.bindings.iter() {
            let r = (|| -> Result<(), panweave_codec::CodecError> {
                w.u8(b.src_endpoint.0)?;
                w.u16_le(b.cluster.0)?;
                match b.destination {
                    BindingDestination::Group(g) => {
                        w.u8(1)?;
                        w.u16_le(g.0)
                    }
                    BindingDestination::Unicast { address, endpoint } => {
                        w.u8(3)?;
                        w.u64_le(address.0)?;
                        w.u8(endpoint.0)
                    }
                }
            })();
            if r.is_err() {
                return Err(StorageError::Full);
            }
        }
        let n = w.position();
        self.storage.store(Key::single(Kind::Bindings), &buf[..n])
    }

    /// Persists the group table.
    pub fn persist_groups(&mut self) -> Result<(), StorageError> {
        let result = self.persist_groups_inner();
        self.finish_persistence(Kind::Groups, result)
    }

    pub(crate) fn persist_groups_inner(&mut self) -> Result<(), StorageError> {
        let mut buf = P::Record::vec();
        let _ = buf.resize_default(<P::Record as Capacity>::N);
        let mut w = Writer::new(&mut buf);
        let _ = w.u8(GROUPS_FORMAT);
        for g in self.aps.groups.iter() {
            for ep in g.endpoints.iter() {
                if w.u16_le(g.group.0).is_err() || w.u8(ep.0).is_err() {
                    return Err(StorageError::Full);
                }
            }
        }
        let n = w.position();
        let mut previous = P::Record::vec();
        previous
            .resize_default(P::Record::N)
            .map_err(|_| StorageError::Full)?;
        store_if_changed(
            &mut self.storage,
            Key::single(Kind::Groups),
            &buf[..n],
            &mut previous,
        )
    }

    /// Persists everything.
    pub fn persist_all(&mut self) -> Result<(), StorageError> {
        self.persist_nib()?;
        self.persist_children()?;
        self.persist_network_keys()?;
        self.persist_link_keys()?;
        self.persist_bindings()?;
        self.persist_groups()
    }

    /// Erases all persisted network state (factory reset).
    pub fn erase_persisted(&mut self) -> Result<(), StorageError> {
        // BDB 3.1 §13: every reset preserves the single outgoing NWK
        // frame counter (`Kind::NwkFrameCounter`), so a later join never
        // reuses counter values under a key the network still knows.
        for k in [
            Kind::Nib,
            Kind::Children,
            Kind::NetworkKeys,
            Kind::LinkKey,
            Kind::ApsFrameCounter,
            Kind::Aib,
            Kind::Bindings,
            Kind::Groups,
            Kind::GreenPower,
            Kind::DirectPastKeys,
            Kind::DirectConfig,
            Kind::DirectAdminKey,
            Kind::StartupSets,
        ] {
            if let Err(error) = self.storage.erase_kind(k) {
                self.persistence.erase_pending = true;
                self.persistence.retry_at =
                    Some(self.now + panweave_types::Duration::from_millis(100));
                return self.note_persistence_result(k, Err(error));
            }
        }
        self.persistence = PersistenceState::default();
        Ok(())
    }

    /// Restores persisted state after a reset (BDB 3.1 §7.1 initialization
    /// procedure, step "restore persistent data"). On success the NWK
    /// layer is marked joined with the frame counter continuing past the
    /// last persisted reservation; the caller then calls
    /// [`Stack::resume`].
    pub fn restore(&mut self) -> Result<Restored, StorageError> {
        self.restore_detail = RestoreDetail::NotRun;
        // The outgoing NWK frame counter outlives a factory reset (BDB
        // 3.1 §13): continue past the last reservation either way.
        let mut fc = [0u8; 4];
        let counter_present = match self
            .storage
            .load(Key::single(Kind::NwkFrameCounter), &mut fc)?
        {
            Some(4) => {
                self.nwk
                    .security
                    .restore_outgoing_counter(u32::from_le_bytes(fc));
                true
            }
            Some(_) => return Err(StorageError::Corrupt),
            None => false,
        };
        self.restore_startup_sets()?;
        let nib = record::<S, P::Record>(&mut self.storage, Key::single(Kind::Nib))?;
        let keys = record::<S, P::Record>(&mut self.storage, Key::single(Kind::NetworkKeys))?;
        let (nib, keys) = match (nib, keys) {
            (Some(n), Some(k)) => (n, k),
            (None, None) => {
                self.restore_detail = RestoreDetail::Empty;
                return Ok(Restored::FactoryNew);
            }
            _ => {
                self.restore_detail = RestoreDetail::Incomplete;
                return Ok(Restored::FactoryNew);
            }
        };
        if !counter_present {
            // A saved network must never resume with a fresh counter under
            // its old key. An interrupted initial formation also fails closed.
            self.restore_detail = RestoreDetail::Incomplete;
            return Err(StorageError::Corrupt);
        }
        if nib.first() != Some(&NIB_FORMAT) || keys.first() != Some(&KEYS_FORMAT) {
            self.restore_detail = if nib.is_empty() || keys.is_empty() {
                RestoreDetail::Malformed
            } else {
                RestoreDetail::UnknownFormat
            };
            return Ok(Restored::FactoryNew);
        }
        let mut r = Reader::new(&nib);
        let parsed = (|| -> Result<(), panweave_codec::CodecError> {
            if r.u8()? != NIB_FORMAT {
                return Err(panweave_codec::CodecError::Unsupported { what: "NIB format" });
            }
            let n = &mut self.nwk.nib;
            n.pan_id = PanId(r.u16_le()?);
            n.extended_pan_id = ExtendedAddress(r.u64_le()?);
            n.network_address = ShortAddress(r.u16_le()?);
            n.channel_page = ChannelPage(r.u8()?);
            n.channel = Channel::new(r.u8()?).unwrap_or(Channel::DEFAULT_2_4GHZ);
            n.update_id = r.u8()?;
            n.depth = r.u8()?;
            n.parent_address = ShortAddress(r.u16_le()?);
            n.parent_ieee = ExtendedAddress(r.u64_le()?);
            n.manager_addr = ShortAddress(r.u16_le()?);
            let _device_type = r.u8()?;
            n.router_started = false;
            let distributed = r.u8()? != 0;
            self.config.distributed = distributed;
            n.parent_information = panweave_nwk::command::ParentInformation(r.u8()?);
            n.stack_profile = r.u8()?;
            Ok(())
        })();
        if parsed.is_err() {
            self.restore_detail = RestoreDetail::Malformed;
            return Ok(Restored::FactoryNew);
        }
        let mut r = Reader::new(&keys);
        let parsed = (|| -> Result<(), panweave_codec::CodecError> {
            if r.u8()? != KEYS_FORMAT {
                return Err(panweave_codec::CodecError::Unsupported { what: "key format" });
            }
            let active = r.u8()?;
            let n = r.u8()?;
            for _ in 0..n {
                let seq = KeySequenceNumber(r.u8()?);
                let key = Key128::from_bytes(r.array::<16>()?);
                if seq.0 == active {
                    self.nwk.security.install_active_key(seq, key);
                    self.network_key_sequence = seq;
                } else {
                    self.nwk.security.install_key(seq, key);
                }
            }
            Ok(())
        })();
        if parsed.is_err() || !self.nwk.security.has_key() {
            self.restore_detail = RestoreDetail::Malformed;
            return Ok(Restored::FactoryNew);
        }
        // Frame counter: continue after the last persisted reservation
        // (never reuse a value, §4.3.4).
        let mut partners: VecOf<u64, <P::Aps as panweave_aps::layer::ApsDims>::Keys> =
            <P::Aps as panweave_aps::layer::ApsDims>::Keys::vec();
        if let Some(aib) = record::<S, P::Record>(&mut self.storage, Key::single(Kind::Aib))? {
            let mut r = Reader::new(&aib);
            let format = r.u8().ok();
            if matches!(format, Some(1..=AIB_FORMAT))
                && let Ok(tc) = r.u64_le()
            {
                self.aps.aib.trust_center_address = ExtendedAddress(tc);
                let n = r.u8().unwrap_or(0);
                for _ in 0..n {
                    let Ok(p) = r.u64_le() else { break };
                    let _ = partners.push(p);
                }
                if format >= Some(2)
                    && let (Ok(dc), Ok(mask), Ok(epid), Ok(insecure)) =
                        (r.u8(), r.u32_le(), r.u64_le(), r.u8())
                {
                    self.aps.aib.designated_coordinator = dc != 0;
                    self.aps.aib.channel_mask = ChannelMask(mask);
                    self.aps.aib.use_extended_pan_id = ExtendedAddress(epid);
                    self.aps.aib.use_insecure_join = insecure != 0;
                }
                if format >= Some(3)
                    && let Ok(pages) = r.u8()
                {
                    self.aps.aib.channel_mask_pages.clear();
                    for _ in 0..pages {
                        let Ok(m) = r.u32_le() else { break };
                        let _ = self.aps.aib.channel_mask_pages.push(ChannelMask(m));
                    }
                }
            }
        }
        self.restore_link_keys(&partners)?;
        // §4.6.3.8: after a reboot every partner's incoming counter is
        // unverified until a challenge succeeds.
        self.aps.security.invalidate_frame_counters();
        self.restore_bindings_and_groups()?;
        self.restore_children()?;
        self.nwk.warm_start();
        let short = self.nwk.nib.network_address;
        self.aps
            .set_network_state(short, DeviceState::JoinedAuthorized);
        self.phase = Phase::Operating;
        self.restore_detail = RestoreDetail::Restored;
        Ok(Restored::OnNetwork)
    }

    /// Why the last [`Stack::restore`] returned what it did.
    pub fn restore_detail(&self) -> RestoreDetail {
        self.restore_detail
    }

    fn restore_link_keys(&mut self, partners: &[u64]) -> Result<(), StorageError> {
        for &p in partners {
            let Some(rec) =
                record::<S, P::Record>(&mut self.storage, Key::with_id(Kind::LinkKey, p))?
            else {
                continue;
            };
            let e = decode_link_key(&rec, ExtendedAddress(p)).map_err(|_| StorageError::Corrupt)?;
            let mut fc = [0u8; 4];
            let mut e = e;
            match self
                .storage
                .load(Key::with_id(Kind::ApsFrameCounter, p), &mut fc)?
            {
                Some(4) => {
                    let bound = u32::from_le_bytes(fc).max(e.outgoing.reserved_until());
                    e.outgoing = panweave_security::frame_counter::OutgoingCounter::restore(bound);
                }
                Some(_) => return Err(StorageError::Corrupt),
                None => {
                    // Legacy snapshots cannot prove that a subsequently
                    // reserved window was not used. Require a new link key
                    // before transmitting under an entry without a bound.
                    e.outgoing =
                        panweave_security::frame_counter::OutgoingCounter::restore(u32::MAX);
                }
            }
            // A persisted entry supersedes the preconfigured one.
            let _ = self.aps.security.keys_mut().insert(e);
        }
        Ok(())
    }

    fn restore_children(&mut self) -> Result<(), StorageError> {
        if !self.nwk.nib.is_router_or_coordinator() {
            return Ok(());
        }
        let Some(rec) = record::<S, P::Record>(&mut self.storage, Key::single(Kind::Children))?
        else {
            return Ok(());
        };
        let mut r = Reader::new(&rec);
        if r.u8().ok() != Some(CHILDREN_FORMAT) {
            return Ok(());
        }
        let limit = self.nwk.nib.router_age_limit;
        while r.remaining() >= 16 {
            let parsed = (|| -> Result<NeighborEntry, panweave_codec::CodecError> {
                let extended = ExtendedAddress(r.u64_le()?);
                let short = ShortAddress(r.u16_le()?);
                let configuration = r.u8()?;
                let timeout = r.u32_le()?;
                let rx_on = r.u8()? != 0;
                let mut e = NeighborEntry::new(
                    extended,
                    short,
                    LogicalDeviceType::EndDevice,
                    rx_on,
                    Relationship::Child,
                    0,
                );
                e.end_device_configuration = configuration;
                e.device_timeout_secs = timeout;
                // §3.6.10.8: a full timeout period after reboot.
                e.timeout_counter_secs = timeout;
                Ok(e)
            })();
            let Ok(e) = parsed else { break };
            let _ = self.nwk.neighbors.insert(e, limit);
        }
        Ok(())
    }

    fn restore_bindings_and_groups(&mut self) -> Result<(), StorageError> {
        if let Some(rec) = record::<S, P::Record>(&mut self.storage, Key::single(Kind::Bindings))? {
            let mut r = Reader::new(&rec);
            if r.u8().ok() == Some(BINDINGS_FORMAT) {
                while r.remaining() >= 4 {
                    let Ok(ep) = r.u8() else { break };
                    let Ok(cluster) = r.u16_le() else { break };
                    let dest = match r.u8() {
                        Ok(1) => r
                            .u16_le()
                            .ok()
                            .map(|g| BindingDestination::Group(GroupAddress(g))),
                        Ok(3) => match (r.u64_le(), r.u8()) {
                            (Ok(a), Ok(e)) => Some(BindingDestination::Unicast {
                                address: ExtendedAddress(a),
                                endpoint: Endpoint(e),
                            }),
                            _ => None,
                        },
                        _ => None,
                    };
                    let Some(destination) = dest else { break };
                    let _ = self.aps.bindings.bind(BindingEntry {
                        src_endpoint: Endpoint(ep),
                        cluster: ClusterId(cluster),
                        destination,
                    });
                }
            }
        }
        if let Some(rec) = record::<S, P::Record>(&mut self.storage, Key::single(Kind::Groups))? {
            let mut r = Reader::new(&rec);
            if r.u8().ok() == Some(GROUPS_FORMAT) {
                while r.remaining() >= 3 {
                    let (Ok(g), Ok(ep)) = (r.u16_le(), r.u8()) else {
                        break;
                    };
                    let _ = self.aps.groups.add(GroupAddress(g), Endpoint(ep));
                }
            }
        }
        Ok(())
    }

    /// Resumes operation after [`Stack::restore`] reported
    /// [`Restored::OnNetwork`] (BDB 3.1 §7.1 / §10.1): the coordinator and
    /// routers resume on their network (routers re-announce), end devices
    /// perform a secured rejoin.
    pub fn resume(&mut self) -> Result<(), NwkStatus> {
        if self.phase != Phase::Operating {
            return Err(NwkStatus::InvalidRequest);
        }
        self.sync_security_model();
        let nib = &self.nwk.nib;
        let (pan, page, channel, short) = (
            nib.pan_id,
            nib.channel_page,
            nib.channel,
            nib.network_address,
        );
        match self.config.role {
            LogicalDeviceType::Coordinator | LogicalDeviceType::Router => {
                let _ = (pan, page, channel);
                self.nwk
                    .start_router()
                    .map_err(|_| NwkStatus::InvalidRequest)?;
                let _ = self
                    .zdo
                    .device_announce(short, self.config.ieee, self.config.capability());
                // §2.4.3.1.12.1: announce the end device children after
                // apsParentAnnounceBaseTimer plus jitter.
                self.schedule_parent_annce(0);
                self.pump();
                Ok(())
            }
            LogicalDeviceType::EndDevice => {
                self.mac.start(pan, page, channel, short, false, false);
                let r = self.join(crate::JoinMode::SecuredRejoin);
                self.pump();
                r
            }
        }
    }
}
