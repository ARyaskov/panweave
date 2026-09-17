//! Security material: network keys (R23.2 §4.3.3, Table 4-3) and the APS
//! device key-pair set (§4.4.12, Table 4-36).

use core::fmt;

use heapless::Vec;
use panweave_types::{ExtendedAddress, Key128, KeyAttributes, KeySequenceNumber};
use zeroize::Zeroize;

use crate::frame_counter::OutgoingCounter;

/// One network security material descriptor.
#[derive(Clone)]
pub struct NetworkKeySlot {
    /// Key sequence number assigned by the Trust Center.
    pub sequence: KeySequenceNumber,
    /// The key.
    pub key: Key128,
}

impl fmt::Debug for NetworkKeySlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkKeySlot")
            .field("sequence", &self.sequence)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for NetworkKeySlot {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Network key storage: the active key plus one alternate (a device SHALL
/// be able to store two network keys, §4.3.4.1) and the single outgoing
/// frame counter shared across keys (§4.3.4 optimisation).
#[derive(Clone, Debug, Default)]
pub struct NetworkKeys {
    slots: Vec<NetworkKeySlot, 2>,
    active: Option<KeySequenceNumber>,
    /// Outgoing NWK frame counter shared by all keys.
    pub outgoing: OutgoingCounter,
}

impl NetworkKeys {
    /// No keys.
    pub const fn new() -> Self {
        NetworkKeys {
            slots: Vec::new(),
            active: None,
            outgoing: OutgoingCounter::new(),
        }
    }

    /// Installs a key. If a key with the same sequence exists it is
    /// replaced; otherwise the non-active slot is evicted when full.
    pub fn install(&mut self, sequence: KeySequenceNumber, key: Key128) {
        if let Some(s) = self.slots.iter_mut().find(|s| s.sequence == sequence) {
            s.key = key;
            return;
        }
        if self.slots.is_full() {
            // Evict the non-active key.
            let victim = self
                .slots
                .iter()
                .position(|s| Some(s.sequence) != self.active)
                .unwrap_or(0);
            let _ = self.slots.swap_remove(victim);
        }
        let _ = self.slots.push(NetworkKeySlot { sequence, key });
    }

    /// Installs a key and makes it active in one step (network formation
    /// or initial join).
    pub fn install_active(&mut self, sequence: KeySequenceNumber, key: Key128) {
        self.install(sequence, key);
        self.active = Some(sequence);
    }

    /// Switches to the key with `sequence` (APSME-SWITCH-KEY). Returns
    /// false when the key is unknown. Applies the outgoing counter reset
    /// rule of §4.3.4.
    pub fn switch_to(&mut self, sequence: KeySequenceNumber) -> bool {
        if self.slots.iter().any(|s| s.sequence == sequence) {
            if self.active != Some(sequence) {
                self.active = Some(sequence);
                self.outgoing.on_key_switch();
            }
            true
        } else {
            false
        }
    }

    /// The active key sequence number.
    #[inline]
    pub const fn active_sequence(&self) -> Option<KeySequenceNumber> {
        self.active
    }

    /// The active key.
    pub fn active(&self) -> Option<&NetworkKeySlot> {
        let a = self.active?;
        self.slots.iter().find(|s| s.sequence == a)
    }

    /// Looks up a key by sequence number.
    pub fn get(&self, sequence: KeySequenceNumber) -> Option<&NetworkKeySlot> {
        self.slots.iter().find(|s| s.sequence == sequence)
    }

    /// True when at least one key is installed and active.
    #[inline]
    pub fn has_active(&self) -> bool {
        self.active().is_some()
    }

    /// Iterates installed keys.
    pub fn iter(&self) -> impl Iterator<Item = &NetworkKeySlot> {
        self.slots.iter()
    }

    /// Removes all keys (leave / factory reset). The outgoing counter is
    /// preserved as required by §4.3.4.
    pub fn clear_keys(&mut self) {
        self.slots.clear();
        self.active = None;
    }
}

/// `apsLinkKeyType` (Table 4-36).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum LinkKeyKind {
    /// Unique link key shared with one peer.
    Unique,
    /// Global link key shared with every device (well-known or distributed
    /// global key).
    Global,
}

/// `InitialJoinAuthentication` (Table 4-36).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum InitialJoinAuthentication {
    /// No authentication (well-known key).
    #[default]
    None,
    /// Install-code derived key.
    InstallCodeKey,
    /// Anonymous key negotiation (well-known passphrase).
    AnonymousKeyNegotiation,
    /// Key negotiation authenticated by a pre-shared passphrase.
    KeyNegotiationWithAuthentication,
}

impl InitialJoinAuthentication {
    /// Table 2-121 `InitialJoinMethod` value.
    pub const fn raw(self) -> u8 {
        match self {
            InitialJoinAuthentication::None => 0,
            InitialJoinAuthentication::InstallCodeKey => 1,
            InitialJoinAuthentication::AnonymousKeyNegotiation => 2,
            InitialJoinAuthentication::KeyNegotiationWithAuthentication => 3,
        }
    }
}

/// `PostJoinKeyUpdateMethod` (Table 4-36) / `ActiveLinkKeyType`
/// (Table 2-121): how the current link key was established.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PostJoinKeyUpdate {
    /// Not updated since the join (0x00).
    #[default]
    NotUpdated,
    /// Request Key / Transport Key (0x01).
    KeyRequest,
    /// Unauthenticated (anonymous) key negotiation (0x02).
    UnauthenticatedNegotiation,
    /// Authenticated key negotiation (0x03).
    AuthenticatedNegotiation,
    /// Certificate-based mutual authentication (0x04).
    CertificateBased,
}

impl PostJoinKeyUpdate {
    /// Table 2-121 value.
    pub const fn raw(self) -> u8 {
        match self {
            PostJoinKeyUpdate::NotUpdated => 0,
            PostJoinKeyUpdate::KeyRequest => 1,
            PostJoinKeyUpdate::UnauthenticatedNegotiation => 2,
            PostJoinKeyUpdate::AuthenticatedNegotiation => 3,
            PostJoinKeyUpdate::CertificateBased => 4,
        }
    }
}

/// `KeyNegotiationState` (Table 4-36).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum KeyNegotiationState {
    /// No negotiation performed or in progress.
    #[default]
    None,
    /// Negotiation started.
    Started,
    /// Negotiation completed.
    Complete,
}

/// One key-pair descriptor entry.
#[derive(Clone)]
pub struct LinkKeyEntry {
    /// Peer device address.
    pub partner: ExtendedAddress,
    /// The link key.
    pub key: Key128,
    /// Unique or global.
    pub kind: LinkKeyKind,
    /// Provisional / unverified / verified.
    pub attributes: KeyAttributes,
    /// Outgoing APS frame counter for this key.
    pub outgoing: OutgoingCounter,
    /// Next acceptable incoming APS frame counter from the partner.
    pub incoming: u32,
    /// How the initial join was authenticated.
    pub initial_join_authentication: InitialJoinAuthentication,
    /// Key negotiation progress.
    pub negotiation_state: KeyNegotiationState,
    /// Selected key negotiation method (TLV value), 0 when none.
    pub negotiation_method: u8,
    /// How the current key was established after the join.
    pub post_join_key_update: PostJoinKeyUpdate,
    /// The pre-shared secret for key negotiation (`Passphrase`), when
    /// one is set.
    pub passphrase: Option<Key128>,
    /// `PassphraseUpdateAllowed`: a device may obtain an authentication
    /// token once (§2.4.3.4.2).
    pub passphrase_update_allowed: bool,
    /// Peer supports APS frame counter synchronisation (bit 0 of
    /// Features & Capabilities).
    pub frame_counter_sync: bool,
    /// `VerifiedFrameCounter` (§4.6.3.8): the incoming counter is known
    /// to be recent. False after a reboot until a challenge succeeds.
    pub verified_frame_counter: bool,
    /// `apsChallengeFrameCounter`: challenge responses issued under the
    /// current outgoing frame counter (reset when it advances).
    pub challenge_frame_counter: u32,
    /// Expiry in seconds from installation; `0xFFFF` never expires.
    pub timeout_secs: u16,
}

impl LinkKeyEntry {
    /// Builds a provisional unique key entry for `partner`.
    pub fn provisional(partner: ExtendedAddress, key: Key128, kind: LinkKeyKind) -> Self {
        LinkKeyEntry {
            partner,
            key,
            kind,
            attributes: KeyAttributes::ProvisionalKey,
            outgoing: OutgoingCounter::new(),
            incoming: 0,
            initial_join_authentication: InitialJoinAuthentication::None,
            negotiation_state: KeyNegotiationState::None,
            negotiation_method: 0,
            post_join_key_update: PostJoinKeyUpdate::NotUpdated,
            passphrase: None,
            passphrase_update_allowed: true,
            frame_counter_sync: false,
            verified_frame_counter: true,
            challenge_frame_counter: 0,
            timeout_secs: 0xFFFF,
        }
    }

    /// True when the key may protect application traffic (verified or
    /// unverified unique key, or a global key).
    #[inline]
    pub const fn is_verified(&self) -> bool {
        matches!(self.attributes, KeyAttributes::VerifiedKey)
    }

    /// True when a passphrase is set.
    #[inline]
    pub const fn has_passphrase(&self) -> bool {
        self.passphrase.is_some()
    }
}

impl fmt::Debug for LinkKeyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkKeyEntry")
            .field("partner", &self.partner)
            .field("kind", &self.kind)
            .field("attributes", &self.attributes)
            .field("incoming", &self.incoming)
            .field("negotiation_state", &self.negotiation_state)
            .finish_non_exhaustive()
    }
}

impl Drop for LinkKeyEntry {
    fn drop(&mut self) {
        self.key.zeroize();
        if let Some(p) = self.passphrase.as_mut() {
            p.zeroize();
        }
    }
}

/// The APS device key-pair set (`apsDeviceKeyPairSet`).
#[derive(Clone, Debug, Default)]
pub struct LinkKeyTable<const N: usize> {
    entries: Vec<LinkKeyEntry, N>,
}

impl<const N: usize> LinkKeyTable<N> {
    /// Empty table.
    pub const fn new() -> Self {
        LinkKeyTable {
            entries: Vec::new(),
        }
    }

    /// Finds the entry for `partner`.
    pub fn get(&self, partner: ExtendedAddress) -> Option<&LinkKeyEntry> {
        self.entries.iter().find(|e| e.partner == partner)
    }

    /// Mutable lookup.
    pub fn get_mut(&mut self, partner: ExtendedAddress) -> Option<&mut LinkKeyEntry> {
        self.entries.iter_mut().find(|e| e.partner == partner)
    }

    /// Inserts or replaces the entry for `entry.partner`. Returns
    /// `Err(entry)` when the table is full.
    pub fn insert(&mut self, entry: LinkKeyEntry) -> Result<(), LinkKeyEntry> {
        if let Some(e) = self.get_mut(entry.partner) {
            *e = entry;
            return Ok(());
        }
        self.entries.push(entry)
    }

    /// Removes the entry for `partner`.
    pub fn remove(&mut self, partner: ExtendedAddress) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.partner != partner);
        self.entries.len() != before
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// True when no more entries fit.
    pub fn is_full(&self) -> bool {
        self.entries.is_full()
    }

    /// Iterates entries.
    pub fn iter(&self) -> impl Iterator<Item = &LinkKeyEntry> {
        self.entries.iter()
    }

    /// Mutable iteration.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut LinkKeyEntry> {
        self.entries.iter_mut()
    }

    /// Removes every entry.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_keys_two_slots_and_switch() {
        let mut k = NetworkKeys::new();
        assert!(!k.has_active());
        k.install_active(KeySequenceNumber(0), Key128::from_bytes([1; 16]));
        k.install(KeySequenceNumber(1), Key128::from_bytes([2; 16]));
        assert_eq!(k.active_sequence(), Some(KeySequenceNumber(0)));
        assert!(k.get(KeySequenceNumber(1)).is_some());
        // Third key evicts the non-active one.
        k.install(KeySequenceNumber(2), Key128::from_bytes([3; 16]));
        assert!(k.get(KeySequenceNumber(1)).is_none());
        assert!(k.get(KeySequenceNumber(0)).is_some());
        assert!(!k.switch_to(KeySequenceNumber(9)));
        assert!(k.switch_to(KeySequenceNumber(2)));
        assert_eq!(k.active().unwrap().key, Key128::from_bytes([3; 16]));
        k.clear_keys();
        assert!(!k.has_active());
    }

    #[test]
    fn link_key_table_bounded() {
        let mut t = LinkKeyTable::<2>::new();
        let a = ExtendedAddress(1);
        t.insert(LinkKeyEntry::provisional(
            a,
            Key128::WELL_KNOWN_GLOBAL_TCLK,
            LinkKeyKind::Global,
        ))
        .unwrap();
        t.insert(LinkKeyEntry::provisional(
            ExtendedAddress(2),
            Key128::ZERO,
            LinkKeyKind::Unique,
        ))
        .unwrap();
        assert!(t.is_full());
        assert!(
            t.insert(LinkKeyEntry::provisional(
                ExtendedAddress(3),
                Key128::ZERO,
                LinkKeyKind::Unique
            ))
            .is_err()
        );
        // Replacing an existing partner does not need space.
        let mut e = LinkKeyEntry::provisional(a, Key128::ZERO, LinkKeyKind::Unique);
        e.attributes = KeyAttributes::VerifiedKey;
        t.insert(e).unwrap();
        assert!(t.get(a).unwrap().is_verified());
        assert!(t.remove(a));
        assert!(!t.remove(a));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn debug_output_redacts_keys() {
        let e = LinkKeyEntry::provisional(
            ExtendedAddress(1),
            Key128::WELL_KNOWN_GLOBAL_TCLK,
            LinkKeyKind::Global,
        );
        let mut buf = [0u8; 256];
        struct W<'a>(&'a mut [u8], usize);
        impl fmt::Write for W<'_> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                let end = self.1 + s.len();
                if end > self.0.len() {
                    return Err(fmt::Error);
                }
                self.0[self.1..end].copy_from_slice(s.as_bytes());
                self.1 = end;
                Ok(())
            }
        }
        let len = {
            let mut w = W(&mut buf, 0);
            fmt::write(&mut w, format_args!("{e:?}")).unwrap();
            w.1
        };
        let s = core::str::from_utf8(&buf[..len]).unwrap();
        assert!(!s.contains("ZigBee"));
        assert!(!s.contains("key:"));
    }
}
