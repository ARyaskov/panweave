//! Network key rotation (ZD 1.1 §9): the ZDD keeps the network keys it
//! switched away from so a ZVD whose Basic authorization key was derived
//! from a past key can still open a Limited Authorization session
//! (§9.1) and Trust Center rejoin; the ZDD's APSME refuses to tunnel any
//! Transport Key message conveying an active or prospective network key
//! to a ZVD and closes the connection (§9).

use heapless::Vec;
use panweave_security::cipher::BlockCipher;
use panweave_types::{ExtendedAddress, Key128, KeySequenceNumber};

use crate::auth;
use crate::tlv::Psk;
use crate::tunnel::SessionKind;

/// APS Transport Key command identifier (R23.2 Table 4-35).
const APS_TRANSPORT_KEY: u8 = 0x05;
/// StandardKeyType "standard network key" (R23.2 Table 4-36).
const STANDARD_NETWORK_KEY: u8 = 0x01;
/// Key Identifier "key-transport key" (R23.2 Table 4-30).
const KEY_TRANSPORT_KEY: u8 = 0x02;

/// One past network key (§9.1: "the current network key prior to
/// switching to a new network key along with the network key sequence
/// number").
#[derive(Clone, Debug)]
pub struct PastKey {
    /// Its sequence number.
    pub sequence: KeySequenceNumber,
    /// The key.
    pub key: Key128,
}

/// The past network keys a ZDD stores (at least one, §9.1); the oldest
/// gives way when full.
#[derive(Clone, Debug, Default)]
pub struct PastNetworkKeys<const N: usize> {
    keys: Vec<PastKey, N>,
}

impl<const N: usize> PastNetworkKeys<N> {
    /// Octets one entry takes in [`Self::encode`].
    pub const ENTRY_LEN: usize = 17;

    /// No past keys.
    pub const fn new() -> Self {
        PastNetworkKeys { keys: Vec::new() }
    }

    /// Records the key being switched away from. A key with the same
    /// sequence number is replaced; when full, the oldest entry goes.
    pub fn record(&mut self, sequence: KeySequenceNumber, key: Key128) {
        if let Some(e) = self.keys.iter_mut().find(|e| e.sequence == sequence) {
            e.key = key;
            return;
        }
        if self.keys.is_full() && !self.keys.is_empty() {
            let _ = self.keys.remove(0);
        }
        let _ = self.keys.push(PastKey { sequence, key });
    }

    /// The past key with this sequence number.
    pub fn get(&self, sequence: KeySequenceNumber) -> Option<&Key128> {
        self.keys
            .iter()
            .find(|e| e.sequence == sequence)
            .map(|e| &e.key)
    }

    /// Forgets a key (e.g. once every ZVD has re-authorized).
    pub fn remove(&mut self, sequence: KeySequenceNumber) -> bool {
        match self.keys.iter().position(|e| e.sequence == sequence) {
            Some(i) => {
                let _ = self.keys.remove(i);
                true
            }
            None => false,
        }
    }

    /// The entries, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &PastKey> {
        self.keys.iter()
    }

    /// Number of stored keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether nothing is stored.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The Basic authorization key of `zvd` derived from the past
    /// network key with `sequence` (§6.3.2.1), if that key is stored.
    pub fn basic_key<C: BlockCipher>(
        &self,
        zvd: ExtendedAddress,
        sequence: KeySequenceNumber,
    ) -> Option<Key128> {
        self.get(sequence).map(|k| auth::basic_key::<C>(zvd, k))
    }

    /// Serialises the entries (sequence, 16 key octets each) for
    /// non-volatile storage; returns the length, or `None` when `out` is
    /// too small.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let n = self.keys.len() * Self::ENTRY_LEN;
        let out = out.get_mut(..n)?;
        for (chunk, e) in out.chunks_exact_mut(Self::ENTRY_LEN).zip(self.keys.iter()) {
            chunk[0] = e.sequence.0;
            chunk[1..].copy_from_slice(e.key.as_bytes());
        }
        Some(n)
    }

    /// Restores entries written by [`Self::encode`] (extra entries are
    /// dropped, a trailing partial entry is ignored).
    pub fn decode(bytes: &[u8]) -> Self {
        let mut s = Self::new();
        for chunk in bytes.chunks_exact(Self::ENTRY_LEN) {
            let mut k = [0u8; 16];
            k.copy_from_slice(&chunk[1..]);
            s.record(KeySequenceNumber(chunk[0]), Key128::from_bytes(k));
        }
        s
    }
}

/// What a secure session authorizes once established (§6.3, §9.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SessionClass {
    /// A provisioning session (a Table 1 pre-shared secret).
    Provisioning,
    /// Basic authorization: access to the network.
    Basic,
    /// Admin authorization: the Commissioning Service and the network.
    Admin,
    /// A Limited Authorization session (§9.1): a Basic key derived from
    /// a past network key; only a Trust Center rejoin is allowed.
    Limited,
}

impl SessionClass {
    /// Classifies an established session on the ZDD from the PSK the
    /// ZVD selected and the network key sequence number it announced in
    /// Message 1, against the active sequence number.
    pub fn classify(
        psk: Psk,
        peer_key_sequence: Option<u8>,
        active_sequence: KeySequenceNumber,
    ) -> Self {
        match psk {
            Psk::AdminAuthorization => SessionClass::Admin,
            Psk::BasicAuthorization => {
                if peer_key_sequence.is_some_and(|s| s != active_sequence.0) {
                    SessionClass::Limited
                } else {
                    SessionClass::Basic
                }
            }
            Psk::SymmetricToken | Psk::InstallCode | Psk::Passcode | Psk::Anonymous => {
                SessionClass::Provisioning
            }
        }
    }

    /// How the Tunnel Service treats NPDUs of this session (§7.7.3.6.2,
    /// §9.1: a Limited Authorization session follows the rules of a
    /// simple provisioning session, so only the unsecured NPDUs of the
    /// Trust Center rejoin pass).
    pub const fn tunnel_kind(self) -> SessionKind {
        match self {
            SessionClass::Provisioning | SessionClass::Limited => SessionKind::ZvdProvisioning,
            SessionClass::Basic | SessionClass::Admin => SessionKind::Authorized,
        }
    }

    /// Whether the Commissioning Service of a provisioned ZDD may be
    /// used (§6.3.2.1: Admin only).
    pub const fn allows_commissioning(self) -> bool {
        matches!(self, SessionClass::Admin)
    }

    /// Whether the ZDD may derive a Basic authorization key for the ZVD
    /// from a Transport Key message conveying a network key (§9.1: only
    /// inside a Limited Authorization session).
    pub const fn allows_basic_key_translation(self) -> bool {
        matches!(self, SessionClass::Limited)
    }
}

/// The APSME's answer to the NWK layer's request to forward a frame to
/// a ZVD over the Bluetooth connection (§9).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Forwarding {
    /// Forward as usual.
    Forward,
    /// A Transport Key message conveying an active or prospective
    /// network key: do not forward, and close the Bluetooth connection
    /// so the ZVD re-establishes its session.
    Decline,
}

/// Inspects the APS frame (the NWK payload) the NWK layer wants to
/// forward to a ZVD (§9): an unsecured Transport Key command with
/// StandardKeyType "standard network key", or an APS-secured command
/// whose auxiliary header names the key-transport key, is declined.
/// Anything else, including frames too short to be either, is
/// forwarded.
pub fn forwarding_decision(aps_frame: &[u8]) -> Forwarding {
    let Some(&fc) = aps_frame.first() else {
        return Forwarding::Forward;
    };
    if fc & 0x03 != 0x01 {
        // Not an APS command frame.
        return Forwarding::Forward;
    }
    // Command header: frame control, counter, optional extended header.
    let mut pos = 2;
    if fc & 0x80 != 0 {
        let ext = aps_frame.get(2).copied().unwrap_or(0);
        // Fragmentation sub-field 0: no block number / ack bitfield.
        pos += if ext.trailing_zeros() >= 2 { 1 } else { 3 };
    }
    if fc & 0x20 == 0 {
        // Rule 1: unsecured, look at the command and its key type.
        let declined = aps_frame.get(pos) == Some(&APS_TRANSPORT_KEY)
            && aps_frame.get(pos + 1) == Some(&STANDARD_NETWORK_KEY);
        return if declined {
            Forwarding::Decline
        } else {
            Forwarding::Forward
        };
    }
    // Rule 2: secured, look at the key identifier of the auxiliary
    // header's security control field.
    match aps_frame.get(pos) {
        Some(control) if (control >> 3) & 0x03 == KEY_TRANSPORT_KEY => Forwarding::Decline,
        _ => Forwarding::Forward,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_security::cipher::SoftwareAes;

    const ZVD: ExtendedAddress = ExtendedAddress(0x001F_EE00_0000_0001);

    #[test]
    fn past_keys_are_kept_and_derive_basic_keys() {
        let mut past: PastNetworkKeys<2> = PastNetworkKeys::new();
        assert!(past.is_empty());
        let k1 = Key128::from_bytes([1; 16]);
        let k2 = Key128::from_bytes([2; 16]);
        let k3 = Key128::from_bytes([3; 16]);
        past.record(KeySequenceNumber(1), k1.clone());
        past.record(KeySequenceNumber(2), k2.clone());
        assert_eq!(past.len(), 2);
        // Full: the oldest goes.
        past.record(KeySequenceNumber(3), k3.clone());
        assert!(past.get(KeySequenceNumber(1)).is_none());
        assert_eq!(past.get(KeySequenceNumber(2)), Some(&k2));
        assert_eq!(past.get(KeySequenceNumber(3)), Some(&k3));
        assert_eq!(
            past.basic_key::<SoftwareAes>(ZVD, KeySequenceNumber(2)),
            Some(auth::basic_key::<SoftwareAes>(ZVD, &k2))
        );
        assert!(
            past.basic_key::<SoftwareAes>(ZVD, KeySequenceNumber(1))
                .is_none()
        );
        // Same sequence replaces.
        past.record(KeySequenceNumber(3), k1.clone());
        assert_eq!(past.get(KeySequenceNumber(3)), Some(&k1));
        assert_eq!(past.len(), 2);
        // Persistence round trip.
        let mut buf = [0u8; 64];
        let n = past.encode(&mut buf).unwrap();
        assert_eq!(n, 34);
        let back: PastNetworkKeys<2> = PastNetworkKeys::decode(&buf[..n]);
        assert_eq!(back.get(KeySequenceNumber(2)), Some(&k2));
        assert_eq!(back.get(KeySequenceNumber(3)), Some(&k1));
        assert!(past.encode(&mut buf[..10]).is_none());
        assert!(past.remove(KeySequenceNumber(2)));
        assert!(!past.remove(KeySequenceNumber(2)));
    }

    #[test]
    fn sessions_are_classified() {
        let active = KeySequenceNumber(5);
        assert_eq!(
            SessionClass::classify(Psk::BasicAuthorization, None, active),
            SessionClass::Basic
        );
        assert_eq!(
            SessionClass::classify(Psk::BasicAuthorization, Some(5), active),
            SessionClass::Basic
        );
        let limited = SessionClass::classify(Psk::BasicAuthorization, Some(4), active);
        assert_eq!(limited, SessionClass::Limited);
        assert_eq!(limited.tunnel_kind(), SessionKind::ZvdProvisioning);
        assert!(!limited.allows_commissioning());
        assert!(limited.allows_basic_key_translation());
        let admin = SessionClass::classify(Psk::AdminAuthorization, Some(4), active);
        assert_eq!(admin, SessionClass::Admin);
        assert!(admin.allows_commissioning());
        assert_eq!(admin.tunnel_kind(), SessionKind::Authorized);
        assert!(!admin.allows_basic_key_translation());
        assert_eq!(
            SessionClass::classify(Psk::Anonymous, None, active),
            SessionClass::Provisioning
        );
        assert_eq!(
            SessionClass::classify(Psk::InstallCode, Some(1), active).tunnel_kind(),
            SessionKind::ZvdProvisioning
        );
    }

    #[test]
    fn transport_key_messages_are_not_tunnelled() {
        // Unsecured Transport Key, standard network key.
        assert_eq!(
            forwarding_decision(&[0x01, 0x10, 0x05, 0x01, 0x00]),
            Forwarding::Decline
        );
        // Unsecured Transport Key with a Trust Center link key passes.
        assert_eq!(
            forwarding_decision(&[0x01, 0x10, 0x05, 0x04]),
            Forwarding::Forward
        );
        // Another unsecured command passes.
        assert_eq!(
            forwarding_decision(&[0x01, 0x10, 0x0E, 0x01]),
            Forwarding::Forward
        );
        // Secured command under the key-transport key (key id 2 in bits
        // 3-4 of the security control: 0x10 | level 5).
        assert_eq!(
            forwarding_decision(&[0x21, 0x10, 0x15, 0, 0, 0, 0]),
            Forwarding::Decline
        );
        // Secured command under the key-load key passes (it carries a
        // link key).
        assert_eq!(
            forwarding_decision(&[0x21, 0x10, 0x1D, 0, 0, 0, 0]),
            Forwarding::Forward
        );
        // Extended header before the command identifier.
        assert_eq!(
            forwarding_decision(&[0x81, 0x10, 0x00, 0x05, 0x01]),
            Forwarding::Decline
        );
        // Data frames and empty input pass.
        assert_eq!(
            forwarding_decision(&[0x00, 0x01, 0x06, 0x00, 0x04, 0x01, 0x01, 0x10]),
            Forwarding::Forward
        );
        assert_eq!(forwarding_decision(&[]), Forwarding::Forward);
        assert_eq!(forwarding_decision(&[0x01]), Forwarding::Forward);
    }
}
