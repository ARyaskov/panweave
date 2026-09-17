//! APS frame security (R23.2 §4.4.1) over the device key-pair set
//! (`apsDeviceKeyPairSet`, Table 4-36).
//!
//! Outgoing frames are protected with the link key shared with the
//! destination (or a key derived from it for key transport / key load,
//! §4.5.3); incoming frames select the key by the sender's IEEE address.
//! Per-partner incoming frame counters are enforced for unique link keys
//! (§4.4.1.2 step 4) and every outgoing counter is reservation-backed so
//! that a value is never reused after a reset.

use panweave_security::aux_header::{AuxHeader, KeyIdentifier, SecurityLevel};
use panweave_security::challenge;
use panweave_security::cipher::BlockCipher;
use panweave_security::frame::{self, SecurityError};
use panweave_security::frame_counter::{CounterError, Reservation};
use panweave_security::key_hierarchy;
use panweave_security::material::{LinkKeyEntry, LinkKeyKind, LinkKeyTable};
use panweave_types::{ExtendedAddress, FrameCounter, Key128, KeyAttributes};
use subtle::ConstantTimeEq;

/// Result of unprotecting an incoming APS frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ApsUnsecured {
    /// The key-pair entry (partner address) used.
    pub partner: ExtendedAddress,
    /// Key identifier of the auxiliary header.
    pub key_id: KeyIdentifier,
    /// Whether the auxiliary header carried an extended nonce.
    pub extended_nonce: bool,
    /// Received frame counter.
    pub frame_counter: FrameCounter,
    /// Link key kind of the entry.
    pub kind: LinkKeyKind,
    /// Key attributes of the entry.
    pub attributes: KeyAttributes,
    /// Start of the plaintext payload.
    pub payload_start: usize,
    /// End (exclusive) of the plaintext payload.
    pub payload_end: usize,
}

/// Failure to secure an outgoing frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SecureError {
    /// No usable key-pair entry for the partner.
    NoKey,
    /// The outgoing counter needs a persisted reservation first.
    CounterPending,
    /// The outgoing counter is exhausted.
    CounterExhausted,
    /// Cryptographic processing failed.
    Security(SecurityError),
}

/// APS security state.
pub struct ApsSecurity<C: BlockCipher, const N: usize> {
    keys: LinkKeyTable<N>,
    ciphers: [Option<(ExtendedAddress, KeyIdentifier, C)>; 2],
    next_slot: usize,
}

impl<C: BlockCipher, const N: usize> Default for ApsSecurity<C, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: BlockCipher, const N: usize> ApsSecurity<C, N> {
    /// Empty state.
    pub const fn new() -> Self {
        ApsSecurity {
            keys: LinkKeyTable::new(),
            ciphers: [None, None],
            next_slot: 0,
        }
    }

    /// The key-pair set (read-only).
    pub const fn keys(&self) -> &LinkKeyTable<N> {
        &self.keys
    }

    /// Mutable access to the key-pair set. Cached ciphers are dropped
    /// because a key may change.
    pub fn keys_mut(&mut self) -> &mut LinkKeyTable<N> {
        self.ciphers = [None, None];
        &mut self.keys
    }

    /// Entry for `partner`.
    pub fn entry(&self, partner: ExtendedAddress) -> Option<&LinkKeyEntry> {
        self.keys.get(partner)
    }

    /// Installs or replaces the entry for `entry.partner`.
    pub fn install(&mut self, entry: LinkKeyEntry) -> Result<(), LinkKeyEntry> {
        self.ciphers = [None, None];
        let partner = entry.partner;
        self.keys.remove(partner);
        self.keys.insert(entry)
    }

    /// Replaces the key of an existing entry, resetting its counters and
    /// setting the attributes (a transported or negotiated key).
    pub fn replace_key(
        &mut self,
        partner: ExtendedAddress,
        key: Key128,
        attributes: KeyAttributes,
        kind: LinkKeyKind,
    ) -> bool {
        self.ciphers = [None, None];
        match self.keys.get_mut(partner) {
            Some(e) => {
                e.key = key;
                e.attributes = attributes;
                e.kind = kind;
                e.incoming = 0;
                e.outgoing = panweave_security::frame_counter::OutgoingCounter::new();
                true
            }
            None => false,
        }
    }

    /// Renames the partner of an entry (a pre-installed Trust Center key
    /// whose owner became known, §4.6.3.1).
    pub fn rename(&mut self, from: ExtendedAddress, to: ExtendedAddress) -> bool {
        if from == to {
            return true;
        }
        if self.keys.get(from).is_none() {
            return false;
        }
        self.ciphers = [None, None];
        self.keys.remove(to);
        match self.keys.get_mut(from) {
            Some(e) => {
                e.partner = to;
                true
            }
            None => false,
        }
    }

    /// Removes the entry for `partner`.
    pub fn remove(&mut self, partner: ExtendedAddress) -> bool {
        self.ciphers = [None, None];
        self.keys.remove(partner)
    }

    /// Sets the key attributes of an entry.
    pub fn set_attributes(&mut self, partner: ExtendedAddress, attributes: KeyAttributes) -> bool {
        match self.keys.get_mut(partner) {
            Some(e) => {
                e.attributes = attributes;
                true
            }
            None => false,
        }
    }

    /// Resets the incoming frame counter of an entry (Confirm Key,
    /// §4.4.8.1.3 step 6).
    pub fn reset_incoming(&mut self, partner: ExtendedAddress) {
        if let Some(e) = self.keys.get_mut(partner) {
            e.incoming = 0;
        }
    }

    /// Answers an APS frame counter challenge from `partner`
    /// (§4.6.3.8.4): returns the outgoing counter, the challenge frame
    /// counter used and the MIC, or `None` without a key-pair entry.
    pub fn answer_challenge(
        &mut self,
        local: ExtendedAddress,
        partner: ExtendedAddress,
        challenge: u64,
    ) -> Option<(u32, u32, [u8; challenge::MIC_LEN])> {
        let e = self.keys.get_mut(partner)?;
        let outgoing = e.outgoing.peek();
        let challenge_fc = e.challenge_frame_counter;
        e.challenge_frame_counter = e.challenge_frame_counter.wrapping_add(1);
        let aad = challenge::response_authenticated_octets(local, challenge, outgoing);
        let mic = challenge::challenge_mic::<C>(&e.key, outgoing, local, challenge_fc, &aad);
        Some((outgoing, challenge_fc, mic))
    }

    /// Validates a challenge response from `partner` (§4.6.3.8.5) and,
    /// when it authenticates, marks the partner's counter verified with
    /// `aps_frame_counter` as the next acceptable value.
    pub fn validate_challenge(
        &mut self,
        partner: ExtendedAddress,
        challenge: u64,
        aps_frame_counter: u32,
        challenge_fc: u32,
        mic: &[u8; challenge::MIC_LEN],
    ) -> bool {
        let Some(e) = self.keys.get_mut(partner) else {
            return false;
        };
        let aad = challenge::response_authenticated_octets(partner, challenge, aps_frame_counter);
        let expected =
            challenge::challenge_mic::<C>(&e.key, aps_frame_counter, partner, challenge_fc, &aad);
        if !bool::from(expected.ct_eq(mic)) {
            return false;
        }
        e.incoming = aps_frame_counter;
        e.verified_frame_counter = true;
        true
    }

    /// Marks every entry's incoming counter unverified (after a reboot,
    /// §4.6.3.8).
    pub fn invalidate_frame_counters(&mut self) {
        for e in self.keys.iter_mut() {
            e.verified_frame_counter = false;
            e.challenge_frame_counter = 0;
        }
    }

    /// Finds an entry whose outgoing counter needs a reservation and
    /// starts it.
    pub fn start_counter_reservation(&mut self) -> Option<(ExtendedAddress, Reservation)> {
        for e in self.keys.iter_mut() {
            if let Some(r) = e.outgoing.start_reservation() {
                return Some((e.partner, r));
            }
        }
        None
    }

    /// Acknowledges a persisted reservation.
    pub fn commit_counter_reservation(&mut self, partner: ExtendedAddress, r: Reservation) {
        if let Some(e) = self.keys.get_mut(partner) {
            e.outgoing.commit_reservation(r);
        }
    }

    fn cipher_for(&mut self, partner: ExtendedAddress, key_id: KeyIdentifier) -> Option<&C> {
        if let Some(i) = self
            .ciphers
            .iter()
            .position(|c| matches!(c, Some((p, k, _)) if *p == partner && *k == key_id))
        {
            return self
                .ciphers
                .get(i)
                .and_then(|c| c.as_ref())
                .map(|(_, _, c)| c);
        }
        let entry = self.keys.get(partner)?;
        let key = match key_id {
            KeyIdentifier::Data => entry.key.clone(),
            KeyIdentifier::KeyTransport => key_hierarchy::key_transport_key::<C>(&entry.key),
            KeyIdentifier::KeyLoad => key_hierarchy::key_load_key::<C>(&entry.key),
            KeyIdentifier::Network => return None,
        };
        let slot = self.next_slot % 2;
        self.next_slot = self.next_slot.wrapping_add(1);
        let s = self.ciphers.get_mut(slot)?;
        *s = Some((partner, key_id, C::new(&key)));
        s.as_ref().map(|(_, _, c)| c)
    }

    /// Length of the auxiliary header for the given nonce choice.
    #[inline]
    pub const fn aux_header_len(extended_nonce: bool) -> usize {
        1 + 4 + if extended_nonce { 8 } else { 0 }
    }

    /// Secures the APS frame in `buf` (§4.4.1.1). `buf[..header_len]` is
    /// the APS header (security bit already set), the auxiliary header
    /// slot of [`Self::aux_header_len`] octets is reserved and the
    /// payload of `payload_len` octets follows. `partner` selects the
    /// key-pair entry, which must be PROVISIONAL or VERIFIED (§4.4.1.1
    /// step 1); `local_ieee` is the nonce source and, when
    /// `extended_nonce` is set, is carried in the auxiliary header.
    /// Returns the total secured length.
    #[allow(clippy::too_many_arguments)]
    pub fn secure_outgoing(
        &mut self,
        buf: &mut [u8],
        header_len: usize,
        payload_len: usize,
        level: SecurityLevel,
        partner: ExtendedAddress,
        key_id: KeyIdentifier,
        local_ieee: ExtendedAddress,
        extended_nonce: bool,
    ) -> Result<usize, SecureError> {
        if key_id == KeyIdentifier::Network {
            return Err(SecureError::NoKey);
        }
        let counter = {
            let e = self.keys.get_mut(partner).ok_or(SecureError::NoKey)?;
            if e.attributes == KeyAttributes::UnverifiedKey {
                return Err(SecureError::NoKey);
            }
            let c = e.outgoing.allocate().map_err(|err| match err {
                CounterError::Exhausted => SecureError::CounterExhausted,
                CounterError::ReservationRequired => SecureError::CounterPending,
            })?;
            // §4.6.3.8.2: the challenge frame counter restarts whenever
            // the outgoing counter advances.
            e.challenge_frame_counter = 0;
            c
        };
        let aux = AuxHeader::link(
            level,
            key_id,
            counter,
            if extended_nonce {
                Some(local_ieee)
            } else {
                None
            },
        );
        let cipher = self.cipher_for(partner, key_id).ok_or(SecureError::NoKey)?;
        frame::protect_in_place(cipher, &aux, local_ieee, buf, header_len, payload_len)
            .map_err(SecureError::Security)
    }

    /// Unprotects the incoming APS frame in `buf` (§4.4.1.2). `sender`
    /// is the sender's IEEE address as known from the NWK layer (used for
    /// the nonce and key lookup when the auxiliary header carries no
    /// extended nonce). When no entry exists for the sender and
    /// `fallback` names a pre-installed entry (a joined-but-unauthorized
    /// device's Trust Center key, step 2), that entry is used instead.
    pub fn unsecure_incoming(
        &mut self,
        buf: &mut [u8],
        header_len: usize,
        level: SecurityLevel,
        sender: Option<ExtendedAddress>,
        fallback: Option<ExtendedAddress>,
    ) -> Result<ApsUnsecured, SecurityError> {
        let aux = frame::peek_aux(buf, header_len)?;
        if aux.control.key_id == KeyIdentifier::Network {
            return Err(SecurityError::PolicyRejected);
        }
        if aux.frame_counter == FrameCounter::MAX {
            return Err(SecurityError::BadFrameCounter);
        }
        let source = aux.source.or(sender).ok_or(SecurityError::NoKey)?;
        let partner = if self.keys.get(source).is_some() {
            source
        } else {
            fallback
                .filter(|f| self.keys.get(*f).is_some())
                .ok_or(SecurityError::NoKey)?
        };
        let (kind, attributes) = {
            let e = self.keys.get(partner).ok_or(SecurityError::NoKey)?;
            if e.kind == LinkKeyKind::Unique && aux.frame_counter.0 < e.incoming {
                return Err(SecurityError::BadFrameCounter);
            }
            (e.kind, e.attributes)
        };
        let key_id = aux.control.key_id;
        let cipher = self
            .cipher_for(partner, key_id)
            .ok_or(SecurityError::NoKey)?;
        let u = frame::unprotect_in_place(cipher, level, source, buf, header_len)?;
        if let Some(e) = self.keys.get_mut(partner) {
            // §4.6.3.8: while the partner's counter is unverified and the
            // partner supports synchronization, nothing is stored and the
            // frame is dropped pending a challenge.
            if e.kind == LinkKeyKind::Unique && e.frame_counter_sync && !e.verified_frame_counter {
                return Err(SecurityError::UnverifiedFrameCounter);
            }
            e.incoming = aux.frame_counter.0.saturating_add(1);
        }
        Ok(ApsUnsecured {
            partner,
            key_id,
            extended_nonce: aux.control.extended_nonce,
            frame_counter: aux.frame_counter,
            kind,
            attributes,
            payload_start: u.payload_start,
            payload_end: u.payload_end,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_security::cipher::SoftwareAes;

    const A: ExtendedAddress = ExtendedAddress(0xAAAA);
    const B: ExtendedAddress = ExtendedAddress(0xBBBB);

    fn armed(partner: ExtendedAddress) -> ApsSecurity<SoftwareAes, 4> {
        let mut s = ApsSecurity::<SoftwareAes, 4>::new();
        let mut e =
            LinkKeyEntry::provisional(partner, Key128::from_bytes([9; 16]), LinkKeyKind::Unique);
        e.attributes = KeyAttributes::VerifiedKey;
        s.install(e).unwrap();
        let (p, r) = s.start_counter_reservation().unwrap();
        s.commit_counter_reservation(p, r);
        s
    }

    fn secure(
        tx: &mut ApsSecurity<SoftwareAes, 4>,
        local: ExtendedAddress,
        partner: ExtendedAddress,
        key_id: KeyIdentifier,
        ext: bool,
    ) -> ([u8; 64], usize) {
        let header = [0x21, 0x07];
        let mut buf = [0u8; 64];
        buf[..2].copy_from_slice(&header);
        let aux = ApsSecurity::<SoftwareAes, 4>::aux_header_len(ext);
        buf[2 + aux..2 + aux + 3].copy_from_slice(&[1, 2, 3]);
        let n = tx
            .secure_outgoing(
                &mut buf,
                2,
                3,
                SecurityLevel::EncMic32,
                partner,
                key_id,
                local,
                ext,
            )
            .unwrap();
        (buf, n)
    }

    #[test]
    fn data_key_round_trip_with_and_without_extended_nonce() {
        let mut a = armed(B);
        let mut b = armed(A);
        for ext in [false, true] {
            let (buf, n) = secure(&mut a, A, B, KeyIdentifier::Data, ext);
            let mut rx = buf;
            let u = b
                .unsecure_incoming(&mut rx[..n], 2, SecurityLevel::EncMic32, Some(A), None)
                .unwrap();
            assert_eq!(u.partner, A);
            assert_eq!(u.extended_nonce, ext);
            assert_eq!(&rx[u.payload_start..u.payload_end], &[1, 2, 3]);
            // Replay is rejected for unique keys.
            let mut replay = buf;
            assert_eq!(
                b.unsecure_incoming(&mut replay[..n], 2, SecurityLevel::EncMic32, Some(A), None),
                Err(SecurityError::BadFrameCounter)
            );
        }
    }

    #[test]
    fn derived_keys_and_fallback_entry() {
        let mut tc = armed(B);
        // Joiner only knows a pre-installed key under the placeholder.
        let mut joiner = armed(ExtendedAddress(u64::MAX));
        let (buf, n) = secure(&mut tc, A, B, KeyIdentifier::KeyTransport, true);
        let mut rx = buf;
        assert_eq!(
            joiner.unsecure_incoming(&mut rx[..n], 2, SecurityLevel::EncMic32, None, None),
            Err(SecurityError::NoKey)
        );
        let mut rx = buf;
        let u = joiner
            .unsecure_incoming(
                &mut rx[..n],
                2,
                SecurityLevel::EncMic32,
                None,
                Some(ExtendedAddress(u64::MAX)),
            )
            .unwrap();
        assert_eq!(u.key_id, KeyIdentifier::KeyTransport);
        assert_eq!(&rx[u.payload_start..u.payload_end], &[1, 2, 3]);
        assert!(joiner.rename(ExtendedAddress(u64::MAX), A));
        assert!(joiner.entry(A).is_some());
        // Key-load derivative differs from key-transport.
        let (buf2, n2) = secure(&mut tc, A, B, KeyIdentifier::KeyLoad, true);
        let mut rx = buf2;
        let u = joiner
            .unsecure_incoming(&mut rx[..n2], 2, SecurityLevel::EncMic32, None, None)
            .unwrap();
        assert_eq!(u.key_id, KeyIdentifier::KeyLoad);
    }

    #[test]
    fn unverified_key_cannot_encrypt_and_counter_needs_reservation() {
        let mut s = ApsSecurity::<SoftwareAes, 4>::new();
        s.install(LinkKeyEntry::provisional(
            B,
            Key128::ZERO,
            LinkKeyKind::Unique,
        ))
        .unwrap();
        let mut buf = [0u8; 32];
        assert_eq!(
            s.secure_outgoing(
                &mut buf,
                2,
                0,
                SecurityLevel::EncMic32,
                B,
                KeyIdentifier::Data,
                A,
                false
            ),
            Err(SecureError::CounterPending)
        );
        let (p, r) = s.start_counter_reservation().unwrap();
        s.commit_counter_reservation(p, r);
        assert!(s.set_attributes(B, KeyAttributes::UnverifiedKey));
        assert_eq!(
            s.secure_outgoing(
                &mut buf,
                2,
                0,
                SecurityLevel::EncMic32,
                B,
                KeyIdentifier::Data,
                A,
                false
            ),
            Err(SecureError::NoKey)
        );
        assert!(s.set_attributes(B, KeyAttributes::VerifiedKey));
        assert!(
            s.secure_outgoing(
                &mut buf,
                2,
                0,
                SecurityLevel::EncMic32,
                B,
                KeyIdentifier::Data,
                A,
                false
            )
            .is_ok()
        );
        // Network key identifier is never valid at the APS layer.
        assert_eq!(
            s.secure_outgoing(
                &mut buf,
                2,
                0,
                SecurityLevel::EncMic32,
                B,
                KeyIdentifier::Network,
                A,
                false
            ),
            Err(SecureError::NoKey)
        );
    }
}
