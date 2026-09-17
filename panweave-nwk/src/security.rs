//! NWK frame security processing (R23.2 §4.3.1) on top of
//! `panweave-security`.
//!
//! Outgoing frames use the active network key, the shared outgoing frame
//! counter and an extended nonce with the local IEEE address (§4.3.1.1).
//! Incoming frames select the key by sequence number, enforce per-sender
//! frame-counter freshness (§4.3.1.2) and restore the level bits.

use panweave_security::aux_header::{AuxHeader, SecurityLevel};
use panweave_security::cipher::BlockCipher;
use panweave_security::frame::{self, SecurityError};
use panweave_security::frame_counter::{FreshnessError, IncomingCounters, Reservation};
use panweave_security::material::NetworkKeys;
use panweave_types::{ExtendedAddress, FrameCounter, Key128, KeySequenceNumber};

/// NWK security state: keys, counters and cached cipher instances.
pub struct NwkSecurity<C: BlockCipher, const N: usize> {
    /// Network keys and the outgoing frame counter.
    pub keys: NetworkKeys,
    /// Incoming frame counters per sender.
    pub incoming: IncomingCounters<N>,
    ciphers: [Option<(KeySequenceNumber, C)>; 2],
}

/// Result of unprotecting an incoming NWK frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Unsecured {
    /// Sender IEEE address from the auxiliary header.
    pub sender: ExtendedAddress,
    /// Key sequence number used.
    pub key_sequence: KeySequenceNumber,
    /// Received frame counter.
    pub frame_counter: FrameCounter,
    /// Start of the plaintext payload in the buffer.
    pub payload_start: usize,
    /// End (exclusive) of the plaintext payload.
    pub payload_end: usize,
}

impl<C: BlockCipher, const N: usize> Default for NwkSecurity<C, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: BlockCipher, const N: usize> NwkSecurity<C, N> {
    /// Empty state (no keys).
    pub const fn new() -> Self {
        NwkSecurity {
            keys: NetworkKeys::new(),
            incoming: IncomingCounters::new(),
            ciphers: [None, None],
        }
    }

    /// Installs a network key and makes it active.
    pub fn install_active_key(&mut self, sequence: KeySequenceNumber, key: Key128) {
        self.keys.install_active(sequence, key);
        self.ciphers = [None, None];
    }

    /// Installs an alternate (not yet active) network key.
    pub fn install_key(&mut self, sequence: KeySequenceNumber, key: Key128) {
        self.keys.install(sequence, key);
        self.ciphers = [None, None];
    }

    /// Switches the active key (APSME-SWITCH-KEY, §4.6.3.4): resets
    /// incoming counters and applies the outgoing counter rule. Returns
    /// false when the sequence is unknown.
    pub fn switch_key(&mut self, sequence: KeySequenceNumber) -> bool {
        if self.keys.active_sequence() == Some(sequence) {
            return true;
        }
        if !self.keys.switch_to(sequence) {
            return false;
        }
        self.incoming.reset_all();
        true
    }

    /// True when an active key is installed.
    pub fn has_key(&self) -> bool {
        self.keys.has_active()
    }

    /// Active key sequence number.
    pub fn active_sequence(&self) -> Option<KeySequenceNumber> {
        self.keys.active_sequence()
    }

    /// Removes all keys (leave without rejoin). The outgoing counter is
    /// preserved (§4.3.4).
    pub fn clear_keys(&mut self) {
        self.keys.clear_keys();
        self.incoming.reset_all();
        self.ciphers = [None, None];
    }

    fn cipher_for(&mut self, sequence: KeySequenceNumber) -> Option<&C> {
        let idx = self
            .ciphers
            .iter()
            .position(|c| matches!(c, Some((s, _)) if *s == sequence));
        let idx = match idx {
            Some(i) => i,
            None => {
                let key = self.keys.get(sequence)?.key.clone();
                let slot = self.ciphers.iter().position(Option::is_none).unwrap_or(1);
                self.ciphers[slot] = Some((sequence, C::new(&key)));
                slot
            }
        };
        self.ciphers[idx].as_ref().map(|(_, c)| c)
    }

    /// Pending outgoing-counter reservation to persist, if any.
    pub fn start_counter_reservation(&mut self) -> Option<Reservation> {
        self.keys.outgoing.start_reservation()
    }

    /// Acknowledges a persisted reservation.
    pub fn commit_counter_reservation(&mut self, r: Reservation) {
        self.keys.outgoing.commit_reservation(r);
    }

    /// Restores the persisted outgoing counter bound.
    pub fn restore_outgoing_counter(&mut self, reserved_until: u32) {
        self.keys.outgoing =
            panweave_security::frame_counter::OutgoingCounter::restore(reserved_until);
    }

    /// Secures the NWK frame in `buf` (header at `..header_len`, the
    /// auxiliary header slot reserved, payload of `payload_len` bytes
    /// following). Returns the total secured length.
    pub fn secure_outgoing(
        &mut self,
        buf: &mut [u8],
        header_len: usize,
        payload_len: usize,
        level: SecurityLevel,
        local_ieee: ExtendedAddress,
    ) -> Result<usize, SecurityError> {
        let sequence = self.keys.active_sequence().ok_or(SecurityError::NoKey)?;
        let counter = self
            .keys
            .outgoing
            .allocate()
            .map_err(|_| SecurityError::FrameCounter)?;
        let aux = AuxHeader::network(level, counter, local_ieee, sequence);
        let cipher = self.cipher_for(sequence).ok_or(SecurityError::NoKey)?;
        frame::protect_in_place(cipher, &aux, local_ieee, buf, header_len, payload_len)
    }

    /// Length of the auxiliary header written by [`Self::secure_outgoing`].
    pub const fn aux_header_len() -> usize {
        1 + 4 + 8 + 1
    }

    /// Unprotects the incoming secured frame in `buf` and records the
    /// sender's frame counter on success.
    pub fn unsecure_incoming(
        &mut self,
        buf: &mut [u8],
        header_len: usize,
        level: SecurityLevel,
        all_fresh: bool,
    ) -> Result<Unsecured, SecurityError> {
        let aux = frame::peek_aux(buf, header_len)?;
        let sequence = aux.key_sequence.ok_or(SecurityError::Malformed)?;
        let sender = aux.source.ok_or(SecurityError::Malformed)?;
        if aux.frame_counter == FrameCounter::MAX {
            return Err(SecurityError::BadFrameCounter);
        }
        if !self.incoming.is_fresh(sender, aux.frame_counter) {
            return Err(SecurityError::BadFrameCounter);
        }
        let cipher = self.cipher_for(sequence).ok_or(SecurityError::NoKey)?;
        let u = frame::unprotect_in_place(cipher, level, sender, buf, header_len)?;
        match self
            .incoming
            .check_and_update(sender, aux.frame_counter, all_fresh)
        {
            Ok(()) => {}
            Err(FreshnessError::TableFull) => return Err(SecurityError::PolicyRejected),
            Err(_) => return Err(SecurityError::BadFrameCounter),
        }
        Ok(Unsecured {
            sender,
            key_sequence: sequence,
            frame_counter: aux.frame_counter,
            payload_start: u.payload_start,
            payload_end: u.payload_end,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_security::cipher::SoftwareAes;

    fn armed() -> NwkSecurity<SoftwareAes, 4> {
        let mut s = NwkSecurity::<SoftwareAes, 4>::new();
        s.install_active_key(KeySequenceNumber(0), Key128::from_bytes([1; 16]));
        let r = s.start_counter_reservation().unwrap();
        s.commit_counter_reservation(r);
        s
    }

    #[test]
    fn secure_then_unsecure_with_freshness() {
        let mut tx = armed();
        let mut rx = armed();
        let me = ExtendedAddress(0xAA);
        let header = [0x08, 0x02, 0x01, 0x00, 0x02, 0x00, 30, 1];
        let mut buf = [0u8; 64];
        buf[..8].copy_from_slice(&header);
        let ps = 8 + NwkSecurity::<SoftwareAes, 4>::aux_header_len();
        buf[ps..ps + 3].copy_from_slice(&[1, 2, 3]);
        let n = tx
            .secure_outgoing(&mut buf, 8, 3, SecurityLevel::EncMic32, me)
            .unwrap();
        let mut rxbuf = buf;
        let u = rx
            .unsecure_incoming(&mut rxbuf[..n], 8, SecurityLevel::EncMic32, true)
            .unwrap();
        assert_eq!(u.sender, me);
        assert_eq!(u.frame_counter, FrameCounter(0));
        assert_eq!(&rxbuf[u.payload_start..u.payload_end], &[1, 2, 3]);
        // Replay of the same frame is rejected.
        let mut replay = buf;
        assert_eq!(
            rx.unsecure_incoming(&mut replay[..n], 8, SecurityLevel::EncMic32, true),
            Err(SecurityError::BadFrameCounter)
        );
        // Unknown key sequence is rejected.
        let mut other = NwkSecurity::<SoftwareAes, 4>::new();
        other.install_active_key(KeySequenceNumber(5), Key128::from_bytes([2; 16]));
        let mut b2 = buf;
        assert_eq!(
            other.unsecure_incoming(&mut b2[..n], 8, SecurityLevel::EncMic32, true),
            Err(SecurityError::NoKey)
        );
    }

    #[test]
    fn counter_reservation_gates_transmission() {
        let mut s = NwkSecurity::<SoftwareAes, 4>::new();
        s.install_active_key(KeySequenceNumber(0), Key128::ZERO);
        let mut buf = [0u8; 40];
        assert_eq!(
            s.secure_outgoing(&mut buf, 8, 0, SecurityLevel::EncMic32, ExtendedAddress(1)),
            Err(SecurityError::FrameCounter)
        );
        let r = s.start_counter_reservation().unwrap();
        s.commit_counter_reservation(r);
        assert!(
            s.secure_outgoing(&mut buf, 8, 0, SecurityLevel::EncMic32, ExtendedAddress(1))
                .is_ok()
        );
        assert!(s.switch_key(KeySequenceNumber(0)));
        assert!(!s.switch_key(KeySequenceNumber(1)));
        s.install_key(KeySequenceNumber(1), Key128::from_bytes([3; 16]));
        assert!(s.switch_key(KeySequenceNumber(1)));
        assert_eq!(s.active_sequence(), Some(KeySequenceNumber(1)));
    }
}
