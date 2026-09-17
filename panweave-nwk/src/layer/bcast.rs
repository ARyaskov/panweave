//! Broadcast communication (R23.2 §3.6.6): broadcast transaction records,
//! passive acknowledgement, jittered relay and retransmission, unicast
//! copies to sleepy children.

use heapless::Vec;
use panweave_security::cipher::BlockCipher;
use panweave_types::{Instant, Rng, ShortAddress, ShortAddressKind};

use super::{BroadcastBuf, NpduBuf, Nwk, NwkAction, NwkError, PendingTx, TxKind};
use crate::broadcast::{BroadcastRecord, PASSIVE_ACK_TRACKED};
use crate::nib::constants;

impl<
    C: BlockCipher,
    R: Rng,
    const NEIGHBORS: usize,
    const ROUTES: usize,
    const RDT: usize,
    const BTT: usize,
> Nwk<C, R, NEIGHBORS, ROUTES, RDT, BTT>
{
    /// Router neighbors expected to relay a broadcast (passive ack set).
    fn passive_ack_set(&self, exclude: ShortAddress) -> Vec<ShortAddress, PASSIVE_ACK_TRACKED> {
        let mut v = Vec::new();
        if !self.config.passive_ack {
            return v;
        }
        for n in self.neighbors.routers() {
            if n.short != exclude && n.outgoing_cost != 0 && n.short.is_unicast() {
                let _ = v.push(n.short);
            }
        }
        v
    }

    /// Originates a broadcast from the higher layer or the NWK layer
    /// itself.
    pub(crate) fn originate_broadcast(
        &mut self,
        plaintext: NpduBuf,
        header_len: usize,
        secure: bool,
    ) -> Result<(), NwkError> {
        let src = self.nib.network_address;
        let sequence = *plaintext.get(7).unwrap_or(&0);
        let dst = ShortAddress(u16::from_le_bytes([
            *plaintext.get(2).unwrap_or(&0xFF),
            *plaintext.get(3).unwrap_or(&0xFF),
        ]));
        let on_air = match self.finalize_frame(&plaintext, header_len, secure) {
            Ok(f) => f,
            Err(NwkError::CounterPending) => {
                // Park the plaintext until the reservation is committed.
                if self.nib.is_end_device() {
                    return Err(NwkError::Busy);
                }
                let record = BroadcastRecord {
                    source: src,
                    sequence,
                    expires: self.now + self.nib.network_broadcast_delivery_time,
                    awaiting: self.passive_ack_set(ShortAddress::NO_SHORT_ADDRESS),
                    retries: 0,
                    next_tx: Some(self.now + super::tx::COUNTER_RETRY_DELAY),
                    relay_pending: true,
                };
                if self.btt.insert(record, self.now).is_none() {
                    return Err(NwkError::Busy);
                }
                self.store_broadcast_buf(BroadcastBuf {
                    source: src,
                    sequence,
                    frame: NpduBuf::new(),
                    plaintext: Some((plaintext, header_len, secure)),
                });
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        if self.nib.is_end_device() {
            // End devices send to their parent and keep no BTT (§3.6.6).
            let handle = self.alloc_mac_handle();
            self.push_action(NwkAction::MacData {
                handle,
                dst: self.nib.parent_address,
                frame: on_air,
                ack: true,
                indirect: false,
            });
            return Ok(());
        }
        let record = BroadcastRecord {
            source: src,
            sequence,
            expires: self.now + self.nib.network_broadcast_delivery_time,
            awaiting: self.passive_ack_set(ShortAddress::NO_SHORT_ADDRESS),
            retries: 0,
            next_tx: None,
            relay_pending: true,
        };
        if self.btt.insert(record, self.now).is_none() {
            return Err(NwkError::Busy);
        }
        self.transmit_broadcast(
            src,
            sequence,
            on_air,
            dst,
            true,
            Some((plaintext, header_len, secure)),
        )
    }

    /// Transmits (or retransmits) a broadcast and arms the passive-ack
    /// timer.
    ///
    /// `own` carries the plaintext of a broadcast this device originates:
    /// its copies for sleepy children are then secured only when each
    /// child polls (fresh counters, §3.6.2.2). Relayed broadcasts keep
    /// the originator's protection and are copied as received.
    fn transmit_broadcast(
        &mut self,
        src: ShortAddress,
        sequence: u8,
        on_air: NpduBuf,
        dst: ShortAddress,
        first: bool,
        own: Option<(NpduBuf, usize, bool)>,
    ) -> Result<(), NwkError> {
        let handle = self.alloc_mac_handle();
        self.push_action(NwkAction::MacData {
            handle,
            dst: ShortAddress::BROADCAST_ALL,
            frame: on_air.clone(),
            ack: false,
            indirect: false,
        });
        // Unicast copies for sleepy end-device children (§3.6.6, all
        // devices broadcast only).
        let mut sleepy: Vec<ShortAddress, 8> = Vec::new();
        if first && dst.kind() == ShortAddressKind::BroadcastAll {
            for n in self.neighbors.end_device_children() {
                if !n.rx_on_when_idle && n.short != src {
                    let _ = sleepy.push(n.short);
                }
            }
        }
        for child in &sleepy {
            if let Some((plaintext, header_len, secure)) = &own {
                let id = self.alloc_tx_id();
                let _ = self.transmit_pending(PendingTx {
                    id,
                    frame: plaintext.clone(),
                    header_len: *header_len,
                    dst: *child,
                    next_hop: *child,
                    mac_handle: None,
                    retries_left: 0,
                    retry_at: None,
                    awaiting_route: false,
                    secure: *secure,
                    indirect: true,
                    relayed_from: None,
                    source_route: false,
                    kind: TxKind::Command,
                    created: self.now,
                });
                continue;
            }
            let handle = self.alloc_mac_handle();
            self.push_action(NwkAction::MacData {
                handle,
                dst: *child,
                frame: on_air.clone(),
                ack: true,
                indirect: true,
            });
        }
        let retries = self.nib.max_broadcast_retries;
        let timeout = self.nib.passive_ack_timeout;
        let now = self.now;
        if let Some(rec) = self.btt.get_mut(src, sequence) {
            rec.next_tx = if rec.retries < retries {
                Some(now + timeout)
            } else {
                None
            };
        }
        // Keep the on-air copy for retransmission.
        if let Some(b) = self
            .bcast_bufs
            .iter_mut()
            .find(|b| b.source == src && b.sequence == sequence)
        {
            b.frame = on_air;
            b.plaintext = None;
        } else {
            self.store_broadcast_buf(BroadcastBuf {
                source: src,
                sequence,
                frame: on_air,
                plaintext: None,
            });
        }
        Ok(())
    }

    /// Stores a broadcast buffer, dropping the oldest when full.
    fn store_broadcast_buf(&mut self, buf: BroadcastBuf) {
        if let Some(b) = self
            .bcast_bufs
            .iter_mut()
            .find(|b| b.source == buf.source && b.sequence == buf.sequence)
        {
            *b = buf;
            return;
        }
        if self.bcast_bufs.is_full() {
            let _ = self.bcast_bufs.remove(0);
        }
        let _ = self.bcast_bufs.push(buf);
    }

    /// Handles a received broadcast. Returns true when the frame must be
    /// delivered to the higher layer (first reception).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn on_broadcast_received(
        &mut self,
        src: ShortAddress,
        sequence: u8,
        dst: ShortAddress,
        radius: u8,
        mac_src: ShortAddress,
        buf: &[u8],
        header_len: usize,
        payload_start: usize,
        payload_end: usize,
        secured: bool,
    ) -> bool {
        if !self.in_broadcast_group(dst) {
            return false;
        }
        let my = self.nib.network_address;
        // Own broadcast echoed back (or address conflict, §3.6.1.10.2).
        if src == my {
            if let Some(rec) = self.btt.get_mut(src, sequence) {
                rec.passive_ack(mac_src);
                return false;
            }
            let operating_long_enough = self.operating_since.is_some_and(|t| {
                self.now
                    .has_reached(t + self.nib.network_broadcast_delivery_time)
            });
            if operating_long_enough && secured && self.nib.is_router_or_coordinator() {
                self.on_local_address_conflict();
            }
            return false;
        }
        if let Some(rec) = self.btt.get_mut(src, sequence) {
            rec.passive_ack(mac_src);
            return false;
        }
        // Sleepy end devices keep no BTT and never relay.
        if self.nib.is_end_device() {
            return true;
        }
        let awaiting = self.passive_ack_set(mac_src);
        let record = BroadcastRecord {
            source: src,
            sequence,
            expires: self.now + self.nib.network_broadcast_delivery_time,
            awaiting,
            retries: 0,
            next_tx: None,
            relay_pending: false,
        };
        if self.btt.insert(record, self.now).is_none() {
            // Table full: drop without delivery or relay (§3.6.6).
            return false;
        }
        // Relay after jitter when we are a started router and the radius
        // permits (radius is decremented once on reception).
        if self.nib.is_router_or_coordinator() && self.nib.router_started && radius > 1 {
            let mut plaintext = NpduBuf::new();
            let ok = plaintext
                .extend_from_slice(buf.get(..header_len).unwrap_or(&[]))
                .is_ok()
                && plaintext
                    .extend_from_slice(buf.get(payload_start..payload_end).unwrap_or(&[]))
                    .is_ok();
            if ok {
                if let Some(r) = plaintext.get_mut(6) {
                    *r = radius - 1;
                }
                if let Some(b) = plaintext.get_mut(1) {
                    *b &= !0x22; // clear security + end device initiator
                }
                // Security is applied at transmission time (the relay copy
                // may still wait for a counter reservation).
                let jitter = self.jitter(
                    panweave_types::Duration::ZERO,
                    constants::MAX_BROADCAST_JITTER,
                );
                let due = self.now + jitter;
                if let Some(rec) = self.btt.get_mut(src, sequence) {
                    rec.relay_pending = true;
                    rec.next_tx = Some(due);
                    rec.retries = 0;
                }
                self.store_broadcast_buf(BroadcastBuf {
                    source: src,
                    sequence,
                    frame: NpduBuf::new(),
                    plaintext: Some((plaintext, header_len, secured)),
                });
                self.stats.broadcasts_relayed = self.stats.broadcasts_relayed.saturating_add(1);
            }
        }
        true
    }

    /// Timer service for broadcasts: jittered relays, passive-ack
    /// retransmissions, expiry.
    pub(crate) fn service_broadcasts(&mut self, now: Instant) {
        let retries_max = self.nib.max_broadcast_retries;
        let mut due: Vec<(ShortAddress, u8), 8> = Vec::new();
        for rec in self.btt.iter() {
            if let Some(t) = rec.next_tx
                && now.has_reached(t)
            {
                let _ = due.push((rec.source, rec.sequence));
            }
        }
        for (src, seq) in due {
            let Some(rec) = self.btt.get_mut(src, seq) else {
                continue;
            };
            let first = rec.relay_pending;
            let done = !first && (rec.fully_acknowledged() || rec.retries >= retries_max);
            if done {
                rec.next_tx = None;
                self.bcast_bufs
                    .retain(|b| !(b.source == src && b.sequence == seq));
                continue;
            }
            if !first {
                rec.retries += 1;
            }
            rec.relay_pending = false;
            // Secure a parked plaintext now; if the counter is still
            // pending, try again shortly without consuming a retry.
            let parked = self
                .bcast_bufs
                .iter()
                .find(|b| b.source == src && b.sequence == seq)
                .and_then(|b| b.plaintext.clone());
            let own = parked.clone();
            if let Some((plain, header_len, secure)) = parked {
                match self.finalize_frame(&plain, header_len, secure) {
                    Ok(on_air) => {
                        if let Some(b) = self
                            .bcast_bufs
                            .iter_mut()
                            .find(|b| b.source == src && b.sequence == seq)
                        {
                            b.frame = on_air;
                            b.plaintext = None;
                        }
                    }
                    Err(NwkError::CounterPending) => {
                        if let Some(rec) = self.btt.get_mut(src, seq) {
                            rec.relay_pending = true;
                            rec.next_tx = Some(now + super::tx::COUNTER_RETRY_DELAY);
                        }
                        continue;
                    }
                    Err(_) => {
                        self.bcast_bufs
                            .retain(|b| !(b.source == src && b.sequence == seq));
                        continue;
                    }
                }
            }
            let frame = self
                .bcast_bufs
                .iter()
                .find(|b| b.source == src && b.sequence == seq)
                .map(|b| b.frame.clone());
            if let Some(frame) = frame
                && !frame.is_empty()
            {
                let dst = ShortAddress(u16::from_le_bytes([
                    *frame.get(2).unwrap_or(&0xFF),
                    *frame.get(3).unwrap_or(&0xFF),
                ]));
                let _ = self.transmit_broadcast(src, seq, frame, dst, first, own);
            } else if let Some(rec) = self.btt.get_mut(src, seq) {
                rec.next_tx = None;
            }
        }
        // Expire records and buffers.
        self.btt.expire(now);
        let btt = &self.btt;
        self.bcast_bufs
            .retain(|b| btt.get(b.source, b.sequence).is_some());
    }
}
