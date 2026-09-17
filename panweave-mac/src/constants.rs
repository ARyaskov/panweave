//! PHY and MAC constants for the IEEE 802.15.4 2.4 GHz O-QPSK PHY as used
//! by Zigbee (R23.2 Annex D.8, D.9; IEEE 802.15.4-2015 §8.4.2, §11.3).
//!
//! Timing constants are expressed in symbols (16 µs each on this PHY) and
//! converted with [`symbols_to_duration`].

use panweave_types::Duration;

/// Symbol period on the 2.4 GHz O-QPSK PHY, in microseconds.
pub const SYMBOL_PERIOD_US: u64 = 16;

/// Maximum PHY packet size (`aMaxPHYPacketSize`).
pub const MAX_PHY_PACKET_SIZE: usize = 127;

/// Length of the frame check sequence appended by the PHY.
pub const FCS_LEN: usize = 2;

/// Maximum MAC frame size excluding the FCS.
pub const MAX_MAC_FRAME_SIZE: usize = MAX_PHY_PACKET_SIZE - FCS_LEN;

/// `aMaxMPDUUnsecuredOverhead`: largest unsecured MAC header + FCS.
pub const MAX_MPDU_UNSECURED_OVERHEAD: usize = 25;

/// `aMaxMACSafePayloadSize`: payload that fits with the largest header.
pub const MAX_MAC_SAFE_PAYLOAD_SIZE: usize = MAX_PHY_PACKET_SIZE - MAX_MPDU_UNSECURED_OVERHEAD;

/// `aBaseSlotDuration` in symbols.
pub const BASE_SLOT_DURATION_SYMBOLS: u64 = 60;

/// `aNumSuperframeSlots`.
pub const NUM_SUPERFRAME_SLOTS: u64 = 16;

/// `aBaseSuperframeDuration` in symbols (960).
pub const BASE_SUPERFRAME_DURATION_SYMBOLS: u64 = BASE_SLOT_DURATION_SYMBOLS * NUM_SUPERFRAME_SLOTS;

/// `macAckWaitDuration` for the unslotted 2.4 GHz PHY, in symbols
/// (aUnitBackoffPeriod + aTurnaroundTime + phySHRDuration + 6 symbols
/// of PHY header/payload = 20 + 12 + 10 + 12).
pub const ACK_WAIT_DURATION_SYMBOLS: u64 = 54;

/// `macMaxFrameRetries` default.
pub const MAX_FRAME_RETRIES: u8 = 3;

/// `macResponseWaitTime` default in multiples of `aBaseSuperframeDuration`
/// (32).
pub const RESPONSE_WAIT_TIME_MULTIPLIER: u64 = 32;

/// `macTransactionPersistenceTime` default in multiples of
/// `aBaseSuperframeDuration` (0x01F4).
pub const TRANSACTION_PERSISTENCE_TIME_MULTIPLIER: u64 = 0x01F4;

/// `macMaxCSMABackoffs` default.
pub const MAX_CSMA_BACKOFFS: u8 = 4;

/// `macMinBE` default (3 per R23.2 Annex D.8).
pub const MIN_BE: u8 = 3;

/// `macMaxBE` default.
pub const MAX_BE: u8 = 5;

/// Beacon order / superframe order value meaning "non-beacon PAN".
pub const NON_BEACON_ORDER: u8 = 15;

/// Broadcast short address at the MAC layer.
pub const MAC_BROADCAST_SHORT: u16 = 0xFFFF;

/// Converts a symbol count to a millisecond [`Duration`], rounding up.
#[inline]
pub const fn symbols_to_duration(symbols: u64) -> Duration {
    Duration::from_millis(symbols.saturating_mul(SYMBOL_PERIOD_US).saturating_add(999) / 1000)
}

/// Duration of an active or energy scan on one channel for scan duration
/// exponent `n`: `aBaseSuperframeDuration * (2^n + 1)` symbols.
///
/// `n` is clamped to `0..=14`.
#[inline]
pub const fn scan_duration_per_channel(n: u8) -> Duration {
    let n = if n > 14 { 14 } else { n };
    symbols_to_duration(BASE_SUPERFRAME_DURATION_SYMBOLS * ((1u64 << n) + 1))
}

/// `macResponseWaitTime` as a duration (~491 ms).
#[inline]
pub const fn response_wait_time() -> Duration {
    symbols_to_duration(RESPONSE_WAIT_TIME_MULTIPLIER * BASE_SUPERFRAME_DURATION_SYMBOLS)
}

/// `macTransactionPersistenceTime` as a duration (~7.7 s).
#[inline]
pub const fn transaction_persistence_time() -> Duration {
    symbols_to_duration(TRANSACTION_PERSISTENCE_TIME_MULTIPLIER * BASE_SUPERFRAME_DURATION_SYMBOLS)
}

/// `macAckWaitDuration` as a duration (rounded up to 1 ms).
#[inline]
pub const fn ack_wait_duration() -> Duration {
    symbols_to_duration(ACK_WAIT_DURATION_SYMBOLS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timing_constants() {
        assert_eq!(symbols_to_duration(960).as_millis(), 16);
        // Scan duration n=3: 960 * 9 symbols = 138.24 ms → 139.
        assert_eq!(scan_duration_per_channel(3).as_millis(), 139);
        assert_eq!(scan_duration_per_channel(99), scan_duration_per_channel(14));
        assert_eq!(response_wait_time().as_millis(), 492);
        assert_eq!(transaction_persistence_time().as_millis(), 7680);
        assert_eq!(ack_wait_duration().as_millis(), 1);
        assert_eq!(MAX_MAC_SAFE_PAYLOAD_SIZE, 102);
    }
}
