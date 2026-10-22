//! ESP32-C6 diagnostics and USB transport helpers, testable on the host.

use crate::protocol::ResetKind;

/// Writes one short USB Serial/JTAG packet, without blocking.
///
/// Full 64-byte packets can remain buffered by the host until a short
/// packet terminates the transfer. The board flushes after this helper;
/// limiting the payload to 63 bytes makes every flushed packet short,
/// including responses whose wire length is a multiple of 64. Empty
/// queues do not produce packets. Refused bytes remain in the session.
#[cfg(feature = "engine")]
pub fn transmit_usb_chunk<const TX: usize>(
    session: &mut crate::Session<TX>,
    mut write: impl FnMut(u8) -> bool,
) -> usize {
    let mut sent = 0;
    session.transmit(|b| {
        if sent == 63 || !write(b) {
            return false;
        }
        sent += 1;
        true
    })
}

/// The name of an ESP32-C6 reset reason code as the ROM reports it
/// (`esp_hal::rtc_cntl::SocResetReason` for the ESP32-C6).
pub const fn reset_reason_name(raw: u8) -> &'static str {
    match raw {
        0x01 => "power-on",
        0x03 => "core software reset",
        0x05 => "deep-sleep wake-up",
        0x06 => "SDIO reset",
        0x07 => "core MWDT0 watchdog",
        0x08 => "core MWDT1 watchdog",
        0x09 => "core RTC watchdog",
        0x0b => "CPU0 MWDT0 watchdog",
        0x0c => "CPU0 software reset",
        0x0d => "CPU0 RTC watchdog",
        0x0f => "brown-out",
        0x10 => "system RTC watchdog",
        0x11 => "CPU0 MWDT1 watchdog",
        0x12 => "super watchdog",
        0x14 => "eFuse CRC error",
        0x15 => "USB UART reset",
        0x16 => "USB-JTAG reset (flashing tool or serial control lines)",
        0x18 => "JTAG CPU reset",
        _ => "unknown",
    }
}

/// Classifies an ESP32-C6 reset reason code; `None` (unreadable) is
/// [`ResetKind::UnknownResetReason`].
pub const fn classify_reset(raw: Option<u8>) -> ResetKind {
    match raw {
        Some(0x01) => ResetKind::ColdBoot,
        Some(0x03 | 0x0c) => ResetKind::SoftwareReset,
        Some(0x07 | 0x08 | 0x09 | 0x0b | 0x0d | 0x10 | 0x11 | 0x12) => ResetKind::WatchdogReset,
        Some(0x05 | 0x06 | 0x0f | 0x14 | 0x15 | 0x16 | 0x18) => ResetKind::OtherReset,
        _ => ResetKind::UnknownResetReason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_reasons_are_classified_from_the_rom_codes() {
        assert_eq!(classify_reset(Some(0x01)), ResetKind::ColdBoot);
        assert_eq!(classify_reset(Some(0x0c)), ResetKind::SoftwareReset);
        // The RTC watchdog the hub arms (and a panic, which it ends in).
        assert_eq!(classify_reset(Some(0x10)), ResetKind::WatchdogReset);
        assert_eq!(classify_reset(Some(0x12)), ResetKind::WatchdogReset);
        // A flashing tool's DTR/RTS reset is not a power-on.
        assert_eq!(classify_reset(Some(0x16)), ResetKind::OtherReset);
        assert_eq!(classify_reset(Some(0x0f)), ResetKind::OtherReset);
        assert_eq!(classify_reset(Some(0x42)), ResetKind::UnknownResetReason);
        assert_eq!(classify_reset(None), ResetKind::UnknownResetReason);
        assert_eq!(reset_reason_name(0x0f), "brown-out");
        assert_eq!(reset_reason_name(0x42), "unknown");
    }
}
