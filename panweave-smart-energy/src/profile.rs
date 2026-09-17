//! Smart Energy profile parameters (SE 1.4a §5.3): the startup, join,
//! end-device, concentrator and APS fragmentation values a Smart Energy
//! device configures its stack with. Values the profile leaves to the
//! stack profile are not repeated here.

use panweave_types::time::Duration;

/// Join parameters (Table 5-2).
pub mod join {
    use super::Duration;

    /// Scan attempts when joining or rejoining.
    pub const SCAN_ATTEMPTS: u8 = 3;
    /// Time between scan attempts.
    pub const TIME_BETWEEN_SCANS: Duration = Duration::from_secs(1);
    /// How quickly a disconnected device attempts to rejoin (upper bound
    /// on the first attempt).
    pub const REJOIN_INTERVAL: Duration = Duration::from_secs(60);
    /// Upper bound on the rejoin interval; restarted by user interaction.
    pub const MAX_REJOIN_INTERVAL: Duration = Duration::from_mins(15);
}

/// End-device parameters (Table 5-4).
pub mod end_device {
    use super::Duration;

    /// Recommended poll rate of an end device that expects data.
    pub const INDIRECT_POLL_RATE: Duration = Duration::from_secs(60);
}

/// Concentrator parameters (Table 5-6).
pub mod concentrator {
    /// Maximum concentrator radius.
    pub const RADIUS: u8 = 11;
}

/// APS fragmentation parameters (Table 5-8).
pub mod fragmentation {
    use super::Duration;

    /// `apsInterframeDelay`.
    pub const INTERFRAME_DELAY: Duration = Duration::from_millis(50);
    /// `apsMaxWindowSize`.
    pub const MAX_WINDOW_SIZE: u8 = 1;
    /// Default Maximum Incoming Transfer Size of the node descriptor.
    pub const MAX_INCOMING_TRANSFER_SIZE: u16 = 128;
}

/// Startup parameters (Table 5-1).
pub mod startup {
    /// Protocol version: Zigbee 2007 and later.
    pub const PROTOCOL_VERSION: u8 = 0x02;
    /// Startup Control of an uncommissioned device: join by association
    /// when instructed.
    pub const STARTUP_CONTROL_UNCOMMISSIONED: u8 = 2;
    /// Startup Control of a commissioned device: part of the network
    /// named by the extended PAN ID, no explicit join or rejoin.
    pub const STARTUP_CONTROL_COMMISSIONED: u8 = 0;
    /// Insecure join is never used as a fallback.
    pub const USE_INSECURE_JOIN: bool = false;
}

/// Time synchronization (§5.12.1.1): clients keep within this drift of
/// the ESI per 24 hours.
pub const TIME_ACCURACY_PER_DAY: Duration = Duration::from_secs(60);

/// Binding parameters (Table 5-9).
pub mod binding {
    use super::Duration;

    /// `EndDeviceBindTimeout` of the coordinator.
    pub const END_DEVICE_BIND_TIMEOUT: Duration = Duration::from_secs(60);
}

/// The stack settings a Smart Energy device applies (Tables 5-2, 5-4,
/// 5-6, 5-8, 5-9), gathered so a runtime configuration can be set from
/// one value; `PRESET` holds the profile's values.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Preset {
    /// `:Config_NWK_Scan_Attempts`.
    pub scan_attempts: u8,
    /// `:Config_NWK_Time_btwn_Scans`.
    pub time_between_scans: Duration,
    /// `:Config_Rejoin_Interval`.
    pub rejoin_interval: Duration,
    /// `:Config_Max_Rejoin_Interval`.
    pub max_rejoin_interval: Duration,
    /// Indirect poll rate of an end device.
    pub indirect_poll_rate: Duration,
    /// Concentrator radius of a coordinator / ESI.
    pub concentrator_radius: u8,
    /// `apsInterframeDelay`.
    pub interframe_delay: Duration,
    /// `apsMaxWindowSize`.
    pub max_window_size: u8,
    /// Node descriptor Maximum Incoming Transfer Size.
    pub max_incoming_transfer_size: u16,
    /// `EndDeviceBindTimeout`.
    pub end_device_bind_timeout: Duration,
}

/// The profile's values.
pub const PRESET: Preset = Preset {
    scan_attempts: join::SCAN_ATTEMPTS,
    time_between_scans: join::TIME_BETWEEN_SCANS,
    rejoin_interval: join::REJOIN_INTERVAL,
    max_rejoin_interval: join::MAX_REJOIN_INTERVAL,
    indirect_poll_rate: end_device::INDIRECT_POLL_RATE,
    concentrator_radius: concentrator::RADIUS,
    interframe_delay: fragmentation::INTERFRAME_DELAY,
    max_window_size: fragmentation::MAX_WINDOW_SIZE,
    max_incoming_transfer_size: fragmentation::MAX_INCOMING_TRANSFER_SIZE,
    end_device_bind_timeout: binding::END_DEVICE_BIND_TIMEOUT,
};

impl Preset {
    /// `:Config_NWK_Time_btwn_Scans` in octet durations (32 µs), the
    /// unit of the ZDO configuration attribute, saturated to the field.
    pub fn time_between_scans_octets(&self) -> u16 {
        let octets = self.time_between_scans.as_millis() * 1000 / 32;
        u16::try_from(octets).unwrap_or(u16::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_carries_the_table_values() {
        assert_eq!(PRESET.scan_attempts, 3);
        assert_eq!(PRESET.time_between_scans_octets(), 31_250);
        assert_eq!(PRESET.max_rejoin_interval.as_millis(), 15 * 60 * 1000);
        assert_eq!(PRESET.interframe_delay.as_millis(), 50);
        assert_eq!(PRESET.max_incoming_transfer_size, 128);
        assert_eq!(PRESET.end_device_bind_timeout.as_millis(), 60_000);
    }
}
