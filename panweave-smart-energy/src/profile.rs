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
