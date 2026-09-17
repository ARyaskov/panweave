//! ZDO configuration attributes (R23.2 §2.5.5, Table 2-134 / 2-135): the
//! `:Config_*` values a device is provisioned with. The descriptors
//! (`:Config_Node_Descriptor`, `:Config_Power_Descriptor`,
//! `:Config_Simple_Descriptors`) live in the [`crate::Zdo`] instance; the
//! remaining attributes are collected here with their default values and
//! consumed by the runtime's network manager.

use panweave_types::time::Duration;

/// Duration of one octet at 250 kb/s (`OctetDuration`, 32 µs) — the unit
/// of `:Config_NWK_Time_btwn_Scans`.
pub const OCTET_DURATION_US: u64 = 32;

/// The provisioned ZDO attributes of Table 2-134.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConfigAttributes {
    /// `:Config_NWK_Scan_Attempts` (mandatory): discovery attempts before
    /// giving up on finding a parent; default 5, valid 1–255.
    pub scan_attempts: u8,
    /// `:Config_NWK_Time_btwn_Scans` (mandatory) in octet durations;
    /// default 0x0C35.
    pub time_between_scans_octets: u16,
    /// `:Config_Permit_Join_Duration` (optional): seconds passed to
    /// NLME-PERMIT-JOINING when the application gives none; default 0
    /// (closed).
    pub permit_join_duration: u8,
    /// `:Config_Max_Bind` (optional): binding table capacity advertised
    /// to the application.
    pub max_bind: u8,
    /// `:Config_Parent_Link_Retry_Threshold` (optional): failed
    /// transmissions to the parent before a rejoin; default 3.
    pub parent_link_retry_threshold: u8,
    /// `:Config_Rejoin_Interval` (optional) in seconds between rejoin
    /// attempts of an end device that lost its parent; default 60.
    pub rejoin_interval_secs: u16,
    /// `:Config_Max_Rejoin_Interval` (optional): upper bound of the
    /// exponential back-off; default 3600.
    pub max_rejoin_interval_secs: u16,
}

impl ConfigAttributes {
    /// Table 2-135 defaults.
    pub const DEFAULT: ConfigAttributes = ConfigAttributes {
        scan_attempts: 5,
        time_between_scans_octets: 0x0C35,
        permit_join_duration: 0,
        max_bind: 8,
        parent_link_retry_threshold: 3,
        rejoin_interval_secs: 60,
        max_rejoin_interval_secs: 3600,
    };

    /// `:Config_NWK_Time_btwn_Scans` as a duration (rounded up to a
    /// millisecond).
    pub const fn time_between_scans(&self) -> Duration {
        let us = self.time_between_scans_octets as u64 * OCTET_DURATION_US;
        Duration::from_millis(us.div_ceil(1000))
    }
}

impl Default for ConfigAttributes {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_follow_table_2_135() {
        let c = ConfigAttributes::DEFAULT;
        assert_eq!(c.scan_attempts, 5);
        assert_eq!(c.time_between_scans_octets, 0x0C35);
        // 3125 octet durations × 32 µs = 100 ms.
        assert_eq!(c.time_between_scans(), Duration::from_millis(100));
    }
}
