//! Mandatory attributes and commands of the standard clusters (ZCL rev 8,
//! the "M/O" columns of the per-cluster tables), for validating an
//! endpoint composition. Conditionally mandatory items ("M*", mandatory
//! when a feature is supported) are not listed; a cluster with no
//! unconditional requirements has empty lists.
//!
//! Only the clusters with an implementation are covered; [`requirements`]
//! answers `None` for the others.

use panweave_types::{AttributeId, ClusterId, CommandId};

/// Unconditional requirements of one cluster.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ClusterRequirements {
    /// Cluster identifier.
    pub id: ClusterId,
    /// Specification section of the cluster.
    pub section: &'static str,
    /// Attributes a server SHALL implement.
    pub server_attributes: &'static [AttributeId],
    /// Cluster-specific commands a server SHALL receive.
    pub server_commands: &'static [CommandId],
    /// Cluster-specific commands a client SHALL receive.
    pub client_commands: &'static [CommandId],
}

macro_rules! attrs {
    ($($id:literal),* $(,)?) => { &[$(AttributeId($id)),*] };
}
macro_rules! cmds {
    ($($id:literal),* $(,)?) => { &[$(CommandId($id)),*] };
}

/// The requirements of every covered cluster.
pub const ALL: &[ClusterRequirements] = &[
    ClusterRequirements {
        id: ClusterId(0x0000),
        section: "ZCL §3.2",
        // ZCLVersion, PowerSource.
        server_attributes: attrs![0x0000, 0x0007],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0001),
        section: "ZCL §3.3",
        server_attributes: attrs![],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0002),
        section: "ZCL §3.4",
        // CurrentTemperature.
        server_attributes: attrs![0x0000],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0003),
        section: "ZCL §3.5",
        // IdentifyTime; Identify, Identify Query; Identify Query Response.
        server_attributes: attrs![0x0000],
        server_commands: cmds![0x00, 0x01],
        client_commands: cmds![0x00],
    },
    ClusterRequirements {
        id: ClusterId(0x0004),
        section: "ZCL §3.6",
        // NameSupport; Add .. Add Group If Identifying; the four responses.
        server_attributes: attrs![0x0000],
        server_commands: cmds![0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        client_commands: cmds![0x00, 0x01, 0x02, 0x03],
    },
    ClusterRequirements {
        id: ClusterId(0x0005),
        section: "ZCL §3.7",
        // SceneCount, CurrentScene, CurrentGroup, SceneValid, NameSupport;
        // Add .. Get Scene Membership; their responses.
        server_attributes: attrs![0x0000, 0x0001, 0x0002, 0x0003, 0x0004],
        server_commands: cmds![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        client_commands: cmds![0x00, 0x01, 0x02, 0x03, 0x04, 0x06],
    },
    ClusterRequirements {
        id: ClusterId(0x0006),
        section: "ZCL §3.8",
        // OnOff; Off, On, Toggle.
        server_attributes: attrs![0x0000],
        server_commands: cmds![0x00, 0x01, 0x02],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0007),
        section: "ZCL §3.9",
        // SwitchType, SwitchActions.
        server_attributes: attrs![0x0000, 0x0010],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0008),
        section: "ZCL §3.10",
        // CurrentLevel; Move to Level .. Stop (with On/Off).
        server_attributes: attrs![0x0000],
        server_commands: cmds![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x001c),
        section: "ZCL §3.10 (Pulse Width Modulation)",
        server_attributes: attrs![0x0000],
        server_commands: cmds![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0009),
        section: "ZCL §3.11",
        // Reset Alarm, Reset All Alarms; Alarm.
        server_attributes: attrs![],
        server_commands: cmds![0x00, 0x01],
        client_commands: cmds![0x00],
    },
    ClusterRequirements {
        id: ClusterId(0x000a),
        section: "ZCL §3.12",
        // Time, TimeStatus.
        server_attributes: attrs![0x0000, 0x0001],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0015),
        section: "ZCL §13.2",
        // Startup Parameters and Join Parameters mandatory attributes;
        // Restart Device, Reset Startup Parameters; the four responses.
        server_attributes: attrs![
            0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0010, 0x0012, 0x0013, 0x0014,
            0x0015, 0x0016, 0x0017
        ],
        server_commands: cmds![0x00, 0x03],
        client_commands: cmds![0x00, 0x01, 0x02, 0x03],
    },
    ClusterRequirements {
        id: ClusterId(0x001b),
        section: "ZCL §15.2",
        // StartTime, FinishTime; Signal State; Signal State Response /
        // Notification.
        server_attributes: attrs![0x0000, 0x0001],
        server_commands: cmds![0x01],
        client_commands: cmds![0x00, 0x01],
    },
    ClusterRequirements {
        id: ClusterId(0x0020),
        section: "ZCL §3.16",
        // Check-inInterval, LongPollInterval, ShortPollInterval,
        // FastPollTimeout; Check-in Response, Fast Poll Stop; Check-in.
        server_attributes: attrs![0x0000, 0x0001, 0x0002, 0x0003],
        server_commands: cmds![0x00, 0x01],
        client_commands: cmds![0x00],
    },
    ClusterRequirements {
        id: ClusterId(0x0025),
        section: "ZCL §3.18",
        // TC Keep-Alive Base, TC Keep-Alive Jitter.
        server_attributes: attrs![0x0000, 0x0001],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0100),
        section: "ZCL §7.2",
        // Status, ClosedLimit, Mode.
        server_attributes: attrs![0x0002, 0x0010, 0x0011],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0101),
        section: "ZCL §7.3",
        // LockState, LockType, ActuatorEnabled; Lock Door, Unlock Door;
        // their responses.
        server_attributes: attrs![0x0000, 0x0001, 0x0002],
        server_commands: cmds![0x00, 0x01],
        client_commands: cmds![0x00, 0x01],
    },
    ClusterRequirements {
        id: ClusterId(0x0102),
        section: "ZCL §7.4",
        // WindowCoveringType, ConfigStatus, Mode; Up/Open, Down/Close, Stop.
        server_attributes: attrs![0x0000, 0x0007, 0x0017],
        server_commands: cmds![0x00, 0x01, 0x02],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0103),
        section: "ZCL §7.5",
        // MovingState, SafetyStatus, Capabilities, BarrierPosition;
        // Go To Percent, Stop.
        server_attributes: attrs![0x0001, 0x0002, 0x0003, 0x000a],
        server_commands: cmds![0x00, 0x01],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0200),
        section: "ZCL §6.2",
        // MaxPressure, MaxSpeed, MaxFlow, EffectiveOperationMode,
        // EffectiveControlMode, Capacity, OperationMode.
        server_attributes: attrs![0x0000, 0x0001, 0x0002, 0x0011, 0x0012, 0x0013, 0x0020],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0201),
        section: "ZCL §6.3",
        // LocalTemperature, ControlSequenceOfOperation, SystemMode;
        // Setpoint Raise/Lower.
        server_attributes: attrs![0x0000, 0x001b, 0x001c],
        server_commands: cmds![0x00],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0202),
        section: "ZCL §6.4",
        // FanMode, FanModeSequence.
        server_attributes: attrs![0x0000, 0x0001],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0203),
        section: "ZCL §6.5",
        // DehumidificationCooling, RHDehumidificationSetpoint,
        // DehumidificationHysteresis, DehumidificationMaxCool.
        server_attributes: attrs![0x0001, 0x0010, 0x0013, 0x0014],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0204),
        section: "ZCL §6.6",
        // TemperatureDisplayMode, KeypadLockout.
        server_attributes: attrs![0x0000, 0x0001],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0300),
        section: "ZCL §5.2",
        // ColorMode, Options, EnhancedColorMode, ColorCapabilities; the
        // commands are mandatory per supported capability only.
        server_attributes: attrs![0x0008, 0x000f, 0x4001, 0x400a],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0301),
        section: "ZCL §5.3",
        // PhysicalMinLevel, PhysicalMaxLevel, MinLevel, MaxLevel.
        server_attributes: attrs![0x0000, 0x0001, 0x0010, 0x0011],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0400),
        section: "ZCL §4.2",
        // MeasuredValue, MinMeasuredValue, MaxMeasuredValue.
        server_attributes: attrs![0x0000, 0x0001, 0x0002],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0401),
        section: "ZCL §4.3",
        // LevelStatus.
        server_attributes: attrs![0x0000],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0402),
        section: "ZCL §4.4",
        server_attributes: attrs![0x0000, 0x0001, 0x0002],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0403),
        section: "ZCL §4.5",
        server_attributes: attrs![0x0000, 0x0001, 0x0002],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0404),
        section: "ZCL §4.6",
        server_attributes: attrs![0x0000, 0x0001, 0x0002],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0405),
        section: "ZCL §4.7",
        server_attributes: attrs![0x0000, 0x0001, 0x0002],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0406),
        section: "ZCL §4.8",
        // Occupancy, OccupancySensorType, OccupancySensorTypeBitmap.
        server_attributes: attrs![0x0000, 0x0001, 0x0002],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0500),
        section: "ZCL §8.2",
        // ZoneState, ZoneType, ZoneStatus, IAS_CIE_Address, ZoneID; Zone
        // Enroll Response; Zone Status Change Notification, Zone Enroll
        // Request.
        server_attributes: attrs![0x0000, 0x0001, 0x0002, 0x0010, 0x0011],
        server_commands: cmds![0x00],
        client_commands: cmds![0x00, 0x01],
    },
    ClusterRequirements {
        id: ClusterId(0x0501),
        section: "ZCL §8.3",
        // Arm .. Get Zone Status; Arm Response .. Get Zone Status Response.
        server_attributes: attrs![],
        server_commands: cmds![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
        client_commands: cmds![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    },
    ClusterRequirements {
        id: ClusterId(0x0502),
        section: "ZCL §8.4",
        // MaxDuration; Start Warning, Squawk.
        server_attributes: attrs![0x0000],
        server_commands: cmds![0x00, 0x01],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0b00),
        section: "ZCL §15.3",
        // BasicIdentification.
        server_attributes: attrs![0x0000],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0b01),
        section: "ZCL §10.13",
        // CompanyName, MeterTypeID, DataQualityID, POD, AvailablePower,
        // PowerThreshold.
        server_attributes: attrs![0x0000, 0x0001, 0x0004, 0x000c, 0x000d, 0x000e],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0b02),
        section: "ZCL §15.4",
        // Get Alerts; Get Alerts Response, Alerts Notification, Event
        // Notification.
        server_attributes: attrs![],
        server_commands: cmds![0x00],
        client_commands: cmds![0x00, 0x01, 0x02],
    },
    ClusterRequirements {
        id: ClusterId(0x0b03),
        section: "ZCL §15.5",
        // LogMaxSize, LogQueueMaxSize; Log Request, Log Queue Request;
        // Log Notification .. Statistics Available.
        server_attributes: attrs![0x0000, 0x0001],
        server_commands: cmds![0x00, 0x01],
        client_commands: cmds![0x00, 0x01, 0x02, 0x03],
    },
    ClusterRequirements {
        id: ClusterId(0x0b04),
        section: "ZCL §4.9",
        // MeasurementType.
        server_attributes: attrs![0x0000],
        server_commands: cmds![],
        client_commands: cmds![],
    },
    ClusterRequirements {
        id: ClusterId(0x0b05),
        section: "ZCL §3.15",
        server_attributes: attrs![],
        server_commands: cmds![],
        client_commands: cmds![],
    },
];

/// Requirements of `id`, when covered.
pub fn requirements(id: ClusterId) -> Option<&'static ClusterRequirements> {
    ALL.iter().find(|r| r.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_unique_and_sorted_within_entries() {
        for (i, r) in ALL.iter().enumerate() {
            assert!(
                ALL.iter().skip(i.saturating_add(1)).all(|o| o.id != r.id),
                "{:?} listed twice",
                r.id
            );
            assert!(r.server_attributes.is_sorted(), "{:?}", r.id);
            assert!(r.server_commands.is_sorted(), "{:?}", r.id);
            assert!(r.client_commands.is_sorted(), "{:?}", r.id);
        }
        assert!(requirements(ClusterId(0x0006)).is_some());
        assert!(requirements(ClusterId(0xfc00)).is_none());
    }
}
