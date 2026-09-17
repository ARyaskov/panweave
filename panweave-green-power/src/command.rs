//! GPD command identifiers (GP Basic 1.1.2 §A.4.1, Tables 54–56).

/// Identify.
pub const IDENTIFY: u8 = 0x00;
/// Recall Scene 0 (0x10–0x17: scenes 0–7).
pub const RECALL_SCENE_0: u8 = 0x10;
/// Store Scene 0 (0x17–0x1E: scenes 0–7).
pub const STORE_SCENE_0: u8 = 0x17;
/// Off.
pub const OFF: u8 = 0x1F;
/// On.
pub const ON: u8 = 0x20;
/// Toggle.
pub const TOGGLE: u8 = 0x21;
/// Release.
pub const RELEASE: u8 = 0x22;
/// Move Up.
pub const MOVE_UP: u8 = 0x30;
/// Move Down.
pub const MOVE_DOWN: u8 = 0x31;
/// Step Up.
pub const STEP_UP: u8 = 0x32;
/// Step Down.
pub const STEP_DOWN: u8 = 0x33;
/// Level Control / Stop.
pub const LEVEL_STOP: u8 = 0x34;
/// Move Up (with On/Off).
pub const MOVE_UP_WITH_ON_OFF: u8 = 0x35;
/// Move Down (with On/Off).
pub const MOVE_DOWN_WITH_ON_OFF: u8 = 0x36;
/// Step Up (with On/Off).
pub const STEP_UP_WITH_ON_OFF: u8 = 0x37;
/// Step Down (with On/Off).
pub const STEP_DOWN_WITH_ON_OFF: u8 = 0x38;
/// Press 1 of 1.
pub const PRESS_1_OF_1: u8 = 0x60;
/// Release 1 of 1.
pub const RELEASE_1_OF_1: u8 = 0x61;
/// Attribute Reporting.
pub const ATTRIBUTE_REPORTING: u8 = 0xA0;
/// Manufacturer-specific Attribute Reporting.
pub const MANUFACTURER_ATTRIBUTE_REPORTING: u8 = 0xA1;
/// Multi-Cluster Reporting.
pub const MULTI_CLUSTER_REPORTING: u8 = 0xA2;
/// Manufacturer-specific Multi-Cluster Reporting.
pub const MANUFACTURER_MULTI_CLUSTER_REPORTING: u8 = 0xA3;
/// Request Attributes.
pub const REQUEST_ATTRIBUTES: u8 = 0xA4;
/// Read Attributes Response.
pub const READ_ATTRIBUTES_RESPONSE: u8 = 0xA5;
/// Manufacturer-defined GPD commands (0xB0–0xBF).
pub const MANUFACTURER_FIRST: u8 = 0xB0;
/// Last manufacturer-defined GPD command.
pub const MANUFACTURER_LAST: u8 = 0xBF;
/// Commissioning.
pub const COMMISSIONING: u8 = 0xE0;
/// Decommissioning.
pub const DECOMMISSIONING: u8 = 0xE1;
/// Success.
pub const SUCCESS: u8 = 0xE2;
/// Channel Request (Maintenance frame).
pub const CHANNEL_REQUEST: u8 = 0xE3;
/// Application Description.
pub const APPLICATION_DESCRIPTION: u8 = 0xE4;
/// Last of the reserved commissioning commands (0xE5–0xEF).
pub const COMMISSIONING_RANGE_LAST: u8 = 0xEF;
/// Commissioning Reply (to the GPD).
pub const COMMISSIONING_REPLY: u8 = 0xF0;
/// Write Attributes (to the GPD).
pub const WRITE_ATTRIBUTES: u8 = 0xF1;
/// Read Attributes (to the GPD).
pub const READ_ATTRIBUTES: u8 = 0xF2;
/// Channel Configuration (to the GPD, Maintenance frame).
pub const CHANNEL_CONFIGURATION: u8 = 0xF3;
/// First command reserved for the direction to the GPD (0xF0–0xFF).
pub const TO_GPD_FIRST: u8 = 0xF0;

/// True for the commands a GPD sends while commissioning: Commissioning,
/// Decommissioning, Success, Channel Request, Application Description and
/// the reserved 0xE5–0xEF (§A.3.5.2.3, §A.3.9.1 step 12).
pub const fn is_commissioning(id: u8) -> bool {
    id >= COMMISSIONING && id <= COMMISSIONING_RANGE_LAST
}

/// True for the commands defined in the direction to the GPD
/// (0xF0–0xFF); a GPD never sends them (§A.1.5.2.2).
pub const fn is_to_gpd(id: u8) -> bool {
    id >= TO_GPD_FIRST
}

/// True for the manufacturer-defined range 0xB0–0xBF.
pub const fn is_manufacturer_defined(id: u8) -> bool {
    id >= MANUFACTURER_FIRST && id <= MANUFACTURER_LAST
}
