//! Touchlink Commissioning cluster (ZCL8 §13.3): the inter-PAN
//! commissioning commands (scan, device information, identify, reset to
//! factory new, network start / join / update and their responses) and
//! the utility commands (endpoint information, get group identifiers,
//! get endpoint list) as codecs, plus the cluster constants. The
//! procedures that drive them live in `panweave-bdb::touchlink`; the
//! network key transport in `panweave-security::touchlink`.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{ClusterId, CommandId, ProfileId};

use crate::cluster::{ClusterDef, ClusterInstance, Role};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x1000);
/// Profile identifier of the inter-PAN commissioning commands
/// (§13.3.4.1); the utility commands use the Home Automation profile.
pub const PROFILE_ID: ProfileId = ProfileId(0xc05e);

/// `aplcInterPANTransIdLifetime` in milliseconds (Table 13-21).
pub const TRANSACTION_LIFETIME_MS: u64 = 8_000;
/// `aplcMinStartupDelayTime` in milliseconds.
pub const MIN_STARTUP_DELAY_MS: u64 = 2_000;
/// `aplcRxWindowDuration` in milliseconds.
pub const RX_WINDOW_MS: u64 = 5_000;
/// `aplcScanTimeBaseDuration` in milliseconds.
pub const SCAN_TIME_BASE_MS: u64 = 250;

/// Scan Request.
pub const CMD_SCAN_REQUEST: CommandId = CommandId(0x00);
/// Scan Response.
pub const CMD_SCAN_RESPONSE: CommandId = CommandId(0x01);
/// Device Information Request.
pub const CMD_DEVICE_INFORMATION_REQUEST: CommandId = CommandId(0x02);
/// Device Information Response.
pub const CMD_DEVICE_INFORMATION_RESPONSE: CommandId = CommandId(0x03);
/// Identify Request.
pub const CMD_IDENTIFY_REQUEST: CommandId = CommandId(0x06);
/// Reset To Factory New Request.
pub const CMD_RESET_TO_FACTORY_NEW_REQUEST: CommandId = CommandId(0x07);
/// Network Start Request.
pub const CMD_NETWORK_START_REQUEST: CommandId = CommandId(0x10);
/// Network Start Response.
pub const CMD_NETWORK_START_RESPONSE: CommandId = CommandId(0x11);
/// Network Join Router Request.
pub const CMD_NETWORK_JOIN_ROUTER_REQUEST: CommandId = CommandId(0x12);
/// Network Join Router Response.
pub const CMD_NETWORK_JOIN_ROUTER_RESPONSE: CommandId = CommandId(0x13);
/// Network Join End Device Request.
pub const CMD_NETWORK_JOIN_END_DEVICE_REQUEST: CommandId = CommandId(0x14);
/// Network Join End Device Response.
pub const CMD_NETWORK_JOIN_END_DEVICE_RESPONSE: CommandId = CommandId(0x15);
/// Network Update Request.
pub const CMD_NETWORK_UPDATE_REQUEST: CommandId = CommandId(0x16);
/// Endpoint Information.
pub const CMD_ENDPOINT_INFORMATION: CommandId = CommandId(0x40);
/// Get Group Identifiers Request.
pub const CMD_GET_GROUP_IDENTIFIERS_REQUEST: CommandId = CommandId(0x41);
/// Get Group Identifiers Response.
pub const CMD_GET_GROUP_IDENTIFIERS_RESPONSE: CommandId = CommandId(0x41);
/// Get Endpoint List Request.
pub const CMD_GET_ENDPOINT_LIST_REQUEST: CommandId = CommandId(0x42);
/// Get Endpoint List Response.
pub const CMD_GET_ENDPOINT_LIST_RESPONSE: CommandId = CommandId(0x42);

/// Cluster definition.
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 2,
    received: &[
        CMD_SCAN_REQUEST,
        CMD_DEVICE_INFORMATION_REQUEST,
        CMD_IDENTIFY_REQUEST,
        CMD_RESET_TO_FACTORY_NEW_REQUEST,
        CMD_NETWORK_START_REQUEST,
        CMD_NETWORK_JOIN_ROUTER_REQUEST,
        CMD_NETWORK_JOIN_END_DEVICE_REQUEST,
        CMD_NETWORK_UPDATE_REQUEST,
        CMD_GET_GROUP_IDENTIFIERS_REQUEST,
        CMD_GET_ENDPOINT_LIST_REQUEST,
    ],
    generated: &[
        CMD_SCAN_RESPONSE,
        CMD_DEVICE_INFORMATION_RESPONSE,
        CMD_NETWORK_START_RESPONSE,
        CMD_NETWORK_JOIN_ROUTER_RESPONSE,
        CMD_NETWORK_JOIN_END_DEVICE_RESPONSE,
        CMD_ENDPOINT_INFORMATION,
        CMD_GET_GROUP_IDENTIFIERS_RESPONSE,
        CMD_GET_ENDPOINT_LIST_RESPONSE,
    ],
};

/// Builds a server instance (no attributes).
pub fn server<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF, Role::Server)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF, Role::Client)
}

/// ZigBee Information field (Figure 13-9 / 13-21).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ZigbeeInfo {
    /// Logical type: 0 coordinator, 1 router, 2 end device.
    pub logical_type: u8,
    /// `RxOnWhenIdle`.
    pub rx_on_when_idle: bool,
}

impl ZigbeeInfo {
    /// Router.
    pub const ROUTER: ZigbeeInfo = ZigbeeInfo {
        logical_type: 1,
        rx_on_when_idle: true,
    };

    const fn raw(self) -> u8 {
        (self.logical_type & 0x03) | ((self.rx_on_when_idle as u8) << 2)
    }

    const fn from_raw(v: u8) -> ZigbeeInfo {
        ZigbeeInfo {
            logical_type: v & 0x03,
            rx_on_when_idle: v & 0x04 != 0,
        }
    }

    /// Whether the device is a router.
    pub const fn is_router(self) -> bool {
        self.logical_type == 1
    }
}

/// Touchlink Information field (Figures 13-10 / 13-22).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TouchlinkInfo {
    /// Factory new.
    pub factory_new: bool,
    /// Address assignment capable.
    pub address_assignment: bool,
    /// Link initiator (request) / touchlink initiator (response).
    pub initiator: bool,
    /// Priority request (response only).
    pub priority_request: bool,
    /// Profile Interop (Zigbee 3.0) rather than the ZLL profile.
    pub profile_interop: bool,
}

impl TouchlinkInfo {
    const fn raw(self) -> u8 {
        (self.factory_new as u8)
            | ((self.address_assignment as u8) << 1)
            | ((self.initiator as u8) << 4)
            | ((self.priority_request as u8) << 5)
            | ((self.profile_interop as u8) << 7)
    }

    const fn from_raw(v: u8) -> TouchlinkInfo {
        TouchlinkInfo {
            factory_new: v & 0x01 != 0,
            address_assignment: v & 0x02 != 0,
            initiator: v & 0x10 != 0,
            priority_request: v & 0x20 != 0,
            profile_interop: v & 0x80 != 0,
        }
    }
}

/// Scan Request (§13.3.2.2.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ScanRequest {
    /// Transaction identifier (non-zero).
    pub transaction: u32,
    /// ZigBee information of the initiator.
    pub zigbee: ZigbeeInfo,
    /// Touchlink information of the initiator.
    pub touchlink: TouchlinkInfo,
}

impl ScanRequest {
    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.transaction)?;
        w.u8(self.zigbee.raw())?;
        w.u8(self.touchlink.raw())
    }

    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(ScanRequest {
            transaction: r.u32_le()?,
            zigbee: ZigbeeInfo::from_raw(r.u8()?),
            touchlink: TouchlinkInfo::from_raw(r.u8()?),
        })
    }
}

/// The single sub-device fields of a Scan Response (present when the
/// number of sub-devices is 1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SubDevice {
    /// Endpoint.
    pub endpoint: u8,
    /// Profile identifier.
    pub profile: u16,
    /// Device identifier.
    pub device: u16,
    /// Device version (low nibble).
    pub version: u8,
    /// Group identifiers required.
    pub group_count: u8,
}

/// Scan Response (§13.3.2.3.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ScanResponse {
    /// Transaction identifier.
    pub transaction: u32,
    /// RSSI correction (0–0x20).
    pub rssi_correction: u8,
    /// ZigBee information of the target.
    pub zigbee: ZigbeeInfo,
    /// Touchlink information of the target.
    pub touchlink: TouchlinkInfo,
    /// Key bitmask (bit i: key index i supported).
    pub key_bitmask: u16,
    /// Response identifier (random).
    pub response: u32,
    /// Extended PAN identifier (current or proposed; 0 none).
    pub extended_pan_id: u64,
    /// `nwkUpdateId` (0 when factory new).
    pub update_id: u8,
    /// Logical channel.
    pub channel: u8,
    /// PAN identifier.
    pub pan_id: u16,
    /// Network address (0xffff when factory new).
    pub network_address: u16,
    /// Number of sub-devices.
    pub sub_devices: u8,
    /// Total group identifiers required.
    pub total_groups: u8,
    /// The sub-device, when exactly one.
    pub sub_device: Option<SubDevice>,
}

impl ScanResponse {
    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.transaction)?;
        w.u8(self.rssi_correction)?;
        w.u8(self.zigbee.raw())?;
        w.u8(self.touchlink.raw())?;
        w.u16_le(self.key_bitmask)?;
        w.u32_le(self.response)?;
        w.u64_le(self.extended_pan_id)?;
        w.u8(self.update_id)?;
        w.u8(self.channel)?;
        w.u16_le(self.pan_id)?;
        w.u16_le(self.network_address)?;
        w.u8(self.sub_devices)?;
        w.u8(self.total_groups)?;
        if self.sub_devices == 1 {
            let d = self.sub_device.ok_or(CodecError::Unrepresentable {
                field: "sub-device",
            })?;
            w.u8(d.endpoint)?;
            w.u16_le(d.profile)?;
            w.u16_le(d.device)?;
            w.u8(d.version & 0x0f)?;
            w.u8(d.group_count)?;
        }
        Ok(())
    }

    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        let transaction = r.u32_le()?;
        let rssi_correction = r.u8()?;
        let zigbee = ZigbeeInfo::from_raw(r.u8()?);
        let touchlink = TouchlinkInfo::from_raw(r.u8()?);
        let key_bitmask = r.u16_le()?;
        let response = r.u32_le()?;
        let extended_pan_id = r.u64_le()?;
        let update_id = r.u8()?;
        let channel = r.u8()?;
        let pan_id = r.u16_le()?;
        let network_address = r.u16_le()?;
        let sub_devices = r.u8()?;
        let total_groups = r.u8()?;
        let sub_device = if sub_devices == 1 {
            Some(SubDevice {
                endpoint: r.u8()?,
                profile: r.u16_le()?,
                device: r.u16_le()?,
                version: r.u8()? & 0x0f,
                group_count: r.u8()?,
            })
        } else {
            None
        };
        Ok(ScanResponse {
            transaction,
            rssi_correction,
            zigbee,
            touchlink,
            key_bitmask,
            response,
            extended_pan_id,
            update_id,
            channel,
            pan_id,
            network_address,
            sub_devices,
            total_groups,
            sub_device,
        })
    }
}

/// Device Information Request (§13.3.2.2.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceInformationRequest {
    /// Transaction identifier.
    pub transaction: u32,
    /// Start index into the device information table.
    pub start_index: u8,
}

impl DeviceInformationRequest {
    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.transaction)?;
        w.u8(self.start_index)
    }

    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(DeviceInformationRequest {
            transaction: r.u32_le()?,
            start_index: r.u8()?,
        })
    }
}

/// A device information record (Figure 13-24 / 13-33).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceRecord {
    /// IEEE address.
    pub ieee: u64,
    /// Endpoint.
    pub endpoint: u8,
    /// Profile identifier.
    pub profile: u16,
    /// Device identifier.
    pub device: u16,
    /// Device version (low nibble).
    pub version: u8,
    /// Group identifiers required.
    pub group_count: u8,
    /// Sort tag (0: unsorted).
    pub sort: u8,
}

/// Records per Device Information Response (§13.3.2.3.2.4).
pub const MAX_DEVICE_RECORDS: usize = 5;

/// Device Information Response (§13.3.2.3.2).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceInformationResponse {
    /// Transaction identifier.
    pub transaction: u32,
    /// Number of sub-devices of the node.
    pub sub_devices: u8,
    /// Start index echoed.
    pub start_index: u8,
    /// Records.
    pub records: Vec<DeviceRecord, MAX_DEVICE_RECORDS>,
}

impl DeviceInformationResponse {
    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.transaction)?;
        w.u8(self.sub_devices)?;
        w.u8(self.start_index)?;
        w.u8(u8::try_from(self.records.len()).unwrap_or(0))?;
        for d in &self.records {
            w.u64_le(d.ieee)?;
            w.u8(d.endpoint)?;
            w.u16_le(d.profile)?;
            w.u16_le(d.device)?;
            w.u8(d.version & 0x0f)?;
            w.u8(d.group_count)?;
            w.u8(d.sort)?;
        }
        Ok(())
    }

    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        let transaction = r.u32_le()?;
        let sub_devices = r.u8()?;
        let start_index = r.u8()?;
        let n = r.u8()?;
        if usize::from(n) > MAX_DEVICE_RECORDS {
            return Err(CodecError::InvalidField {
                field: "device information record count",
                value: u32::from(n),
            });
        }
        let mut records = Vec::new();
        for _ in 0..n {
            let d = DeviceRecord {
                ieee: r.u64_le()?,
                endpoint: r.u8()?,
                profile: r.u16_le()?,
                device: r.u16_le()?,
                version: r.u8()? & 0x0f,
                group_count: r.u8()?,
                sort: r.u8()?,
            };
            let _ = records.push(d);
        }
        Ok(DeviceInformationResponse {
            transaction,
            sub_devices,
            start_index,
            records,
        })
    }
}

/// Identify Request (§13.3.2.2.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct IdentifyRequest {
    /// Transaction identifier.
    pub transaction: u32,
    /// Duration: 0 exit, 1–0xfffe seconds, 0xffff default.
    pub duration: u16,
}

/// Identify for the receiver's default time.
pub const IDENTIFY_DEFAULT: u16 = 0xffff;

impl IdentifyRequest {
    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.transaction)?;
        w.u16_le(self.duration)
    }

    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(IdentifyRequest {
            transaction: r.u32_le()?,
            duration: r.u16_le()?,
        })
    }
}

/// Reads a transaction-identifier-only payload (Reset To Factory New
/// Request, §13.3.2.2.4).
pub fn parse_transaction(payload: &[u8]) -> Result<u32, CodecError> {
    Reader::new(payload).u32_le()
}

/// Network parameters carried by the start / join requests.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetworkAssignment {
    /// Network address assigned to the target.
    pub network_address: u16,
    /// Group identifiers begin (0: none).
    pub groups_begin: u16,
    /// Group identifiers end.
    pub groups_end: u16,
    /// Free network address range begin (0: none).
    pub free_addresses_begin: u16,
    /// Free network address range end.
    pub free_addresses_end: u16,
    /// Free group identifier range begin (0: none).
    pub free_groups_begin: u16,
    /// Free group identifier range end.
    pub free_groups_end: u16,
}

impl NetworkAssignment {
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.network_address)?;
        w.u16_le(self.groups_begin)?;
        w.u16_le(self.groups_end)?;
        w.u16_le(self.free_addresses_begin)?;
        w.u16_le(self.free_addresses_end)?;
        w.u16_le(self.free_groups_begin)?;
        w.u16_le(self.free_groups_end)
    }

    fn parse(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(NetworkAssignment {
            network_address: r.u16_le()?,
            groups_begin: r.u16_le()?,
            groups_end: r.u16_le()?,
            free_addresses_begin: r.u16_le()?,
            free_addresses_end: r.u16_le()?,
            free_groups_begin: r.u16_le()?,
            free_groups_end: r.u16_le()?,
        })
    }
}

/// Network Start Request (§13.3.2.2.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetworkStartRequest {
    /// Transaction identifier.
    pub transaction: u32,
    /// Extended PAN identifier (0: target chooses).
    pub extended_pan_id: u64,
    /// Key index.
    pub key_index: u8,
    /// Encrypted network key.
    pub encrypted_key: [u8; 16],
    /// Logical channel (0: target chooses).
    pub channel: u8,
    /// PAN identifier (0: target chooses).
    pub pan_id: u16,
    /// Address and group assignment.
    pub assignment: NetworkAssignment,
    /// Initiator IEEE address.
    pub initiator_ieee: u64,
    /// Initiator network address.
    pub initiator_address: u16,
}

impl NetworkStartRequest {
    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.transaction)?;
        w.u64_le(self.extended_pan_id)?;
        w.u8(self.key_index)?;
        w.bytes(&self.encrypted_key)?;
        w.u8(self.channel)?;
        w.u16_le(self.pan_id)?;
        self.assignment.encode(w)?;
        w.u64_le(self.initiator_ieee)?;
        w.u16_le(self.initiator_address)
    }

    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(NetworkStartRequest {
            transaction: r.u32_le()?,
            extended_pan_id: r.u64_le()?,
            key_index: r.u8()?,
            encrypted_key: r.array::<16>()?,
            channel: r.u8()?,
            pan_id: r.u16_le()?,
            assignment: NetworkAssignment::parse(&mut r)?,
            initiator_ieee: r.u64_le()?,
            initiator_address: r.u16_le()?,
        })
    }
}

/// Network Start Response (§13.3.2.3.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetworkStartResponse {
    /// Transaction identifier.
    pub transaction: u32,
    /// Status: 0 success, 1 failure.
    pub status: u8,
    /// Extended PAN identifier of the new network.
    pub extended_pan_id: u64,
    /// `nwkUpdateId` (0).
    pub update_id: u8,
    /// Logical channel.
    pub channel: u8,
    /// PAN identifier.
    pub pan_id: u16,
}

impl NetworkStartResponse {
    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.transaction)?;
        w.u8(self.status)?;
        w.u64_le(self.extended_pan_id)?;
        w.u8(self.update_id)?;
        w.u8(self.channel)?;
        w.u16_le(self.pan_id)
    }

    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(NetworkStartResponse {
            transaction: r.u32_le()?,
            status: r.u8()?,
            extended_pan_id: r.u64_le()?,
            update_id: r.u8()?,
            channel: r.u8()?,
            pan_id: r.u16_le()?,
        })
    }
}

/// Network Join Router / End Device Request (§13.3.2.2.6 / .7, same
/// format).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetworkJoinRequest {
    /// Transaction identifier.
    pub transaction: u32,
    /// Extended PAN identifier.
    pub extended_pan_id: u64,
    /// Key index.
    pub key_index: u8,
    /// Encrypted network key.
    pub encrypted_key: [u8; 16],
    /// `nwkUpdateId` of the initiator.
    pub update_id: u8,
    /// Logical channel.
    pub channel: u8,
    /// PAN identifier.
    pub pan_id: u16,
    /// Address and group assignment.
    pub assignment: NetworkAssignment,
}

impl NetworkJoinRequest {
    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.transaction)?;
        w.u64_le(self.extended_pan_id)?;
        w.u8(self.key_index)?;
        w.bytes(&self.encrypted_key)?;
        w.u8(self.update_id)?;
        w.u8(self.channel)?;
        w.u16_le(self.pan_id)?;
        self.assignment.encode(w)
    }

    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(NetworkJoinRequest {
            transaction: r.u32_le()?,
            extended_pan_id: r.u64_le()?,
            key_index: r.u8()?,
            encrypted_key: r.array::<16>()?,
            update_id: r.u8()?,
            channel: r.u8()?,
            pan_id: r.u16_le()?,
            assignment: NetworkAssignment::parse(&mut r)?,
        })
    }
}

/// A status response (Network Join Router / End Device Response,
/// §13.3.2.3.4 / .5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct StatusResponse {
    /// Transaction identifier.
    pub transaction: u32,
    /// Status: 0 success, 1 failure.
    pub status: u8,
}

/// Success.
pub const STATUS_SUCCESS: u8 = 0;
/// Failure.
pub const STATUS_FAILURE: u8 = 1;

impl StatusResponse {
    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.transaction)?;
        w.u8(self.status)
    }

    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(StatusResponse {
            transaction: r.u32_le()?,
            status: r.u8()?,
        })
    }
}

/// Network Update Request (§13.3.2.2.8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetworkUpdateRequest {
    /// Transaction identifier.
    pub transaction: u32,
    /// Extended PAN identifier.
    pub extended_pan_id: u64,
    /// `nwkUpdateId` of the initiator.
    pub update_id: u8,
    /// Logical channel.
    pub channel: u8,
    /// PAN identifier.
    pub pan_id: u16,
    /// Network address of the target.
    pub network_address: u16,
}

impl NetworkUpdateRequest {
    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.transaction)?;
        w.u64_le(self.extended_pan_id)?;
        w.u8(self.update_id)?;
        w.u8(self.channel)?;
        w.u16_le(self.pan_id)?;
        w.u16_le(self.network_address)
    }

    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(NetworkUpdateRequest {
            transaction: r.u32_le()?,
            extended_pan_id: r.u64_le()?,
            update_id: r.u8()?,
            channel: r.u8()?,
            pan_id: r.u16_le()?,
            network_address: r.u16_le()?,
        })
    }
}

/// Endpoint Information (§13.3.2.3.6).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EndpointInformation {
    /// IEEE address of the sender.
    pub ieee: u64,
    /// Network address of the sender.
    pub network_address: u16,
    /// Endpoint.
    pub endpoint: u8,
    /// Profile identifier.
    pub profile: u16,
    /// Device identifier.
    pub device: u16,
    /// Device version (low nibble).
    pub version: u8,
}

impl EndpointInformation {
    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u64_le(self.ieee)?;
        w.u16_le(self.network_address)?;
        w.u8(self.endpoint)?;
        w.u16_le(self.profile)?;
        w.u16_le(self.device)?;
        w.u8(self.version & 0x0f)
    }

    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        Ok(EndpointInformation {
            ieee: r.u64_le()?,
            network_address: r.u16_le()?,
            endpoint: r.u8()?,
            profile: r.u16_le()?,
            device: r.u16_le()?,
            version: r.u8()? & 0x0f,
        })
    }
}

/// A group identifier record of Get Group Identifiers Response.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GroupRecord {
    /// Group identifier.
    pub group: u16,
    /// Group type (0).
    pub group_type: u8,
}

/// Records per Get Group Identifiers Response kept here.
pub const MAX_GROUP_RECORDS: usize = 8;

/// Get Group Identifiers Response (§13.3.2.3.7).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetGroupIdentifiersResponse {
    /// Total group identifiers of the endpoint.
    pub total: u8,
    /// Start index echoed.
    pub start_index: u8,
    /// Records.
    pub records: Vec<GroupRecord, MAX_GROUP_RECORDS>,
}

impl GetGroupIdentifiersResponse {
    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.total)?;
        w.u8(self.start_index)?;
        w.u8(u8::try_from(self.records.len()).unwrap_or(0))?;
        for g in &self.records {
            w.u16_le(g.group)?;
            w.u8(g.group_type)?;
        }
        Ok(())
    }

    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        let total = r.u8()?;
        let start_index = r.u8()?;
        let n = r.u8()?;
        let mut records = Vec::new();
        for _ in 0..n {
            let g = GroupRecord {
                group: r.u16_le()?,
                group_type: r.u8()?,
            };
            records.push(g).map_err(|_| CodecError::Unrepresentable {
                field: "group records",
            })?;
        }
        Ok(GetGroupIdentifiersResponse {
            total,
            start_index,
            records,
        })
    }
}

/// An endpoint record of Get Endpoint List Response.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EndpointRecord {
    /// Network address.
    pub network_address: u16,
    /// Endpoint.
    pub endpoint: u8,
    /// Profile identifier.
    pub profile: u16,
    /// Device identifier.
    pub device: u16,
    /// Device version.
    pub version: u8,
}

/// Records per Get Endpoint List Response kept here.
pub const MAX_ENDPOINT_RECORDS: usize = 8;

/// Get Endpoint List Response (§13.3.2.3.8).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetEndpointListResponse {
    /// Total endpoints.
    pub total: u8,
    /// Start index echoed.
    pub start_index: u8,
    /// Records.
    pub records: Vec<EndpointRecord, MAX_ENDPOINT_RECORDS>,
}

impl GetEndpointListResponse {
    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.total)?;
        w.u8(self.start_index)?;
        w.u8(u8::try_from(self.records.len()).unwrap_or(0))?;
        for e in &self.records {
            w.u16_le(e.network_address)?;
            w.u8(e.endpoint)?;
            w.u16_le(e.profile)?;
            w.u16_le(e.device)?;
            w.u8(e.version & 0x0f)?;
        }
        Ok(())
    }

    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        let total = r.u8()?;
        let start_index = r.u8()?;
        let n = r.u8()?;
        let mut records = Vec::new();
        for _ in 0..n {
            let e = EndpointRecord {
                network_address: r.u16_le()?,
                endpoint: r.u8()?,
                profile: r.u16_le()?,
                device: r.u16_le()?,
                version: r.u8()? & 0x0f,
            };
            records.push(e).map_err(|_| CodecError::Unrepresentable {
                field: "endpoint records",
            })?;
        }
        Ok(GetEndpointListResponse {
            total,
            start_index,
            records,
        })
    }
}

/// The `nwkUpdateId` to keep of two candidates (§13.3.4.10): the larger,
/// unless they differ by more than 200 (a wrap), then the smaller.
pub const fn newer_update_id(a: u8, b: u8) -> u8 {
    if a.abs_diff(b) > 200 {
        if a < b { a } else { b }
    } else if a > b {
        a
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T: PartialEq + core::fmt::Debug>(
        v: &T,
        enc: impl Fn(&T, &mut Writer<'_>) -> Result<(), CodecError>,
        dec: impl Fn(&[u8]) -> Result<T, CodecError>,
    ) -> usize {
        let mut buf = [0u8; 96];
        let mut w = Writer::new(&mut buf);
        enc(v, &mut w).unwrap();
        let n = w.position();
        assert_eq!(&dec(&buf[..n]).unwrap(), v);
        n
    }

    #[test]
    fn scan_request_and_response_round_trip() {
        let req = ScanRequest {
            transaction: 0x1234_5678,
            zigbee: ZigbeeInfo::ROUTER,
            touchlink: TouchlinkInfo {
                factory_new: true,
                address_assignment: true,
                initiator: true,
                priority_request: false,
                profile_interop: true,
            },
        };
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        req.encode(&mut w).unwrap();
        assert_eq!(&buf[..6], &[0x78, 0x56, 0x34, 0x12, 0x05, 0x93]);
        assert_eq!(ScanRequest::parse(&buf[..6]).unwrap(), req);

        let rsp = ScanResponse {
            transaction: 0x1234_5678,
            rssi_correction: 0x10,
            zigbee: ZigbeeInfo::ROUTER,
            touchlink: TouchlinkInfo {
                factory_new: false,
                address_assignment: true,
                initiator: false,
                priority_request: true,
                profile_interop: true,
            },
            key_bitmask: 0x8010,
            response: 0xdead_beef,
            extended_pan_id: 0x1122_3344_5566_7788,
            update_id: 3,
            channel: 11,
            pan_id: 0x1a2b,
            network_address: 0x0001,
            sub_devices: 1,
            total_groups: 2,
            sub_device: Some(SubDevice {
                endpoint: 1,
                profile: 0x0104,
                device: 0x0101,
                version: 2,
                group_count: 2,
            }),
        };
        assert_eq!(
            roundtrip(&rsp, ScanResponse::encode, ScanResponse::parse),
            29 + 7
        );
        let multi = ScanResponse {
            sub_devices: 3,
            sub_device: None,
            ..rsp
        };
        assert_eq!(
            roundtrip(&multi, ScanResponse::encode, ScanResponse::parse),
            29
        );
    }

    #[test]
    fn start_join_update_round_trip() {
        let a = NetworkAssignment {
            network_address: 0x0002,
            groups_begin: 1,
            groups_end: 2,
            free_addresses_begin: 0x8000,
            free_addresses_end: 0xfff7,
            free_groups_begin: 0x8000,
            free_groups_end: 0xfeff,
        };
        let start = NetworkStartRequest {
            transaction: 7,
            extended_pan_id: 0,
            key_index: 15,
            encrypted_key: [0xab; 16],
            channel: 0,
            pan_id: 0,
            assignment: a,
            initiator_ieee: 0x0101,
            initiator_address: 0x0001,
        };
        assert_eq!(
            roundtrip(
                &start,
                NetworkStartRequest::encode,
                NetworkStartRequest::parse
            ),
            4 + 8 + 1 + 16 + 1 + 2 + 14 + 8 + 2
        );
        let join = NetworkJoinRequest {
            transaction: 7,
            extended_pan_id: 9,
            key_index: 4,
            encrypted_key: [1; 16],
            update_id: 1,
            channel: 15,
            pan_id: 0x4321,
            assignment: a,
        };
        assert_eq!(
            roundtrip(&join, NetworkJoinRequest::encode, NetworkJoinRequest::parse),
            4 + 8 + 1 + 16 + 1 + 1 + 2 + 14
        );
        let rsp = NetworkStartResponse {
            transaction: 7,
            status: 0,
            extended_pan_id: 9,
            update_id: 0,
            channel: 15,
            pan_id: 0x4321,
        };
        roundtrip(
            &rsp,
            NetworkStartResponse::encode,
            NetworkStartResponse::parse,
        );
        roundtrip(
            &StatusResponse {
                transaction: 7,
                status: 1,
            },
            StatusResponse::encode,
            StatusResponse::parse,
        );
        roundtrip(
            &NetworkUpdateRequest {
                transaction: 8,
                extended_pan_id: 9,
                update_id: 2,
                channel: 20,
                pan_id: 0x4321,
                network_address: 0x0002,
            },
            NetworkUpdateRequest::encode,
            NetworkUpdateRequest::parse,
        );
        roundtrip(
            &IdentifyRequest {
                transaction: 7,
                duration: IDENTIFY_DEFAULT,
            },
            IdentifyRequest::encode,
            IdentifyRequest::parse,
        );
        assert_eq!(parse_transaction(&[1, 0, 0, 0]).unwrap(), 1);
    }

    #[test]
    fn information_and_utility_round_trip() {
        let mut records = Vec::new();
        records
            .push(DeviceRecord {
                ieee: 0x0102,
                endpoint: 1,
                profile: 0x0104,
                device: 0x0100,
                version: 1,
                group_count: 1,
                sort: 0,
            })
            .unwrap();
        let dir = DeviceInformationResponse {
            transaction: 7,
            sub_devices: 1,
            start_index: 0,
            records,
        };
        roundtrip(
            &dir,
            DeviceInformationResponse::encode,
            DeviceInformationResponse::parse,
        );
        assert!(DeviceInformationResponse::parse(&[7, 0, 0, 0, 1, 0, 6]).is_err());
        roundtrip(
            &DeviceInformationRequest {
                transaction: 7,
                start_index: 2,
            },
            DeviceInformationRequest::encode,
            DeviceInformationRequest::parse,
        );
        roundtrip(
            &EndpointInformation {
                ieee: 5,
                network_address: 6,
                endpoint: 7,
                profile: 0x0104,
                device: 0x0100,
                version: 1,
            },
            EndpointInformation::encode,
            EndpointInformation::parse,
        );
        let mut groups = Vec::new();
        groups
            .push(GroupRecord {
                group: 0x0001,
                group_type: 0,
            })
            .unwrap();
        roundtrip(
            &GetGroupIdentifiersResponse {
                total: 1,
                start_index: 0,
                records: groups,
            },
            GetGroupIdentifiersResponse::encode,
            GetGroupIdentifiersResponse::parse,
        );
        let mut eps = Vec::new();
        eps.push(EndpointRecord {
            network_address: 1,
            endpoint: 1,
            profile: 0x0104,
            device: 0x0100,
            version: 1,
        })
        .unwrap();
        roundtrip(
            &GetEndpointListResponse {
                total: 1,
                start_index: 0,
                records: eps,
            },
            GetEndpointListResponse::encode,
            GetEndpointListResponse::parse,
        );
    }

    #[test]
    fn update_id_comparison_handles_wrap() {
        assert_eq!(newer_update_id(5, 3), 5);
        assert_eq!(newer_update_id(250, 2), 2);
        assert_eq!(newer_update_id(2, 250), 2);
        assert_eq!(newer_update_id(7, 7), 7);
    }
}
