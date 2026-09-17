//! Commissioning cluster (ZCL8 §13.2): the startup attribute set (SAS)
//! with the join, end-device and concentrator parameters, the Restart
//! Device consistency check of Table 13-5, and Save / Restore / Reset
//! Startup Parameters over a bounded store of saved sets. The keys are
//! write-only credentials (reads answer NOT_AUTHORIZED, §13.2.2.2.1)
//! and never appear in `Debug` output. Installing a set into the stack
//! is the runtime's job: the dispatcher hands an accepted Restart Device
//! over as a [`Restart`] request.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{AttributeId, ClusterId, CommandId, Key128};

use crate::attribute::{Access, AttributeDef, AttributeTable};
use crate::cluster::{ClusterDef, ClusterInstance, ClusterState, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0015);

/// `ShortAddress` (uint16).
pub const SHORT_ADDRESS: AttributeDef = AttributeDef::new(0x0000, DataType::Uint(2), Access::RW);
/// `ExtendedPANId` (EUI64).
pub const EXTENDED_PAN_ID: AttributeDef = AttributeDef::new(0x0001, DataType::Eui64, Access::RW);
/// `PANId` (uint16).
pub const PAN_ID: AttributeDef = AttributeDef::new(0x0002, DataType::Uint(2), Access::RW);
/// `ChannelMask` (map32).
pub const CHANNEL_MASK: AttributeDef = AttributeDef::new(0x0003, DataType::Bitmap(4), Access::RW);
/// `ProtocolVersion` (uint8).
pub const PROTOCOL_VERSION: AttributeDef = AttributeDef::new(0x0004, DataType::Uint(1), Access::RW);
/// `StackProfile` (uint8).
pub const STACK_PROFILE: AttributeDef = AttributeDef::new(0x0005, DataType::Uint(1), Access::RW);
/// `StartupControl` (enum8).
pub const STARTUP_CONTROL: AttributeDef = AttributeDef::new(0x0006, DataType::Enum8, Access::RW);
/// `TrustCenterAddress` (EUI64).
pub const TRUST_CENTER_ADDRESS: AttributeDef =
    AttributeDef::new(0x0010, DataType::Eui64, Access::RW);
/// `NetworkKey` (key128, write-only credential).
pub const NETWORK_KEY: AttributeDef =
    AttributeDef::new(0x0012, DataType::Key128, Access::WO_SECRET);
/// `UseInsecureJoin` (bool).
pub const USE_INSECURE_JOIN: AttributeDef = AttributeDef::new(0x0013, DataType::Bool, Access::RW);
/// `PreconfiguredLinkKey` (key128, write-only credential).
pub const PRECONFIGURED_LINK_KEY: AttributeDef =
    AttributeDef::new(0x0014, DataType::Key128, Access::WO_SECRET);
/// `NetworkKeySeqNum` (uint8).
pub const NETWORK_KEY_SEQ_NUM: AttributeDef =
    AttributeDef::new(0x0015, DataType::Uint(1), Access::RW);
/// `NetworkKeyType` (enum8).
pub const NETWORK_KEY_TYPE: AttributeDef = AttributeDef::new(0x0016, DataType::Enum8, Access::RW);
/// `NetworkManagerAddress` (uint16).
pub const NETWORK_MANAGER_ADDRESS: AttributeDef =
    AttributeDef::new(0x0017, DataType::Uint(2), Access::RW);
/// `ScanAttempts` (uint8).
pub const SCAN_ATTEMPTS: AttributeDef = AttributeDef::new(0x0020, DataType::Uint(1), Access::RW);
/// `TimeBetweenScans` (uint16 ms).
pub const TIME_BETWEEN_SCANS: AttributeDef =
    AttributeDef::new(0x0021, DataType::Uint(2), Access::RW);
/// `RejoinInterval` (uint16 s).
pub const REJOIN_INTERVAL: AttributeDef = AttributeDef::new(0x0022, DataType::Uint(2), Access::RW);
/// `MaxRejoinInterval` (uint16 s).
pub const MAX_REJOIN_INTERVAL: AttributeDef =
    AttributeDef::new(0x0023, DataType::Uint(2), Access::RW);
/// `IndirectPollRate` (uint16 ms).
pub const INDIRECT_POLL_RATE: AttributeDef =
    AttributeDef::new(0x0030, DataType::Uint(2), Access::RW);
/// `ParentRetryThreshold` (uint8, read-only).
pub const PARENT_RETRY_THRESHOLD: AttributeDef =
    AttributeDef::new(0x0031, DataType::Uint(1), Access::RO);
/// `ConcentratorFlag` (bool).
pub const CONCENTRATOR_FLAG: AttributeDef = AttributeDef::new(0x0040, DataType::Bool, Access::RW);
/// `ConcentratorRadius` (uint8).
pub const CONCENTRATOR_RADIUS: AttributeDef =
    AttributeDef::new(0x0041, DataType::Uint(1), Access::RW);
/// `ConcentratorDiscoveryTime` (uint8 s).
pub const CONCENTRATOR_DISCOVERY_TIME: AttributeDef =
    AttributeDef::new(0x0042, DataType::Uint(1), Access::RW);

/// `StartupControl` values (Table 13-5).
pub mod startup_control {
    /// Already part of the network: no join or rejoin.
    pub const SILENT_JOIN: u8 = 0x00;
    /// Form the network.
    pub const FORM: u8 = 0x01;
    /// Rejoin the network.
    pub const REJOIN: u8 = 0x02;
    /// Join from scratch by MAC association.
    pub const ASSOCIATE: u8 = 0x03;
}

/// The global commissioning EPID (§13.2.4.1).
pub const GLOBAL_COMMISSIONING_EPID: u64 = 0x0050_C277_1000_0000;

/// Restart Device.
pub const CMD_RESTART_DEVICE: CommandId = CommandId(0x00);
/// Save Startup Parameters.
pub const CMD_SAVE_STARTUP_PARAMETERS: CommandId = CommandId(0x01);
/// Restore Startup Parameters.
pub const CMD_RESTORE_STARTUP_PARAMETERS: CommandId = CommandId(0x02);
/// Reset Startup Parameters.
pub const CMD_RESET_STARTUP_PARAMETERS: CommandId = CommandId(0x03);
/// Restart Device Response.
pub const CMD_RESTART_DEVICE_RESPONSE: CommandId = CommandId(0x00);
/// Save Startup Parameters Response.
pub const CMD_SAVE_STARTUP_PARAMETERS_RESPONSE: CommandId = CommandId(0x01);
/// Restore Startup Parameters Response.
pub const CMD_RESTORE_STARTUP_PARAMETERS_RESPONSE: CommandId = CommandId(0x02);
/// Reset Startup Parameters Response.
pub const CMD_RESET_STARTUP_PARAMETERS_RESPONSE: CommandId = CommandId(0x03);

/// Restart Device options (Figure 13-2).
pub mod restart_options {
    /// Startup mode: install the current startup set.
    pub const MODE_INSTALL: u8 = 0b000;
    /// Startup mode: restart with the current stack state.
    pub const MODE_KEEP: u8 = 0b001;
    /// Immediate.
    pub const IMMEDIATE: u8 = 1 << 3;
}

/// Reset Startup Parameters options (Figure 13-6).
pub mod reset_options {
    /// Reset the current set.
    pub const RESET_CURRENT: u8 = 1 << 0;
    /// Reset every saved set.
    pub const RESET_ALL: u8 = 1 << 1;
    /// Erase the index.
    pub const ERASE_INDEX: u8 = 1 << 2;
}

/// Cluster definition.
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 2,
    received: &[
        CMD_RESTART_DEVICE,
        CMD_SAVE_STARTUP_PARAMETERS,
        CMD_RESTORE_STARTUP_PARAMETERS,
        CMD_RESET_STARTUP_PARAMETERS,
    ],
    generated: &[
        CMD_RESTART_DEVICE_RESPONSE,
        CMD_SAVE_STARTUP_PARAMETERS_RESPONSE,
        CMD_RESTORE_STARTUP_PARAMETERS_RESPONSE,
        CMD_RESET_STARTUP_PARAMETERS_RESPONSE,
    ],
};

/// Saved startup sets a server keeps (the index allows 256).
pub const MAX_SAVED: usize = 2;
/// All 2.4 GHz channels.
pub const DEFAULT_CHANNEL_MASK: u32 = 0x07ff_f800;

/// A startup attribute set (Tables 13-2, 13-7 – 13-9).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct StartupSet {
    /// `ShortAddress`.
    pub short_address: u16,
    /// `ExtendedPANId`.
    pub extended_pan_id: u64,
    /// `PANId`.
    pub pan_id: u16,
    /// `ChannelMask`.
    pub channel_mask: u32,
    /// `ProtocolVersion`.
    pub protocol_version: u8,
    /// `StackProfile`.
    pub stack_profile: u8,
    /// `StartupControl`.
    pub startup_control: u8,
    /// `TrustCenterAddress`.
    pub trust_center_address: u64,
    /// `NetworkKey` (all zeros: unspecified).
    pub network_key: Key128,
    /// `UseInsecureJoin`.
    pub use_insecure_join: bool,
    /// `PreconfiguredLinkKey` (all zeros: unspecified).
    pub preconfigured_link_key: Key128,
    /// `NetworkKeySeqNum`.
    pub network_key_seq_num: u8,
    /// `NetworkKeyType`.
    pub network_key_type: u8,
    /// `NetworkManagerAddress`.
    pub network_manager_address: u16,
    /// `ScanAttempts`.
    pub scan_attempts: u8,
    /// `TimeBetweenScans` (ms).
    pub time_between_scans: u16,
    /// `RejoinInterval` (s).
    pub rejoin_interval: u16,
    /// `MaxRejoinInterval` (s).
    pub max_rejoin_interval: u16,
    /// `IndirectPollRate` (ms).
    pub indirect_poll_rate: u16,
    /// `ParentRetryThreshold`.
    pub parent_retry_threshold: u8,
    /// `ConcentratorFlag`.
    pub concentrator: bool,
    /// `ConcentratorRadius`.
    pub concentrator_radius: u8,
    /// `ConcentratorDiscoveryTime` (s).
    pub concentrator_discovery_time: u8,
}

impl Default for StartupSet {
    /// The un-commissioned defaults of §13.2.2.2 (stack profile 2).
    fn default() -> Self {
        StartupSet {
            short_address: 0xffff,
            extended_pan_id: 0,
            pan_id: 0xffff,
            channel_mask: DEFAULT_CHANNEL_MASK,
            protocol_version: 2,
            stack_profile: 2,
            startup_control: startup_control::ASSOCIATE,
            trust_center_address: 0,
            network_key: Key128::default(),
            use_insecure_join: true,
            preconfigured_link_key: Key128::default(),
            network_key_seq_num: 0,
            network_key_type: 5,
            network_manager_address: 0,
            scan_attempts: 5,
            time_between_scans: 0x64,
            rejoin_interval: 0x3c,
            max_rejoin_interval: 0x0e10,
            indirect_poll_rate: 0,
            parent_retry_threshold: 0xff,
            concentrator: false,
            concentrator_radius: 0x0f,
            concentrator_discovery_time: 0,
        }
    }
}

const fn zero_key(k: &Key128) -> bool {
    let b = k.as_bytes();
    let mut i = 0;
    while i < 16 {
        if b[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

impl StartupSet {
    /// Whether the set is consistent for its `StartupControl` (Table
    /// 13-5 required attributes): a silent join needs an address, PAN,
    /// Trust Center and network key; forming and rejoining need an
    /// extended PAN ID; association needs nothing.
    pub fn is_consistent(&self) -> bool {
        let epid_ok = self.extended_pan_id != 0 && self.extended_pan_id != u64::MAX;
        match self.startup_control {
            startup_control::SILENT_JOIN => {
                epid_ok
                    && self.short_address <= 0xfff7
                    && self.pan_id <= 0xfffe
                    && self.trust_center_address != 0
                    && !zero_key(&self.network_key)
            }
            startup_control::FORM | startup_control::REJOIN => epid_ok,
            startup_control::ASSOCIATE => true,
            _ => false,
        }
    }
}

/// Server state: the saved startup sets by index.
#[derive(Clone, Default, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct State {
    /// Saved sets.
    pub saved: Vec<(u8, StartupSet), MAX_SAVED>,
}

/// An accepted Restart Device (§13.2.2.3.1) for the runtime.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Restart {
    /// Install `startup` (else restart with the current stack state).
    pub install: bool,
    /// Restart immediately after the delay (else at a convenient moment).
    pub immediate: bool,
    /// Delay in seconds.
    pub delay: u8,
    /// Jitter field: add RAND(jitter × 80) ms.
    pub jitter: u8,
    /// The current startup set.
    pub startup: StartupSet,
}

/// A response frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Response {
    /// Response command.
    pub command: CommandId,
    /// Status.
    pub status: ZclStatus,
}

/// Result of a received command.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Outcome {
    /// Respond, and hand a restart to the runtime when accepted.
    Reply {
        /// The response.
        response: Response,
        /// Restart request.
        restart: Option<Restart>,
    },
    /// Refused with a Default Response.
    Default(ZclStatus),
}

/// Write guard: `StartupControl` and `StackProfile` must be known,
/// `ShortAddress` and `PANId` in range; a rejoin with a cleared
/// extended PAN ID is FAILURE (§13.2.2).
fn guard<const A: usize>(t: &AttributeTable<A>, id: AttributeId, v: &Value<'_>) -> ZclStatus {
    let val = v.as_u64().unwrap_or(u64::MAX);
    match id {
        i if i == STARTUP_CONTROL.id => {
            if val > u64::from(startup_control::ASSOCIATE) {
                ZclStatus::InvalidValue
            } else if val == u64::from(startup_control::REJOIN)
                && t.u64(EXTENDED_PAN_ID.id).is_none_or(|e| e == 0)
            {
                ZclStatus::Failure
            } else {
                ZclStatus::Success
            }
        }
        i if i == SHORT_ADDRESS.id && val > 0xfff7 => ZclStatus::InvalidValue,
        i if i == PAN_ID.id && val > 0xfffe => ZclStatus::InvalidValue,
        i if i == STACK_PROFILE.id && !(1..=2).contains(&val) => ZclStatus::InvalidValue,
        i if i == EXTENDED_PAN_ID.id
            && val == 0
            && t.u64(STARTUP_CONTROL.id) == Some(u64::from(startup_control::REJOIN)) =>
        {
            ZclStatus::Failure
        }
        _ => ZclStatus::Success,
    }
}

fn u8v(v: u8) -> Value<'static> {
    Value::Uint {
        width: 1,
        value: u64::from(v),
    }
}

fn u16v(v: u16) -> Value<'static> {
    Value::Uint {
        width: 2,
        value: u64::from(v),
    }
}

/// Writes `set` into the attributes.
pub fn store<const A: usize>(c: &mut ClusterInstance<A>, set: &StartupSet) {
    c.set(SHORT_ADDRESS.id, &u16v(set.short_address));
    c.set(EXTENDED_PAN_ID.id, &Value::Eui64(set.extended_pan_id));
    c.set(PAN_ID.id, &u16v(set.pan_id));
    c.set(
        CHANNEL_MASK.id,
        &Value::Bits {
            width: 4,
            bits: u64::from(set.channel_mask),
        },
    );
    c.set(PROTOCOL_VERSION.id, &u8v(set.protocol_version));
    c.set(STACK_PROFILE.id, &u8v(set.stack_profile));
    c.set(STARTUP_CONTROL.id, &Value::Enum8(set.startup_control));
    c.set(
        TRUST_CENTER_ADDRESS.id,
        &Value::Eui64(set.trust_center_address),
    );
    c.set(NETWORK_KEY.id, &Value::Key128(*set.network_key.as_bytes()));
    c.set(
        USE_INSECURE_JOIN.id,
        &Value::Bool(Some(set.use_insecure_join)),
    );
    c.set(
        PRECONFIGURED_LINK_KEY.id,
        &Value::Key128(*set.preconfigured_link_key.as_bytes()),
    );
    c.set(NETWORK_KEY_SEQ_NUM.id, &u8v(set.network_key_seq_num));
    c.set(NETWORK_KEY_TYPE.id, &Value::Enum8(set.network_key_type));
    c.set(
        NETWORK_MANAGER_ADDRESS.id,
        &u16v(set.network_manager_address),
    );
    c.set(SCAN_ATTEMPTS.id, &u8v(set.scan_attempts));
    c.set(TIME_BETWEEN_SCANS.id, &u16v(set.time_between_scans));
    c.set(REJOIN_INTERVAL.id, &u16v(set.rejoin_interval));
    c.set(MAX_REJOIN_INTERVAL.id, &u16v(set.max_rejoin_interval));
    c.set(INDIRECT_POLL_RATE.id, &u16v(set.indirect_poll_rate));
    c.set(PARENT_RETRY_THRESHOLD.id, &u8v(set.parent_retry_threshold));
    c.set(CONCENTRATOR_FLAG.id, &Value::Bool(Some(set.concentrator)));
    c.set(CONCENTRATOR_RADIUS.id, &u8v(set.concentrator_radius));
    c.set(
        CONCENTRATOR_DISCOVERY_TIME.id,
        &u8v(set.concentrator_discovery_time),
    );
}

fn key_of<const A: usize>(c: &ClusterInstance<A>, id: AttributeId) -> Key128 {
    match c.attributes.value(id) {
        Some(Value::Key128(k)) => Key128::from_bytes(k),
        _ => Key128::default(),
    }
}

/// Reads the current startup set from the attributes.
pub fn load<const A: usize>(c: &ClusterInstance<A>) -> StartupSet {
    let d = StartupSet::default();
    let u8_ = |id: AttributeId, def: u8| c.u8(id).unwrap_or(def);
    let u16_ = |id: AttributeId, def: u16| c.u16(id).unwrap_or(def);
    StartupSet {
        short_address: u16_(SHORT_ADDRESS.id, d.short_address),
        extended_pan_id: c.u64(EXTENDED_PAN_ID.id).unwrap_or(d.extended_pan_id),
        pan_id: u16_(PAN_ID.id, d.pan_id),
        channel_mask: c
            .u64(CHANNEL_MASK.id)
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(d.channel_mask),
        protocol_version: u8_(PROTOCOL_VERSION.id, d.protocol_version),
        stack_profile: u8_(STACK_PROFILE.id, d.stack_profile),
        startup_control: u8_(STARTUP_CONTROL.id, d.startup_control),
        trust_center_address: c
            .u64(TRUST_CENTER_ADDRESS.id)
            .unwrap_or(d.trust_center_address),
        network_key: key_of(c, NETWORK_KEY.id),
        use_insecure_join: c.bool(USE_INSECURE_JOIN.id),
        preconfigured_link_key: key_of(c, PRECONFIGURED_LINK_KEY.id),
        network_key_seq_num: u8_(NETWORK_KEY_SEQ_NUM.id, d.network_key_seq_num),
        network_key_type: u8_(NETWORK_KEY_TYPE.id, d.network_key_type),
        network_manager_address: u16_(NETWORK_MANAGER_ADDRESS.id, d.network_manager_address),
        scan_attempts: u8_(SCAN_ATTEMPTS.id, d.scan_attempts),
        time_between_scans: u16_(TIME_BETWEEN_SCANS.id, d.time_between_scans),
        rejoin_interval: u16_(REJOIN_INTERVAL.id, d.rejoin_interval),
        max_rejoin_interval: u16_(MAX_REJOIN_INTERVAL.id, d.max_rejoin_interval),
        indirect_poll_rate: u16_(INDIRECT_POLL_RATE.id, d.indirect_poll_rate),
        parent_retry_threshold: u8_(PARENT_RETRY_THRESHOLD.id, d.parent_retry_threshold),
        concentrator: c.bool(CONCENTRATOR_FLAG.id),
        concentrator_radius: u8_(CONCENTRATOR_RADIUS.id, d.concentrator_radius),
        concentrator_discovery_time: u8_(
            CONCENTRATOR_DISCOVERY_TIME.id,
            d.concentrator_discovery_time,
        ),
    }
}

/// Builds a server holding `current` as the startup set (the
/// application seeds it from the stack's live attributes).
pub fn server<const A: usize>(current: &StartupSet) -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(DEF, Role::Server);
    let d = StartupSet::default();
    c.add_attribute(SHORT_ADDRESS, &u16v(d.short_address))?;
    c.add_attribute(EXTENDED_PAN_ID, &Value::Eui64(d.extended_pan_id))?;
    c.add_attribute(PAN_ID, &u16v(d.pan_id))?;
    c.add_attribute(
        CHANNEL_MASK,
        &Value::Bits {
            width: 4,
            bits: u64::from(d.channel_mask),
        },
    )?;
    c.add_attribute(PROTOCOL_VERSION, &u8v(d.protocol_version))?;
    c.add_attribute(STACK_PROFILE, &u8v(d.stack_profile))?;
    c.add_attribute(STARTUP_CONTROL, &Value::Enum8(d.startup_control))?;
    c.add_attribute(TRUST_CENTER_ADDRESS, &Value::Eui64(d.trust_center_address))?;
    c.add_attribute(NETWORK_KEY, &Value::Key128([0; 16]))?;
    c.add_attribute(USE_INSECURE_JOIN, &Value::Bool(Some(d.use_insecure_join)))?;
    c.add_attribute(PRECONFIGURED_LINK_KEY, &Value::Key128([0; 16]))?;
    c.add_attribute(NETWORK_KEY_SEQ_NUM, &u8v(d.network_key_seq_num))?;
    c.add_attribute(NETWORK_KEY_TYPE, &Value::Enum8(d.network_key_type))?;
    c.add_attribute(NETWORK_MANAGER_ADDRESS, &u16v(d.network_manager_address))?;
    c.add_attribute(SCAN_ATTEMPTS, &u8v(d.scan_attempts))?;
    c.add_attribute(TIME_BETWEEN_SCANS, &u16v(d.time_between_scans))?;
    c.add_attribute(REJOIN_INTERVAL, &u16v(d.rejoin_interval))?;
    c.add_attribute(MAX_REJOIN_INTERVAL, &u16v(d.max_rejoin_interval))?;
    c.add_attribute(INDIRECT_POLL_RATE, &u16v(d.indirect_poll_rate))?;
    c.add_attribute(PARENT_RETRY_THRESHOLD, &u8v(d.parent_retry_threshold))?;
    c.add_attribute(CONCENTRATOR_FLAG, &Value::Bool(Some(d.concentrator)))?;
    c.add_attribute(CONCENTRATOR_RADIUS, &u8v(d.concentrator_radius))?;
    c.add_attribute(
        CONCENTRATOR_DISCOVERY_TIME,
        &u8v(d.concentrator_discovery_time),
    )?;
    store(&mut c, current);
    c.state = ClusterState::Commissioning(State::default());
    c.write_guard = Some(guard::<A>);
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF, Role::Client)
}

fn state<const A: usize>(c: &mut ClusterInstance<A>) -> Option<&mut State> {
    match &mut c.state {
        ClusterState::Commissioning(s) => Some(s),
        _ => None,
    }
}

/// The saved startup sets.
pub fn saved<const A: usize>(c: &ClusterInstance<A>) -> &[(u8, StartupSet)] {
    match &c.state {
        ClusterState::Commissioning(s) => s.saved.as_slice(),
        _ => &[],
    }
}

fn reply(command: CommandId, status: ZclStatus) -> Outcome {
    Outcome::Reply {
        response: Response { command, status },
        restart: None,
    }
}

/// Handles a received command (§13.2.2.3).
pub fn handle<const A: usize>(
    c: &mut ClusterInstance<A>,
    cmd: CommandId,
    payload: &[u8],
) -> Outcome {
    let mut r = Reader::new(payload);
    match cmd {
        CMD_RESTART_DEVICE => {
            let (Ok(options), Ok(delay), Ok(jitter)) = (r.u8(), r.u8(), r.u8()) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let mode = options & 0x07;
            if mode > restart_options::MODE_KEEP {
                return reply(CMD_RESTART_DEVICE_RESPONSE, ZclStatus::InvalidField);
            }
            let startup = load(c);
            let install = mode == restart_options::MODE_INSTALL;
            if install && !startup.is_consistent() {
                return reply(CMD_RESTART_DEVICE_RESPONSE, ZclStatus::Failure);
            }
            Outcome::Reply {
                response: Response {
                    command: CMD_RESTART_DEVICE_RESPONSE,
                    status: ZclStatus::Success,
                },
                restart: Some(Restart {
                    install,
                    immediate: options & restart_options::IMMEDIATE != 0,
                    delay,
                    jitter,
                    startup,
                }),
            }
        }
        CMD_SAVE_STARTUP_PARAMETERS => {
            let (Ok(_options), Ok(index)) = (r.u8(), r.u8()) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let current = load(c);
            let Some(s) = state(c) else {
                return reply(CMD_SAVE_STARTUP_PARAMETERS_RESPONSE, ZclStatus::Failure);
            };
            let status = if let Some(slot) = s.saved.iter_mut().find(|(i, _)| *i == index) {
                slot.1 = current;
                ZclStatus::Success
            } else if s.saved.push((index, current)).is_ok() {
                ZclStatus::Success
            } else {
                ZclStatus::InsufficientSpace
            };
            reply(CMD_SAVE_STARTUP_PARAMETERS_RESPONSE, status)
        }
        CMD_RESTORE_STARTUP_PARAMETERS => {
            let (Ok(_options), Ok(index)) = (r.u8(), r.u8()) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let set = state(c).and_then(|s| {
                s.saved
                    .iter()
                    .find(|(i, _)| *i == index)
                    .map(|(_, set)| set.clone())
            });
            match set {
                Some(set) => {
                    store(c, &set);
                    reply(CMD_RESTORE_STARTUP_PARAMETERS_RESPONSE, ZclStatus::Success)
                }
                None => reply(
                    CMD_RESTORE_STARTUP_PARAMETERS_RESPONSE,
                    ZclStatus::InvalidField,
                ),
            }
        }
        CMD_RESET_STARTUP_PARAMETERS => {
            let (Ok(options), Ok(index)) = (r.u8(), r.u8()) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            if options & reset_options::RESET_CURRENT != 0 {
                store(c, &StartupSet::default());
            }
            if let Some(s) = state(c) {
                let erase = options & reset_options::ERASE_INDEX != 0;
                if options & reset_options::RESET_ALL != 0 {
                    if erase {
                        s.saved.clear();
                    } else {
                        for (_, set) in s.saved.iter_mut() {
                            *set = StartupSet::default();
                        }
                    }
                } else if (options & reset_options::RESET_CURRENT == 0 || erase)
                    && let Some(pos) = s.saved.iter().position(|(i, _)| *i == index)
                {
                    if erase {
                        s.saved.swap_remove(pos);
                    } else if let Some(slot) = s.saved.get_mut(pos) {
                        slot.1 = StartupSet::default();
                    }
                }
            }
            reply(CMD_RESET_STARTUP_PARAMETERS_RESPONSE, ZclStatus::Success)
        }
        _ => Outcome::Default(ZclStatus::UnsupportedClusterCommand),
    }
}

/// Encodes a Restart Device payload.
pub fn encode_restart(
    options: u8,
    delay: u8,
    jitter: u8,
    out: &mut [u8],
) -> Result<usize, CodecError> {
    let mut w = Writer::new(out);
    w.u8(options)?;
    w.u8(delay)?;
    w.u8(jitter)?;
    Ok(w.position())
}

/// Encodes a Save / Restore / Reset Startup Parameters payload.
pub fn encode_index(options: u8, index: u8, out: &mut [u8]) -> Result<usize, CodecError> {
    let mut w = Writer::new(out);
    w.u8(options)?;
    w.u8(index)?;
    Ok(w.position())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cs() -> ClusterInstance<24> {
        let mut set = StartupSet::default();
        set.extended_pan_id = 0x1122_3344_5566_7788;
        set.network_key = Key128::from_bytes([7; 16]);
        server(&set).unwrap()
    }

    #[test]
    fn attributes_round_trip_and_keys_are_write_only() {
        let c = cs();
        let set = load(&c);
        assert_eq!(set.extended_pan_id, 0x1122_3344_5566_7788);
        assert_eq!(set.network_key, Key128::from_bytes([7; 16]));
        assert_eq!(set.startup_control, startup_control::ASSOCIATE);
        assert!(!NETWORK_KEY.access.has(Access::READ));
        assert!(NETWORK_KEY.access.has(Access::SECRET));
        let a = c.attributes.get(NETWORK_KEY.id, None).unwrap();
        let mut s = heapless::String::<256>::new();
        core::fmt::write(&mut s, format_args!("{a:?}")).unwrap();
        assert!(s.contains("REDACTED") && !s.contains("7, 7, 7"), "{s}");
    }

    #[test]
    fn consistency_per_startup_control() {
        let mut set = StartupSet::default();
        assert!(set.is_consistent(), "association needs nothing");
        set.startup_control = startup_control::REJOIN;
        assert!(!set.is_consistent(), "rejoin needs an EPID");
        set.extended_pan_id = 1;
        assert!(set.is_consistent());
        set.startup_control = startup_control::SILENT_JOIN;
        assert!(!set.is_consistent());
        set.short_address = 0x1234;
        set.pan_id = 0x5678;
        set.trust_center_address = 0xaa;
        set.network_key = Key128::from_bytes([1; 16]);
        assert!(set.is_consistent());
        set.startup_control = 9;
        assert!(!set.is_consistent());
    }

    #[test]
    fn restart_checks_consistency_and_reports_the_set() {
        let mut c = cs();
        let mut buf = [0u8; 4];
        let n = encode_restart(restart_options::IMMEDIATE, 3, 10, &mut buf).unwrap();
        let o = handle(&mut c, CMD_RESTART_DEVICE, &buf[..n]);
        let Outcome::Reply { response, restart } = o else {
            panic!("{o:?}");
        };
        assert_eq!(
            response,
            Response {
                command: CMD_RESTART_DEVICE_RESPONSE,
                status: ZclStatus::Success
            }
        );
        let r = restart.unwrap();
        assert!(r.install && r.immediate);
        assert_eq!((r.delay, r.jitter), (3, 10));
        assert_eq!(r.startup.extended_pan_id, 0x1122_3344_5566_7788);
        // Silent join without a Trust Center: FAILURE, no restart.
        c.set(
            STARTUP_CONTROL.id,
            &Value::Enum8(startup_control::SILENT_JOIN),
        );
        let n = encode_restart(0, 0, 0, &mut buf).unwrap();
        let o = handle(&mut c, CMD_RESTART_DEVICE, &buf[..n]);
        assert!(matches!(
            o,
            Outcome::Reply {
                response: Response {
                    status: ZclStatus::Failure,
                    ..
                },
                restart: None
            }
        ));
        // Keeping the stack state skips the check.
        let n = encode_restart(restart_options::MODE_KEEP, 0, 0, &mut buf).unwrap();
        let o = handle(&mut c, CMD_RESTART_DEVICE, &buf[..n]);
        assert!(matches!(
            o,
            Outcome::Reply {
                restart: Some(Restart { install: false, .. }),
                ..
            }
        ));
        assert_eq!(
            handle(&mut c, CMD_RESTART_DEVICE, &[0]),
            Outcome::Default(ZclStatus::MalformedCommand)
        );
    }

    #[test]
    fn save_restore_reset() {
        let mut c = cs();
        let mut buf = [0u8; 2];
        let n = encode_index(0, 1, &mut buf).unwrap();
        let o = handle(&mut c, CMD_SAVE_STARTUP_PARAMETERS, &buf[..n]);
        assert!(matches!(
            o,
            Outcome::Reply {
                response: Response {
                    command: CMD_SAVE_STARTUP_PARAMETERS_RESPONSE,
                    status: ZclStatus::Success
                },
                ..
            }
        ));
        // Change the current set, save under 2, then the store is full.
        c.set(PAN_ID.id, &u16v(0x4444));
        let n = encode_index(0, 2, &mut buf).unwrap();
        handle(&mut c, CMD_SAVE_STARTUP_PARAMETERS, &buf[..n]);
        let n = encode_index(0, 3, &mut buf).unwrap();
        let o = handle(&mut c, CMD_SAVE_STARTUP_PARAMETERS, &buf[..n]);
        assert!(matches!(
            o,
            Outcome::Reply {
                response: Response {
                    status: ZclStatus::InsufficientSpace,
                    ..
                },
                ..
            }
        ));
        assert_eq!(saved(&c).len(), 2);
        // Restore 1 brings the old PAN ID back; unknown index is INVALID_FIELD.
        let n = encode_index(0, 1, &mut buf).unwrap();
        handle(&mut c, CMD_RESTORE_STARTUP_PARAMETERS, &buf[..n]);
        assert_eq!(c.u16(PAN_ID.id), Some(0xffff));
        let n = encode_index(0, 7, &mut buf).unwrap();
        let o = handle(&mut c, CMD_RESTORE_STARTUP_PARAMETERS, &buf[..n]);
        assert!(matches!(
            o,
            Outcome::Reply {
                response: Response {
                    status: ZclStatus::InvalidField,
                    ..
                },
                ..
            }
        ));
        // Reset index 2 to defaults, then erase it; reset current.
        let n = encode_index(0, 2, &mut buf).unwrap();
        handle(&mut c, CMD_RESET_STARTUP_PARAMETERS, &buf[..n]);
        assert_eq!(
            saved(&c).iter().find(|(i, _)| *i == 2).unwrap().1.pan_id,
            0xffff
        );
        let n = encode_index(reset_options::ERASE_INDEX, 2, &mut buf).unwrap();
        handle(&mut c, CMD_RESET_STARTUP_PARAMETERS, &buf[..n]);
        assert_eq!(saved(&c).len(), 1);
        let n = encode_index(reset_options::RESET_CURRENT, 0, &mut buf).unwrap();
        let o = handle(&mut c, CMD_RESET_STARTUP_PARAMETERS, &buf[..n]);
        assert!(matches!(
            o,
            Outcome::Reply {
                response: Response {
                    command: CMD_RESET_STARTUP_PARAMETERS_RESPONSE,
                    status: ZclStatus::Success
                },
                ..
            }
        ));
        assert_eq!(load(&c), StartupSet::default());
        let n = encode_index(
            reset_options::RESET_ALL | reset_options::ERASE_INDEX,
            0,
            &mut buf,
        )
        .unwrap();
        handle(&mut c, CMD_RESET_STARTUP_PARAMETERS, &buf[..n]);
        assert!(saved(&c).is_empty());
    }

    #[test]
    fn writes_are_guarded() {
        let c = cs();
        assert_eq!(
            guard(&c.attributes, STARTUP_CONTROL.id, &Value::Enum8(4)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            guard(&c.attributes, SHORT_ADDRESS.id, &u16v(0xfff8)),
            ZclStatus::InvalidValue
        );
        assert_eq!(
            guard(&c.attributes, STARTUP_CONTROL.id, &Value::Enum8(2)),
            ZclStatus::Success
        );
        let mut d: ClusterInstance<24> = server(&StartupSet::default()).unwrap();
        assert_eq!(
            guard(&d.attributes, STARTUP_CONTROL.id, &Value::Enum8(2)),
            ZclStatus::Failure,
            "rejoin without an EPID"
        );
        d.set(STARTUP_CONTROL.id, &Value::Enum8(2));
        d.set(EXTENDED_PAN_ID.id, &Value::Eui64(5));
        assert_eq!(
            guard(&d.attributes, EXTENDED_PAN_ID.id, &Value::Eui64(0)),
            ZclStatus::Failure
        );
    }
}
