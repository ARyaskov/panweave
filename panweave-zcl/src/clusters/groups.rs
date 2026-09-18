//! Groups cluster (ZCL8 §3.6), revision 4. The group table itself is the
//! APS `apsGroupTable`; the server commands are executed against a
//! [`GroupStore`] supplied by the runtime.

use heapless::Vec;
use panweave_codec::{Reader, Writer};
use panweave_types::{ClusterId, CommandId, Endpoint, GroupAddress};

use crate::attribute::{Access, AttributeDef};
use crate::cluster::{ClusterDef, ClusterInstance, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0004);
/// `NameSupport` (bit 7: group names supported).
pub const NAME_SUPPORT: AttributeDef = AttributeDef::new(0x0000, DataType::Bitmap(1), Access::RO);

/// Add Group.
pub const CMD_ADD_GROUP: CommandId = CommandId(0x00);
/// View Group.
pub const CMD_VIEW_GROUP: CommandId = CommandId(0x01);
/// Get Group Membership.
pub const CMD_GET_GROUP_MEMBERSHIP: CommandId = CommandId(0x02);
/// Remove Group.
pub const CMD_REMOVE_GROUP: CommandId = CommandId(0x03);
/// Remove All Groups.
pub const CMD_REMOVE_ALL_GROUPS: CommandId = CommandId(0x04);
/// Add Group If Identifying.
pub const CMD_ADD_GROUP_IF_IDENTIFYING: CommandId = CommandId(0x05);
/// Add Group Response.
pub const CMD_ADD_GROUP_RESPONSE: CommandId = CommandId(0x00);
/// View Group Response.
pub const CMD_VIEW_GROUP_RESPONSE: CommandId = CommandId(0x01);
/// Get Group Membership Response.
pub const CMD_GET_GROUP_MEMBERSHIP_RESPONSE: CommandId = CommandId(0x02);
/// Remove Group Response.
pub const CMD_REMOVE_GROUP_RESPONSE: CommandId = CommandId(0x03);

/// Largest group identifier accepted (§3.6.2.3.2.2 step 1).
pub const MAX_GROUP_ID: u16 = 0xFFF7;
/// Groups listed in one membership response.
pub const MAX_LISTED: usize = 16;

/// Cluster definition.
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 4,
    received: &[
        CMD_ADD_GROUP,
        CMD_VIEW_GROUP,
        CMD_GET_GROUP_MEMBERSHIP,
        CMD_REMOVE_GROUP,
        CMD_REMOVE_ALL_GROUPS,
        CMD_ADD_GROUP_IF_IDENTIFYING,
    ],
    generated: &[
        CMD_ADD_GROUP_RESPONSE,
        CMD_VIEW_GROUP_RESPONSE,
        CMD_GET_GROUP_MEMBERSHIP_RESPONSE,
        CMD_REMOVE_GROUP_RESPONSE,
    ],
};

/// Builds a server instance (group names unsupported).
pub fn server<const A: usize>() -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(DEF, Role::Server);
    c.add_attribute(NAME_SUPPORT, &Value::Bits { width: 1, bits: 0 })?;
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF.mirrored(), Role::Client)
}

/// Errors of a [`GroupStore`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GroupError {
    /// No free entry.
    Full,
    /// The endpoint is not a member of the group.
    NotFound,
    /// Invalid endpoint or group.
    Invalid,
}

/// The group table as seen by the cluster (`apsGroupTable`, §3.6.2.3).
pub trait GroupStore {
    /// Adds `endpoint` to `group`; adding an existing membership succeeds.
    fn add(&mut self, group: GroupAddress, endpoint: Endpoint) -> Result<(), GroupError>;
    /// Removes `endpoint` from `group`.
    fn remove(&mut self, group: GroupAddress, endpoint: Endpoint) -> Result<(), GroupError>;
    /// Removes `endpoint` from every group.
    fn remove_all(&mut self, endpoint: Endpoint);
    /// True when `endpoint` is a member of `group`.
    fn contains(&self, group: GroupAddress, endpoint: Endpoint) -> bool;
    /// Groups `endpoint` is a member of.
    fn members(&self, endpoint: Endpoint, out: &mut Vec<GroupAddress, MAX_LISTED>);
    /// Remaining capacity (§3.6.2.4.3.1: 0xfe / 0xff when unknown).
    fn capacity(&self) -> u8;
}

impl<const N: usize> GroupStore for panweave_aps::tables::GroupTable<N> {
    fn add(&mut self, group: GroupAddress, endpoint: Endpoint) -> Result<(), GroupError> {
        match panweave_aps::tables::GroupTable::add(self, group, endpoint) {
            Ok(()) => Ok(()),
            Err(panweave_types::ApsStatus::TableFull) => Err(GroupError::Full),
            Err(_) => Err(GroupError::Invalid),
        }
    }
    fn remove(&mut self, group: GroupAddress, endpoint: Endpoint) -> Result<(), GroupError> {
        panweave_aps::tables::GroupTable::remove(self, group, endpoint)
            .map_err(|_| GroupError::NotFound)
    }
    fn remove_all(&mut self, endpoint: Endpoint) {
        panweave_aps::tables::GroupTable::remove_all(self, endpoint);
    }
    fn contains(&self, group: GroupAddress, endpoint: Endpoint) -> bool {
        panweave_aps::tables::GroupTable::contains(self, group, endpoint)
    }
    fn members(&self, endpoint: Endpoint, out: &mut Vec<GroupAddress, MAX_LISTED>) {
        for e in self.iter() {
            if e.endpoints.contains(endpoint) && out.push(e.group).is_err() {
                break;
            }
        }
    }
    fn capacity(&self) -> u8 {
        u8::try_from(N.saturating_sub(self.len())).unwrap_or(0xfd)
    }
}

/// Result of a received Groups server command.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// Send the cluster-specific response written to the output buffer.
    Response(CommandId),
    /// Reply with a Default Response (subject to the usual rules).
    Default(ZclStatus),
    /// Nothing to send (group / broadcast delivery, §3.6.2.3.1).
    None,
}

fn valid(group: u16) -> bool {
    (1..=MAX_GROUP_ID).contains(&group)
}

fn add(store: &mut impl GroupStore, endpoint: Endpoint, group: u16) -> ZclStatus {
    if !valid(group) {
        return ZclStatus::InvalidValue;
    }
    match store.add(GroupAddress(group), endpoint) {
        Ok(()) => ZclStatus::Success,
        Err(GroupError::Full) => ZclStatus::InsufficientSpace,
        Err(_) => ZclStatus::InvalidValue,
    }
}

/// Executes a command received by the server on `endpoint` (§3.6.2.3).
/// `unicast` is false for group / broadcast deliveries; `identifying` is
/// the endpoint's Identify state. Response payloads are written to `out`.
pub fn handle(
    store: &mut impl GroupStore,
    endpoint: Endpoint,
    command: CommandId,
    payload: &[u8],
    unicast: bool,
    identifying: bool,
    out: &mut Writer<'_>,
) -> Outcome {
    let mut r = Reader::new(payload);
    match command {
        CMD_ADD_GROUP => {
            let Ok(group) = r.u16_le() else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let status = add(store, endpoint, group);
            if !unicast {
                return Outcome::None;
            }
            let _ = out.u8(status.raw());
            let _ = out.u16_le(group);
            Outcome::Response(CMD_ADD_GROUP_RESPONSE)
        }
        CMD_VIEW_GROUP => {
            let Ok(group) = r.u16_le() else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let status = if !valid(group) {
                ZclStatus::InvalidValue
            } else if store.contains(GroupAddress(group), endpoint) {
                ZclStatus::Success
            } else {
                ZclStatus::NotFound
            };
            if !unicast {
                return Outcome::None;
            }
            let _ = out.u8(status.raw());
            let _ = out.u16_le(group);
            // Names are unsupported: the null string.
            let _ = out.u8(0);
            Outcome::Response(CMD_VIEW_GROUP_RESPONSE)
        }
        CMD_GET_GROUP_MEMBERSHIP => {
            let Ok(count) = r.u8() else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let mut mine: Vec<GroupAddress, MAX_LISTED> = Vec::new();
            store.members(endpoint, &mut mine);
            let mut listed: Vec<GroupAddress, MAX_LISTED> = Vec::new();
            if count == 0 {
                listed = mine;
            } else {
                for _ in 0..count {
                    let Ok(g) = r.u16_le() else {
                        return Outcome::Default(ZclStatus::MalformedCommand);
                    };
                    if mine.contains(&GroupAddress(g)) {
                        let _ = listed.push(GroupAddress(g));
                    }
                }
            }
            if listed.is_empty() && !unicast {
                return Outcome::None;
            }
            let _ = out.u8(store.capacity());
            let _ = out.u8(u8::try_from(listed.len()).unwrap_or(u8::MAX));
            for g in &listed {
                let _ = out.u16_le(g.0);
            }
            Outcome::Response(CMD_GET_GROUP_MEMBERSHIP_RESPONSE)
        }
        CMD_REMOVE_GROUP => {
            let Ok(group) = r.u16_le() else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let status = if !valid(group) {
                ZclStatus::InvalidValue
            } else if store.remove(GroupAddress(group), endpoint).is_ok() {
                ZclStatus::Success
            } else {
                ZclStatus::NotFound
            };
            if !unicast {
                return Outcome::None;
            }
            let _ = out.u8(status.raw());
            let _ = out.u16_le(group);
            Outcome::Response(CMD_REMOVE_GROUP_RESPONSE)
        }
        CMD_REMOVE_ALL_GROUPS => {
            store.remove_all(endpoint);
            Outcome::Default(ZclStatus::Success)
        }
        CMD_ADD_GROUP_IF_IDENTIFYING => {
            if !identifying {
                return Outcome::Default(ZclStatus::Success);
            }
            let Ok(group) = r.u16_le() else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            Outcome::Default(add(store, endpoint, group))
        }
        _ => Outcome::Default(ZclStatus::UnsupportedClusterCommand),
    }
}

/// Encodes an Add Group / Add Group If Identifying payload (client side)
/// with an empty name.
pub fn add_group_payload(group: GroupAddress) -> [u8; 3] {
    let g = group.0.to_le_bytes();
    [g[0], g[1], 0]
}
