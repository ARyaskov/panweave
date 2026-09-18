//! Scenes cluster (ZCL8 §3.7), revision 3. The scene table belongs to the
//! endpoint ([`crate::layer::EndpointInstance::scenes`]); the extension
//! field sets of the On/Off and Level Control servers of the endpoint are
//! gathered and applied by the endpoint dispatcher, which alone sees every
//! cluster of the endpoint.

use heapless::Vec;
use panweave_codec::{Reader, Writer};
use panweave_types::{ClusterId, CommandId};

use crate::attribute::{Access, AttributeDef};
use crate::cluster::{ClusterDef, ClusterInstance, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0005);
/// `SceneCount`.
pub const SCENE_COUNT: AttributeDef = AttributeDef::new(0x0000, DataType::Uint(1), Access::RO);
/// `CurrentScene`.
pub const CURRENT_SCENE: AttributeDef = AttributeDef::new(0x0001, DataType::Uint(1), Access::RO);
/// `CurrentGroup`.
pub const CURRENT_GROUP: AttributeDef = AttributeDef::new(0x0002, DataType::Uint(2), Access::RO);
/// `SceneValid`.
pub const SCENE_VALID: AttributeDef = AttributeDef::new(0x0003, DataType::Bool, Access::RO);
/// `NameSupport` (bit 7: names supported).
pub const NAME_SUPPORT: AttributeDef = AttributeDef::new(0x0004, DataType::Bitmap(1), Access::RO);

/// Add Scene.
pub const CMD_ADD_SCENE: CommandId = CommandId(0x00);
/// View Scene.
pub const CMD_VIEW_SCENE: CommandId = CommandId(0x01);
/// Remove Scene.
pub const CMD_REMOVE_SCENE: CommandId = CommandId(0x02);
/// Remove All Scenes.
pub const CMD_REMOVE_ALL_SCENES: CommandId = CommandId(0x03);
/// Store Scene.
pub const CMD_STORE_SCENE: CommandId = CommandId(0x04);
/// Recall Scene.
pub const CMD_RECALL_SCENE: CommandId = CommandId(0x05);
/// Get Scene Membership.
pub const CMD_GET_SCENE_MEMBERSHIP: CommandId = CommandId(0x06);
/// Enhanced Add Scene.
pub const CMD_ENHANCED_ADD_SCENE: CommandId = CommandId(0x40);
/// Enhanced View Scene.
pub const CMD_ENHANCED_VIEW_SCENE: CommandId = CommandId(0x41);
/// Copy Scene.
pub const CMD_COPY_SCENE: CommandId = CommandId(0x42);
/// Add Scene Response.
pub const CMD_ADD_SCENE_RESPONSE: CommandId = CommandId(0x00);
/// View Scene Response.
pub const CMD_VIEW_SCENE_RESPONSE: CommandId = CommandId(0x01);
/// Remove Scene Response.
pub const CMD_REMOVE_SCENE_RESPONSE: CommandId = CommandId(0x02);
/// Remove All Scenes Response.
pub const CMD_REMOVE_ALL_SCENES_RESPONSE: CommandId = CommandId(0x03);
/// Store Scene Response.
pub const CMD_STORE_SCENE_RESPONSE: CommandId = CommandId(0x04);
/// Get Scene Membership Response.
pub const CMD_GET_SCENE_MEMBERSHIP_RESPONSE: CommandId = CommandId(0x06);
/// Enhanced Add Scene Response.
pub const CMD_ENHANCED_ADD_SCENE_RESPONSE: CommandId = CommandId(0x40);
/// Enhanced View Scene Response.
pub const CMD_ENHANCED_VIEW_SCENE_RESPONSE: CommandId = CommandId(0x41);
/// Copy Scene Response.
pub const CMD_COPY_SCENE_RESPONSE: CommandId = CommandId(0x42);

/// Largest group identifier (§3.7.2.4.2.2 step 1).
pub const MAX_GROUP_ID: u16 = 0xFFF7;
/// Scene table capacity (§3.7.2.3.2 default).
pub const MAX_SCENES: usize = 16;
/// Room for the extension field sets of one entry (On/Off and Level
/// Control sets are 4 octets each).
pub const MAX_EXTENSION_BYTES: usize = 32;

/// Cluster definition.
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 3,
    received: &[
        CMD_ADD_SCENE,
        CMD_VIEW_SCENE,
        CMD_REMOVE_SCENE,
        CMD_REMOVE_ALL_SCENES,
        CMD_STORE_SCENE,
        CMD_RECALL_SCENE,
        CMD_GET_SCENE_MEMBERSHIP,
        CMD_ENHANCED_ADD_SCENE,
        CMD_ENHANCED_VIEW_SCENE,
        CMD_COPY_SCENE,
    ],
    generated: &[
        CMD_ADD_SCENE_RESPONSE,
        CMD_VIEW_SCENE_RESPONSE,
        CMD_REMOVE_SCENE_RESPONSE,
        CMD_REMOVE_ALL_SCENES_RESPONSE,
        CMD_STORE_SCENE_RESPONSE,
        CMD_GET_SCENE_MEMBERSHIP_RESPONSE,
        CMD_ENHANCED_ADD_SCENE_RESPONSE,
        CMD_ENHANCED_VIEW_SCENE_RESPONSE,
        CMD_COPY_SCENE_RESPONSE,
    ],
};

/// One scene table entry (Table 3-41); names are not supported.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SceneEntry {
    /// Scene group ID (0 = no group).
    pub group: u16,
    /// Scene ID.
    pub scene: u8,
    /// Scene transition time in seconds.
    pub transition: u16,
    /// TransitionTime100ms (0–9).
    pub transition_100ms: u8,
    /// Extension field sets: `{cluster u16, length u8, fields}`…
    pub fields: Vec<u8, MAX_EXTENSION_BYTES>,
}

impl SceneEntry {
    /// The transition time in tenths of a second.
    pub fn tenths(&self) -> u16 {
        self.transition
            .saturating_mul(10)
            .saturating_add(u16::from(self.transition_100ms))
    }

    /// Iterates the extension field sets as `(cluster, fields)`.
    pub fn sets(&self) -> impl Iterator<Item = (ClusterId, &[u8])> {
        FieldSets(&self.fields)
    }
}

/// Iterator over `{cluster u16, length u8, fields}` sets; malformed tails
/// end the iteration.
pub struct FieldSets<'a>(pub &'a [u8]);

impl<'a> Iterator for FieldSets<'a> {
    type Item = (ClusterId, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let mut r = Reader::new(self.0);
        let cluster = r.u16_le().ok()?;
        let len = usize::from(r.u8().ok()?);
        let fields = r.bytes(len).ok()?;
        self.0 = self.0.get(r.position()..).unwrap_or(&[]);
        Some((ClusterId(cluster), fields))
    }
}

/// The scene table (§3.7.2.3).
#[derive(Clone, Debug, Default)]
pub struct SceneTable {
    entries: Vec<SceneEntry, MAX_SCENES>,
}

impl SceneTable {
    /// Empty table.
    pub const fn new() -> Self {
        SceneTable {
            entries: Vec::new(),
        }
    }

    /// Entries.
    pub fn iter(&self) -> impl Iterator<Item = &SceneEntry> {
        self.entries.iter()
    }

    /// Number of scenes.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remaining capacity.
    pub fn capacity(&self) -> u8 {
        u8::try_from(MAX_SCENES - self.entries.len()).unwrap_or(0xfe)
    }

    /// Looks up a scene.
    pub fn get(&self, group: u16, scene: u8) -> Option<&SceneEntry> {
        self.entries
            .iter()
            .find(|e| e.group == group && e.scene == scene)
    }

    /// Inserts or overwrites a scene.
    pub fn put(&mut self, entry: SceneEntry) -> Result<(), ZclStatus> {
        if let Some(e) = self
            .entries
            .iter_mut()
            .find(|e| e.group == entry.group && e.scene == entry.scene)
        {
            *e = entry;
            return Ok(());
        }
        self.entries
            .push(entry)
            .map_err(|_| ZclStatus::InsufficientSpace)
    }

    /// Removes a scene.
    pub fn remove(&mut self, group: u16, scene: u8) -> bool {
        match self
            .entries
            .iter()
            .position(|e| e.group == group && e.scene == scene)
        {
            Some(i) => {
                self.entries.swap_remove(i);
                true
            }
            None => false,
        }
    }

    /// Removes every scene of `group`.
    pub fn remove_group(&mut self, group: u16) {
        self.entries.retain(|e| e.group != group);
    }
}

/// Builds a server instance (names unsupported).
pub fn server<const A: usize>() -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(DEF, Role::Server);
    c.add_attribute(SCENE_COUNT, &Value::Uint { width: 1, value: 0 })?;
    c.add_attribute(CURRENT_SCENE, &Value::Uint { width: 1, value: 0 })?;
    c.add_attribute(CURRENT_GROUP, &Value::Uint { width: 2, value: 0 })?;
    c.add_attribute(SCENE_VALID, &Value::Bool(Some(false)))?;
    c.add_attribute(NAME_SUPPORT, &Value::Bits { width: 1, bits: 0 })?;
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF.mirrored(), Role::Client)
}

/// Marks the device state as no longer matching the current scene
/// (§3.7.2.2.1.4), e.g. after an On/Off or Level Control command.
pub fn invalidate<const A: usize>(c: &mut ClusterInstance<A>) {
    c.set_bool(SCENE_VALID.id, false);
}

fn sync_count<const A: usize>(c: &mut ClusterInstance<A>, t: &SceneTable) {
    c.set_u8(SCENE_COUNT.id, u8::try_from(t.len()).unwrap_or(u8::MAX));
}

fn mark_current<const A: usize>(c: &mut ClusterInstance<A>, group: u16, scene: u8) {
    c.set_u8(CURRENT_SCENE.id, scene);
    c.set_u16(CURRENT_GROUP.id, group);
    c.set_bool(SCENE_VALID.id, true);
}

/// Result of a received Scenes server command.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// Send the cluster-specific response written to the output buffer.
    Response(CommandId),
    /// Reply with a Default Response (subject to the usual rules).
    Default(ZclStatus),
    /// Store Scene: the dispatcher gathers the endpoint's extension field
    /// sets and calls [`complete_store`].
    Store {
        /// Group.
        group: u16,
        /// Scene.
        scene: u8,
    },
    /// Recall Scene: apply the entry's extension field sets over `tenths`
    /// tenths of a second (§3.7.2.4.7.2 step 4), then Default Response
    /// SUCCESS.
    Recall {
        /// Group.
        group: u16,
        /// Scene.
        scene: u8,
        /// Transition time.
        tenths: u16,
    },
    /// Nothing to send (groupcast / broadcast delivery, §3.7.2.4.1).
    None,
}

/// Steps 1–2 of every command: group range and membership.
fn check_group(group: u16, member: &impl Fn(u16) -> bool) -> ZclStatus {
    if group > MAX_GROUP_ID {
        ZclStatus::InvalidValue
    } else if group != 0 && !member(group) {
        ZclStatus::InvalidField
    } else {
        ZclStatus::Success
    }
}

fn status_response(
    out: &mut Writer<'_>,
    cmd: CommandId,
    status: ZclStatus,
    group: u16,
    scene: Option<u8>,
    unicast: bool,
) -> Outcome {
    if !unicast {
        return Outcome::None;
    }
    let _ = out.u8(status.raw());
    let _ = out.u16_le(group);
    if let Some(s) = scene {
        let _ = out.u8(s);
    }
    Outcome::Response(cmd)
}

/// Executes a command received by the server (§3.7.2.4) against the
/// endpoint's scene table `t`. `member` answers whether the endpoint
/// belongs to a group; `unicast` is false for group / broadcast
/// deliveries. Response payloads are written to `out`.
pub fn handle<const A: usize>(
    c: &mut ClusterInstance<A>,
    t: &mut SceneTable,
    command: CommandId,
    payload: &[u8],
    unicast: bool,
    member: &impl Fn(u16) -> bool,
    out: &mut Writer<'_>,
) -> Outcome {
    let mut r = Reader::new(payload);
    match command {
        CMD_ADD_SCENE | CMD_ENHANCED_ADD_SCENE => {
            let enhanced = command == CMD_ENHANCED_ADD_SCENE;
            let rsp = if enhanced {
                CMD_ENHANCED_ADD_SCENE_RESPONSE
            } else {
                CMD_ADD_SCENE_RESPONSE
            };
            let (Ok(group), Ok(scene), Ok(time), Ok(name_len)) =
                (r.u16_le(), r.u8(), r.u16_le(), r.u8())
            else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            // Names are discarded (§3.7.2.3.1); an invalid string is empty.
            if name_len != 0xff && r.bytes(usize::from(name_len)).is_err() {
                return Outcome::Default(ZclStatus::MalformedCommand);
            }
            let mut status = check_group(group, member);
            if status.is_success() {
                let mut fields = Vec::new();
                // Keep whole, well-formed sets that fit; drop the rest.
                for (cl, f) in FieldSets(r.bytes(r.remaining()).unwrap_or(&[])) {
                    let need = 3 + f.len();
                    if fields.len() + need > MAX_EXTENSION_BYTES {
                        break;
                    }
                    let _ = fields.extend_from_slice(&cl.0.to_le_bytes());
                    let _ = fields.push(u8::try_from(f.len()).unwrap_or(0));
                    let _ = fields.extend_from_slice(f);
                }
                let (transition, transition_100ms) = if enhanced {
                    (time / 10, u8::try_from(time % 10).unwrap_or(0))
                } else {
                    (time, 0)
                };
                status = match t.put(SceneEntry {
                    group,
                    scene,
                    transition,
                    transition_100ms,
                    fields,
                }) {
                    Ok(()) => ZclStatus::Success,
                    Err(s) => s,
                };
                sync_count(c, t);
            }
            status_response(out, rsp, status, group, Some(scene), unicast)
        }
        CMD_VIEW_SCENE | CMD_ENHANCED_VIEW_SCENE => {
            let enhanced = command == CMD_ENHANCED_VIEW_SCENE;
            let rsp = if enhanced {
                CMD_ENHANCED_VIEW_SCENE_RESPONSE
            } else {
                CMD_VIEW_SCENE_RESPONSE
            };
            let (Ok(group), Ok(scene)) = (r.u16_le(), r.u8()) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let mut status = check_group(group, member);
            let entry = if status.is_success() {
                let e = t.get(group, scene).cloned();
                if e.is_none() {
                    status = ZclStatus::NotFound;
                }
                e
            } else {
                None
            };
            if !unicast {
                return Outcome::None;
            }
            let _ = out.u8(status.raw());
            let _ = out.u16_le(group);
            let _ = out.u8(scene);
            if let Some(e) = entry {
                let time = if enhanced { e.tenths() } else { e.transition };
                let _ = out.u16_le(time);
                let _ = out.u8(0); // null name
                let _ = out.bytes(&e.fields);
            }
            Outcome::Response(rsp)
        }
        CMD_REMOVE_SCENE => {
            let (Ok(group), Ok(scene)) = (r.u16_le(), r.u8()) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let mut status = check_group(group, member);
            if status.is_success() {
                if t.remove(group, scene) {
                    sync_count(c, t);
                } else {
                    status = ZclStatus::NotFound;
                }
            }
            status_response(
                out,
                CMD_REMOVE_SCENE_RESPONSE,
                status,
                group,
                Some(scene),
                unicast,
            )
        }
        CMD_REMOVE_ALL_SCENES => {
            let Ok(group) = r.u16_le() else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let status = check_group(group, member);
            if status.is_success() {
                t.remove_group(group);
                sync_count(c, t);
            }
            status_response(
                out,
                CMD_REMOVE_ALL_SCENES_RESPONSE,
                status,
                group,
                None,
                unicast,
            )
        }
        CMD_STORE_SCENE => {
            let (Ok(group), Ok(scene)) = (r.u16_le(), r.u8()) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let status = check_group(group, member);
            if !status.is_success() {
                return status_response(
                    out,
                    CMD_STORE_SCENE_RESPONSE,
                    status,
                    group,
                    Some(scene),
                    unicast,
                );
            }
            Outcome::Store { group, scene }
        }
        CMD_RECALL_SCENE => {
            let (Ok(group), Ok(scene)) = (r.u16_le(), r.u8()) else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let time = r.u16_le().ok();
            let status = check_group(group, member);
            if !status.is_success() {
                return Outcome::Default(status);
            }
            let Some(entry_tenths) = t.get(group, scene).map(SceneEntry::tenths) else {
                return Outcome::Default(ZclStatus::NotFound);
            };
            let tenths = match time {
                Some(t) if t != 0xffff => t,
                _ => entry_tenths,
            };
            mark_current(c, group, scene);
            Outcome::Recall {
                group,
                scene,
                tenths,
            }
        }
        CMD_GET_SCENE_MEMBERSHIP => {
            let Ok(group) = r.u16_le() else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let status = check_group(group, member);
            let capacity = t.capacity();
            let mut ids: Vec<u8, MAX_SCENES> = Vec::new();
            if status.is_success() {
                for e in t.iter().filter(|e| e.group == group) {
                    let _ = ids.push(e.scene);
                }
            }
            if !unicast && ids.is_empty() {
                return Outcome::None;
            }
            let _ = out.u8(status.raw());
            let _ = out.u8(capacity);
            let _ = out.u16_le(group);
            if status.is_success() {
                let _ = out.u8(u8::try_from(ids.len()).unwrap_or(u8::MAX));
                let _ = out.bytes(&ids);
            }
            Outcome::Response(CMD_GET_SCENE_MEMBERSHIP_RESPONSE)
        }
        CMD_COPY_SCENE => {
            let (Ok(mode), Ok(from_g), Ok(from_s), Ok(to_g), Ok(to_s)) =
                (r.u8(), r.u16_le(), r.u8(), r.u16_le(), r.u8())
            else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let copy_all = mode & 0x01 != 0;
            let mut status = check_group(from_g, member);
            if status.is_success() {
                status = check_group(to_g, member);
            }
            if status.is_success() {
                status = copy(t, copy_all, from_g, from_s, to_g, to_s);
                sync_count(c, t);
            }
            if !unicast {
                return Outcome::None;
            }
            let _ = out.u8(status.raw());
            let _ = out.u16_le(from_g);
            let _ = out.u8(from_s);
            Outcome::Response(CMD_COPY_SCENE_RESPONSE)
        }
        _ => Outcome::Default(ZclStatus::UnsupportedClusterCommand),
    }
}

/// Copy Scene (§3.7.2.4.11.6 steps 3–5).
fn copy(t: &mut SceneTable, all: bool, from_g: u16, from_s: u8, to_g: u16, to_s: u8) -> ZclStatus {
    if all {
        let sources: Vec<SceneEntry, MAX_SCENES> =
            t.iter().filter(|e| e.group == from_g).cloned().collect();
        for src in sources {
            let mut e = src;
            e.group = to_g;
            if t.put(e).is_err() {
                return ZclStatus::InsufficientSpace;
            }
        }
        ZclStatus::Success
    } else {
        let Some(mut e) = t.get(from_g, from_s).cloned() else {
            return ZclStatus::InvalidField;
        };
        e.group = to_g;
        e.scene = to_s;
        match t.put(e) {
            Ok(()) => ZclStatus::Success,
            Err(s) => s,
        }
    }
}

/// Completes a Store Scene (§3.7.2.4.6.2 steps 3–5) with the endpoint's
/// current extension field sets (`{cluster, length, fields}`…):
/// transition time and name of an existing entry are kept.
pub fn complete_store<const A: usize>(
    c: &mut ClusterInstance<A>,
    t: &mut SceneTable,
    group: u16,
    scene: u8,
    field_sets: &[u8],
    unicast: bool,
    out: &mut Writer<'_>,
) -> Outcome {
    let (transition, transition_100ms) = t
        .get(group, scene)
        .map_or((0, 0), |e| (e.transition, e.transition_100ms));
    let mut fields = Vec::new();
    let _ = fields.extend_from_slice(
        field_sets
            .get(..MAX_EXTENSION_BYTES.min(field_sets.len()))
            .unwrap_or(&[]),
    );
    let status = match t.put(SceneEntry {
        group,
        scene,
        transition,
        transition_100ms,
        fields,
    }) {
        Ok(()) => ZclStatus::Success,
        Err(s) => s,
    };
    sync_count(c, t);
    if status.is_success() {
        mark_current(c, group, scene);
    }
    status_response(
        out,
        CMD_STORE_SCENE_RESPONSE,
        status,
        group,
        Some(scene),
        unicast,
    )
}

/// Stores the global scene (group 0, scene 0; §3.8.2.2.2) from the
/// endpoint's extension field sets.
pub fn store_global<const A: usize>(
    c: &mut ClusterInstance<A>,
    t: &mut SceneTable,
    field_sets: &[u8],
) {
    let mut sink = [0u8; 4];
    let mut w = Writer::new(&mut sink);
    let _ = complete_store(c, t, 0, 0, field_sets, false, &mut w);
}

/// The global scene's transition time and field sets, if stored; marks
/// it current.
pub fn global<const A: usize>(c: &mut ClusterInstance<A>, t: &SceneTable) -> Option<SceneEntry> {
    let e = t.get(0, 0).cloned()?;
    mark_current(c, 0, 0);
    Some(e)
}

/// Encodes one extension field set.
pub fn write_field_set(out: &mut Writer<'_>, cluster: ClusterId, fields: &[u8]) {
    let _ = out.u16_le(cluster.0);
    let _ = out.u8(u8::try_from(fields.len()).unwrap_or(0));
    let _ = out.bytes(fields);
}
