//! Keep-Alive cluster (ZCL8 §3.18), revision 1: the Trust Center's server
//! attributes that pace the routers' keep-alive reads (§3.18.4). The
//! client behaviour (periodic APS-encrypted Read Attributes, three
//! failures → Trust Center search) is run by the runtime.

use panweave_types::ClusterId;

use crate::attribute::{Access, AttributeDef};
use crate::cluster::{ClusterDef, ClusterInstance, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0025);
/// `TCKeepAliveBase` (minutes).
pub const TC_KEEP_ALIVE_BASE: AttributeDef =
    AttributeDef::new(0x0000, DataType::Uint(1), Access::RO);
/// `TCKeepAliveJitter` (seconds).
pub const TC_KEEP_ALIVE_JITTER: AttributeDef =
    AttributeDef::new(0x0001, DataType::Uint(2), Access::RO);

/// Default `TCKeepAliveBase`: 10 minutes.
pub const DEFAULT_BASE_MINUTES: u8 = 0x0A;
/// Default `TCKeepAliveJitter`: 300 s.
pub const DEFAULT_JITTER_SECONDS: u16 = 0x012C;
/// Successive read failures after which the Trust Center is considered
/// lost (§3.18.4).
pub const MAX_FAILURES: u8 = 3;

/// Cluster definition.
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[],
    generated: &[],
};

/// Builds a server instance with the given base (minutes, non-zero) and
/// jitter (seconds).
pub fn server<const A: usize>(
    base_minutes: u8,
    jitter_seconds: u16,
) -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(DEF, Role::Server);
    c.add_attribute(
        TC_KEEP_ALIVE_BASE,
        &Value::Uint {
            width: 1,
            value: u64::from(base_minutes.max(1)),
        },
    )?;
    c.add_attribute(
        TC_KEEP_ALIVE_JITTER,
        &Value::Uint {
            width: 2,
            value: u64::from(jitter_seconds),
        },
    )?;
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF.mirrored(), Role::Client)
}
