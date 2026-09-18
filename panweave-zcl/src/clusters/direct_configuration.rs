//! Zigbee Direct Configuration cluster (Zigbee Direct 1.1 §11.3, cluster
//! 0x003D): a Trust Center (or, on a distributed network, any device)
//! switches a ZDD's Zigbee Direct interface on and off and sets the
//! Anonymous Join Timeout. The server keeps `InterfaceState` and
//! `AnonymousJoinTimeout`; the dispatcher enforces the §11.3.5.1
//! authorization (APS security with the Trust Center on a centralized
//! network) and hands the resulting configuration to the application.

use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{ClusterId, CommandId};

use crate::attribute::{Access, AttributeDef};
use crate::cluster::{ClusterDef, ClusterInstance, ClusterState, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x003d);

/// `InterfaceState` (map8: bit 0 enabled).
pub const INTERFACE_STATE: AttributeDef =
    AttributeDef::new(0x0000, DataType::Bitmap(1), Access::RO);
/// `AnonymousJoinTimeout` (uint24 seconds, 0 = never, 0xFFFFFF = always
/// while the network is open).
pub const ANONYMOUS_JOIN_TIMEOUT: AttributeDef =
    AttributeDef::new(0x0001, DataType::Uint(3), Access::RO);

/// The interface is enabled (`InterfaceState` bit 0).
pub const INTERFACE_ENABLED: u8 = 0x01;
/// `AnonymousJoinTimeout` value: the anonymous secret is accepted as
/// long as the network is open.
pub const ANONYMOUS_JOIN_ALWAYS: u32 = 0x00FF_FFFF;
/// Largest configurable timeout (Table 57 range).
pub const ANONYMOUS_JOIN_MAX: u32 = 0x0010_0000;
/// The recommended default timeout (§11.3.5.3.2).
pub const ANONYMOUS_JOIN_DEFAULT: u32 = 3600;

/// Configure Zigbee Direct Interface (client → server).
pub const CMD_CONFIGURE_INTERFACE: CommandId = CommandId(0x00);
/// Configure Zigbee Direct Anonymous Join Timeout.
pub const CMD_CONFIGURE_ANONYMOUS_JOIN_TIMEOUT: CommandId = CommandId(0x01);
/// Configure Zigbee Direct Interface Response (server → client).
pub const CMD_CONFIGURE_INTERFACE_RESPONSE: CommandId = CommandId(0x00);

/// Cluster definition.
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[
        CMD_CONFIGURE_INTERFACE,
        CMD_CONFIGURE_ANONYMOUS_JOIN_TIMEOUT,
    ],
    generated: &[CMD_CONFIGURE_INTERFACE_RESPONSE],
};

/// Configure Zigbee Direct Interface Response (Table 63).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InterfaceResponse {
    /// SUCCESS or FAILURE.
    pub status: ZclStatus,
    /// The interface state after the command.
    pub enabled: bool,
}

impl InterfaceResponse {
    /// Parses the payload.
    pub fn parse(payload: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(payload);
        let status = ZclStatus::from_raw(r.u8()?);
        let state = r.u8()?;
        Ok(InterfaceResponse {
            status,
            enabled: state & INTERFACE_ENABLED != 0,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        w.u8(self.status.raw())?;
        w.u8(u8::from(self.enabled))?;
        Ok(w.position())
    }
}

/// Server state (`ClusterState::DirectConfiguration`).
#[derive(Clone, Copy, Debug)]
pub struct State {
    /// The network uses centralized security: commands must be
    /// APS-secured and come from the Trust Center (§11.3.5.1).
    pub centralized: bool,
}

/// Builds a server: the interface `enabled`, the anonymous join
/// timeout `timeout` seconds, on a `centralized` network.
pub fn server<const A: usize>(
    enabled: bool,
    timeout: u32,
    centralized: bool,
) -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(DEF, Role::Server);
    c.add_attribute(
        INTERFACE_STATE,
        &Value::Bits {
            width: 1,
            bits: u64::from(u8::from(enabled)),
        },
    )?;
    c.add_attribute(
        ANONYMOUS_JOIN_TIMEOUT,
        &Value::Uint {
            width: 3,
            value: u64::from(timeout & ANONYMOUS_JOIN_ALWAYS),
        },
    )?;
    c.state = ClusterState::DirectConfiguration(State { centralized });
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF.mirrored(), Role::Client)
}

/// Whether the server's interface is enabled.
pub fn interface_enabled<const A: usize>(c: &ClusterInstance<A>) -> bool {
    c.u8(INTERFACE_STATE.id).unwrap_or(0) & INTERFACE_ENABLED != 0
}

/// The server's `AnonymousJoinTimeout`.
pub fn anonymous_join_timeout<const A: usize>(c: &ClusterInstance<A>) -> u32 {
    u32::try_from(c.u64(ANONYMOUS_JOIN_TIMEOUT.id).unwrap_or(0)).unwrap_or(ANONYMOUS_JOIN_ALWAYS)
}

/// Sets the interface state (also from the application, e.g. after a
/// local stimulus); returns whether it changed.
pub fn set_interface<const A: usize>(c: &mut ClusterInstance<A>, enabled: bool) -> bool {
    if interface_enabled(c) == enabled {
        return false;
    }
    c.set(
        INTERFACE_STATE.id,
        &Value::Bits {
            width: 1,
            bits: u64::from(u8::from(enabled)),
        },
    );
    true
}

/// Sets the anonymous join timeout; returns whether it changed.
pub fn set_anonymous_join_timeout<const A: usize>(
    c: &mut ClusterInstance<A>,
    timeout: u32,
) -> bool {
    if anonymous_join_timeout(c) == timeout {
        return false;
    }
    c.set(
        ANONYMOUS_JOIN_TIMEOUT.id,
        &Value::Uint {
            width: 3,
            value: u64::from(timeout & ANONYMOUS_JOIN_ALWAYS),
        },
    );
    true
}

/// Result of a received command.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Outcome {
    /// Reply with this Configure Zigbee Direct Interface Response;
    /// `changed` when the application must switch the interface.
    Interface {
        /// The response.
        response: InterfaceResponse,
        /// The state changed.
        changed: bool,
    },
    /// The timeout was set (Default Response SUCCESS); `changed` when
    /// the countdown restarts.
    Timeout {
        /// The new timeout.
        seconds: u32,
        /// The value changed.
        changed: bool,
    },
    /// Refused with this status.
    Default(ZclStatus),
}

/// Handles a received command from a `unicast` frame that was
/// `aps_secured` (§11.3.5.1: on a centralized network only APS-secured
/// commands are authorized; the caller passes `from_trust_center` for
/// the source check).
pub fn handle<const A: usize>(
    c: &mut ClusterInstance<A>,
    cmd: CommandId,
    payload: &[u8],
    unicast: bool,
    aps_secured: bool,
    from_trust_center: bool,
) -> Outcome {
    if !unicast {
        // §11.3.5.4.2: groupcast and broadcast are ignored.
        return Outcome::Default(ZclStatus::Success);
    }
    let centralized = match c.state {
        ClusterState::DirectConfiguration(s) => s.centralized,
        _ => true,
    };
    if centralized && !(aps_secured && from_trust_center) {
        return Outcome::Default(ZclStatus::NotAuthorized);
    }
    match cmd {
        CMD_CONFIGURE_INTERFACE => {
            let Some(&state) = payload.first() else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            let enabled = state & INTERFACE_ENABLED != 0;
            let changed = set_interface(c, enabled);
            Outcome::Interface {
                response: InterfaceResponse {
                    status: ZclStatus::Success,
                    enabled,
                },
                changed,
            }
        }
        CMD_CONFIGURE_ANONYMOUS_JOIN_TIMEOUT => {
            let Ok(seconds) = Reader::new(payload).u24_le() else {
                return Outcome::Default(ZclStatus::MalformedCommand);
            };
            if seconds > ANONYMOUS_JOIN_MAX && seconds != ANONYMOUS_JOIN_ALWAYS {
                return Outcome::Default(ZclStatus::InvalidValue);
            }
            let changed = set_anonymous_join_timeout(c, seconds);
            Outcome::Timeout { seconds, changed }
        }
        _ => Outcome::Default(ZclStatus::UnsupportedClusterCommand),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_and_timeout_are_configured_by_an_authorized_source() {
        let mut c: ClusterInstance<4> = server(true, ANONYMOUS_JOIN_DEFAULT, true).unwrap();
        // Broadcasts are ignored, unsecured unicasts refused.
        assert_eq!(
            handle(&mut c, CMD_CONFIGURE_INTERFACE, &[0], false, true, true),
            Outcome::Default(ZclStatus::Success)
        );
        assert!(interface_enabled(&c));
        assert_eq!(
            handle(&mut c, CMD_CONFIGURE_INTERFACE, &[0], true, false, true),
            Outcome::Default(ZclStatus::NotAuthorized)
        );
        assert_eq!(
            handle(&mut c, CMD_CONFIGURE_INTERFACE, &[0], true, true, false),
            Outcome::Default(ZclStatus::NotAuthorized)
        );
        // Disable, then disable again (no change), reserved bits ignored.
        assert_eq!(
            handle(&mut c, CMD_CONFIGURE_INTERFACE, &[0xfe], true, true, true),
            Outcome::Interface {
                response: InterfaceResponse {
                    status: ZclStatus::Success,
                    enabled: false
                },
                changed: true
            }
        );
        assert_eq!(
            handle(&mut c, CMD_CONFIGURE_INTERFACE, &[0], true, true, true),
            Outcome::Interface {
                response: InterfaceResponse {
                    status: ZclStatus::Success,
                    enabled: false
                },
                changed: false
            }
        );
        let mut buf = [0u8; 2];
        let n = InterfaceResponse {
            status: ZclStatus::Success,
            enabled: false,
        }
        .encode(&mut buf)
        .unwrap();
        assert_eq!(&buf[..n], &[0, 0]);
        assert!(!InterfaceResponse::parse(&buf[..n]).unwrap().enabled);
        // Timeout: range checked, ALWAYS accepted.
        assert_eq!(
            handle(
                &mut c,
                CMD_CONFIGURE_ANONYMOUS_JOIN_TIMEOUT,
                &[0x01, 0x00, 0x20],
                true,
                true,
                true
            ),
            Outcome::Default(ZclStatus::InvalidValue)
        );
        assert_eq!(
            handle(
                &mut c,
                CMD_CONFIGURE_ANONYMOUS_JOIN_TIMEOUT,
                &[0xff, 0xff, 0xff],
                true,
                true,
                true
            ),
            Outcome::Timeout {
                seconds: ANONYMOUS_JOIN_ALWAYS,
                changed: true
            }
        );
        assert_eq!(anonymous_join_timeout(&c), ANONYMOUS_JOIN_ALWAYS);
        assert_eq!(
            handle(
                &mut c,
                CMD_CONFIGURE_ANONYMOUS_JOIN_TIMEOUT,
                &[0x00, 0x00, 0x00],
                true,
                true,
                true
            ),
            Outcome::Timeout {
                seconds: 0,
                changed: true
            }
        );
        // A distributed network needs no security.
        let mut d: ClusterInstance<4> = server(false, 0, false).unwrap();
        assert_eq!(
            handle(&mut d, CMD_CONFIGURE_INTERFACE, &[1], true, false, false),
            Outcome::Interface {
                response: InterfaceResponse {
                    status: ZclStatus::Success,
                    enabled: true
                },
                changed: true
            }
        );
    }
}
