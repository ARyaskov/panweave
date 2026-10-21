//! Trust Center security messages: the authorization policy in force,
//! devices that are not authorized, and administrator exemptions from
//! the key-exchange requirement (added in 0.2.1, after the existing
//! tags).

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};

use super::{ProtocolError, read_bool};

/// Exemptions a [`SecurityStatus`] lists (the stack holds at most this
/// many).
pub const MAX_EXEMPTIONS: usize = 8;
/// Unauthorized registered devices a [`SecurityStatus`] lists.
pub const MAX_UNAUTHORIZED: usize = 8;
/// Longest exemption window, seconds.
pub const MAX_EXEMPTION_SECONDS: u16 = 3600;

/// How the Trust Center regards a device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeviceAuthorization {
    /// The policy is satisfied.
    Authorized,
    /// Authorized only through an administrator exemption.
    Exempt,
    /// Holds the network key, inside its key-exchange window.
    PendingKeyExchange,
    /// Never completed the required key exchange: no application access.
    KeyExchangeIncomplete,
    /// No key-pair entry at the Trust Center: no application access.
    Unknown,
}

impl DeviceAuthorization {
    /// The wire code.
    pub const fn code(self) -> u8 {
        match self {
            DeviceAuthorization::Authorized => 0,
            DeviceAuthorization::Exempt => 1,
            DeviceAuthorization::PendingKeyExchange => 2,
            DeviceAuthorization::KeyExchangeIncomplete => 3,
            DeviceAuthorization::Unknown => 4,
        }
    }

    /// The value of a wire code (unknown codes read as
    /// [`DeviceAuthorization::Unknown`]).
    pub const fn from_code(c: u8) -> Self {
        match c {
            0 => DeviceAuthorization::Authorized,
            1 => DeviceAuthorization::Exempt,
            2 => DeviceAuthorization::PendingKeyExchange,
            3 => DeviceAuthorization::KeyExchangeIncomplete,
            _ => DeviceAuthorization::Unknown,
        }
    }

    /// A short name.
    pub const fn name(self) -> &'static str {
        match self {
            DeviceAuthorization::Authorized => "authorized",
            DeviceAuthorization::Exempt => "exempt",
            DeviceAuthorization::PendingKeyExchange => "pending-key-exchange",
            DeviceAuthorization::KeyExchangeIncomplete => "key-exchange-incomplete",
            DeviceAuthorization::Unknown => "unknown",
        }
    }
}

/// An exemption from the key-exchange requirement.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExemptionInfo {
    /// The device.
    pub ieee: u64,
    /// Seconds left to join under the exemption; `None` once the device
    /// joined (the exemption is then permanent until revoked).
    pub remaining_s: Option<u16>,
}

/// Application frames the Trust Center refused, by reason.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DeniedCounts {
    /// The originator's IEEE address could not be resolved.
    pub unresolved: u32,
    /// The claimed IEEE address contradicted the address map.
    pub inconsistent: u32,
    /// The originator has no key-pair entry.
    pub unknown: u32,
    /// The originator was inside its key-exchange window.
    pub pending: u32,
    /// The originator never completed the key exchange.
    pub incomplete: u32,
}

/// The Trust Center's security state.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct SecurityStatus {
    /// `bdbTrustCenterRequireKeyExchange`.
    pub require_key_exchange: bool,
    /// `bdbTrustCenterNodeJoinTimeout`, seconds.
    pub node_join_timeout_s: u16,
    /// Devices inside their key-exchange window.
    pub pending_key_exchanges: u8,
    /// Devices removed because the window passed.
    pub key_exchange_timeouts: u32,
    /// Application frames dropped from unauthorized devices (all
    /// reasons).
    pub unauthorized_frames_dropped: u32,
    /// The same, by reason.
    pub denied: DeniedCounts,
    /// Commissioning exemptions consumed by a join.
    pub exemptions_used: u32,
    /// Commissioning exemptions that expired unused.
    pub exemptions_expired: u32,
    /// Link-key entries in use.
    pub link_keys: u8,
    /// Link-key entries available.
    pub link_key_capacity: u8,
    /// Exemptions in force.
    pub exemptions: Vec<ExemptionInfo, MAX_EXEMPTIONS>,
    /// Registered devices without application access.
    pub unauthorized: Vec<(u64, DeviceAuthorization), MAX_UNAUTHORIZED>,
}

fn count(n: usize) -> Result<u8, CodecError> {
    u8::try_from(n).map_err(|_| CodecError::Unrepresentable { field: "count" })
}

pub(crate) fn write_security(w: &mut Writer<'_>, s: &SecurityStatus) -> Result<(), CodecError> {
    w.u8(u8::from(s.require_key_exchange))?;
    w.u16_le(s.node_join_timeout_s)?;
    w.u8(s.pending_key_exchanges)?;
    w.u32_le(s.key_exchange_timeouts)?;
    w.u32_le(s.unauthorized_frames_dropped)?;
    for v in [
        s.denied.unresolved,
        s.denied.inconsistent,
        s.denied.unknown,
        s.denied.pending,
        s.denied.incomplete,
        s.exemptions_used,
        s.exemptions_expired,
    ] {
        w.u32_le(v)?;
    }
    w.u8(s.link_keys)?;
    w.u8(s.link_key_capacity)?;
    w.u8(count(s.exemptions.len())?)?;
    for e in &s.exemptions {
        w.u64_le(e.ieee)?;
        match e.remaining_s {
            Some(v) => {
                w.u8(1)?;
                w.u16_le(v)?;
            }
            None => w.u8(0)?,
        }
    }
    w.u8(count(s.unauthorized.len())?)?;
    for (ieee, a) in &s.unauthorized {
        w.u64_le(*ieee)?;
        w.u8(a.code())?;
    }
    Ok(())
}

pub(crate) fn read_security(r: &mut Reader<'_>) -> Result<SecurityStatus, ProtocolError> {
    let mut s = SecurityStatus {
        require_key_exchange: read_bool(r)?,
        node_join_timeout_s: r.u16_le()?,
        pending_key_exchanges: r.u8()?,
        key_exchange_timeouts: r.u32_le()?,
        unauthorized_frames_dropped: r.u32_le()?,
        denied: DeniedCounts {
            unresolved: r.u32_le()?,
            inconsistent: r.u32_le()?,
            unknown: r.u32_le()?,
            pending: r.u32_le()?,
            incomplete: r.u32_le()?,
        },
        exemptions_used: r.u32_le()?,
        exemptions_expired: r.u32_le()?,
        link_keys: r.u8()?,
        link_key_capacity: r.u8()?,
        ..SecurityStatus::default()
    };
    for _ in 0..r.u8()? {
        let ieee = r.u64_le()?;
        let remaining_s = if read_bool(r)? {
            Some(r.u16_le()?)
        } else {
            None
        };
        s.exemptions
            .push(ExemptionInfo { ieee, remaining_s })
            .map_err(|_| ProtocolError::Malformed)?;
    }
    for _ in 0..r.u8()? {
        let ieee = r.u64_le()?;
        let a = DeviceAuthorization::from_code(r.u8()?);
        s.unauthorized
            .push((ieee, a))
            .map_err(|_| ProtocolError::Malformed)?;
    }
    Ok(s)
}
