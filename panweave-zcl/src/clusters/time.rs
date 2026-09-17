//! Time cluster (ZCL8 §3.12): a real-time clock exposed as the `Time`
//! attribute (seconds since 2000-01-01 00:00:00 UTC), the `TimeStatus`
//! flags, the time zone / DST attributes and the derived `StandardTime`,
//! `LocalTime`, `LastSetTime` and `ValidUntilTime`. The clock runs on
//! the dispatcher's monotonic time: the server keeps the UTC value that
//! was last set and the instant it was set at, and refreshes the
//! attributes every second; a write of `Time` over the air (allowed only
//! while the Master bit is clear) resets that base.

use panweave_types::time::{Duration, Instant};
use panweave_types::{AttributeId, ClusterId};

use crate::attribute::{Access, AttributeDef, AttributeTable};
use crate::cluster::{ClusterDef, ClusterInstance, ClusterState, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x000a);
/// `Time` (UTC, read / conditionally writable).
pub const TIME: AttributeDef = AttributeDef::new(0x0000, DataType::UtcTime, Access::RW);
/// `TimeStatus` (map8).
pub const TIME_STATUS: AttributeDef = AttributeDef::new(0x0001, DataType::Bitmap(1), Access::RW);
/// `TimeZone` (int32 seconds).
pub const TIME_ZONE: AttributeDef = AttributeDef::new(0x0002, DataType::Int(4), Access::RW);
/// `DstStart` (uint32, UTC semantics).
pub const DST_START: AttributeDef = AttributeDef::new(0x0003, DataType::Uint(4), Access::RW);
/// `DstEnd` (uint32, UTC semantics).
pub const DST_END: AttributeDef = AttributeDef::new(0x0004, DataType::Uint(4), Access::RW);
/// `DstShift` (int32 seconds).
pub const DST_SHIFT: AttributeDef = AttributeDef::new(0x0005, DataType::Int(4), Access::RW);
/// `StandardTime` (uint32).
pub const STANDARD_TIME: AttributeDef = AttributeDef::new(0x0006, DataType::Uint(4), Access::RO);
/// `LocalTime` (uint32).
pub const LOCAL_TIME: AttributeDef = AttributeDef::new(0x0007, DataType::Uint(4), Access::RO);
/// `LastSetTime` (UTC).
pub const LAST_SET_TIME: AttributeDef = AttributeDef::new(0x0008, DataType::UtcTime, Access::RO);
/// `ValidUntilTime` (UTC).
pub const VALID_UNTIL_TIME: AttributeDef = AttributeDef::new(0x0009, DataType::UtcTime, Access::RW);

/// The invalid time (non-value).
pub const INVALID: u32 = 0xffff_ffff;
/// Widest time zone / DST shift: one day.
pub const MAX_OFFSET_SECS: i32 = 86_400;

/// `TimeStatus` bits (Table 3-70).
pub mod status {
    /// Master clock (set internally to the time standard).
    pub const MASTER: u8 = 0x01;
    /// Synchronized over the network.
    pub const SYNCHRONIZED: u8 = 0x02;
    /// Master for time zone and DST.
    pub const MASTER_ZONE_DST: u8 = 0x04;
    /// Time synchronization should be superseded.
    pub const SUPERSEDING: u8 = 0x08;
    /// Bits a write over the air cannot change.
    pub const FIXED: u8 = MASTER | MASTER_ZONE_DST;
}

/// Cluster definition (attribute-only).
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 2,
    received: &[],
    generated: &[],
};

/// The clock behind a Time server.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Clock {
    /// UTC seconds at `base_at`, `None` while unset.
    pub base: Option<u32>,
    /// Monotonic instant `base` was set at.
    pub base_at: Instant,
    /// The `Time` value the server last wrote itself (to detect writes
    /// from the network).
    pub published: u32,
    /// The status bits fixed by the product.
    pub fixed_status: u8,
}

fn write_guard<const A: usize>(t: &AttributeTable<A>, id: AttributeId, _: &Value<'_>) -> ZclStatus {
    let status = t.u64(TIME_STATUS.id).unwrap_or(0);
    let master = status & u64::from(status::MASTER) != 0;
    let master_zone = status & u64::from(status::MASTER_ZONE_DST) != 0;
    match id {
        i if i == TIME.id && master => ZclStatus::ReadOnly,
        i if (i == TIME_ZONE.id || i == DST_START.id || i == DST_END.id || i == DST_SHIFT.id)
            && master_zone =>
        {
            ZclStatus::ReadOnly
        }
        _ => ZclStatus::Success,
    }
}

const fn u32v(v: u32) -> Value<'static> {
    Value::Uint {
        width: 4,
        value: v as u64,
    }
}

const fn utc(v: u32) -> Value<'static> {
    Value::Time {
        ty: DataType::UtcTime,
        raw: v,
    }
}

const fn i32v(v: i32) -> Value<'static> {
    Value::Int {
        width: 4,
        value: v as i64,
    }
}

/// Builds a server. `fixed_status` are the product's `Master` /
/// `MasterZoneDst` bits (with `Superseding` if wanted); `zone` adds the
/// time zone and DST attributes.
pub fn server<const A: usize>(
    fixed_status: u8,
    zone: bool,
) -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(DEF, Role::Server);
    c.add_attribute(TIME, &utc(INVALID))?;
    c.add_attribute(
        TIME_STATUS,
        &Value::Bits {
            width: 1,
            bits: u64::from(fixed_status & !status::SYNCHRONIZED),
        },
    )?;
    if zone {
        c.add_attribute(TIME_ZONE, &i32v(0))?;
        c.add_attribute(DST_START, &u32v(INVALID))?;
        c.add_attribute(DST_END, &u32v(INVALID))?;
        c.add_attribute(DST_SHIFT, &i32v(0))?;
        c.add_attribute(STANDARD_TIME, &u32v(INVALID))?;
        c.add_attribute(LOCAL_TIME, &u32v(INVALID))?;
    }
    c.add_attribute(LAST_SET_TIME, &utc(INVALID))?;
    c.add_attribute(VALID_UNTIL_TIME, &utc(INVALID))?;
    c.write_guard = Some(write_guard::<A>);
    c.state = ClusterState::Time(Clock {
        base: None,
        base_at: Instant::from_millis(0),
        published: INVALID,
        fixed_status,
    });
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF, Role::Client)
}

fn clock<const A: usize>(c: &mut ClusterInstance<A>) -> Option<&mut Clock> {
    match &mut c.state {
        ClusterState::Time(k) => Some(k),
        _ => None,
    }
}

/// Sets the clock from the application (the master clock, or a client
/// that synchronized elsewhere) to `utc` at `now`.
pub fn set<const A: usize>(c: &mut ClusterInstance<A>, utc: u32, now: Instant) {
    if let Some(k) = clock(c) {
        k.base = Some(utc);
        k.base_at = now;
        k.published = utc;
    }
    c.set(TIME.id, &self::utc(utc));
    c.set(LAST_SET_TIME.id, &self::utc(utc));
    refresh_derived(c, utc);
    c.tick = Some(now + Duration::from_secs(1));
}

/// The current UTC time of the server at `now`, `None` while unset.
pub fn now<const A: usize>(c: &ClusterInstance<A>, now: Instant) -> Option<u32> {
    let ClusterState::Time(k) = &c.state else {
        return None;
    };
    let base = k.base?;
    let elapsed = now.as_millis().saturating_sub(k.base_at.as_millis()) / 1000;
    Some(base.saturating_add(u32::try_from(elapsed).unwrap_or(u32::MAX)))
}

/// Whether the clock is trusted at `utc` (`ValidUntilTime` not passed).
pub fn is_valid<const A: usize>(c: &ClusterInstance<A>, utc: u32) -> bool {
    match c.u64(VALID_UNTIL_TIME.id) {
        Some(v) if v != u64::from(INVALID) => u64::from(utc) <= v,
        _ => true,
    }
}

/// Local standard time and local time for `utc` from the zone / DST
/// attributes (`None` without the zone attributes).
pub fn local_times<const A: usize>(c: &ClusterInstance<A>, utc: u32) -> Option<(u32, u32)> {
    let zone = c.attributes.value(TIME_ZONE.id)?.as_i64()?;
    let standard = i64::from(utc).saturating_add(zone);
    let dst_start = c.u64(DST_START.id).unwrap_or(u64::from(INVALID));
    let dst_end = c.u64(DST_END.id).unwrap_or(u64::from(INVALID));
    let shift = c
        .attributes
        .value(DST_SHIFT.id)
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let in_dst = dst_start != u64::from(INVALID)
        && dst_end != u64::from(INVALID)
        && dst_start <= u64::from(utc)
        && u64::from(utc) <= dst_end;
    let local = if in_dst {
        standard.saturating_add(shift)
    } else {
        standard
    };
    let clamp = |v: i64| u32::try_from(v.clamp(0, i64::from(INVALID) - 1)).unwrap_or(INVALID);
    Some((clamp(standard), clamp(local)))
}

fn refresh_derived<const A: usize>(c: &mut ClusterInstance<A>, utc: u32) {
    if let Some((standard, local)) = local_times(c, utc) {
        c.set(STANDARD_TIME.id, &u32v(standard));
        c.set(LOCAL_TIME.id, &u32v(local));
    }
}

/// Advances the clock (called by the dispatcher every second while the
/// clock runs): applies a `Time` written over the air as the new base,
/// keeps the fixed `TimeStatus` bits, and refreshes the derived
/// attributes. Returns the current UTC time when the clock runs.
pub fn tick<const A: usize>(c: &mut ClusterInstance<A>, now: Instant) -> Option<u32> {
    let fixed = match &c.state {
        ClusterState::Time(k) => k.fixed_status,
        _ => return None,
    };
    // The fixed bits survive a write of TimeStatus (§3.12.2.2.2);
    // Synchronized is meaningless on a master clock.
    let status = c.u8(TIME_STATUS.id).unwrap_or(0);
    let mut wanted = (status & !status::FIXED) | fixed;
    if wanted & status::MASTER != 0 {
        wanted &= !status::SYNCHRONIZED;
    }
    if wanted != status {
        c.set(
            TIME_STATUS.id,
            &Value::Bits {
                width: 1,
                bits: u64::from(wanted),
            },
        );
    }
    let attr = c
        .u64(TIME.id)
        .map_or(INVALID, |v| u32::try_from(v).unwrap_or(INVALID));
    let published = clock(c).map_or(INVALID, |k| k.published);
    if attr != published {
        // Written over the air (the guard allowed it): new base.
        if attr == INVALID {
            if let Some(k) = clock(c) {
                k.base = None;
                k.published = INVALID;
            }
            c.tick = None;
            return None;
        }
        set(c, attr, now);
        return Some(attr);
    }
    let utc = self::now(c, now)?;
    if let Some(k) = clock(c) {
        k.published = utc;
    }
    c.set(TIME.id, &self::utc(utc));
    refresh_derived(c, utc);
    c.tick = Some(now + Duration::from_secs(1));
    Some(utc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_runs_and_guards_writes() {
        let mut c: ClusterInstance<16> = server(status::MASTER_ZONE_DST, true).unwrap();
        let t0 = Instant::from_millis(10_000);
        assert_eq!(now(&c, t0), None);
        assert!(tick(&mut c, t0).is_none());
        // Zone: UTC+1 with DST +1 h between 1000 and 2000.
        c.set(TIME_ZONE.id, &i32v(3600));
        c.set(DST_START.id, &u32v(1000));
        c.set(DST_END.id, &u32v(2000));
        c.set(DST_SHIFT.id, &i32v(3600));
        set(&mut c, 500, t0);
        assert_eq!(now(&c, t0 + Duration::from_secs(5)), Some(505));
        assert_eq!(tick(&mut c, t0 + Duration::from_secs(5)), Some(505));
        assert_eq!(c.u64(TIME.id), Some(505));
        assert_eq!(c.u64(STANDARD_TIME.id), Some(505 + 3600));
        assert_eq!(c.u64(LOCAL_TIME.id), Some(505 + 3600));
        assert_eq!(c.u64(LAST_SET_TIME.id), Some(500));
        assert_eq!(local_times(&c, 1500), Some((5100, 8700)));
        // A network write of Time (not master): accepted, LastSetTime
        // follows, the clock continues from the written value.
        assert_eq!(
            (c.write_guard.unwrap())(&c.attributes, TIME.id, &utc(9000)),
            ZclStatus::Success
        );
        c.set(TIME.id, &utc(9000));
        assert_eq!(tick(&mut c, t0 + Duration::from_secs(6)), Some(9000));
        assert_eq!(c.u64(LAST_SET_TIME.id), Some(9000));
        assert_eq!(now(&c, t0 + Duration::from_secs(16)), Some(9010));
        // The zone attributes are read-only (MasterZoneDst); Time would
        // be read-only on a master clock.
        assert_eq!(
            (c.write_guard.unwrap())(&c.attributes, TIME_ZONE.id, &i32v(0)),
            ZclStatus::ReadOnly
        );
        let mut m: ClusterInstance<16> =
            server(status::MASTER | status::SUPERSEDING, false).unwrap();
        assert_eq!(
            (m.write_guard.unwrap())(&m.attributes, TIME.id, &utc(1)),
            ZclStatus::ReadOnly
        );
        // A written TimeStatus keeps the fixed bits and drops
        // Synchronized on a master.
        m.set(
            TIME_STATUS.id,
            &Value::Bits {
                width: 1,
                bits: u64::from(status::SYNCHRONIZED),
            },
        );
        set(&mut m, 100, t0);
        let _ = tick(&mut m, t0 + Duration::from_secs(1));
        assert_eq!(
            m.u8(TIME_STATUS.id),
            Some(status::MASTER | status::SUPERSEDING)
        );
        assert!(is_valid(&m, 100));
        m.set(VALID_UNTIL_TIME.id, &utc(150));
        assert!(!is_valid(&m, 151));
    }
}
