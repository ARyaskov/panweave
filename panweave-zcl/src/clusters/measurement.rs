//! Measurement and sensing clusters (ZCL8 chapter 4): Illuminance
//! Measurement, Illuminance Level Sensing, Temperature, Pressure and
//! Flow Measurement, the Water Content clusters (Relative Humidity, Leaf
//! Wetness, Soil Moisture) and Occupancy Sensing. All are attribute-only
//! server clusters whose `MeasuredValue` (or status) is reportable; the
//! application feeds readings through the `set_*` helpers and the
//! reporting engine does the rest. §4.1.3 conventions: `MinMeasuredValue`
//! / `MaxMeasuredValue` bound the sensor's range and `Tolerance` its
//! accuracy, each in the units of `MeasuredValue`.

use panweave_types::ClusterId;

use crate::attribute::{Access, AttributeDef, DefaultReporting};
use crate::cluster::{ClusterDef, ClusterInstance, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Default reporting shared by the measured values: at most every 10 s
/// on change, at least every 5 minutes (a product tunes these; BDB 3.1
/// §6.5 requires a default to exist).
const fn reporting(change: u64) -> DefaultReporting {
    DefaultReporting {
        min: 10,
        max: 300,
        change,
    }
}

const fn def(id: ClusterId) -> ClusterDef {
    ClusterDef {
        id,
        revision: 3,
        received: &[],
        generated: &[],
    }
}

/// Builds a client instance of `id` (no attributes or commands).
fn client_of<const A: usize>(id: ClusterId) -> ClusterInstance<A> {
    ClusterInstance::new(def(id), Role::Client)
}

/// Illuminance Measurement (§4.2): `MeasuredValue = 10000 · log10(lux) + 1`.
pub mod illuminance {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0400);
    /// `MeasuredValue` (uint16, reportable).
    pub const MEASURED_VALUE: AttributeDef =
        AttributeDef::new(0x0000, DataType::Uint(2), Access::RO_REPORT);
    /// `MinMeasuredValue`.
    pub const MIN_MEASURED_VALUE: AttributeDef =
        AttributeDef::new(0x0001, DataType::Uint(2), Access::RO);
    /// `MaxMeasuredValue`.
    pub const MAX_MEASURED_VALUE: AttributeDef =
        AttributeDef::new(0x0002, DataType::Uint(2), Access::RO);
    /// `Tolerance`.
    pub const TOLERANCE: AttributeDef = AttributeDef::new(0x0003, DataType::Uint(2), Access::RO);
    /// `LightSensorType`.
    pub const LIGHT_SENSOR_TYPE: AttributeDef =
        AttributeDef::new(0x0004, DataType::Enum8, Access::RO);
    /// Too low to measure.
    pub const TOO_LOW: u16 = 0x0000;
    /// Invalid / undefined.
    pub const INVALID: u16 = 0xffff;
    /// Default reporting of `MeasuredValue`.
    pub const DEFAULT_REPORTING: DefaultReporting = reporting(500);
    /// Cluster definition.
    pub const DEF: ClusterDef = def(ID);

    /// `LightSensorType` values (Table 4-6).
    pub mod sensor_type {
        /// Photodiode.
        pub const PHOTODIODE: u8 = 0x00;
        /// CMOS.
        pub const CMOS: u8 = 0x01;
        /// Unknown.
        pub const UNKNOWN: u8 = 0xff;
    }

    /// Builds a server measuring `min..=max` (0xffff = undefined).
    pub fn server<const A: usize>(min: u16, max: u16) -> Result<ClusterInstance<A>, ZclStatus> {
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.add_reported_attribute(
            MEASURED_VALUE,
            &Value::Uint {
                width: 2,
                value: u64::from(INVALID),
            },
            DEFAULT_REPORTING,
        )?;
        c.add_attribute(
            MIN_MEASURED_VALUE,
            &Value::Uint {
                width: 2,
                value: u64::from(min),
            },
        )?;
        c.add_attribute(
            MAX_MEASURED_VALUE,
            &Value::Uint {
                width: 2,
                value: u64::from(max),
            },
        )?;
        Ok(c)
    }

    /// Builds a client instance.
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        client_of(ID)
    }

    /// Sets the measured value; returns whether it changed.
    pub fn set_measured<const A: usize>(c: &mut ClusterInstance<A>, value: u16) -> bool {
        c.set_u16(MEASURED_VALUE.id, value)
    }

    /// The measured value, `None` when invalid.
    pub fn measured<const A: usize>(c: &ClusterInstance<A>) -> Option<u16> {
        c.u16(MEASURED_VALUE.id).filter(|v| *v != INVALID)
    }
}

/// Illuminance Level Sensing (§4.3).
pub mod illuminance_level {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0401);
    /// `LevelStatus` (enum8, reportable).
    pub const LEVEL_STATUS: AttributeDef =
        AttributeDef::new(0x0000, DataType::Enum8, Access::RO_REPORT);
    /// `LightSensorType`.
    pub const LIGHT_SENSOR_TYPE: AttributeDef =
        AttributeDef::new(0x0001, DataType::Enum8, Access::RO);
    /// `IlluminanceTargetLevel` (uint16, writable).
    pub const ILLUMINANCE_TARGET_LEVEL: AttributeDef =
        AttributeDef::new(0x0010, DataType::Uint(2), Access::RW);
    /// `IlluminanceTargetLevel` "not valid".
    pub const TARGET_INVALID: u16 = 0xffff;
    /// Default reporting of `LevelStatus`.
    pub const DEFAULT_REPORTING: DefaultReporting = reporting(0);
    /// Cluster definition.
    pub const DEF: ClusterDef = def(ID);

    /// `LevelStatus` values (Table 4-9).
    pub mod level_status {
        /// Illuminance on target.
        pub const ON_TARGET: u8 = 0x00;
        /// Below target.
        pub const BELOW_TARGET: u8 = 0x01;
        /// Above target.
        pub const ABOVE_TARGET: u8 = 0x02;
    }

    /// Builds a server with `target` as the initial target level.
    pub fn server<const A: usize>(target: u16) -> Result<ClusterInstance<A>, ZclStatus> {
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.add_reported_attribute(
            LEVEL_STATUS,
            &Value::Enum8(level_status::ON_TARGET),
            DEFAULT_REPORTING,
        )?;
        c.add_attribute(
            ILLUMINANCE_TARGET_LEVEL,
            &Value::Uint {
                width: 2,
                value: u64::from(target),
            },
        )?;
        Ok(c)
    }

    /// Builds a client instance.
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        client_of(ID)
    }

    /// Sets the level status; returns whether it changed.
    pub fn set_level_status<const A: usize>(c: &mut ClusterInstance<A>, status: u8) -> bool {
        c.set(LEVEL_STATUS.id, &Value::Enum8(status))
    }

    /// The configured target level (`None` when not valid).
    pub fn target<const A: usize>(c: &ClusterInstance<A>) -> Option<u16> {
        c.u16(ILLUMINANCE_TARGET_LEVEL.id)
            .filter(|v| *v != TARGET_INVALID)
    }
}

/// Temperature Measurement (§4.4): `MeasuredValue = 100 · °C`.
pub mod temperature {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0402);
    /// `MeasuredValue` (int16, reportable).
    pub const MEASURED_VALUE: AttributeDef =
        AttributeDef::new(0x0000, DataType::Int(2), Access::RO_REPORT);
    /// `MinMeasuredValue`.
    pub const MIN_MEASURED_VALUE: AttributeDef =
        AttributeDef::new(0x0001, DataType::Int(2), Access::RO);
    /// `MaxMeasuredValue`.
    pub const MAX_MEASURED_VALUE: AttributeDef =
        AttributeDef::new(0x0002, DataType::Int(2), Access::RO);
    /// `Tolerance`.
    pub const TOLERANCE: AttributeDef = AttributeDef::new(0x0003, DataType::Uint(2), Access::RO);
    /// Unknown measurement / undefined bound (0x8000).
    pub const UNKNOWN: i16 = i16::MIN;
    /// Default reporting of `MeasuredValue` (0.5 °C).
    pub const DEFAULT_REPORTING: DefaultReporting = reporting(50);
    /// Cluster definition.
    pub const DEF: ClusterDef = def(ID);

    /// Builds a server measuring `min..=max` in 0.01 °C.
    pub fn server<const A: usize>(min: i16, max: i16) -> Result<ClusterInstance<A>, ZclStatus> {
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.add_reported_attribute(MEASURED_VALUE, &int16(UNKNOWN), DEFAULT_REPORTING)?;
        c.add_attribute(MIN_MEASURED_VALUE, &int16(min))?;
        c.add_attribute(MAX_MEASURED_VALUE, &int16(max))?;
        Ok(c)
    }

    /// Builds a client instance.
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        client_of(ID)
    }

    /// Sets the measured value in 0.01 °C (`None` = unknown); returns
    /// whether it changed.
    pub fn set_measured<const A: usize>(c: &mut ClusterInstance<A>, value: Option<i16>) -> bool {
        c.set_i16(MEASURED_VALUE.id, value.unwrap_or(UNKNOWN))
    }

    /// The measured value in 0.01 °C, `None` when unknown.
    pub fn measured<const A: usize>(c: &ClusterInstance<A>) -> Option<i16> {
        c.i16(MEASURED_VALUE.id).filter(|v| *v != UNKNOWN)
    }
}

/// Pressure Measurement (§4.5): `MeasuredValue = 10 · kPa`.
pub mod pressure {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0403);
    /// `MeasuredValue` (int16, reportable).
    pub const MEASURED_VALUE: AttributeDef =
        AttributeDef::new(0x0000, DataType::Int(2), Access::RO_REPORT);
    /// `MinMeasuredValue`.
    pub const MIN_MEASURED_VALUE: AttributeDef =
        AttributeDef::new(0x0001, DataType::Int(2), Access::RO);
    /// `MaxMeasuredValue`.
    pub const MAX_MEASURED_VALUE: AttributeDef =
        AttributeDef::new(0x0002, DataType::Int(2), Access::RO);
    /// `Tolerance`.
    pub const TOLERANCE: AttributeDef = AttributeDef::new(0x0003, DataType::Uint(2), Access::RO);
    /// `ScaledValue` (int16, extended set).
    pub const SCALED_VALUE: AttributeDef =
        AttributeDef::new(0x0010, DataType::Int(2), Access::RO_REPORT);
    /// `MinScaledValue`.
    pub const MIN_SCALED_VALUE: AttributeDef =
        AttributeDef::new(0x0011, DataType::Int(2), Access::RO);
    /// `MaxScaledValue`.
    pub const MAX_SCALED_VALUE: AttributeDef =
        AttributeDef::new(0x0012, DataType::Int(2), Access::RO);
    /// `ScaledTolerance`.
    pub const SCALED_TOLERANCE: AttributeDef =
        AttributeDef::new(0x0013, DataType::Uint(2), Access::RO);
    /// `Scale` (int8).
    pub const SCALE: AttributeDef = AttributeDef::new(0x0014, DataType::Int(1), Access::RO);
    /// Unknown measurement / undefined bound (0x8000).
    pub const UNKNOWN: i16 = i16::MIN;
    /// Default reporting of `MeasuredValue` (0.5 kPa).
    pub const DEFAULT_REPORTING: DefaultReporting = reporting(5);
    /// Cluster definition.
    pub const DEF: ClusterDef = def(ID);

    /// Builds a server measuring `min..=max` in 0.1 kPa.
    pub fn server<const A: usize>(min: i16, max: i16) -> Result<ClusterInstance<A>, ZclStatus> {
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.add_reported_attribute(MEASURED_VALUE, &int16(UNKNOWN), DEFAULT_REPORTING)?;
        c.add_attribute(MIN_MEASURED_VALUE, &int16(min))?;
        c.add_attribute(MAX_MEASURED_VALUE, &int16(max))?;
        Ok(c)
    }

    /// Builds a client instance.
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        client_of(ID)
    }

    /// Sets the measured value in 0.1 kPa (`None` = unknown).
    pub fn set_measured<const A: usize>(c: &mut ClusterInstance<A>, value: Option<i16>) -> bool {
        c.set_i16(MEASURED_VALUE.id, value.unwrap_or(UNKNOWN))
    }

    /// The measured value in 0.1 kPa, `None` when unknown.
    pub fn measured<const A: usize>(c: &ClusterInstance<A>) -> Option<i16> {
        c.i16(MEASURED_VALUE.id).filter(|v| *v != UNKNOWN)
    }
}

/// Flow Measurement (§4.6): `MeasuredValue = 10 · m³/h`.
pub mod flow {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0404);
    /// `MeasuredValue` (uint16, reportable).
    pub const MEASURED_VALUE: AttributeDef =
        AttributeDef::new(0x0000, DataType::Uint(2), Access::RO_REPORT);
    /// `MinMeasuredValue`.
    pub const MIN_MEASURED_VALUE: AttributeDef =
        AttributeDef::new(0x0001, DataType::Uint(2), Access::RO);
    /// `MaxMeasuredValue`.
    pub const MAX_MEASURED_VALUE: AttributeDef =
        AttributeDef::new(0x0002, DataType::Uint(2), Access::RO);
    /// `Tolerance`.
    pub const TOLERANCE: AttributeDef = AttributeDef::new(0x0003, DataType::Uint(2), Access::RO);
    /// Unknown measurement / undefined bound.
    pub const UNKNOWN: u16 = 0xffff;
    /// Default reporting of `MeasuredValue` (0.5 m³/h).
    pub const DEFAULT_REPORTING: DefaultReporting = reporting(5);
    /// Cluster definition.
    pub const DEF: ClusterDef = def(ID);

    /// Builds a server measuring `min..=max` in 0.1 m³/h.
    pub fn server<const A: usize>(min: u16, max: u16) -> Result<ClusterInstance<A>, ZclStatus> {
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.add_reported_attribute(MEASURED_VALUE, &uint16(UNKNOWN), DEFAULT_REPORTING)?;
        c.add_attribute(MIN_MEASURED_VALUE, &uint16(min))?;
        c.add_attribute(MAX_MEASURED_VALUE, &uint16(max))?;
        Ok(c)
    }

    /// Builds a client instance.
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        client_of(ID)
    }

    /// Sets the measured value in 0.1 m³/h (`None` = unknown).
    pub fn set_measured<const A: usize>(c: &mut ClusterInstance<A>, value: Option<u16>) -> bool {
        c.set_u16(MEASURED_VALUE.id, value.unwrap_or(UNKNOWN))
    }

    /// The measured value in 0.1 m³/h, `None` when unknown.
    pub fn measured<const A: usize>(c: &ClusterInstance<A>) -> Option<u16> {
        c.u16(MEASURED_VALUE.id).filter(|v| *v != UNKNOWN)
    }
}

/// Water Content Measurement (§4.7): `MeasuredValue = 100 · %`, for the
/// Relative Humidity, Leaf Wetness and Soil Moisture clusters.
pub mod water_content {
    use super::*;

    /// Relative Humidity.
    pub const RELATIVE_HUMIDITY: ClusterId = ClusterId(0x0405);
    /// Leaf Wetness.
    pub const LEAF_WETNESS: ClusterId = ClusterId(0x0407);
    /// Soil Moisture.
    pub const SOIL_MOISTURE: ClusterId = ClusterId(0x0408);
    /// `MeasuredValue` (uint16, reportable).
    pub const MEASURED_VALUE: AttributeDef =
        AttributeDef::new(0x0000, DataType::Uint(2), Access::RO_REPORT);
    /// `MinMeasuredValue`.
    pub const MIN_MEASURED_VALUE: AttributeDef =
        AttributeDef::new(0x0001, DataType::Uint(2), Access::RO);
    /// `MaxMeasuredValue`.
    pub const MAX_MEASURED_VALUE: AttributeDef =
        AttributeDef::new(0x0002, DataType::Uint(2), Access::RO);
    /// `Tolerance`.
    pub const TOLERANCE: AttributeDef = AttributeDef::new(0x0003, DataType::Uint(2), Access::RO);
    /// Unknown measurement / undefined bound.
    pub const UNKNOWN: u16 = 0xffff;
    /// 100 %.
    pub const MAX_PERCENT: u16 = 0x2710;
    /// Default reporting of `MeasuredValue` (1 %).
    pub const DEFAULT_REPORTING: DefaultReporting = reporting(100);

    /// Builds a server of `cluster` (one of the three identifiers)
    /// measuring `min..=max` in 0.01 %.
    pub fn server<const A: usize>(
        cluster: ClusterId,
        min: u16,
        max: u16,
    ) -> Result<ClusterInstance<A>, ZclStatus> {
        if !matches!(cluster, RELATIVE_HUMIDITY | LEAF_WETNESS | SOIL_MOISTURE)
            || max > MAX_PERCENT && max != UNKNOWN
        {
            return Err(ZclStatus::InvalidValue);
        }
        let mut c = ClusterInstance::new(def(cluster), Role::Server);
        c.add_reported_attribute(MEASURED_VALUE, &uint16(UNKNOWN), DEFAULT_REPORTING)?;
        c.add_attribute(MIN_MEASURED_VALUE, &uint16(min))?;
        c.add_attribute(MAX_MEASURED_VALUE, &uint16(max))?;
        Ok(c)
    }

    /// Builds a client instance of `cluster`.
    pub fn client<const A: usize>(cluster: ClusterId) -> ClusterInstance<A> {
        client_of(cluster)
    }

    /// Sets the measured value in 0.01 % (`None` = unknown); values above
    /// 100 % are refused.
    pub fn set_measured<const A: usize>(c: &mut ClusterInstance<A>, value: Option<u16>) -> bool {
        match value {
            Some(v) if v > MAX_PERCENT => false,
            v => c.set_u16(MEASURED_VALUE.id, v.unwrap_or(UNKNOWN)),
        }
    }

    /// The measured value in 0.01 %, `None` when unknown.
    pub fn measured<const A: usize>(c: &ClusterInstance<A>) -> Option<u16> {
        c.u16(MEASURED_VALUE.id).filter(|v| *v != UNKNOWN)
    }
}

/// Occupancy Sensing (§4.8).
pub mod occupancy {
    use super::*;

    /// Cluster identifier.
    pub const ID: ClusterId = ClusterId(0x0406);
    /// `Occupancy` (map8, reportable; bit 0 = occupied).
    pub const OCCUPANCY: AttributeDef =
        AttributeDef::new(0x0000, DataType::Bitmap(1), Access::RO_REPORT);
    /// `OccupancySensorType` (enum8).
    pub const OCCUPANCY_SENSOR_TYPE: AttributeDef =
        AttributeDef::new(0x0001, DataType::Enum8, Access::RO);
    /// `OccupancySensorTypeBitmap` (map8).
    pub const OCCUPANCY_SENSOR_TYPE_BITMAP: AttributeDef =
        AttributeDef::new(0x0002, DataType::Bitmap(1), Access::RO);
    /// `PIROccupiedToUnoccupiedDelay` (uint16 s, writable).
    pub const PIR_OCCUPIED_TO_UNOCCUPIED_DELAY: AttributeDef =
        AttributeDef::new(0x0010, DataType::Uint(2), Access::RW);
    /// `PIRUnoccupiedToOccupiedDelay` (uint16 s, writable).
    pub const PIR_UNOCCUPIED_TO_OCCUPIED_DELAY: AttributeDef =
        AttributeDef::new(0x0011, DataType::Uint(2), Access::RW);
    /// `PIRUnoccupiedToOccupiedThreshold` (uint8, writable).
    pub const PIR_UNOCCUPIED_TO_OCCUPIED_THRESHOLD: AttributeDef =
        AttributeDef::new(0x0012, DataType::Uint(1), Access::RW);
    /// `UltrasonicOccupiedToUnoccupiedDelay`.
    pub const ULTRASONIC_OCCUPIED_TO_UNOCCUPIED_DELAY: AttributeDef =
        AttributeDef::new(0x0020, DataType::Uint(2), Access::RW);
    /// `UltrasonicUnoccupiedToOccupiedDelay`.
    pub const ULTRASONIC_UNOCCUPIED_TO_OCCUPIED_DELAY: AttributeDef =
        AttributeDef::new(0x0021, DataType::Uint(2), Access::RW);
    /// `UltrasonicUnoccupiedToOccupiedThreshold`.
    pub const ULTRASONIC_UNOCCUPIED_TO_OCCUPIED_THRESHOLD: AttributeDef =
        AttributeDef::new(0x0022, DataType::Uint(1), Access::RW);
    /// `PhysicalContactOccupiedToUnoccupiedDelay`.
    pub const PHYSICAL_CONTACT_OCCUPIED_TO_UNOCCUPIED_DELAY: AttributeDef =
        AttributeDef::new(0x0030, DataType::Uint(2), Access::RW);
    /// `PhysicalContactUnoccupiedToOccupiedDelay`.
    pub const PHYSICAL_CONTACT_UNOCCUPIED_TO_OCCUPIED_DELAY: AttributeDef =
        AttributeDef::new(0x0031, DataType::Uint(2), Access::RW);
    /// `PhysicalContactUnoccupiedToOccupiedThreshold`.
    pub const PHYSICAL_CONTACT_UNOCCUPIED_TO_OCCUPIED_THRESHOLD: AttributeDef =
        AttributeDef::new(0x0032, DataType::Uint(1), Access::RW);
    /// `Occupancy` bit 0.
    pub const OCCUPIED: u8 = 0x01;
    /// Default reporting of `Occupancy` (on change).
    pub const DEFAULT_REPORTING: DefaultReporting = reporting(0);
    /// Cluster definition.
    pub const DEF: ClusterDef = def(ID);

    /// `OccupancySensorTypeBitmap` bits (Table 4-23).
    pub mod sensor_bits {
        /// PIR.
        pub const PIR: u8 = 0x01;
        /// Ultrasonic.
        pub const ULTRASONIC: u8 = 0x02;
        /// Physical contact.
        pub const PHYSICAL_CONTACT: u8 = 0x04;
    }

    /// `OccupancySensorType` values (Table 4-22).
    pub mod sensor_type {
        /// PIR.
        pub const PIR: u8 = 0x00;
        /// Ultrasonic.
        pub const ULTRASONIC: u8 = 0x01;
        /// PIR and ultrasonic.
        pub const PIR_AND_ULTRASONIC: u8 = 0x02;
        /// Physical contact.
        pub const PHYSICAL_CONTACT: u8 = 0x03;
    }

    /// The `OccupancySensorType` aligned with a sensor bitmap (Table
    /// 4-24): a contact sensor combined with others reports the other
    /// type; contact alone reports Physical contact.
    pub const fn sensor_type_for(bits: u8) -> u8 {
        match bits & (sensor_bits::PIR | sensor_bits::ULTRASONIC) {
            0 => sensor_type::PHYSICAL_CONTACT,
            sensor_bits::PIR => sensor_type::PIR,
            sensor_bits::ULTRASONIC => sensor_type::ULTRASONIC,
            _ => sensor_type::PIR_AND_ULTRASONIC,
        }
    }

    /// Builds a server for the sensor technologies in `sensor_bits`.
    pub fn server<const A: usize>(sensor_bits: u8) -> Result<ClusterInstance<A>, ZclStatus> {
        if sensor_bits == 0 || sensor_bits & !0x07 != 0 {
            return Err(ZclStatus::InvalidValue);
        }
        let mut c = ClusterInstance::new(DEF, Role::Server);
        c.add_reported_attribute(
            OCCUPANCY,
            &Value::Bits { width: 1, bits: 0 },
            DEFAULT_REPORTING,
        )?;
        c.add_attribute(
            OCCUPANCY_SENSOR_TYPE,
            &Value::Enum8(sensor_type_for(sensor_bits)),
        )?;
        c.add_attribute(
            OCCUPANCY_SENSOR_TYPE_BITMAP,
            &Value::Bits {
                width: 1,
                bits: u64::from(sensor_bits),
            },
        )?;
        Ok(c)
    }

    /// Builds a client instance.
    pub fn client<const A: usize>() -> ClusterInstance<A> {
        client_of(ID)
    }

    /// Sets the sensed occupancy; returns whether it changed.
    pub fn set_occupied<const A: usize>(c: &mut ClusterInstance<A>, occupied: bool) -> bool {
        c.set(
            OCCUPANCY.id,
            &Value::Bits {
                width: 1,
                bits: u64::from(occupied),
            },
        )
    }

    /// Whether the area is sensed as occupied.
    pub fn occupied<const A: usize>(c: &ClusterInstance<A>) -> bool {
        c.u8(OCCUPANCY.id).is_some_and(|v| v & OCCUPIED != 0)
    }
}

const fn int16(v: i16) -> Value<'static> {
    Value::Int {
        width: 2,
        value: v as i64,
    }
}

const fn uint16(v: u16) -> Value<'static> {
    Value::Uint {
        width: 2,
        value: v as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn servers_hold_and_report_readings() {
        let mut t: ClusterInstance<8> = temperature::server(-4000, 12500).unwrap();
        assert_eq!(temperature::measured(&t), None);
        assert!(temperature::set_measured(&mut t, Some(2150)));
        assert_eq!(temperature::measured(&t), Some(2150));
        assert!(!temperature::set_measured(&mut t, Some(2150)));
        assert!(temperature::set_measured(&mut t, Some(-1050)));
        assert_eq!(temperature::measured(&t), Some(-1050));
        assert!(temperature::set_measured(&mut t, None));
        assert_eq!(temperature::measured(&t), None);
        assert_eq!(t.i16(temperature::MIN_MEASURED_VALUE.id), Some(-4000));
        assert!(
            t.attributes
                .get(temperature::MEASURED_VALUE.id, None)
                .unwrap()
                .default_reporting()
                .is_some()
        );

        let mut h: ClusterInstance<8> =
            water_content::server(water_content::RELATIVE_HUMIDITY, 0, 10000).unwrap();
        assert!(water_content::set_measured(&mut h, Some(4567)));
        assert!(!water_content::set_measured(&mut h, Some(10001)));
        assert_eq!(water_content::measured(&h), Some(4567));
        assert!(water_content::server::<8>(ClusterId(0x0406), 0, 100).is_err());

        let mut o: ClusterInstance<8> = occupancy::server(
            occupancy::sensor_bits::PIR | occupancy::sensor_bits::PHYSICAL_CONTACT,
        )
        .unwrap();
        assert_eq!(
            o.u8(occupancy::OCCUPANCY_SENSOR_TYPE.id),
            Some(occupancy::sensor_type::PIR)
        );
        assert!(!occupancy::occupied(&o));
        assert!(occupancy::set_occupied(&mut o, true));
        assert!(occupancy::occupied(&o));
        assert!(occupancy::server::<8>(0).is_err());
        assert_eq!(
            occupancy::sensor_type_for(occupancy::sensor_bits::PHYSICAL_CONTACT),
            occupancy::sensor_type::PHYSICAL_CONTACT
        );

        let mut l: ClusterInstance<8> = illuminance::server(1, 0xfffe).unwrap();
        assert_eq!(illuminance::measured(&l), None);
        assert!(illuminance::set_measured(&mut l, 30001));
        assert_eq!(illuminance::measured(&l), Some(30001));
        let mut s: ClusterInstance<8> = illuminance_level::server(20000).unwrap();
        assert_eq!(illuminance_level::target(&s), Some(20000));
        assert!(illuminance_level::set_level_status(
            &mut s,
            illuminance_level::level_status::ABOVE_TARGET
        ));
        let mut p: ClusterInstance<8> = pressure::server(-100, 12000).unwrap();
        assert!(pressure::set_measured(&mut p, Some(1013)));
        assert_eq!(pressure::measured(&p), Some(1013));
        let mut f: ClusterInstance<8> = flow::server(0, 0xfffe).unwrap();
        assert!(flow::set_measured(&mut f, Some(12)));
        assert_eq!(flow::measured(&f), Some(12));
    }
}
