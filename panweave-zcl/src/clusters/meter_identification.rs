//! Meter Identification cluster (ZCL8 §10.13): attributes describing a
//! utility metering device; no cluster-specific commands.

use panweave_types::ClusterId;

use crate::attribute::{Access, AttributeDef};
use crate::cluster::{ClusterDef, ClusterInstance, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0b01);

/// `CompanyName` (string, ≤16).
pub const COMPANY_NAME: AttributeDef = AttributeDef::new(0x0000, DataType::CharString, Access::RO);
/// `MeterTypeID` (Table 10-216).
pub const METER_TYPE_ID: AttributeDef = AttributeDef::new(0x0001, DataType::Uint(2), Access::RO);
/// `DataQualityID` (Table 10-217).
pub const DATA_QUALITY_ID: AttributeDef = AttributeDef::new(0x0004, DataType::Uint(2), Access::RO);
/// `CustomerName` (string, ≤16, writable).
pub const CUSTOMER_NAME: AttributeDef = AttributeDef::new(0x0005, DataType::CharString, Access::RW);
/// `Model` (octstr, ≤16).
pub const MODEL: AttributeDef = AttributeDef::new(0x0006, DataType::OctetString, Access::RO);
/// `PartNumber` (octstr, ≤16).
pub const PART_NUMBER: AttributeDef = AttributeDef::new(0x0007, DataType::OctetString, Access::RO);
/// `ProductRevision` (octstr, ≤6).
pub const PRODUCT_REVISION: AttributeDef =
    AttributeDef::new(0x0008, DataType::OctetString, Access::RO);
/// `SoftwareRevision` (octstr, ≤6).
pub const SOFTWARE_REVISION: AttributeDef =
    AttributeDef::new(0x000a, DataType::OctetString, Access::RO);
/// `UtilityName` (string, ≤16).
pub const UTILITY_NAME: AttributeDef = AttributeDef::new(0x000b, DataType::CharString, Access::RO);
/// `POD` — point of delivery (string, ≤16).
pub const POD: AttributeDef = AttributeDef::new(0x000c, DataType::CharString, Access::RO);
/// `AvailablePower` (int24, InstantaneousDemand formatting).
pub const AVAILABLE_POWER: AttributeDef = AttributeDef::new(0x000d, DataType::Int(3), Access::RO);
/// `PowerThreshold` (int24, InstantaneousDemand formatting).
pub const POWER_THRESHOLD: AttributeDef = AttributeDef::new(0x000e, DataType::Int(3), Access::RO);

/// Cluster definition.
pub const DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 2,
    received: &[],
    generated: &[],
};

/// Meter Type IDs (Table 10-216).
pub mod meter_type {
    /// Utility primary meter.
    pub const UTILITY_PRIMARY: u16 = 0x0000;
    /// Utility production meter.
    pub const UTILITY_PRODUCTION: u16 = 0x0001;
    /// Utility secondary meter.
    pub const UTILITY_SECONDARY: u16 = 0x0002;
    /// Private primary meter.
    pub const PRIVATE_PRIMARY: u16 = 0x0100;
    /// Private production meter.
    pub const PRIVATE_PRODUCTION: u16 = 0x0101;
    /// Private secondary meter.
    pub const PRIVATE_SECONDARY: u16 = 0x0102;
    /// Generic meter.
    pub const GENERIC: u16 = 0x0110;
}

/// Data Quality IDs (Table 10-217).
pub mod data_quality {
    /// All data certified.
    pub const ALL_CERTIFIED: u16 = 0x0000;
    /// Only instantaneous power not certified.
    pub const INSTANTANEOUS_POWER_NOT_CERTIFIED: u16 = 0x0001;
    /// Only cumulated consumption not certified.
    pub const CUMULATED_CONSUMPTION_NOT_CERTIFIED: u16 = 0x0002;
    /// Not certified data.
    pub const NOT_CERTIFIED: u16 = 0x0003;
}

/// The mandatory attributes of a server.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Identity<'a> {
    /// `CompanyName`.
    pub company_name: &'a [u8],
    /// `MeterTypeID`.
    pub meter_type: u16,
    /// `DataQualityID`.
    pub data_quality: u16,
    /// `POD`.
    pub pod: &'a [u8],
    /// `AvailablePower`.
    pub available_power: i32,
    /// `PowerThreshold`.
    pub power_threshold: i32,
}

/// Builds a server with the mandatory attributes; the optional ones are
/// added by the application.
pub fn server<const A: usize>(identity: &Identity<'_>) -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(DEF, Role::Server);
    c.add_attribute(
        COMPANY_NAME,
        &Value::String {
            ty: DataType::CharString,
            bytes: Some(identity.company_name),
        },
    )?;
    c.add_attribute(
        METER_TYPE_ID,
        &Value::Uint {
            width: 2,
            value: u64::from(identity.meter_type),
        },
    )?;
    c.add_attribute(
        DATA_QUALITY_ID,
        &Value::Uint {
            width: 2,
            value: u64::from(identity.data_quality),
        },
    )?;
    c.add_attribute(
        POD,
        &Value::String {
            ty: DataType::CharString,
            bytes: Some(identity.pod),
        },
    )?;
    c.add_attribute(
        AVAILABLE_POWER,
        &Value::Int {
            width: 3,
            value: i64::from(identity.available_power),
        },
    )?;
    c.add_attribute(
        POWER_THRESHOLD,
        &Value::Int {
            width: 3,
            value: i64::from(identity.power_threshold),
        },
    )?;
    Ok(c)
}

/// Builds a client instance.
pub fn client<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(DEF.mirrored(), Role::Client)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_carries_the_mandatory_set() {
        let c: ClusterInstance<8> = server(&Identity {
            company_name: b"Acme",
            meter_type: meter_type::UTILITY_PRIMARY,
            data_quality: data_quality::ALL_CERTIFIED,
            pod: b"IT001E123",
            available_power: 3300,
            power_threshold: -1,
        })
        .unwrap();
        assert_eq!(c.u16(METER_TYPE_ID.id), Some(0));
        assert_eq!(
            c.attributes
                .value(AVAILABLE_POWER.id)
                .and_then(|v| v.as_i64()),
            Some(3300)
        );
        assert_eq!(
            c.attributes
                .value(POWER_THRESHOLD.id)
                .and_then(|v| v.as_i64()),
            Some(-1)
        );
        assert!(matches!(
            c.attributes.value(POD.id),
            Some(Value::String {
                bytes: Some(b"IT001E123"),
                ..
            })
        ));
    }
}
