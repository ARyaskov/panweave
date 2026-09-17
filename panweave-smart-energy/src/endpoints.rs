//! Cluster instances for Smart Energy endpoints: the server and client
//! instances of the profile's clusters with their mandatory attributes
//! at the specification defaults, so an endpoint builder can assemble a
//! Table 5-13 device from [`crate::devices`] (the general clusters —
//! Basic, Identify, Time, Alarms, Keep-Alive, Commissioning, Power
//! Configuration, OTA — come from `panweave-zcl`).

use panweave_zcl::attribute::{Access, AttributeDef};
use panweave_zcl::types::{DataType, Value};
use panweave_zcl::{ClusterInstance, Role, ZclStatus};

use crate::clusters::{
    calendar, device_management, drlc, energy_management, events, mdu_pairing, messaging, metering,
    prepayment, price, sub_ghz, tunneling,
};
use crate::key_establishment::{self, Suite};
use crate::{ClusterId, cluster};

/// Both cryptographic suites, as §5.4.8.2 asks of every device.
pub const ALL_SUITES: u16 = Suite::Suite1.bit() | Suite::Suite2.bit();

/// Whether a server instance of `id` can be built here.
pub const fn has_server(id: ClusterId) -> bool {
    matches!(
        id.0,
        0x0800
            | 0x0700
            | 0x0701
            | 0x0702
            | 0x0703
            | 0x0704
            | 0x0705
            | 0x0706
            | 0x0707
            | 0x0708
            | 0x0709
            | 0x070A
            | 0x070B
    )
}

/// Whether a client instance of `id` can be built here.
pub const fn has_client(id: ClusterId) -> bool {
    has_server(id)
}

fn uint(width: u8, value: u64) -> Value<'static> {
    Value::Uint { width, value }
}

fn bits(width: u8, bits: u64) -> Value<'static> {
    Value::Bits { width, bits }
}

/// A server instance of `id` with its mandatory attributes at their
/// defaults, or `None` for a cluster this crate does not provide.
pub fn server(id: ClusterId) -> Option<Result<ClusterInstance<24>, ZclStatus>> {
    Some(match id {
        cluster::KEY_ESTABLISHMENT => key_establishment::server(ALL_SUITES),
        cluster::PRICE => Ok(ClusterInstance::new(price::SERVER_DEF, Role::Server)),
        cluster::DEMAND_RESPONSE_LOAD_CONTROL => {
            Ok(ClusterInstance::new(drlc::SERVER_DEF, Role::Server))
        }
        cluster::METERING => metering_server(),
        cluster::MESSAGING => Ok(ClusterInstance::new(messaging::SERVER_DEF, Role::Server)),
        cluster::TUNNELING => {
            let mut c = ClusterInstance::new(tunneling::SERVER_DEF, Role::Server);
            c.add_attribute(tunneling::CLOSE_TUNNEL_TIMEOUT, &uint(2, 0xffff))
                .map(|_| c)
        }
        cluster::PREPAYMENT => prepayment_server(),
        cluster::ENERGY_MANAGEMENT => energy_management_server(),
        cluster::CALENDAR => Ok(ClusterInstance::new(calendar::SERVER_DEF, Role::Server)),
        cluster::DEVICE_MANAGEMENT => {
            let mut c = ClusterInstance::new(device_management::SERVER_DEF, Role::Server);
            c.add_attribute(device_management::server_attr::PROVIDER_ID, &uint(4, 0))
                .map(|_| c)
        }
        cluster::EVENTS => Ok(ClusterInstance::new(events::SERVER_DEF, Role::Server)),
        cluster::MDU_PAIRING => Ok(ClusterInstance::new(mdu_pairing::SERVER_DEF, Role::Server)),
        cluster::SUB_GHZ => {
            let mut c = ClusterInstance::new(sub_ghz::SERVER_DEF, Role::Server);
            c.add_attribute(sub_ghz::CHANNEL_CHANGE, &bits(4, 0))
                .map(|_| c)
        }
        _ => return None,
    })
}

/// A client instance of `id` with its mandatory attributes, or `None`.
pub fn client(id: ClusterId) -> Option<Result<ClusterInstance<24>, ZclStatus>> {
    Some(match id {
        cluster::KEY_ESTABLISHMENT => key_establishment::client(ALL_SUITES),
        cluster::PRICE => Ok(ClusterInstance::new(price::CLIENT_DEF, Role::Client)),
        cluster::DEMAND_RESPONSE_LOAD_CONTROL => drlc_client(),
        cluster::METERING => Ok(ClusterInstance::new(metering::CLIENT_DEF, Role::Client)),
        cluster::MESSAGING => Ok(ClusterInstance::new(messaging::CLIENT_DEF, Role::Client)),
        cluster::TUNNELING => Ok(ClusterInstance::new(tunneling::CLIENT_DEF, Role::Client)),
        cluster::PREPAYMENT => Ok(ClusterInstance::new(prepayment::CLIENT_DEF, Role::Client)),
        cluster::ENERGY_MANAGEMENT => Ok(ClusterInstance::new(
            energy_management::CLIENT_DEF,
            Role::Client,
        )),
        cluster::CALENDAR => Ok(ClusterInstance::new(calendar::CLIENT_DEF, Role::Client)),
        cluster::DEVICE_MANAGEMENT => {
            let mut c = ClusterInstance::new(device_management::CLIENT_DEF, Role::Client);
            c.add_attribute(device_management::client_attr::PROVIDER_ID, &uint(4, 0))
                .map(|_| c)
        }
        cluster::EVENTS => Ok(ClusterInstance::new(events::CLIENT_DEF, Role::Client)),
        cluster::MDU_PAIRING => Ok(ClusterInstance::new(mdu_pairing::CLIENT_DEF, Role::Client)),
        cluster::SUB_GHZ => Ok(ClusterInstance::new(sub_ghz::CLIENT_DEF, Role::Client)),
        _ => return None,
    })
}

/// A Metering server with the Table D-11 / D-24 / D-25 mandatory
/// attributes: an electric kWh meter reading zero.
pub fn metering_server() -> Result<ClusterInstance<24>, ZclStatus> {
    let mut c = ClusterInstance::new(metering::SERVER_DEF, Role::Server);
    c.add_attribute(metering::CURRENT_SUMMATION_DELIVERED, &uint(6, 0))?;
    c.add_attribute(metering::STATUS, &bits(1, 0))?;
    c.add_attribute(
        metering::UNIT_OF_MEASURE,
        &Value::Enum8(metering::unit_of_measure::KWH),
    )?;
    // Three digits after the decimal point, no leading-zero
    // suppression (Table D-25 example formatting).
    c.add_attribute(metering::SUMMATION_FORMATTING, &bits(1, 0x03))?;
    c.add_attribute(
        metering::METERING_DEVICE_TYPE,
        &bits(1, u64::from(metering::device_type::ELECTRIC)),
    )?;
    Ok(c)
}

/// A DRLC client with the Table D-7 attributes at their defaults for
/// a device of `device_class` bits.
pub fn drlc_client_for(device_class: u16) -> Result<ClusterInstance<24>, ZclStatus> {
    let mut c = ClusterInstance::new(drlc::CLIENT_DEF, Role::Client);
    c.add_attribute(drlc::UTILITY_ENROLLMENT_GROUP, &uint(1, 0))?;
    c.add_attribute(
        drlc::START_RANDOMIZATION_MINUTES,
        &uint(1, u64::from(drlc::DEFAULT_START_RANDOMIZATION_MINUTES)),
    )?;
    c.add_attribute(drlc::DURATION_RANDOMIZATION_MINUTES, &uint(1, 0))?;
    c.add_attribute(drlc::DEVICE_CLASS_VALUE, &uint(2, u64::from(device_class)))?;
    Ok(c)
}

fn drlc_client() -> Result<ClusterInstance<24>, ZclStatus> {
    drlc_client_for(drlc::device_class::SIMPLE_MISC_LOADS)
}

/// A Prepayment server with the mandatory information-set attributes.
pub fn prepayment_server() -> Result<ClusterInstance<24>, ZclStatus> {
    let mut c = ClusterInstance::new(prepayment::SERVER_DEF, Role::Server);
    let def = |id: panweave_types::AttributeId, ty| AttributeDef::new(id.0, ty, Access::RO);
    c.add_attribute(
        def(
            prepayment::attr::PAYMENT_CONTROL_CONFIGURATION,
            DataType::Bitmap(2),
        ),
        &bits(2, 0),
    )?;
    c.add_attribute(
        def(prepayment::attr::CREDIT_REMAINING, DataType::Int(4)),
        &Value::Int { width: 4, value: 0 },
    )?;
    c.add_attribute(
        def(prepayment::attr::CREDIT_STATUS, DataType::Bitmap(1)),
        &bits(1, 0),
    )?;
    Ok(c)
}

/// An Energy Management server with the Table D-192 attributes.
pub fn energy_management_server() -> Result<ClusterInstance<24>, ZclStatus> {
    let mut c = ClusterInstance::new(energy_management::SERVER_DEF, Role::Server);
    c.add_attribute(energy_management::LOAD_CONTROL_STATE, &bits(1, 0))?;
    c.add_attribute(
        energy_management::CURRENT_EVENT_ID,
        &uint(4, u64::from(energy_management::NO_EVENT)),
    )?;
    c.add_attribute(
        energy_management::CURRENT_EVENT_STATUS,
        &bits(
            1,
            u64::from(energy_management::event_status_bits::EXTENDED_BITS),
        ),
    )?;
    c.add_attribute(energy_management::CONFORMANCE_LEVEL, &uint(1, 0))?;
    let unsupported = uint(2, u64::from(energy_management::TIME_UNSUPPORTED));
    c.add_attribute(energy_management::MINIMUM_OFF_TIME, &unsupported)?;
    c.add_attribute(energy_management::MINIMUM_ON_TIME, &unsupported)?;
    c.add_attribute(energy_management::MINIMUM_CYCLE_PERIOD, &unsupported)?;
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::{DEVICES, common};

    #[test]
    fn every_profile_cluster_of_every_device_is_instantiable() {
        for d in DEVICES {
            for c in d
                .servers
                .iter()
                .chain(d.optional_servers)
                .chain(common::SERVERS)
                .chain(common::OPTIONAL_SERVERS)
            {
                if c.0 >= 0x0700 {
                    assert!(
                        server(*c).is_some_and(|r| r.is_ok()),
                        "{} server {:?}",
                        d.name,
                        c
                    );
                }
            }
            for c in d
                .clients
                .iter()
                .chain(d.optional_clients)
                .chain(common::CLIENTS)
                .chain(common::OPTIONAL_CLIENTS)
            {
                if c.0 >= 0x0700 {
                    assert!(
                        client(*c).is_some_and(|r| r.is_ok()),
                        "{} client {:?}",
                        d.name,
                        c
                    );
                }
            }
        }
        assert!(server(cluster::BASIC).is_none());
        assert!(!has_server(cluster::TIME) && has_client(cluster::PRICE));
        let m = metering_server().unwrap();
        for a in metering::MANDATORY {
            assert!(m.u64(a.id).is_some(), "{:?}", a.id);
        }
        assert_eq!(
            m.u8(metering::UNIT_OF_MEASURE.id),
            Some(metering::unit_of_measure::KWH)
        );
    }
}
