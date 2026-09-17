//! A temperature sensor end device reporting its readings to a bound
//! coordinator through the default reporting configuration of the
//! Temperature Measurement cluster (ZCL8 §4.4, BDB 3.1 §6.5): a change
//! beyond the reportable change is reported after the minimum interval,
//! a smaller one waits for the maximum interval.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_aps::tables::{BindingDestination, BindingEntry};
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::MemoryStorage;
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, DeviceId, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId,
};
use panweave_zcl::Role;
use panweave_zcl::clusters::identify;
use panweave_zcl::clusters::measurement::temperature;
use panweave_zcl::global::{AttributeValue, Records};
use panweave_zcl::layer::EndpointInstance;
use panweave_zcl::types::Value;
use panweave_zdo::descriptor::SimpleDescriptor;

const NETWORK_KEY: panweave_types::Key128 = panweave_types::Key128::from_bytes([0x5A; 16]);
const COORD_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
const SENSOR_IEEE: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0002);

fn node(role: LogicalDeviceType, ieee: ExtendedAddress, seed: u64) -> SimStack {
    let mut cfg = StackConfig::new(role, ieee);
    cfg.trust_center_policy.allow_joins = true;
    cfg.sleepy = role == LogicalDeviceType::EndDevice;
    cfg.poll_interval = Duration::from_millis(1000);
    let mut n = SimStack::new(
        cfg,
        MacServiceConfig::default(),
        TestRng::seed(seed),
        MemoryStorage::new(),
    );
    let mut ep = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    ep.add_instance(identify::server().unwrap()).unwrap();
    let (servers, clients, device): (&[ClusterId], &[ClusterId], DeviceId) = match role {
        LogicalDeviceType::EndDevice => {
            ep.add_instance(temperature::server(-4000, 12500).unwrap())
                .unwrap();
            (
                &[ClusterId(0), identify::ID, temperature::ID],
                &[identify::ID],
                DeviceId(0x0302),
            )
        }
        _ => {
            ep.add_instance(temperature::client()).unwrap();
            (
                &[ClusterId(0), identify::ID],
                &[identify::ID, temperature::ID],
                DeviceId(0x0005),
            )
        }
    };
    let desc = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        device,
        1,
        servers,
        clients,
    )
    .unwrap();
    n.add_endpoint(desc, ep).unwrap();
    n
}

fn reported(events: &[StackEvent]) -> Option<i64> {
    events.iter().find_map(|e| match e {
        StackEvent::ZclReport(f) if f.origin.cluster == temperature::ID => {
            let recs: Vec<AttributeValue> = Records::new(&f.payload).map(Result::unwrap).collect();
            match recs.first()?.value {
                Value::Int { value, .. } => Some(value),
                _ => None,
            }
        }
        _ => None,
    })
}

#[test]
fn temperature_sensor_reports_through_its_default_configuration() {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "coord",
        node(LogicalDeviceType::Coordinator, COORD_IEEE, 41),
        Box::new(OnOffApp::default()),
    );
    let s = sim.add_stack(
        "sensor",
        node(LogicalDeviceType::EndDevice, SENSOR_IEEE, 42),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(180).unwrap();
    sim.stack(s).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.events(s)
            .iter()
            .any(|e| matches!(e, StackEvent::Joined { .. }))
    }));
    // Bind the sensor's cluster to the coordinator (finding & binding
    // would do the same).
    sim.stack(s)
        .aps
        .bindings
        .bind(BindingEntry {
            src_endpoint: Endpoint(1),
            cluster: temperature::ID,
            destination: BindingDestination::Unicast {
                address: COORD_IEEE,
                endpoint: Endpoint(1),
            },
        })
        .unwrap();
    sim.run_for(Duration::from_secs(12));
    sim.take_events(c);
    // A first reading (from unknown): reported.
    {
        let cl = sim
            .stack(s)
            .zcl
            .cluster_mut(Endpoint(1), temperature::ID, Role::Server)
            .unwrap();
        assert!(temperature::set_measured(cl, Some(2150)));
    }
    assert!(
        sim.run_until(Duration::from_secs(30), |x| reported(x.events(c)).is_some()),
        "{:?}",
        sim.events(c)
    );
    assert_eq!(reported(sim.events(c)), Some(2150));
    sim.take_events(c);
    // +0.2 °C is under the 0.5 °C reportable change: nothing within the
    // minimum interval, the periodic report comes at the maximum.
    {
        let cl = sim
            .stack(s)
            .zcl
            .cluster_mut(Endpoint(1), temperature::ID, Role::Server)
            .unwrap();
        assert!(temperature::set_measured(cl, Some(2170)));
    }
    assert!(!sim.run_until(Duration::from_secs(60), |x| reported(x.events(c)).is_some()));
    // +1 °C: reported after the minimum interval.
    {
        let cl = sim
            .stack(s)
            .zcl
            .cluster_mut(Endpoint(1), temperature::ID, Role::Server)
            .unwrap();
        assert!(temperature::set_measured(cl, Some(2270)));
    }
    assert!(sim.run_until(Duration::from_secs(30), |x| reported(x.events(c)).is_some()));
    assert_eq!(reported(sim.events(c)), Some(2270));
}
