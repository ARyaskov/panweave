//! The hub against simulated devices: interview, capability discovery,
//! IAS Zone enrolment and notifications, light control, reporting,
//! timeouts and recovery after a hub reboot. These run the real stack on
//! both sides over the simulator's radio medium; they say nothing about
//! interoperability with any particular commercial device.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod common;

use common::*;
use panweave_hub::model::{
    Capabilities, ContactState, DeviceCategory, Flag, InterviewStatus, LeakState, LogicalType,
    PowerSource,
};
use panweave_hub::protocol::{
    CommandStage, ErrorCode, Event, LightCommand, Request, Response, SensorEvent,
};
use panweave_hub::registry::zone_type;
use panweave_types::Endpoint;
use panweave_types::time::Duration;
use panweave_zcl::Role;
use panweave_zcl::clusters::ias_zone::{self, EnrollMode};
use panweave_zcl::clusters::{level, on_off, power_configuration};

const ALARM1: u16 = 1 << 0;
const ALARM2: u16 = 1 << 1;
const TAMPER: u16 = 1 << 2;
const BATTERY: u16 = 1 << 3;

fn sensor_events(events: &[Event], ieee: u64) -> Vec<SensorEvent> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Sensor { ieee: i, event } if *i == ieee => Some(*event),
            _ => None,
        })
        .collect()
}

fn set_zone(sim: &mut panweave_sim::Simulator, node: usize, status: u16) {
    sim.stack(node)
        .zcl
        .set_zone_status(Endpoint(1), status)
        .unwrap();
}

fn device(
    sim: &mut panweave_sim::Simulator,
    c: usize,
    ieee: u64,
) -> panweave_hub::protocol::DeviceInfo {
    match request(sim, c, &Request::GetDevice { ieee }) {
        Response::Device(d) => d,
        r => panic!("{r:?}"),
    }
}

#[test]
fn water_leak_sensor_is_interviewed_enrolled_and_reports_leaks() {
    let (mut sim, c) = network();
    let s = join(
        &mut sim,
        c,
        "leak",
        zone_sensor(
            LEAK,
            zone_type::WATER_SENSOR,
            EnrollMode::AutoRequest,
            b"leak-sim",
        ),
        LEAK,
    );
    let d = device(&mut sim, c, LEAK);
    // Device interview: descriptors and Basic attributes.
    assert_eq!(d.summary.interview, InterviewStatus::Complete, "{d:?}");
    assert_eq!(d.summary.category, DeviceCategory::WaterLeakSensor);
    assert_eq!(d.summary.model.as_slice(), b"leak-sim");
    assert_eq!(d.manufacturer.as_slice(), b"Sim Devices");
    assert_eq!(d.logical_type, Some(LogicalType::EndDevice));
    assert_eq!(d.rx_on_when_idle, Some(false));
    assert_eq!(d.power_source, PowerSource::Battery);
    assert_eq!(d.endpoints.len(), 1);
    assert_eq!(d.endpoints[0].device_id, 0x0402);
    assert!(d.endpoints[0].inputs.contains(&0x0500));
    // Capability discovery from clusters and attributes.
    assert!(d.summary.capabilities.contains(
        Capabilities::IAS_ZONE | Capabilities::WATER_LEAK | Capabilities::POWER_CONFIGURATION
    ));
    assert!(!d.summary.capabilities.contains(Capabilities::ON_OFF));
    // IAS enrolment (Auto-Enroll-Request): the device knows its CIE and
    // is enrolled with the zone id the hub allocated.
    let zone = d.zone.unwrap();
    assert!(zone.enrolled);
    assert_eq!(zone.zone_type, Some(zone_type::WATER_SENSOR));
    let srv = sim
        .stack(s)
        .zcl
        .cluster(Endpoint(1), ias_zone::ID, Role::Server)
        .unwrap();
    assert!(ias_zone::is_enrolled(srv));
    assert_eq!(
        ias_zone::cie_address(srv).map(|a| a.0),
        Some(HUB),
        "the hub wrote itself as the CIE"
    );
    // The initial state was read: dry.
    assert_eq!(d.state.water_leak, LeakState::Dry);
    take_hub_events(&mut sim, c);

    // Alarm1 on a water sensor: water.
    set_zone(&mut sim, s, ALARM1);
    wait_event(&mut sim, c, 30, |e| {
        matches!(
            e,
            Event::Sensor {
                event: SensorEvent::WaterLeakDetected,
                ..
            }
        )
    });
    // The same status again (a periodic notification): no duplicate.
    set_zone(&mut sim, s, ALARM1 | TAMPER);
    wait_event(&mut sim, c, 30, |e| {
        matches!(
            e,
            Event::Sensor {
                event: SensorEvent::TamperDetected,
                ..
            }
        )
    });
    sim.run_for(Duration::from_secs(5));
    let events = take_hub_events(&mut sim, c);
    let leaks = sensor_events(&events, LEAK)
        .into_iter()
        .filter(|e| *e == SensorEvent::WaterLeakDetected)
        .count();
    assert_eq!(leaks, 1, "deduplicated: {events:?}");
    // Alarm2 is not defined for a water sensor: Alarm2 alone is dry.
    set_zone(&mut sim, s, ALARM2);
    wait_event(&mut sim, c, 30, |e| {
        matches!(
            e,
            Event::Sensor {
                event: SensorEvent::WaterLeakCleared,
                ..
            }
        )
    });
    let d = device(&mut sim, c, LEAK);
    assert_eq!(d.state.water_leak, LeakState::Dry);
    assert_eq!(d.state.zone_status, Some(ALARM2));
    // The battery bit of the zone status.
    take_hub_events(&mut sim, c);
    set_zone(&mut sim, s, BATTERY);
    wait_event(&mut sim, c, 30, |e| {
        matches!(
            e,
            Event::Sensor {
                event: SensorEvent::BatteryLow,
                ..
            }
        )
    });
    assert_eq!(device(&mut sim, c, LEAK).state.battery_low, Flag::Set);
}

#[test]
fn contact_sensor_without_enroll_request_is_enrolled_unsolicited() {
    let (mut sim, c) = network();
    // Trip-to-Pair: the zone never asks to enrol by itself.
    let s = join(
        &mut sim,
        c,
        "contact",
        zone_sensor(
            CONTACT,
            zone_type::CONTACT_SWITCH,
            EnrollMode::TripToPair,
            b"door-sim",
        ),
        CONTACT,
    );
    let d = device(&mut sim, c, CONTACT);
    assert_eq!(d.summary.category, DeviceCategory::ContactSensor);
    assert!(d.summary.capabilities.contains(Capabilities::CONTACT));
    assert!(d.zone.unwrap().enrolled, "{d:?}");
    assert_eq!(d.state.contact, ContactState::Closed);
    take_hub_events(&mut sim, c);
    set_zone(&mut sim, s, ALARM1);
    wait_event(&mut sim, c, 30, |e| {
        matches!(
            e,
            Event::Sensor {
                ieee: CONTACT,
                event: SensorEvent::ContactOpened
            }
        )
    });
    set_zone(&mut sim, s, 0);
    wait_event(&mut sim, c, 30, |e| {
        matches!(
            e,
            Event::Sensor {
                ieee: CONTACT,
                event: SensorEvent::ContactClosed
            }
        )
    });
    assert_eq!(
        device(&mut sim, c, CONTACT).state.contact,
        ContactState::Closed
    );
    // Alarm2 (a second portal on a contact switch) is not the primary
    // contact: no event, the raw status is kept.
    take_hub_events(&mut sim, c);
    set_zone(&mut sim, s, ALARM2);
    wait_event(
        &mut sim,
        c,
        30,
        |e| matches!(e, Event::DeviceStateChanged { ieee: CONTACT, state } if state.zone_status == Some(ALARM2)),
    );
    let events = take_hub_events(&mut sim, c);
    assert!(sensor_events(&events, CONTACT).is_empty(), "{events:?}");
    assert_eq!(
        device(&mut sim, c, CONTACT).state.contact,
        ContactState::Closed
    );
}

#[test]
fn bulb_is_controlled_and_its_state_confirmed() {
    let (mut sim, c) = network();
    let b = join(&mut sim, c, "bulb", bulb(), BULB);
    let d = device(&mut sim, c, BULB);
    assert_eq!(d.summary.category, DeviceCategory::DimmableLight);
    assert!(
        d.summary
            .capabilities
            .contains(Capabilities::ON_OFF | Capabilities::LEVEL)
    );
    assert!(!d.summary.capabilities.contains(Capabilities::COLOR));
    assert_eq!(d.logical_type, Some(LogicalType::Router));
    assert_eq!(d.state.on, Some(false), "initial state read");

    let light = |command| Request::Light {
        ieee: BULB,
        endpoint: 0,
        command,
    };
    let Response::Accepted { command } = request(&mut sim, c, &light(LightCommand::TurnOn)) else {
        panic!()
    };
    let done = wait_event(
        &mut sim,
        c,
        30,
        |e| matches!(e, Event::CommandCompleted { command: id, .. } | Event::CommandFailed { command: id, .. } if *id == command),
    );
    match done {
        Event::CommandCompleted { stage, value, .. } => {
            assert_eq!(stage, CommandStage::Confirmed);
            assert_eq!(value.unwrap().as_u64(), Some(1));
        }
        e => panic!("{e:?}"),
    }
    let srv = sim
        .stack(b)
        .zcl
        .cluster(Endpoint(1), on_off::ID, Role::Server)
        .unwrap();
    assert!(on_off::is_on(srv));
    assert_eq!(device(&mut sim, c, BULB).state.on, Some(true));

    // Level Control: 50 % is level 126 of 1–254.
    let Response::Accepted { command } = request(
        &mut sim,
        c,
        &light(LightCommand::SetBrightness {
            percent: 50,
            transition_ds: 0,
        }),
    ) else {
        panic!()
    };
    wait_event(
        &mut sim,
        c,
        30,
        |e| matches!(e, Event::CommandCompleted { command: id, stage: CommandStage::Confirmed, .. } if *id == command),
    );
    let srv = sim
        .stack(b)
        .zcl
        .cluster(Endpoint(1), level::ID, Role::Server)
        .unwrap();
    assert_eq!(level::current_level(srv), 126);
    assert_eq!(device(&mut sim, c, BULB).state.level, Some(126));

    // Brightness 0 turns the light off; out of range is refused.
    let Response::Accepted { command } = request(
        &mut sim,
        c,
        &light(LightCommand::SetBrightness {
            percent: 0,
            transition_ds: 0,
        }),
    ) else {
        panic!()
    };
    wait_event(
        &mut sim,
        c,
        30,
        |e| matches!(e, Event::CommandCompleted { command: id, .. } if *id == command),
    );
    assert_eq!(device(&mut sim, c, BULB).state.on, Some(false));
    assert_eq!(
        request(
            &mut sim,
            c,
            &light(LightCommand::SetBrightness {
                percent: 101,
                transition_ds: 0
            })
        ),
        Response::Error(ErrorCode::InvalidArgument)
    );

    // A local change on the bulb arrives as an On/Off report (bound and
    // configured by the interview).
    take_hub_events(&mut sim, c);
    sim.stack(b).zcl.set_on_off(Endpoint(1), true).unwrap();
    wait_event(
        &mut sim,
        c,
        30,
        |e| matches!(e, Event::DeviceStateChanged { ieee: BULB, state } if state.on == Some(true)),
    );
}

#[test]
fn unanswered_commands_time_out_and_sensors_cannot_be_switched() {
    let (mut sim, c) = network();
    let b = join(&mut sim, c, "bulb", bulb(), BULB);
    let leak = zone_sensor(
        LEAK,
        zone_type::WATER_SENSOR,
        EnrollMode::AutoRequest,
        b"leak",
    );
    join(&mut sim, c, "leak", leak, LEAK);
    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::Light {
                ieee: LEAK,
                endpoint: 0,
                command: LightCommand::TurnOn
            }
        ),
        Response::Error(ErrorCode::NotSupported)
    );
    assert_eq!(
        request(
            &mut sim,
            c,
            &Request::Light {
                ieee: 0x1234,
                endpoint: 0,
                command: LightCommand::TurnOn
            }
        ),
        Response::Error(ErrorCode::UnknownDevice)
    );
    sim.isolate(b);
    let Response::Accepted { command } = request(
        &mut sim,
        c,
        &Request::Light {
            ieee: BULB,
            endpoint: 0,
            command: LightCommand::Toggle,
        },
    ) else {
        panic!()
    };
    let e = wait_event(
        &mut sim,
        c,
        60,
        |e| matches!(e, Event::CommandFailed { command: id, .. } if *id == command),
    );
    assert!(
        matches!(
            e,
            Event::CommandFailed {
                error: ErrorCode::Timeout,
                stage: CommandStage::Sent,
                ..
            }
        ),
        "{e:?}"
    );
    let Response::Diagnostics(d) = request(&mut sim, c, &Request::GetDiagnostics) else {
        panic!()
    };
    assert_eq!(d.command_timeouts, 1);
    assert_eq!(d.commands, 0);
}

#[test]
fn read_bind_and_configure_reporting_on_request() {
    let (mut sim, c) = network();
    let s = join(
        &mut sim,
        c,
        "leak",
        zone_sensor(
            LEAK,
            zone_type::WATER_SENSOR,
            EnrollMode::AutoRequest,
            b"leak",
        ),
        LEAK,
    );
    // Battery: the sensor measures, the hub reads it on request.
    {
        let cl = sim
            .stack(s)
            .zcl
            .cluster_mut(Endpoint(1), power_configuration::ID, Role::Server)
            .unwrap();
        power_configuration::set_battery(cl, Some(29), Some(150));
    }
    let Response::Accepted { command } = request(
        &mut sim,
        c,
        &Request::ReadAttribute {
            ieee: LEAK,
            endpoint: 1,
            cluster: 0x0001,
            attribute: 0x0021,
        },
    ) else {
        panic!()
    };
    let e = wait_event(
        &mut sim,
        c,
        60,
        |e| matches!(e, Event::CommandCompleted { command: id, .. } | Event::CommandFailed { command: id, .. } if *id == command),
    );
    let Event::CommandCompleted { value, .. } = e else {
        panic!("{e:?}")
    };
    assert_eq!(value.unwrap().as_u64(), Some(150));
    let st = device(&mut sim, c, LEAK).state;
    assert_eq!(st.battery_percent, Some(75));
    assert!(
        device(&mut sim, c, LEAK)
            .summary
            .capabilities
            .contains(Capabilities::BATTERY_PERCENTAGE)
    );

    let Response::Accepted { command } = request(
        &mut sim,
        c,
        &Request::Bind {
            ieee: LEAK,
            endpoint: 1,
            cluster: 0x0001,
        },
    ) else {
        panic!()
    };
    wait_event(
        &mut sim,
        c,
        60,
        |e| matches!(e, Event::CommandCompleted { command: id, stage: CommandStage::Responded, .. } if *id == command),
    );
    // BatteryVoltage is not reportable on this device: the refusal is
    // reported with its ZCL status (UNREPORTABLE_ATTRIBUTE).
    let configure = |attribute, change| Request::ConfigureReporting {
        ieee: LEAK,
        endpoint: 1,
        cluster: 0x0001,
        attribute,
        data_type: 0x20,
        min_interval: 1,
        max_interval: 10,
        change,
    };
    let Response::Accepted { command } = request(&mut sim, c, &configure(0x0020, 1)) else {
        panic!()
    };
    let e = wait_event(
        &mut sim,
        c,
        60,
        |e| matches!(e, Event::CommandFailed { command: id, .. } if *id == command),
    );
    assert!(
        matches!(
            e,
            Event::CommandFailed {
                error: ErrorCode::ZclFailure,
                status: 0x8c,
                ..
            }
        ),
        "{e:?}"
    );
    // Battery reporting: the percentage at most every 10 s, on any
    // change of 1 %.
    let Response::Accepted { command } = request(&mut sim, c, &configure(0x0021, 2)) else {
        panic!()
    };
    wait_event(
        &mut sim,
        c,
        60,
        |e| matches!(e, Event::CommandCompleted { command: id, .. } if *id == command),
    );
    take_hub_events(&mut sim, c);
    {
        let cl = sim
            .stack(s)
            .zcl
            .cluster_mut(Endpoint(1), power_configuration::ID, Role::Server)
            .unwrap();
        power_configuration::set_battery(cl, Some(25), Some(40));
    }
    wait_event(
        &mut sim,
        c,
        60,
        |e| matches!(e, Event::DeviceStateChanged { ieee: LEAK, state } if state.battery_percent == Some(20)),
    );
}

#[test]
fn hub_reboot_restores_the_registry_with_unknown_state() {
    let (mut sim, c) = network();
    let s = join(
        &mut sim,
        c,
        "leak",
        zone_sensor(
            LEAK,
            zone_type::WATER_SENSOR,
            EnrollMode::AutoRequest,
            b"leak",
        ),
        LEAK,
    );
    join(&mut sim, c, "bulb", bulb(), BULB);
    let before = device(&mut sim, c, LEAK);
    // Power loss: everything the registry wrote survives; RAM does not.
    let storage = {
        let (_, app) = sim.stack_and_app::<HubApp>(c).unwrap();
        app.hub.flush();
        app.hub.storage().clone()
    };
    let mut rebooted = HubApp::new(storage);
    assert_eq!(rebooted.hub.restore().unwrap(), 2);
    sim.node_mut(c).app = Box::new(rebooted);
    let after = device(&mut sim, c, LEAK);
    assert_eq!(after.summary.category, before.summary.category);
    assert_eq!(after.endpoints, before.endpoints);
    assert_eq!(after.zone, before.zone);
    assert_eq!(after.manufacturer, before.manufacturer);
    assert_eq!(after.state.water_leak, LeakState::Unknown, "not assumed");
    // The bulb is always reachable: its state is read again.
    wait_event(
        &mut sim,
        c,
        30,
        |e| matches!(e, Event::DeviceStateChanged { ieee: BULB, state } if state.on.is_some()),
    );
    // The sensor's next notification reaches the restored registry.
    set_zone(&mut sim, s, ALARM1);
    wait_event(&mut sim, c, 30, |e| {
        matches!(
            e,
            Event::Sensor {
                ieee: LEAK,
                event: SensorEvent::WaterLeakDetected
            }
        )
    });
}
