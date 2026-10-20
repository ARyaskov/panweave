//! Protocol compatibility: every message survives an encode/decode round
//! trip through the wire framing, and the wire format of v1 is pinned by
//! golden frames (a host built from this crate and a firmware built from
//! the same release agree byte for byte).

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use heapless::Vec as HVec;
use panweave_hub::model::{
    Capabilities, ContactState, DeviceCategory, DeviceState, Flag, InterviewStage, InterviewStatus,
    LeakState, LogicalType, PowerSource,
};
use panweave_hub::protocol::frame::{FrameDecoder, MAX_BODY, MAX_WIRE};
use panweave_hub::protocol::{
    AttributeData, CommandStage, DEVICE_PAGE, DeviceInfo, DeviceList, DeviceSummary, Diagnostics,
    EndpointDescriptor, ErrorCode, Event, HubInfo, LightCommand, Message, NetworkInfo,
    NetworkState, NetworkStatus, ProtocolError, Request, Response, SensorEvent, ZoneInfo,
};

fn full_state() -> DeviceState {
    DeviceState {
        on: Some(true),
        level: Some(200),
        contact: ContactState::Open,
        water_leak: LeakState::Leak,
        motion: Flag::Clear,
        tamper: Flag::Set,
        battery_low: Flag::Unknown,
        trouble: Flag::Clear,
        battery_percent: Some(87),
        battery_mv: Some(2900),
        temperature_centi: Some(-1234),
        humidity_centi: Some(4567),
        zone_status: Some(0x0205),
    }
}

fn summary(i: u64) -> DeviceSummary {
    DeviceSummary {
        ieee: 0x0011_2233_4455_6600 + i,
        short: 0x1000 + u16::try_from(i).unwrap(),
        category: DeviceCategory::ContactSensor,
        capabilities: Capabilities(Capabilities::CONTACT | Capabilities::IAS_ZONE),
        interview: InterviewStatus::Partial,
        present: i.is_multiple_of(2),
        last_seen_s: (!i.is_multiple_of(3)).then_some(1234),
        model: HVec::from_slice(&[b'x'; 32]).unwrap(),
    }
}

/// The largest device description the protocol carries.
fn largest_device() -> DeviceInfo {
    let mut endpoints = HVec::new();
    for e in 0..4 {
        endpoints
            .push(EndpointDescriptor {
                endpoint: e,
                profile: 0x0104,
                device_id: 0x0402,
                inputs: HVec::from_slice(&[0xffff; 16]).unwrap(),
                outputs: HVec::from_slice(&[0xffff; 8]).unwrap(),
            })
            .unwrap();
    }
    DeviceInfo {
        summary: summary(1),
        manufacturer: HVec::from_slice(&[b'm'; 32]).unwrap(),
        sw_build: HVec::from_slice(&[b'b'; 16]).unwrap(),
        manufacturer_code: Some(0x1234),
        logical_type: Some(LogicalType::EndDevice),
        rx_on_when_idle: Some(false),
        power_source: PowerSource::Battery,
        interview_stage: InterviewStage::Reporting,
        endpoints,
        zone: Some(ZoneInfo {
            endpoint: 1,
            zone_type: Some(0x0015),
            zone_id: Some(4),
            enrolled: true,
        }),
        lqi: Some(180),
        state: full_state(),
    }
}

fn every_message() -> Vec<Message> {
    let ieee = 0x0011_2233_4455_6677;
    let attr = AttributeData {
        data_type: 0x42,
        raw: HVec::from_slice(&[32; 32]).unwrap(),
    };
    let requests = [
        Request::GetHubInfo,
        Request::GetNetworkStatus,
        Request::PermitJoin { seconds: 254 },
        Request::CloseNetwork,
        Request::ListDevices { start: 8 },
        Request::GetDevice { ieee },
        Request::InterviewDevice { ieee },
        Request::GetDeviceState { ieee },
        Request::ReadAttribute {
            ieee,
            endpoint: 1,
            cluster: 0x0500,
            attribute: 2,
        },
        Request::ConfigureReporting {
            ieee,
            endpoint: 1,
            cluster: 0x0402,
            attribute: 0,
            data_type: 0x29,
            min_interval: 30,
            max_interval: 3600,
            change: 50,
        },
        Request::Bind {
            ieee,
            endpoint: 2,
            cluster: 6,
        },
        Request::Light {
            ieee,
            endpoint: 0,
            command: LightCommand::TurnOn,
        },
        Request::Light {
            ieee,
            endpoint: 1,
            command: LightCommand::TurnOff,
        },
        Request::Light {
            ieee,
            endpoint: 1,
            command: LightCommand::Toggle,
        },
        Request::Light {
            ieee,
            endpoint: 3,
            command: LightCommand::SetBrightness {
                percent: 55,
                transition_ds: 10,
            },
        },
        Request::RemoveDevice { ieee, leave: true },
        Request::GetDiagnostics,
    ];
    let mut devices = HVec::new();
    for i in 0..DEVICE_PAGE as u64 {
        devices.push(summary(i)).unwrap();
    }
    let responses = [
        Response::HubInfo(HubInfo {
            protocol_version: 1,
            firmware: HVec::from_slice(b"0.1.0").unwrap(),
            ieee,
            max_devices: 32,
            uptime_s: 99,
            persistent: true,
        }),
        Response::NetworkStatus(NetworkStatus {
            state: NetworkState::Up,
            network: NetworkInfo {
                pan_id: 0x1a62,
                extended_pan_id: ieee,
                channel: 15,
            },
            short: 0,
            permit_join_s: 17,
            devices: 3,
        }),
        Response::Done,
        Response::DeviceList(DeviceList {
            total: 30,
            start: 8,
            devices,
        }),
        Response::Device(largest_device()),
        Response::DeviceState {
            ieee,
            state: full_state(),
            last_seen_s: None,
        },
        Response::Accepted { command: 65535 },
        Response::Diagnostics(Diagnostics {
            uptime_s: 1,
            radio_rx: 2,
            radio_tx: 3,
            radio_dropped: 4,
            stack_events_dropped: 5,
            devices: 6,
            max_devices: 32,
            pending: 7,
            commands: 8,
            events_dropped: 9,
            interview_failures: 10,
            command_timeouts: 11,
            storage_writes: 12,
            storage_errors: 13,
            registry_full: 14,
            frames_rx: 15,
            frames_tx: 16,
            frames_corrupt: 17,
            frames_oversize: 18,
            frames_malformed: 19,
            unauthorized: 20,
            responses_dropped: 21,
        }),
        Response::Error(ErrorCode::Unauthorized),
        Response::Error(ErrorCode::Unknown(0xee)),
    ];
    let net = NetworkInfo {
        pan_id: 1,
        extended_pan_id: 2,
        channel: 26,
    };
    let mut events = vec![
        Event::NetworkStarted(net),
        Event::NetworkRestored(net),
        Event::PermitJoinChanged { seconds: 0 },
        Event::DeviceJoined {
            ieee,
            short: 0xabcd,
            rejoin: true,
        },
        Event::DeviceLeft { ieee },
        Event::DeviceInterviewCompleted {
            ieee,
            category: DeviceCategory::DimmableLight,
            capabilities: Capabilities(3),
            partial: false,
        },
        Event::DeviceInterviewFailed {
            ieee,
            stage: InterviewStage::SimpleDescriptors,
            error: ErrorCode::Timeout,
        },
        Event::DeviceStateChanged {
            ieee,
            state: full_state(),
        },
        Event::AttributeReport {
            ieee,
            endpoint: 1,
            cluster: 0x0b04,
            attribute: 0x0505,
            value: attr.clone(),
        },
        Event::CommandCompleted {
            command: 9,
            ieee,
            stage: CommandStage::Confirmed,
            value: Some(attr),
        },
        Event::CommandCompleted {
            command: 9,
            ieee,
            stage: CommandStage::Responded,
            value: None,
        },
        Event::CommandFailed {
            command: 10,
            ieee,
            stage: CommandStage::Sent,
            error: ErrorCode::ZclFailure,
            status: 0x8c,
        },
        Event::HubError {
            error: ErrorCode::StorageFailure,
            detail: 3,
        },
        Event::EventsDropped { count: 500 },
    ];
    for e in [
        SensorEvent::WaterLeakDetected,
        SensorEvent::WaterLeakCleared,
        SensorEvent::WaterLeakStateUnknown,
        SensorEvent::ContactOpened,
        SensorEvent::ContactClosed,
        SensorEvent::ContactStateUnknown,
        SensorEvent::BatteryLow,
        SensorEvent::TamperDetected,
    ] {
        events.push(Event::Sensor { ieee, event: e });
    }
    let mut out = Vec::new();
    for (i, request) in requests.into_iter().enumerate() {
        out.push(Message::Request {
            id: u16::try_from(i).unwrap(),
            request,
        });
    }
    for (i, response) in responses.into_iter().enumerate() {
        out.push(Message::Response {
            id: u16::try_from(i).unwrap() + 1000,
            response,
        });
    }
    for (i, event) in events.into_iter().enumerate() {
        out.push(Message::Event {
            seq: u16::try_from(i).unwrap(),
            event,
        });
    }
    out
}

#[test]
fn every_message_round_trips_through_the_wire() {
    let mut dec = FrameDecoder::new();
    for m in every_message() {
        let mut wire = [0u8; MAX_WIRE];
        let n = m.encode_frame(&mut wire).unwrap();
        let mut got = None;
        for &b in &wire[..n] {
            if let Some(r) = dec.push(b) {
                got = Some(Message::decode(r.unwrap()).unwrap());
            }
        }
        assert_eq!(got.as_ref(), Some(&m));
        // Every prefix is refused, never misread.
        let mut body = [0u8; MAX_BODY];
        let len = m.encode(&mut body).unwrap();
        for cut in 0..len {
            assert!(Message::decode(&body[..cut]).is_err(), "{m:?} cut at {cut}");
        }
    }
}

#[test]
fn the_largest_messages_fit_one_frame() {
    let mut body = [0u8; MAX_BODY];
    let device = Message::Response {
        id: 1,
        response: Response::Device(largest_device()),
    };
    let n = device.encode(&mut body).unwrap();
    assert!(n <= MAX_BODY, "{n}");
    let mut devices = HVec::new();
    for i in 0..DEVICE_PAGE as u64 {
        devices.push(summary(i)).unwrap();
    }
    let list = Message::Response {
        id: 1,
        response: Response::DeviceList(DeviceList {
            total: 32,
            start: 0,
            devices,
        }),
    };
    assert!(list.encode(&mut body).unwrap() <= MAX_BODY);
    assert_eq!(
        Message::decode(&[2, 1, 5, 0, 1]),
        Err(ProtocolError::UnsupportedVersion {
            version: 2,
            id: Some(5)
        })
    );
    assert_eq!(
        Message::decode(&[1, 9, 5, 0, 1]),
        Err(ProtocolError::UnknownKind(9))
    );
}

#[test]
fn the_v1_wire_format_is_stable() {
    // GetHubInfo, request id 0x0102.
    let mut wire = [0u8; MAX_WIRE];
    let n = Message::Request {
        id: 0x0102,
        request: Request::GetHubInfo,
    }
    .encode_frame(&mut wire)
    .unwrap();
    assert_eq!(
        &wire[..n],
        &[0x00, 0x08, 0x01, 0x01, 0x02, 0x01, 0x01, 0x99, 0x80, 0x00]
    );
    // Light on, endpoint auto.
    let mut body = [0u8; MAX_BODY];
    let n = Message::Request {
        id: 7,
        request: Request::Light {
            ieee: 0x0011_2233_4455_6677,
            endpoint: 0,
            command: LightCommand::TurnOn,
        },
    }
    .encode(&mut body)
    .unwrap();
    assert_eq!(
        &body[..n],
        &[
            1, 1, 7, 0, 0x0c, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00
        ]
    );
    // A water leak event.
    let n = Message::Event {
        seq: 3,
        event: Event::Sensor {
            ieee: 1,
            event: SensorEvent::WaterLeakDetected,
        },
    }
    .encode(&mut body)
    .unwrap();
    assert_eq!(&body[..n], &[1, 3, 3, 0, 0x09, 1, 0, 0, 0, 0, 0, 0, 0]);
}
