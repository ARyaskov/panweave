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
use panweave_hub::capture::{CaptureMode, CapturedFrame, MAX_FRAME, flags};
use panweave_hub::diag::{Category, DiagRecord, Severity, code};
use panweave_hub::model::{
    Capabilities, ContactState, DeviceCategory, DeviceState, Flag, InterviewStage, InterviewStatus,
    LeakState, LogicalType, PowerSource,
};
use panweave_hub::protocol::alerts::{
    MAX_BOT_TOKEN, MAX_CHAT_ID, MAX_SSID, MAX_WIFI_PASSWORD, STAGES, kinds,
};
use panweave_hub::protocol::frame::{FrameDecoder, MAX_BODY, MAX_WIRE};
use panweave_hub::protocol::{
    AlertConfigUpdate, AlertError, AlertStage, AlertState, AlertStatus, DeviceAuthorization,
    ExemptionInfo, MAX_EXEMPTIONS, MAX_UNAUTHORIZED, SecurityStatus, TargetMetrics,
};
use panweave_hub::protocol::{
    AttributeData, BootReport, CapturePage, CommandStage, DEVICE_PAGE, DeviceInfo, DeviceList,
    DeviceSummary, Diagnostics, EndpointDescriptor, ErrorCode, Event, HubInfo, LightCommand,
    MAX_BOOT_FINDINGS, MAX_BOOT_PARTITIONS, MAX_CAPTURE_PAGE, MAX_TRACE_PAGE, Message, NetworkInfo,
    NetworkRestore, NetworkState, NetworkStatus, PartitionEntry, PartitionFinding, ProtocolError,
    QueueUsage, RadioDiagnostics, RadioDriverStats, Request, ResetKind, Response,
    RuntimeDiagnostics, SensorEvent, StorageDiagnostics, StoreUsage, TraceConfiguration, TracePage,
    ZoneInfo,
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

/// The largest boot report: every partition and finding slot used.
fn largest_boot_report() -> BootReport {
    let mut partitions = HVec::new();
    for i in 0..MAX_BOOT_PARTITIONS {
        partitions
            .push(PartitionEntry {
                label: HVec::from_slice(&[b'p'; 16]).unwrap(),
                kind: 1,
                subtype: u8::try_from(i).unwrap(),
                offset: 0x9000 + u32::try_from(i).unwrap() * 0x1000,
                size: 0x1000,
            })
            .unwrap();
    }
    let mut findings = HVec::new();
    for i in 0..MAX_BOOT_FINDINGS {
        findings
            .push(PartitionFinding {
                code: u8::try_from(i + 1).unwrap(),
                partition: if i == 0 { 0xff } else { 2 },
            })
            .unwrap();
    }
    BootReport {
        chip: HVec::from_slice(b"ESP32-C6").unwrap(),
        chip_revision: Some(1),
        firmware: HVec::from_slice(b"0.2.1").unwrap(),
        build: HVec::from_slice(&[b'b'; 24]).unwrap(),
        reset: Some(ResetKind::WatchdogReset),
        reset_raw: Some(0x07),
        cpu_mhz: Some(160),
        flash_size: Some(0x40_0000),
        partition_table_read: true,
        partitions,
        findings,
        hubdata: Some((0x31_0000, 0x1_0000)),
        ieee: 0x0011_2233_4455_6677,
        radio_channel: Some(15),
        network: Some(NetworkRestore::CorruptNotFormed),
        registry_devices: Some(32),
        registry_persistent: true,
        usb_ready: true,
        watchdog_s: Some(8),
        boot_ms: Some(812),
    }
}

/// A trace record with every field present.
fn full_record(i: u32) -> DiagRecord {
    let mut r = DiagRecord::new(
        Category::Interview,
        Severity::Warning,
        code::INTERVIEW_TIMEOUT,
    )
    .ieee(0x0011_2233_4455_6677)
    .short(0x1234)
    .endpoint(1)
    .cluster(0x0500)
    .tsn(200)
    .status(3)
    .arg(0x0102 + i);
    r.seq = (u32::MAX - 5).wrapping_add(i);
    r.at_ms = u32::MAX - 1000 + i;
    r
}

fn largest_trace_page() -> TracePage {
    let mut records = HVec::new();
    for i in 0..MAX_TRACE_PAGE {
        records
            .push(full_record(u32::try_from(i).unwrap()))
            .unwrap();
    }
    TracePage {
        uptime_ms: u64::from(u32::MAX) + 5,
        next: 7,
        first_available: u32::MAX - 5,
        dropped: 1000,
        records,
    }
}

fn largest_capture_page() -> CapturePage {
    let mut frames = HVec::new();
    for i in 0..MAX_CAPTURE_PAGE {
        frames
            .push(CapturedFrame {
                seq: u32::try_from(i).unwrap(),
                at_ms: 99,
                channel: 26,
                flags: flags::RX | flags::REDACTED,
                rssi: Some(-90),
                lqi: Some(30),
                original_len: 127,
                data: HVec::from_slice(&[0x5a; MAX_FRAME]).unwrap(),
            })
            .unwrap();
    }
    CapturePage {
        active: true,
        mode: CaptureMode::Sanitized,
        remaining_s: 3600,
        dropped: 17,
        queued: 16,
        uptime_ms: 123_456,
        frames,
    }
}

fn largest_security_status() -> SecurityStatus {
    let mut s = SecurityStatus {
        require_key_exchange: true,
        node_join_timeout_s: 15,
        pending_key_exchanges: 8,
        key_exchange_timeouts: 3,
        unauthorized_frames_dropped: 70_000,
        link_keys: 31,
        link_key_capacity: 32,
        ..SecurityStatus::default()
    };
    for i in 0..MAX_EXEMPTIONS {
        s.exemptions
            .push(ExemptionInfo {
                ieee: 0x1000 + u64::try_from(i).unwrap(),
                remaining_s: (i % 2 == 0).then_some(3600),
            })
            .unwrap();
    }
    for i in 0..MAX_UNAUTHORIZED {
        s.unauthorized
            .push((
                0x2000 + u64::try_from(i).unwrap(),
                DeviceAuthorization::from_code(u8::try_from(i).unwrap()),
            ))
            .unwrap();
    }
    s
}

fn store_usage() -> StoreUsage {
    StoreUsage {
        capacity: 0x8000,
        free: 0x1234,
        writes: 99,
        compactions: 2,
        corrupt_records: 1,
        io_errors: 0,
        formatted_at_open: false,
    }
}

fn queue(len: u16) -> QueueUsage {
    QueueUsage {
        len,
        capacity: 32,
        high_water: 31,
    }
}

fn diagnostic_responses() -> Vec<Response> {
    vec![
        Response::BootReport(largest_boot_report()),
        Response::BootReport(BootReport::default()),
        Response::RadioDiagnostics(RadioDiagnostics {
            channel: Some(11),
            tx_power_dbm: Some(-3),
            energy_detection: false,
            driver: Some(RadioDriverStats {
                tx_attempts: 1,
                tx_acked: 2,
                tx_no_ack: 3,
                tx_cca_failures: 4,
                tx_faults: 5,
                rx_frames: 6,
                rx_malformed: 7,
                config_errors: 8,
                config_flushes: 9,
                last_rssi: Some(-70),
                last_lqi: None,
            }),
            mac_tx_ucast: 10,
            mac_tx_ucast_retry: 11,
            mac_tx_ucast_fail: 12,
            mac_rx_ucast: 13,
            mac_tx_bcast: 14,
            mac_rx_bcast: 15,
            mac_queue_full: 16,
            nwk_malformed: 17,
            nwk_security_failures: 18,
            nwk_replays: 19,
            nwk_no_route: 20,
            nwk_pending_full: 21,
            nwk_pending_high_water: 4,
            nwk_pending: 3,
            nwk_pending_held: 2,
            nwk_pending_capacity: 4,
            aps_tx_success: 22,
            aps_retries: 23,
            aps_ack_failures: 24,
            aps_security_dropped: 25,
            aps_malformed: 26,
        }),
        Response::RadioDiagnostics(RadioDiagnostics::default()),
        Response::StorageDiagnostics(StorageDiagnostics {
            registry_persistent: true,
            registry_devices: 5,
            registry_writes: 6,
            registry_errors: 7,
            registry_full_errors: 8,
            records_skipped: 9,
            last_error: Some(1),
            network: Some(NetworkRestore::Restored),
            stack_store: Some(store_usage()),
            hub_store: None,
        }),
        Response::RuntimeDiagnostics(RuntimeDiagnostics {
            uptime_ms: u64::MAX,
            loop_iterations: Some(1),
            loop_max_us: Some(2),
            loop_overruns: None,
            radio_step_max_us: Some(3),
            watchdog_s: Some(8),
            hub_events: queue(1),
            pending: queue(2),
            commands: queue(3),
            trace: queue(4),
            session_tx: queue(5),
            capture: queue(6),
            hub_events_dropped: 7,
            stack_events_dropped: 8,
            trace_dropped: 9,
            join_trace_dropped: 10,
            capture_dropped: 11,
            usb_rx_bytes: Some(12),
            usb_tx_bytes: None,
            usb_discards: 13,
            devices: 14,
            max_devices: 32,
            interviews_active: 2,
            interviews_stalled: 1,
            target: TargetMetrics {
                stack_size: Some(400_000),
                stack_peak: Some(180_000),
                heap_size: Some(32_768),
                heap_used: Some(20_000),
                heap_peak: None,
                loop_over_20ms: Some(3),
                hub_poll_max_us: Some(12_000),
                radio_idle_ms: Some(15_000),
                rx_bursts_cut: None,
                health: Some(2),
                radio_recoveries: Some(1),
            },
        }),
        Response::TraceConfiguration(TraceConfiguration {
            min_severity: Severity::Debug,
            categories: 0x8001,
            capacity: 128,
            stored: 77,
            dropped: 5,
            filtered: 6,
        }),
        Response::TracePage(largest_trace_page()),
        Response::CapturePage(largest_capture_page()),
        Response::SecurityStatus(largest_security_status()),
        Response::SecurityStatus(SecurityStatus::default()),
        Response::AlertStatus(largest_alert_status()),
        Response::AlertStatus(AlertStatus::default()),
        Response::WifiScan(Some(largest_wifi_scan())),
        Response::WifiScan(Some(panweave_hub::protocol::WifiScan::default())),
        Response::WifiScan(None),
        Response::LightColor {
            ieee: 0x0011_2233_4455_6677,
            color: panweave_hub::model::ColorState::default(),
        },
        Response::LightColor {
            ieee: 1,
            color: full_color(),
        },
        Response::OtaStatus(panweave_hub::protocol::OtaStatus::default()),
        Response::GreenPowerDevices(panweave_hub::protocol::GpdList {
            total: 9,
            start: 0,
            devices: HVec::from_slice(
                &[panweave_hub::protocol::GpdInfo {
                    gpd: panweave_hub::protocol::GpdAddress::SrcId(1),
                    device_id: 2,
                }; panweave_hub::protocol::GPD_PAGE],
            )
            .unwrap(),
        }),
        Response::OtaStatus(panweave_hub::protocol::OtaStatus {
            offer: Some(panweave_hub::protocol::OtaOffer {
                image: panweave_hub::protocol::OtaImage {
                    manufacturer_code: 1,
                    image_type: 2,
                    file_version: 3,
                    size: 4,
                },
                target: None,
                allow_downgrade: false,
            }),
            device: Some(5),
            offset: 6,
            window_offset: 7,
            window_len: 1024,
        }),
        Response::CapturePage(CapturePage {
            active: false,
            mode: CaptureMode::Metadata,
            remaining_s: 0,
            dropped: 0,
            queued: 0,
            uptime_ms: 0,
            frames: HVec::new(),
        }),
    ]
}

fn largest_wifi_scan() -> panweave_hub::protocol::WifiScan {
    use panweave_hub::protocol::alerts::{MAX_SCAN_ENTRIES, MAX_SSID, auth};
    let entry = |i: u8| panweave_hub::protocol::ScanEntry {
        ssid: HVec::from_slice(&[b'a' + i; MAX_SSID]).unwrap(),
        bssid: [0x02, 0, 0, 0, 0, i],
        channel: 13,
        #[allow(clippy::cast_possible_wrap)]
        rssi: -90 - i as i8,
        auth: auth::WPA2_WPA3,
    };
    panweave_hub::protocol::WifiScan {
        scan_ms: u32::MAX,
        seen: u16::MAX,
        target: Some(entry(9)),
        strongest: (0..u8::try_from(MAX_SCAN_ENTRIES).unwrap())
            .map(entry)
            .collect(),
    }
}

fn largest_alert_status() -> AlertStatus {
    AlertStatus {
        state: AlertState::RetryScheduled,
        enabled: true,
        ssid: HVec::from_slice(&[b's'; MAX_SSID]).unwrap(),
        password_set: true,
        token_set: true,
        chat_id: HVec::from_slice(&[b'1'; MAX_CHAT_ID]).unwrap(),
        kinds: kinds::ALL,
        delay_ms: 50_000,
        budget_ms: 2_000,
        min_zigbee_ms: 30_000,
        boot_id: u32::MAX,
        queue_depth: 16,
        queue_capacity: 16,
        overflowed: 7,
        next_attempt_ms: Some(123_456),
        attempts: 9,
        successes: 4,
        failures: 5,
        ambiguous: 1,
        budget_overruns: 2,
        restore_failures: 0,
        last_downtime_ms: Some(1_840),
        max_downtime_ms: Some(2_310),
        stage_ms: [Some(u32::MAX); STAGES],
        last_error: AlertError::BudgetExhausted,
        last_error_stage: Some(AlertStage::ObtainIp),
        last_http_status: Some(429),
        last_message_id: Some(-1),
        probes: 100,
        probes_associated: 99,
        wifi_failure: Some(panweave_hub::protocol::WifiFailure {
            reason: 201,
            rssi: Some(-71),
        }),
        bssid: Some([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]),
        channel: Some(13),
        wpa3_only: true,
    }
}

fn largest_alert_update() -> AlertConfigUpdate {
    AlertConfigUpdate {
        enabled: Some(true),
        kinds: Some(kinds::DEFAULT),
        delay_ms: Some(50_000),
        budget_ms: Some(2_000),
        ssid: Some(HVec::from_slice(&[b's'; MAX_SSID]).unwrap()),
        password: Some(HVec::from_slice(&[b'p'; MAX_WIFI_PASSWORD]).unwrap()),
        token: Some(HVec::from_slice(&[b't'; MAX_BOT_TOKEN]).unwrap()),
        chat_id: Some(HVec::from_slice(&[b'c'; MAX_CHAT_ID]).unwrap()),
        clear_secrets: true,
        bssid: Some(Some([0x02, 0x11, 0x22, 0x33, 0x44, 0x55])),
        channel: Some(Some(13)),
        wpa3_only: Some(true),
    }
}

#[test]
fn the_alert_messages_fit_and_the_status_carries_no_secret_fields() {
    let mut body = [0u8; MAX_BODY];
    let n = Message::Request {
        id: 1,
        request: Request::SetAlertConfig(largest_alert_update()),
    }
    .encode(&mut body)
    .unwrap();
    assert!(n <= MAX_BODY, "{n}");
    // The status of a hub holding a password and a token: neither can
    // appear, the message has no field for them.
    let n = Message::Response {
        id: 1,
        response: Response::AlertStatus(largest_alert_status()),
    }
    .encode(&mut body)
    .unwrap();
    assert!(
        !body[..n]
            .windows(8)
            .any(|w| w == [b'p'; 8] || w == [b't'; 8])
    );
}

fn every_message() -> Vec<Message> {
    let ieee = 0x0011_2233_4455_6677;
    let attr = AttributeData {
        data_type: 0x42,
        raw: HVec::from_slice(&[32; 32]).unwrap(),
    };
    let requests = vec![
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
        Request::Light {
            ieee,
            endpoint: 1,
            command: LightCommand::SetColorTemperature {
                mireds: 370,
                transition_ds: 4,
            },
        },
        Request::Light {
            ieee,
            endpoint: 1,
            command: LightCommand::SetColorXy {
                x: 0x4ccc,
                y: 0xfeff,
                transition_ds: 0,
            },
        },
        Request::Light {
            ieee,
            endpoint: 1,
            command: LightCommand::SetHueSaturation {
                hue: 0xfe,
                saturation: 1,
                transition_ds: 0xffff,
            },
        },
        Request::GetLightColor { ieee },
        Request::AddGroup {
            ieee,
            endpoint: 0,
            group: 0x1234,
        },
        Request::RemoveGroup {
            ieee,
            endpoint: 2,
            group: 0xfff7,
        },
        Request::GroupLight {
            group: 7,
            command: LightCommand::SetBrightness {
                percent: 30,
                transition_ds: 15,
            },
        },
        Request::GroupLight {
            group: 7,
            command: LightCommand::Toggle,
        },
        Request::StoreScene {
            ieee,
            endpoint: 1,
            group: 7,
            scene: 3,
        },
        Request::RecallScene {
            group: 7,
            scene: 3,
            transition_ds: 0,
        },
        Request::OtaOffer(panweave_hub::protocol::OtaOffer {
            image: panweave_hub::protocol::OtaImage {
                manufacturer_code: 0x1234,
                image_type: 0xffff,
                file_version: 0x0102_0304,
                size: 0x0012_3456,
            },
            target: Some(ieee),
            allow_downgrade: true,
        }),
        Request::OtaData {
            offset: 0x0001_0000,
            data: HVec::from_slice(&[0xab; panweave_hub::protocol::MAX_OTA_CHUNK]).unwrap(),
        },
        Request::OtaData {
            offset: 0,
            data: HVec::new(),
        },
        Request::OtaCancel,
        Request::GetOtaStatus,
        Request::GreenPowerCommission { seconds: 180 },
        Request::GreenPowerCommission { seconds: 0 },
        Request::ListGreenPowerDevices { start: 8 },
        Request::RemoveGreenPowerDevice {
            gpd: panweave_hub::protocol::GpdAddress::SrcId(0x8765_4321),
        },
        Request::RemoveGreenPowerDevice {
            gpd: panweave_hub::protocol::GpdAddress::Ieee {
                ieee,
                endpoint: 0xff,
            },
        },
        Request::AddInstallCode {
            ieee,
            code: HVec::from_slice(&[0x5a; panweave_hub::protocol::MAX_INSTALL_CODE]).unwrap(),
        },
        Request::RemoveDevice { ieee, leave: true },
        Request::GetDiagnostics,
        Request::GetBootReport,
        Request::GetRadioDiagnostics,
        Request::GetStorageDiagnostics,
        Request::GetRuntimeDiagnostics,
        Request::GetTraceConfiguration,
        Request::SetTraceConfiguration {
            min_severity: 1,
            categories: 0xffff,
        },
        Request::ReadTrace {
            from: u32::MAX,
            max: 12,
            ieee: Some(ieee),
        },
        Request::ReadTrace {
            from: 0,
            max: 1,
            ieee: None,
        },
        Request::ClearTrace,
        Request::StartCapture {
            seconds: 3600,
            mode: CaptureMode::Raw,
        },
        Request::StopCapture,
        Request::ReadCapture { max: 3 },
        Request::SetKeyExchangeExemption {
            ieee,
            seconds: 3600,
        },
        Request::SetKeyExchangeExemption { ieee, seconds: 0 },
        Request::GetSecurityStatus,
        Request::GetAlertStatus,
        Request::QueueTestAlert,
        Request::RunRadioProbe,
        Request::GetWifiScan,
        Request::SetAlertConfig(AlertConfigUpdate::default()),
        Request::SetAlertConfig(largest_alert_update()),
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
        Event::LightColorChanged {
            ieee: 2,
            color: full_color(),
        },
        Event::OtaDataWanted {
            offset: 512,
            length: 512,
        },
        Event::OtaProgress {
            ieee: 3,
            offset: 150,
            size: 3000,
        },
        Event::OtaFinished {
            ieee: 3,
            status: 0x95,
        },
        Event::GreenPowerCommissioning { seconds: 180 },
        Event::GreenPowerPaired {
            gpd: panweave_hub::protocol::GpdAddress::SrcId(7),
            device_id: 0x02,
        },
        Event::GreenPowerRemoved {
            gpd: panweave_hub::protocol::GpdAddress::Ieee {
                ieee: 9,
                endpoint: 1,
            },
        },
        Event::GreenPowerCommand {
            gpd: panweave_hub::protocol::GpdAddress::SrcId(7),
            command: 0x22,
            payload: HVec::from_slice(&[1; panweave_hub::protocol::MAX_GPD_PAYLOAD]).unwrap(),
        },
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
    for (i, response) in responses
        .into_iter()
        .chain(diagnostic_responses())
        .enumerate()
    {
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

fn full_color() -> panweave_hub::model::ColorState {
    panweave_hub::model::ColorState {
        capabilities: Some(0x1f),
        mireds_min: Some(153),
        mireds_max: Some(500),
        mode: Some(panweave_hub::model::ColorMode::Xy),
        x: Some(0x616b),
        y: Some(0x607d),
        mireds: Some(250),
        hue: Some(0),
        saturation: Some(254),
    }
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
    // The diagnostic pages are sized to fit one frame when full.
    for response in [
        Response::BootReport(largest_boot_report()),
        Response::TracePage(largest_trace_page()),
        Response::CapturePage(largest_capture_page()),
        Response::SecurityStatus(largest_security_status()),
        Response::AlertStatus(largest_alert_status()),
        Response::WifiScan(Some(largest_wifi_scan())),
    ] {
        let n = Message::Response { id: 1, response }
            .encode(&mut body)
            .unwrap();
        assert!(n <= MAX_BODY, "{n}");
    }
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
    // v0.2.1 added requests after the existing tags: none renumbered.
    for (request, tag) in [
        (Request::GetDiagnostics, 0x11),
        (Request::GetBootReport, 0x12),
        (Request::ReadCapture { max: 3 }, 0x1c),
    ] {
        let n = Message::Request { id: 1, request }
            .encode(&mut body)
            .unwrap();
        assert_eq!(body[4], tag);
        assert!(n >= 5);
    }
    let n = Message::Request {
        id: 2,
        request: Request::ReadTrace {
            from: 0x0102_0304,
            max: 12,
            ieee: None,
        },
    }
    .encode(&mut body)
    .unwrap();
    assert_eq!(&body[..n], &[1, 1, 2, 0, 0x18, 4, 3, 2, 1, 12, 0]);
}

#[test]
fn an_older_hub_answers_new_requests_with_unknown_request() {
    // A firmware from before diagnostics decodes the frame header and
    // fails on the tag; its session answers UnknownRequest to the id.
    let mut body = [0u8; MAX_BODY];
    let n = Message::Request {
        id: 9,
        request: Request::GetBootReport,
    }
    .encode(&mut body)
    .unwrap();
    body[4] = 0x7f;
    assert!(matches!(
        Message::decode(&body[..n]),
        Err(ProtocolError::UnknownTag(0x7f))
    ));
}
