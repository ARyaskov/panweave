//! Experimental critical-event notifications (Zigbee → Wi-Fi → Zigbee):
//! status and configuration messages, added after the existing tags.
//!
//! Secrets (the Wi-Fi password and the Telegram bot token) only travel
//! towards the hub, in [`AlertConfigUpdate`]; no response or event ever
//! carries them back: [`AlertStatus`] reports only whether they are set.

use panweave_codec::{CodecError, Reader, Writer};

use super::{ProtocolError, Text, read_bool, read_text, write_text};

/// Longest Wi-Fi SSID (IEEE 802.11).
pub const MAX_SSID: usize = 32;
/// Longest WPA2 passphrase (64 = a raw hexadecimal PSK).
pub const MAX_WIFI_PASSWORD: usize = 64;
/// Longest Telegram bot token accepted.
pub const MAX_BOT_TOKEN: usize = 64;
/// Longest Telegram chat identifier (`-100…` or `@channelname`).
pub const MAX_CHAT_ID: usize = 40;
/// Wi-Fi channels the hub may be pinned to (2.4 GHz; the driver's
/// default country allows 1–13).
pub const WIFI_CHANNELS: core::ops::RangeInclusive<u8> = 1..=13;
/// Number of [`AlertStage`]s.
pub const STAGES: usize = 12;

/// Bounds of the configurable notification check interval.
pub const DELAY_MS: core::ops::RangeInclusive<u32> = 1_000..=3_600_000;
/// Bounds of the configurable Zigbee downtime budget of one attempt.
pub const BUDGET_MS: core::ops::RangeInclusive<u32> = 500..=60_000;

/// [`AlertStatus::kinds`] / [`AlertConfigUpdate::kinds`] bits: which
/// events are queued for notification.
pub mod kinds {
    /// Water leak detected and cleared.
    pub const LEAK: u8 = 1;
    /// Contact opened and closed (batched within a notification interval).
    pub const CONTACT: u8 = 2;
    /// Tamper detected.
    pub const TAMPER: u8 = 4;
    /// Battery low.
    pub const BATTERY_LOW: u8 = 8;
    /// Every kind.
    pub const ALL: u8 = LEAK | CONTACT | TAMPER | BATTERY_LOW;
    /// The default: door changes and leak alarms/recoveries.
    pub const DEFAULT: u8 = LEAK | CONTACT;
}

/// What happened at a sensor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AlertKind {
    /// Water detected.
    WaterLeak,
    /// Water no longer detected.
    WaterLeakCleared,
    /// A contact opened.
    ContactOpened,
    /// A contact closed.
    ContactClosed,
    /// Tamper switch triggered.
    Tamper,
    /// Battery low.
    BatteryLow,
    /// A test notification an administrator queued.
    Test,
}

impl AlertKind {
    /// The wire / storage code.
    pub const fn code(self) -> u8 {
        match self {
            AlertKind::WaterLeak => 1,
            AlertKind::WaterLeakCleared => 2,
            AlertKind::ContactOpened => 3,
            AlertKind::ContactClosed => 4,
            AlertKind::Tamper => 5,
            AlertKind::BatteryLow => 6,
            AlertKind::Test => 7,
        }
    }

    /// The value of a code.
    pub const fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            1 => AlertKind::WaterLeak,
            2 => AlertKind::WaterLeakCleared,
            3 => AlertKind::ContactOpened,
            4 => AlertKind::ContactClosed,
            5 => AlertKind::Tamper,
            6 => AlertKind::BatteryLow,
            7 => AlertKind::Test,
            _ => return None,
        })
    }

    /// The sentence a notification starts with.
    pub const fn sentence(self) -> &'static str {
        match self {
            AlertKind::WaterLeak => "Water leak detected.",
            AlertKind::WaterLeakCleared => "Water leak cleared.",
            AlertKind::ContactOpened => "Contact opened.",
            AlertKind::ContactClosed => "Contact closed.",
            AlertKind::Tamper => "Tamper detected.",
            AlertKind::BatteryLow => "Battery low.",
            AlertKind::Test => "Test notification.",
        }
    }

    /// The [`kinds`] bit that enables it (`0`: always enabled).
    pub const fn kind_bit(self) -> u8 {
        match self {
            AlertKind::WaterLeak | AlertKind::WaterLeakCleared => kinds::LEAK,
            AlertKind::ContactOpened | AlertKind::ContactClosed => kinds::CONTACT,
            AlertKind::Tamper => kinds::TAMPER,
            AlertKind::BatteryLow => kinds::BATTERY_LOW,
            AlertKind::Test => 0,
        }
    }

    /// Whether the kind is an alarm (as opposed to a recovery).
    pub const fn is_alarm(self) -> bool {
        matches!(
            self,
            AlertKind::WaterLeak
                | AlertKind::ContactOpened
                | AlertKind::Tamper
                | AlertKind::BatteryLow
        )
    }
}

/// Where the notification machinery is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AlertState {
    /// The experimental mode is off (the default).
    Disabled,
    /// On, but Wi-Fi or Telegram settings are missing; events are still
    /// queued.
    NotConfigured,
    /// Zigbee operational, nothing pending.
    ZigbeeOperational,
    /// Events pending, waiting for the first delivery attempt.
    WaitingForDelivery,
    /// The radio is being handed from IEEE 802.15.4 to Wi-Fi.
    SwitchingToWifi,
    /// Wi-Fi connection and the Telegram request.
    ConnectingAndTransmitting,
    /// The radio is being handed back to IEEE 802.15.4.
    ReturningToZigbee,
    /// The last attempt failed; another is scheduled.
    RetryScheduled,
    /// IEEE 802.15.4 reception could not be restored after an attempt.
    RadioRestoreFailed,
    /// The firmware has no radio-switching support (built without it).
    Unsupported,
}

impl AlertState {
    /// The wire code.
    pub const fn code(self) -> u8 {
        match self {
            AlertState::Disabled => 0,
            AlertState::NotConfigured => 1,
            AlertState::ZigbeeOperational => 2,
            AlertState::WaitingForDelivery => 3,
            AlertState::SwitchingToWifi => 4,
            AlertState::ConnectingAndTransmitting => 5,
            AlertState::ReturningToZigbee => 6,
            AlertState::RetryScheduled => 7,
            AlertState::RadioRestoreFailed => 8,
            AlertState::Unsupported => 9,
        }
    }

    /// The value of a code (unknown codes read as
    /// [`AlertState::Unsupported`]).
    pub const fn from_code(c: u8) -> Self {
        match c {
            0 => AlertState::Disabled,
            1 => AlertState::NotConfigured,
            2 => AlertState::ZigbeeOperational,
            3 => AlertState::WaitingForDelivery,
            4 => AlertState::SwitchingToWifi,
            5 => AlertState::ConnectingAndTransmitting,
            6 => AlertState::ReturningToZigbee,
            7 => AlertState::RetryScheduled,
            8 => AlertState::RadioRestoreFailed,
            _ => AlertState::Unsupported,
        }
    }

    /// A short name.
    pub const fn name(self) -> &'static str {
        match self {
            AlertState::Disabled => "disabled",
            AlertState::NotConfigured => "not-configured",
            AlertState::ZigbeeOperational => "zigbee-operational",
            AlertState::WaitingForDelivery => "waiting-for-delivery",
            AlertState::SwitchingToWifi => "switching-to-wifi",
            AlertState::ConnectingAndTransmitting => "connecting-and-transmitting",
            AlertState::ReturningToZigbee => "returning-to-zigbee",
            AlertState::RetryScheduled => "retry-scheduled",
            AlertState::RadioRestoreFailed => "radio-restore-failed",
            AlertState::Unsupported => "unsupported",
        }
    }
}

/// A step of one delivery attempt, in order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AlertStage {
    /// Stopping IEEE 802.15.4 reception and releasing the radio.
    StopZigbee,
    /// Wi-Fi driver start.
    WifiStart,
    /// Survey of the access points in range (radio-switch experiment
    /// only; a delivery does not scan).
    Scan,
    /// Scan, association and WPA2 handshake.
    Associate,
    /// DHCP (or the static address).
    ObtainIp,
    /// DNS resolution of the API host.
    Resolve,
    /// TCP connection.
    Connect,
    /// TLS handshake with certificate and host name verification.
    Tls,
    /// Sending the HTTP request.
    Request,
    /// Receiving the HTTP response.
    Response,
    /// Wi-Fi shutdown.
    WifiStop,
    /// Restoring IEEE 802.15.4 reception.
    RestoreZigbee,
}

impl AlertStage {
    /// Every stage, in order.
    pub const ALL: [AlertStage; STAGES] = [
        AlertStage::StopZigbee,
        AlertStage::WifiStart,
        AlertStage::Scan,
        AlertStage::Associate,
        AlertStage::ObtainIp,
        AlertStage::Resolve,
        AlertStage::Connect,
        AlertStage::Tls,
        AlertStage::Request,
        AlertStage::Response,
        AlertStage::WifiStop,
        AlertStage::RestoreZigbee,
    ];

    /// The index of the stage (also its wire code).
    pub const fn index(self) -> usize {
        match self {
            AlertStage::StopZigbee => 0,
            AlertStage::WifiStart => 1,
            AlertStage::Scan => 2,
            AlertStage::Associate => 3,
            AlertStage::ObtainIp => 4,
            AlertStage::Resolve => 5,
            AlertStage::Connect => 6,
            AlertStage::Tls => 7,
            AlertStage::Request => 8,
            AlertStage::Response => 9,
            AlertStage::WifiStop => 10,
            AlertStage::RestoreZigbee => 11,
        }
    }

    /// The stage of an index.
    pub const fn from_index(i: u8) -> Option<Self> {
        if (i as usize) < STAGES {
            Some(Self::ALL[i as usize])
        } else {
            None
        }
    }

    /// A short name.
    pub const fn name(self) -> &'static str {
        match self {
            AlertStage::StopZigbee => "stop-zigbee",
            AlertStage::WifiStart => "wifi-start",
            AlertStage::Scan => "scan",
            AlertStage::Associate => "associate",
            AlertStage::ObtainIp => "obtain-ip",
            AlertStage::Resolve => "dns",
            AlertStage::Connect => "tcp",
            AlertStage::Tls => "tls",
            AlertStage::Request => "request",
            AlertStage::Response => "response",
            AlertStage::WifiStop => "wifi-stop",
            AlertStage::RestoreZigbee => "restore-zigbee",
        }
    }
}

/// Why the last attempt did not deliver.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AlertError {
    /// No error.
    None,
    /// A stage failed (the stage says which: access point, DHCP, DNS,
    /// TCP, TLS…).
    StageFailed,
    /// The shared deadline expired: the attempt was cancelled.
    BudgetExhausted,
    /// The request was sent but no complete response arrived: Telegram
    /// may have published the message (a later message repeats the
    /// events, marked as a possible repeat).
    Ambiguous,
    /// Telegram answered 429 (`retry_after` honoured).
    RateLimited,
    /// Telegram refused the request (wrong token, chat, permissions).
    Rejected,
    /// The response could not be understood.
    BadResponse,
    /// IEEE 802.15.4 reception could not be restored.
    RadioRestore,
    /// The queue could not be written to flash.
    Storage,
}

impl AlertError {
    /// The wire code.
    pub const fn code(self) -> u8 {
        match self {
            AlertError::None => 0,
            AlertError::StageFailed => 1,
            AlertError::BudgetExhausted => 2,
            AlertError::Ambiguous => 3,
            AlertError::RateLimited => 4,
            AlertError::Rejected => 5,
            AlertError::BadResponse => 6,
            AlertError::RadioRestore => 7,
            AlertError::Storage => 8,
        }
    }

    /// The value of a code (unknown codes read as
    /// [`AlertError::BadResponse`]).
    pub const fn from_code(c: u8) -> Self {
        match c {
            0 => AlertError::None,
            1 => AlertError::StageFailed,
            2 => AlertError::BudgetExhausted,
            3 => AlertError::Ambiguous,
            4 => AlertError::RateLimited,
            5 => AlertError::Rejected,
            7 => AlertError::RadioRestore,
            8 => AlertError::Storage,
            _ => AlertError::BadResponse,
        }
    }

    /// A short name.
    pub const fn name(self) -> &'static str {
        match self {
            AlertError::None => "none",
            AlertError::StageFailed => "stage-failed",
            AlertError::BudgetExhausted => "budget-exhausted",
            AlertError::Ambiguous => "ambiguous",
            AlertError::RateLimited => "rate-limited",
            AlertError::Rejected => "rejected",
            AlertError::BadResponse => "bad-response",
            AlertError::RadioRestore => "radio-restore",
            AlertError::Storage => "storage",
        }
    }
}

/// The notification machinery's state, without secrets.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AlertStatus {
    /// Current state.
    pub state: AlertState,
    /// The experimental mode is enabled.
    pub enabled: bool,
    /// Wi-Fi SSID (empty when unset).
    pub ssid: Text<MAX_SSID>,
    /// A Wi-Fi password is stored (its value is never reported).
    pub password_set: bool,
    /// A bot token is stored (its value is never reported).
    pub token_set: bool,
    /// Telegram chat identifier (empty when unset).
    pub chat_id: Text<MAX_CHAT_ID>,
    /// Which events are queued ([`kinds`]).
    pub kinds: u8,
    /// Notification check interval (legacy field name).
    pub delay_ms: u32,
    /// Zigbee downtime budget of one attempt.
    pub budget_ms: u32,
    /// Minimum Zigbee operation between two attempts.
    pub min_zigbee_ms: u32,
    /// This boot's identifier.
    pub boot_id: u32,
    /// Events waiting for delivery.
    pub queue_depth: u8,
    /// Queue capacity.
    pub queue_capacity: u8,
    /// Events that found the queue full (never stored).
    pub overflowed: u32,
    /// Milliseconds until the next attempt, when one is scheduled.
    pub next_attempt_ms: Option<u32>,
    /// Attempts started.
    pub attempts: u32,
    /// Attempts that ended with `ok = true`.
    pub successes: u32,
    /// Attempts that failed (any reason).
    pub failures: u32,
    /// Attempts whose outcome was ambiguous.
    pub ambiguous: u32,
    /// Attempts whose Zigbee downtime exceeded the budget.
    pub budget_overruns: u32,
    /// Attempts after which Zigbee reception could not be restored.
    pub restore_failures: u32,
    /// Zigbee downtime of the last attempt.
    pub last_downtime_ms: Option<u32>,
    /// Longest Zigbee downtime since boot.
    pub max_downtime_ms: Option<u32>,
    /// Duration of each stage in the last attempt (`None`: not reached).
    pub stage_ms: [Option<u32>; STAGES],
    /// Last error.
    pub last_error: AlertError,
    /// Stage of the last error.
    pub last_error_stage: Option<AlertStage>,
    /// HTTP status of the last response.
    pub last_http_status: Option<u16>,
    /// `message_id` of the last delivered message.
    pub last_message_id: Option<i64>,
    /// Radio-switch experiments run (`RunRadioProbe`).
    pub probes: u32,
    /// Of them, those that joined the access point.
    pub probes_associated: u32,
    /// Why the last attempt (delivery or probe) that tried to join the
    /// access point did not: the Wi-Fi driver's disconnect reason (IEEE
    /// 802.11 reason codes below 200; 200–212 are the ESP-IDF driver's:
    /// 201 no access point found, 202 authentication failed, 204
    /// handshake timeout, 210/211 no access point with compatible
    /// security), and the access point's signal in dBm when the driver
    /// reports one. `None` after a join, or when the failure carried no
    /// reason.
    pub wifi_failure: Option<WifiFailure>,
    /// The access point the hub is pinned to (`None`: any with the SSID).
    pub bssid: Option<[u8; 6]>,
    /// The channel the hub is pinned to (`None`: all are scanned).
    pub channel: Option<u8>,
    /// Only WPA3-Personal (SAE) access points are joined.
    pub wpa3_only: bool,
}

/// Access points listed in [`WifiScan::strongest`].
pub const MAX_SCAN_ENTRIES: usize = 6;

/// Security of an access point, as a scan reports it ([`ScanEntry::auth`]).
pub mod auth {
    /// Open.
    pub const OPEN: u8 = 0;
    /// WEP.
    pub const WEP: u8 = 1;
    /// WPA-Personal.
    pub const WPA: u8 = 2;
    /// WPA2-Personal.
    pub const WPA2: u8 = 3;
    /// WPA/WPA2-Personal.
    pub const WPA_WPA2: u8 = 4;
    /// WPA2-Enterprise.
    pub const WPA2_ENTERPRISE: u8 = 5;
    /// WPA3-Personal (SAE).
    pub const WPA3: u8 = 6;
    /// WPA2/WPA3-Personal (transition mode).
    pub const WPA2_WPA3: u8 = 7;
    /// Another method (WAPI, OWE, WPA3-Enterprise…).
    pub const OTHER: u8 = 8;
    /// Not reported.
    pub const UNKNOWN: u8 = 0xFF;

    /// A short name.
    pub const fn name(code: u8) -> &'static str {
        match code {
            OPEN => "open",
            WEP => "WEP",
            WPA => "WPA",
            WPA2 => "WPA2",
            WPA_WPA2 => "WPA/WPA2",
            WPA2_ENTERPRISE => "WPA2-Enterprise",
            WPA3 => "WPA3",
            WPA2_WPA3 => "WPA2/WPA3",
            OTHER => "other",
            _ => "unknown",
        }
    }
}

/// An access point heard by a scan.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ScanEntry {
    /// Its SSID (empty: hidden).
    pub ssid: Text<MAX_SSID>,
    /// Its BSSID (the access point's MAC address).
    pub bssid: [u8; 6],
    /// Channel.
    pub channel: u8,
    /// Signal, dBm.
    pub rssi: i8,
    /// Security ([`auth`]).
    pub auth: u8,
}

/// What the last radio-switch experiment heard (`GetWifiScan`).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct WifiScan {
    /// Duration of the scan, milliseconds.
    pub scan_ms: u32,
    /// Access points heard (all of them, not only the listed ones).
    pub seen: u16,
    /// The strongest one with the configured SSID, when heard.
    pub target: Option<ScanEntry>,
    /// The strongest access points, strongest first.
    pub strongest: heapless::Vec<ScanEntry, MAX_SCAN_ENTRIES>,
}

fn write_scan_entry(w: &mut Writer<'_>, e: &ScanEntry) -> Result<(), CodecError> {
    write_text(w, &e.ssid)?;
    w.bytes(&e.bssid)?;
    w.u8(e.channel)?;
    #[allow(clippy::cast_sign_loss)]
    w.u8(e.rssi as u8)?;
    w.u8(e.auth)
}

fn read_scan_entry(r: &mut Reader<'_>) -> Result<ScanEntry, ProtocolError> {
    let ssid = read_text(r)?;
    let bssid = read_mac(r)?;
    let channel = r.u8()?;
    #[allow(clippy::cast_possible_wrap)]
    let rssi = r.u8()? as i8;
    Ok(ScanEntry {
        ssid,
        bssid,
        channel,
        rssi,
        auth: r.u8()?,
    })
}

fn read_mac(r: &mut Reader<'_>) -> Result<[u8; 6], ProtocolError> {
    r.bytes(6)?.try_into().map_err(|_| ProtocolError::Malformed)
}

/// Encodes an optional [`WifiScan`] (`None`: no experiment has scanned
/// since boot).
pub(crate) fn write_scan(w: &mut Writer<'_>, s: Option<&WifiScan>) -> Result<(), CodecError> {
    let Some(s) = s else {
        return w.u8(0);
    };
    w.u8(1)?;
    w.u32_le(s.scan_ms)?;
    w.u16_le(s.seen)?;
    match &s.target {
        Some(t) => {
            w.u8(1)?;
            write_scan_entry(w, t)?;
        }
        None => w.u8(0)?,
    }
    w.u8(u8::try_from(s.strongest.len())
        .map_err(|_| CodecError::Unrepresentable { field: "count" })?)?;
    for e in &s.strongest {
        write_scan_entry(w, e)?;
    }
    Ok(())
}

/// Decodes [`write_scan`].
pub(crate) fn read_scan(r: &mut Reader<'_>) -> Result<Option<WifiScan>, ProtocolError> {
    if !read_bool(r)? {
        return Ok(None);
    }
    let scan_ms = r.u32_le()?;
    let seen = r.u16_le()?;
    let target = if read_bool(r)? {
        Some(read_scan_entry(r)?)
    } else {
        None
    };
    let n = r.u8()?;
    let mut strongest = heapless::Vec::new();
    for _ in 0..n {
        strongest
            .push(read_scan_entry(r)?)
            .map_err(|_| ProtocolError::Malformed)?;
    }
    Ok(Some(WifiScan {
        scan_ms,
        seen,
        target,
        strongest,
    }))
}

/// A failed join, as reported by the Wi-Fi driver.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WifiFailure {
    /// Disconnect reason code.
    pub reason: u16,
    /// Signal of the access point, dBm (`None`: not reported).
    pub rssi: Option<i8>,
}

impl Default for AlertStatus {
    fn default() -> Self {
        AlertStatus {
            state: AlertState::Disabled,
            enabled: false,
            ssid: Text::new(),
            password_set: false,
            token_set: false,
            chat_id: Text::new(),
            kinds: 0,
            delay_ms: 0,
            budget_ms: 0,
            min_zigbee_ms: 0,
            boot_id: 0,
            queue_depth: 0,
            queue_capacity: 0,
            overflowed: 0,
            next_attempt_ms: None,
            attempts: 0,
            successes: 0,
            failures: 0,
            ambiguous: 0,
            budget_overruns: 0,
            restore_failures: 0,
            last_downtime_ms: None,
            max_downtime_ms: None,
            stage_ms: [None; STAGES],
            last_error: AlertError::None,
            last_error_stage: None,
            last_http_status: None,
            last_message_id: None,
            probes: 0,
            probes_associated: 0,
            wifi_failure: None,
            bssid: None,
            channel: None,
            wpa3_only: false,
        }
    }
}

/// A configuration change: every `None` keeps the stored value.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct AlertConfigUpdate {
    /// Turn the experimental mode on or off.
    pub enabled: Option<bool>,
    /// Which events are queued ([`kinds`]).
    pub kinds: Option<u8>,
    /// Notification check interval ([`DELAY_MS`], legacy field name).
    pub delay_ms: Option<u32>,
    /// Zigbee downtime budget ([`BUDGET_MS`]).
    pub budget_ms: Option<u32>,
    /// Wi-Fi SSID.
    pub ssid: Option<Text<MAX_SSID>>,
    /// Wi-Fi password (write only).
    pub password: Option<Text<MAX_WIFI_PASSWORD>>,
    /// Telegram bot token (write only).
    pub token: Option<Text<MAX_BOT_TOKEN>>,
    /// Telegram chat identifier.
    pub chat_id: Option<Text<MAX_CHAT_ID>>,
    /// Erase the stored password and token first.
    pub clear_secrets: bool,
    /// Pin the access point by BSSID (`Some(None)` removes the pin).
    pub bssid: Option<Option<[u8; 6]>>,
    /// Pin the channel ([`WIFI_CHANNELS`]; `Some(None)` removes the pin).
    pub channel: Option<Option<u8>>,
    /// Join only WPA3-Personal access points.
    pub wpa3_only: Option<bool>,
}

fn write_opt_u32(w: &mut Writer<'_>, v: Option<u32>) -> Result<(), CodecError> {
    match v {
        Some(x) => {
            w.u8(1)?;
            w.u32_le(x)
        }
        None => w.u8(0),
    }
}

fn read_opt_u32(r: &mut Reader<'_>) -> Result<Option<u32>, ProtocolError> {
    Ok(if read_bool(r)? {
        Some(r.u32_le()?)
    } else {
        None
    })
}

fn write_opt_text<const N: usize>(
    w: &mut Writer<'_>,
    v: Option<&Text<N>>,
) -> Result<(), CodecError> {
    match v {
        Some(t) => {
            w.u8(1)?;
            write_text(w, t)
        }
        None => w.u8(0),
    }
}

fn read_opt_text<const N: usize>(r: &mut Reader<'_>) -> Result<Option<Text<N>>, ProtocolError> {
    Ok(if read_bool(r)? {
        Some(read_text(r)?)
    } else {
        None
    })
}

pub(crate) fn write_update(w: &mut Writer<'_>, u: &AlertConfigUpdate) -> Result<(), CodecError> {
    match u.enabled {
        Some(e) => {
            w.u8(1)?;
            w.u8(u8::from(e))?;
        }
        None => w.u8(0)?,
    }
    match u.kinds {
        Some(k) => {
            w.u8(1)?;
            w.u8(k)?;
        }
        None => w.u8(0)?,
    }
    write_opt_u32(w, u.delay_ms)?;
    write_opt_u32(w, u.budget_ms)?;
    write_opt_text(w, u.ssid.as_ref())?;
    write_opt_text(w, u.password.as_ref())?;
    write_opt_text(w, u.token.as_ref())?;
    write_opt_text(w, u.chat_id.as_ref())?;
    w.u8(u8::from(u.clear_secrets))?;
    // 0 keeps, 1 removes, 2 sets.
    match u.bssid {
        None => w.u8(0)?,
        Some(None) => w.u8(1)?,
        Some(Some(m)) => {
            w.u8(2)?;
            w.bytes(&m)?;
        }
    }
    match u.channel {
        None => w.u8(0)?,
        Some(None) => w.u8(1)?,
        Some(Some(c)) => {
            w.u8(2)?;
            w.u8(c)?;
        }
    }
    w.u8(match u.wpa3_only {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    })
}

pub(crate) fn read_update(r: &mut Reader<'_>) -> Result<AlertConfigUpdate, ProtocolError> {
    let enabled = if read_bool(r)? {
        Some(read_bool(r)?)
    } else {
        None
    };
    let kinds = if read_bool(r)? { Some(r.u8()?) } else { None };
    Ok(AlertConfigUpdate {
        enabled,
        kinds,
        delay_ms: read_opt_u32(r)?,
        budget_ms: read_opt_u32(r)?,
        ssid: read_opt_text(r)?,
        password: read_opt_text(r)?,
        token: read_opt_text(r)?,
        chat_id: read_opt_text(r)?,
        clear_secrets: read_bool(r)?,
        bssid: match r.u8()? {
            0 => None,
            1 => Some(None),
            2 => Some(Some(read_mac(r)?)),
            _ => return Err(ProtocolError::Malformed),
        },
        channel: match r.u8()? {
            0 => None,
            1 => Some(None),
            2 => Some(Some(r.u8()?)),
            _ => return Err(ProtocolError::Malformed),
        },
        wpa3_only: match r.u8()? {
            0 => None,
            1 => Some(false),
            2 => Some(true),
            _ => return Err(ProtocolError::Malformed),
        },
    })
}

pub(crate) fn write_status(w: &mut Writer<'_>, s: &AlertStatus) -> Result<(), CodecError> {
    w.u8(s.state.code())?;
    w.u8(u8::from(s.enabled))?;
    write_text(w, &s.ssid)?;
    w.u8(u8::from(s.password_set))?;
    w.u8(u8::from(s.token_set))?;
    write_text(w, &s.chat_id)?;
    w.u8(s.kinds)?;
    w.u32_le(s.delay_ms)?;
    w.u32_le(s.budget_ms)?;
    w.u32_le(s.min_zigbee_ms)?;
    w.u32_le(s.boot_id)?;
    w.u8(s.queue_depth)?;
    w.u8(s.queue_capacity)?;
    w.u32_le(s.overflowed)?;
    write_opt_u32(w, s.next_attempt_ms)?;
    for v in [
        s.attempts,
        s.successes,
        s.failures,
        s.ambiguous,
        s.budget_overruns,
        s.restore_failures,
    ] {
        w.u32_le(v)?;
    }
    write_opt_u32(w, s.last_downtime_ms)?;
    write_opt_u32(w, s.max_downtime_ms)?;
    for v in s.stage_ms {
        write_opt_u32(w, v)?;
    }
    w.u8(s.last_error.code())?;
    match s.last_error_stage {
        Some(st) => {
            w.u8(1)?;
            #[allow(clippy::cast_possible_truncation)]
            w.u8(st.index() as u8)?;
        }
        None => w.u8(0)?,
    }
    match s.last_http_status {
        Some(h) => {
            w.u8(1)?;
            w.u16_le(h)?;
        }
        None => w.u8(0)?,
    }
    match s.last_message_id {
        Some(m) => {
            w.u8(1)?;
            #[allow(clippy::cast_sign_loss)]
            w.u64_le(m as u64)?;
        }
        None => w.u8(0)?,
    }
    w.u32_le(s.probes)?;
    w.u32_le(s.probes_associated)?;
    match s.wifi_failure {
        Some(f) => {
            w.u8(1)?;
            w.u16_le(f.reason)?;
            match f.rssi {
                Some(r) => {
                    w.u8(1)?;
                    #[allow(clippy::cast_sign_loss)]
                    w.u8(r as u8)?;
                }
                None => w.u8(0)?,
            }
        }
        None => w.u8(0)?,
    }
    match s.bssid {
        Some(m) => {
            w.u8(1)?;
            w.bytes(&m)?;
        }
        None => w.u8(0)?,
    }
    w.u8(s.channel.unwrap_or(0))?;
    w.u8(u8::from(s.wpa3_only))
}

pub(crate) fn read_status(r: &mut Reader<'_>) -> Result<AlertStatus, ProtocolError> {
    let mut s = AlertStatus {
        state: AlertState::from_code(r.u8()?),
        enabled: read_bool(r)?,
        ssid: read_text(r)?,
        password_set: read_bool(r)?,
        token_set: read_bool(r)?,
        chat_id: read_text(r)?,
        kinds: r.u8()?,
        delay_ms: r.u32_le()?,
        budget_ms: r.u32_le()?,
        min_zigbee_ms: r.u32_le()?,
        boot_id: r.u32_le()?,
        queue_depth: r.u8()?,
        queue_capacity: r.u8()?,
        overflowed: r.u32_le()?,
        next_attempt_ms: read_opt_u32(r)?,
        attempts: r.u32_le()?,
        successes: r.u32_le()?,
        failures: r.u32_le()?,
        ambiguous: r.u32_le()?,
        budget_overruns: r.u32_le()?,
        restore_failures: r.u32_le()?,
        last_downtime_ms: read_opt_u32(r)?,
        max_downtime_ms: read_opt_u32(r)?,
        ..AlertStatus::default()
    };
    for v in &mut s.stage_ms {
        *v = read_opt_u32(r)?;
    }
    s.last_error = AlertError::from_code(r.u8()?);
    s.last_error_stage = if read_bool(r)? {
        Some(AlertStage::from_index(r.u8()?).ok_or(ProtocolError::Malformed)?)
    } else {
        None
    };
    s.last_http_status = if read_bool(r)? {
        Some(r.u16_le()?)
    } else {
        None
    };
    s.last_message_id = if read_bool(r)? {
        #[allow(clippy::cast_possible_wrap)]
        Some(r.u64_le()? as i64)
    } else {
        None
    };
    s.probes = r.u32_le()?;
    s.probes_associated = r.u32_le()?;
    s.wifi_failure = if read_bool(r)? {
        let reason = r.u16_le()?;
        #[allow(clippy::cast_possible_wrap)]
        let rssi = if read_bool(r)? {
            Some(r.u8()? as i8)
        } else {
            None
        };
        Some(WifiFailure { reason, rssi })
    } else {
        None
    };
    s.bssid = if read_bool(r)? {
        Some(read_mac(r)?)
    } else {
        None
    };
    s.channel = Some(r.u8()?).filter(|c| *c != 0);
    s.wpa3_only = read_bool(r)?;
    Ok(s)
}
