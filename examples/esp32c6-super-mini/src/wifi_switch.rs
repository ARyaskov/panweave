//! **EXPERIMENTAL** (feature `wifi-alerts`, built only by
//! `examples/esp32c6-wifi-alerts`): lending the one radio of the ESP32-C6
//! from IEEE 802.15.4 to Wi-Fi and back, and the network part of a
//! Telegram delivery, for `panweave_hub::alert::attempt`
//! (docs/esp32c6-wifi-alerts.md).
//!
//! Contract with the patched `esp-radio` (its `PANWEAVE-PATCH.md`): the
//! 802.15.4 driver and the Wi-Fi controller are never alive at the same
//! time. [`ZigbeeSwitch::suspend_zigbee`] drops the 802.15.4 driver
//! before [`WifiNetwork::wifi_start`] creates the controller, and
//! [`WifiNetwork::wifi_stop`] drops the controller before
//! [`ZigbeeSwitch::resume_zigbee`] re-creates the 802.15.4 driver —
//! `attempt::run` calls them in that order and always calls both
//! `wifi_stop` and `resume_zigbee`.
//!
//! The network stages are `embassy-net` (DHCP, DNS, TCP) and
//! `embedded-tls` (TLS 1.3), driven from the hub's main task: each stage
//! polls its operation and the network stack's runner until it completes
//! or `deadline.network_end` passes, pausing 1 ms between polls so that
//! the Wi-Fi tasks run.

use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use embassy_net::dns::DnsQueryType;
use embassy_net::tcp::TcpSocket;
use embassy_net::{IpAddress, IpEndpoint, Runner, Stack, StackResources};
use embedded_tls::pki::CertVerifier;
use embedded_tls::{
    Aes128GcmSha256, Certificate, CertificateEntryRef, CertificateRef, CertificateVerifyRef,
    CryptoProvider, NoClock, TlsConfig, TlsConnection, TlsContext, TlsError, TlsVerifier,
};
use esp_hal::peripherals::WIFI;
use esp_hal::rng::Trng;
use esp_radio::wifi::ap::AccessPointInfo;
use esp_radio::wifi::scan::{ScanConfig, ScanTypeConfig};
use esp_radio::wifi::sta::StationConfig;
use esp_radio::wifi::{
    AuthenticationMethod, AuthenticationMethodConfig, Config, ConnectionError, ControllerConfig,
    DisconnectReason, Interface, Password, Ssid, WifiController,
};
use panweave_hub::alert::attempt::{
    Clock, Deadline, NetError, Network, RadioSwitch, RadioSwitchError,
};
use panweave_hub::protocol::alerts::{MAX_SCAN_ENTRIES, auth};
use panweave_hub::protocol::{ScanEntry, WifiFailure, WifiScan};

use crate::hub::Watchdog;
use crate::radio::Radio;
use panweave_hub::boot::StartupStage;

/// The only trust anchor: Go Daddy Root Certificate Authority - G2 (DER;
/// SHA-256 `45140B32…9198EDA`, valid until 2037-12-31), which signs the
/// chain of `api.telegram.org`.
const ROOT_CA: &[u8] = include_bytes!("godaddy-root-g2.der");

/// The largest TLS record (2^14 octets of plaintext plus the expansion
/// TLS 1.3 allows): the server's records are read whole.
const TLS_READ: usize = 16_640;
/// TLS records written: the request is split into records of this size.
const TLS_WRITE: usize = 4096;
/// Largest leaf certificate kept between the certificate and its
/// signature check (the Telegram leaf is 1 698 octets).
const CERT_SIZE: usize = 4096;

/// The attempt's clock: milliseconds since boot. Every reading feeds the
/// watchdog, so an attempt longer than the watchdog period does not
/// reset the chip while it makes progress — and a driver call that
/// blocks for longer still does.
pub struct FirmwareClock<'a> {
    /// The hub's watchdog.
    pub watchdog: &'a Watchdog,
}

impl Clock for FirmwareClock<'_> {
    fn now_ms(&mut self) -> u64 {
        self.watchdog.feed_shared();
        crate::now().as_millis()
    }
}

/// The 802.15.4 side of the hand-over.
pub struct ZigbeeSwitch<'a>(pub &'a mut Radio);

impl RadioSwitch for ZigbeeSwitch<'_> {
    fn suspend_zigbee(&mut self) -> Result<(), RadioSwitchError> {
        self.0.suspend();
        Ok(())
    }

    fn resume_zigbee(&mut self) -> Result<(), RadioSwitchError> {
        self.0.resume();
        if self.0.is_active() {
            crate::startup::mark(StartupStage::Ready);
            Ok(())
        } else {
            Err(RadioSwitchError)
        }
    }
}

/// The memory of the network stack, kept by the caller for the
/// firmware's life and lent to each attempt (about 27 KiB; it lives on
/// the main stack, not in the heap Wi-Fi uses).
pub struct NetBuffers {
    /// Sockets: DHCP, DNS, TCP.
    resources: StackResources<3>,
    tcp_rx: [u8; 4096],
    tcp_tx: [u8; 2048],
    tls_read: [u8; TLS_READ],
    tls_write: [u8; TLS_WRITE],
}

impl NetBuffers {
    /// Empty buffers.
    pub const fn new() -> Self {
        NetBuffers {
            resources: StackResources::new(),
            tcp_rx: [0; 4096],
            tcp_tx: [0; 2048],
            tls_read: [0; TLS_READ],
            tls_write: [0; TLS_WRITE],
        }
    }
}

impl NetBuffers {
    /// Zeroes the TLS and TCP buffers: after a delivery they hold the
    /// request, bot token included, in plaintext.
    pub fn wipe(&mut self) {
        panweave_hub::alert::telegram::wipe(&mut self.tls_write);
        panweave_hub::alert::telegram::wipe(&mut self.tls_read);
        panweave_hub::alert::telegram::wipe(&mut self.tcp_tx);
        panweave_hub::alert::telegram::wipe(&mut self.tcp_rx);
    }
}

impl Default for NetBuffers {
    fn default() -> Self {
        Self::new()
    }
}

/// The driver's reason as its numeric code (IEEE 802.11 reason codes,
/// 200–212 ESP-IDF's own; esp-radio maps them to `DisconnectReason`
/// without a way back).
fn reason_code(reason: DisconnectReason) -> u16 {
    use DisconnectReason as R;
    match reason {
        R::Unspecified => 1,
        R::AuthenticationExpired => 2,
        R::AuthenticationLeave => 3,
        R::DisassociatedDueToInactivity => 4,
        R::AssociationTooMany => 5,
        R::Class2FrameFromNonAuthenticatedStation => 6,
        R::Class3FrameFromNonAssociatedStation => 7,
        R::AssociationLeave => 8,
        R::AssociationNotAuthenticated => 9,
        R::DisassociatedPowerCapabilityBad => 10,
        R::DisassociatedUnsupportedChannel => 11,
        R::BssTransitionDisassociated => 12,
        R::IeInvalid => 13,
        R::MicFailure => 14,
        R::FourWayHandshakeTimeout => 15,
        R::GroupKeyUpdateTimeout => 16,
        R::IeIn4wayDiffers => 17,
        R::GroupCipherInvalid => 18,
        R::PairwiseCipherInvalid => 19,
        R::AkmpInvalid => 20,
        R::UnsupportedRsnIeVersion => 21,
        R::InvalidRsnIeCapabilities => 22,
        R::_802_1xAuthenticationFailed => 23,
        R::CipherSuiteRejected => 24,
        R::TdlsPeerUnreachable => 25,
        R::TdlsUnspecified => 26,
        R::SspRequestedDisassociation => 27,
        R::NoSspRoamingAgreement => 28,
        R::BadCipherOrAkm => 29,
        R::NotAuthorizedThisLocation => 30,
        R::ServiceChangePercludesTs => 31,
        R::UnspecifiedQos => 32,
        R::NotEnoughBandwidth => 33,
        R::MissingAcks => 34,
        R::ExceededTxOp => 35,
        R::StationLeaving => 36,
        R::EndBlockAck => 37,
        R::UnknownBlockAck => 38,
        R::Timeout => 39,
        R::PeerInitiated => 46,
        R::AccessPointInitiatedDisassociation => 47,
        R::InvalidFtActionFrameCount => 48,
        R::InvalidPmkid => 49,
        R::InvalidMde => 50,
        R::InvalidFte => 51,
        R::TransmissionLinkEstablishmentFailed => 67,
        R::AlterativeChannelOccupied => 68,
        R::BeaconTimeout => 200,
        R::NoAccessPointFound => 201,
        R::AuthenticationFailed => 202,
        R::AssociationFailed => 203,
        R::HandshakeTimeout => 204,
        R::ConnectionFailed => 205,
        R::AccessPointTsfReset => 206,
        R::Roaming => 207,
        R::AssociationComebackTimeTooLong => 208,
        R::SaQueryTimeout => 209,
        R::NoAccessPointFoundWithCompatibleSecurity => 210,
        R::NoAccessPointFoundInAuthmodeThreshold => 211,
        R::NoAccessPointFoundInRssiThreshold => 212,
        _ => 0,
    }
}

/// An access point's security as the protocol's [`auth`] code.
fn auth_code(method: Option<AuthenticationMethod>) -> u8 {
    use AuthenticationMethod as M;
    match method {
        None => auth::UNKNOWN,
        Some(M::None) => auth::OPEN,
        Some(M::Wep) => auth::WEP,
        Some(M::Wpa) => auth::WPA,
        Some(M::Wpa2Personal) => auth::WPA2,
        Some(M::WpaWpa2Personal) => auth::WPA_WPA2,
        Some(M::Wpa2Enterprise) => auth::WPA2_ENTERPRISE,
        Some(M::Wpa3Personal) => auth::WPA3,
        Some(M::Wpa2Wpa3Personal) => auth::WPA2_WPA3,
        Some(_) => auth::OTHER,
    }
}

/// An access point as the protocol lists it.
fn scan_entry(ap: &AccessPointInfo) -> ScanEntry {
    let name = ap.ssid.as_str().as_bytes();
    ScanEntry {
        ssid: heapless::Vec::from_slice(&name[..name.len().min(32)]).unwrap_or_default(),
        bssid: ap.bssid,
        channel: ap.channel,
        rssi: ap.signal_strength,
        auth: auth_code(ap.auth_method),
    }
}

/// Which access point may be joined, beyond its SSID and password
/// (`alerts configure --wifi-bssid --wifi-channel`). The security is not
/// part of it: this firmware joins WPA3-Personal only.
#[derive(Clone, Copy, Debug, Default)]
pub struct AccessPointPin {
    /// Only this BSSID: an impostor with the same SSID (another MAC) is
    /// ignored.
    pub bssid: Option<[u8; 6]>,
    /// Only this channel: the join does not sweep the 13 channels.
    pub channel: Option<u8>,
}

/// Whether an access point offers WPA3-Personal (SAE), the only security
/// this firmware joins.
fn offers_sae(method: Option<AuthenticationMethod>) -> bool {
    matches!(
        method,
        Some(
            AuthenticationMethod::Wpa3Personal
                | AuthenticationMethod::Wpa2Wpa3Personal
                | AuthenticationMethod::Wpa3ExtPsk
                | AuthenticationMethod::Wpa3ExtPskMixed
        )
    )
}

/// Lets the scheduler run the Wi-Fi tasks while the main task waits.
fn pause() {
    esp_rtos::CurrentThreadHandle::get().delay(esp_hal::time::Duration::from_millis(1));
}

/// Polls `fut` until it completes, polling `runner` (the network stack)
/// alongside, or until `deadline_ms`. Wakers are not used: every loop
/// polls both, feeds the watchdog, then pauses 1 ms. The wifi-alerts
/// feature selects embassy-time-queue-utils/generic-queue-8: an integrated
/// timer queue must not receive this non-Embassy waker.
fn drive<F: Future>(
    runner: Option<&mut Runner<'_, Interface>>,
    fut: F,
    deadline_ms: u64,
    watchdog: &Watchdog,
) -> Result<F::Output, NetError> {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    let mut step = |cx: &mut Context<'_>| match fut.as_mut().poll(cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    };
    if let Some(runner) = runner {
        let mut run = pin!(runner.run());
        loop {
            if crate::now().as_millis() >= deadline_ms {
                return Err(NetError::Timeout);
            }
            watchdog.feed_shared();
            if let Some(v) = step(&mut cx) {
                return Ok(v);
            }
            let _ = run.as_mut().poll(&mut cx);
            if let Some(v) = step(&mut cx) {
                return Ok(v);
            }
            if crate::now().as_millis() >= deadline_ms {
                return Err(NetError::Timeout);
            }
            pause();
        }
    } else {
        loop {
            if crate::now().as_millis() >= deadline_ms {
                return Err(NetError::Timeout);
            }
            watchdog.feed_shared();
            if let Some(v) = step(&mut cx) {
                return Ok(v);
            }
            if crate::now().as_millis() >= deadline_ms {
                return Err(NetError::Timeout);
            }
            pause();
        }
    }
}

/// `CertVerifier` from embedded-tls, with two checks it lacks: the
/// expected host name is always set, and the chain is exactly a leaf
/// and one intermediate (optionally followed by the root itself).
/// embedded-tls does not check `basicConstraints`, so without the depth
/// limit any certificate issued under the root could sign one for
/// `api.telegram.org`. Certificate dates are not checked: the hub has no
/// wall clock.
struct PinnedVerifier {
    inner: CertVerifier<'static, Aes128GcmSha256, NoClock, CERT_SIZE>,
}

impl TlsVerifier<Aes128GcmSha256> for PinnedVerifier {
    fn set_hostname_verification(&mut self, hostname: &str) -> Result<(), TlsError> {
        <CertVerifier<'static, Aes128GcmSha256, NoClock, CERT_SIZE> as TlsVerifier<
            Aes128GcmSha256,
        >>::set_hostname_verification(&mut self.inner, hostname)
    }

    fn verify_certificate(
        &mut self,
        transcript: &<Aes128GcmSha256 as embedded_tls::TlsCipherSuite>::Hash,
        cert: CertificateRef,
    ) -> Result<(), TlsError> {
        let shape_ok = match cert.entries.as_slice() {
            [CertificateEntryRef::X509(_), CertificateEntryRef::X509(_)] => true,
            [
                CertificateEntryRef::X509(_),
                CertificateEntryRef::X509(_),
                CertificateEntryRef::X509(root),
            ] => *root == ROOT_CA,
            _ => false,
        };
        if !shape_ok {
            return Err(TlsError::InvalidCertificate);
        }
        self.inner.verify_certificate(transcript, cert)
    }

    fn verify_signature(&mut self, verify: CertificateVerifyRef) -> Result<(), TlsError> {
        <CertVerifier<'static, Aes128GcmSha256, NoClock, CERT_SIZE> as TlsVerifier<
            Aes128GcmSha256,
        >>::verify_signature(&mut self.inner, verify)
    }
}

/// TLS crypto: the chip's TRNG and the pinned verifier.
struct Provider<'r> {
    rng: &'r mut Trng,
    verifier: PinnedVerifier,
}

impl CryptoProvider for Provider<'_> {
    type CipherSuite = Aes128GcmSha256;
    type Signature = &'static [u8];

    fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
        &mut *self.rng
    }

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Aes128GcmSha256>, TlsError> {
        Ok(&mut self.verifier)
    }
}

/// An HTTP/1.1 response in `buf` is complete: headers and the body
/// announced by `Content-Length`, or a chunked body's last chunk.
/// Without either, the end is the server closing the connection.
fn http_complete(buf: &[u8]) -> bool {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let body = buf.len() - (end + 4);
    for line in buf[..end].split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        let (name, value) = (&line[..colon], line[colon + 1..].trim_ascii());
        if name.eq_ignore_ascii_case(b"content-length") {
            return core::str::from_utf8(value)
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .is_some_and(|n| body >= n);
        }
        if name.eq_ignore_ascii_case(b"transfer-encoding") && value.eq_ignore_ascii_case(b"chunked")
        {
            return buf.ends_with(b"\r\n0\r\n\r\n");
        }
    }
    false
}

/// Wi-Fi and the network for one attempt: start, join, address, name,
/// TCP, TLS, request, response, stop. Used whole by a delivery
/// (`attempt::run`) and up to the join by the radio-switch experiment
/// (`attempt::run_probe`).
pub struct WifiNetwork<'a> {
    wifi: Option<WIFI<'a>>,
    ssid: &'a [u8],
    password: &'a [u8],
    pin: AccessPointPin,
    buffers: Option<&'a mut NetBuffers>,
    rng: Trng,
    controller: Option<WifiController<'a>>,
    stack: Option<Stack<'a>>,
    runner: Option<Runner<'a, Interface>>,
    socket: Option<TcpSocket<'a>>,
    tls_buffers: Option<(&'a mut [u8], &'a mut [u8])>,
    tls: Option<TlsConnection<'a, TcpSocket<'a>, Aes128GcmSha256>>,
    failure: Option<WifiFailure>,
    scan: Option<WifiScan>,
    watchdog: &'a Watchdog,
}

impl WifiNetwork<'_> {
    /// Directed active scan for the configured SSID (probe requests that
    /// name it, so a hidden network answers), 40–120 ms per channel, one
    /// pass: the strongest answer offering WPA3-Personal, or `None`. For
    /// the experiment's report only (one pass missed a hidden network in
    /// range about one time in three on a board, `wifi-scan-check`).
    fn find_network(&mut self, deadline: Deadline) -> Result<Option<ScanEntry>, NetError> {
        let ssid = Ssid::try_from(self.ssid).map_err(|_| NetError::Failed)?;
        let controller = self.controller.as_mut().ok_or(NetError::Failed)?;
        let config = ScanConfig::default()
            .with_ssid(ssid)
            .with_show_hidden(true)
            .with_scan_type(ScanTypeConfig::Active {
                min: esp_hal::time::Duration::from_millis(40),
                max: esp_hal::time::Duration::from_millis(120),
            });
        let aps = drive(
            None,
            controller.scan_async(&config),
            deadline.network_end,
            self.watchdog,
        )?
        .map_err(|_| NetError::Failed)?;
        let wanted = self.ssid;
        Ok(aps
            .iter()
            .filter(|ap| ap.ssid.as_str().as_bytes() == wanted && offers_sae(ap.auth_method))
            .max_by_key(|ap| ap.signal_strength)
            .map(scan_entry))
    }
}

impl<'a> WifiNetwork<'a> {
    /// What the scan heard (`None`: no scan, or it failed).
    pub fn wifi_scan(&mut self) -> Option<WifiScan> {
        self.scan.take()
    }

    /// Why the access point could not be joined, as the driver reported
    /// it (`None`: joined, not tried, timed out, or no reason given).
    pub fn wifi_failure(&self) -> Option<WifiFailure> {
        self.failure
    }

    /// A network that joins `ssid` with `password` (WPA2-Personal; open
    /// when empty). `wifi` is a re-borrow of the board's peripheral for
    /// this attempt; `buffers` the firmware's network memory.
    ///
    /// # Panics
    ///
    /// When the TRNG has no entropy source (the board keeps one for the
    /// firmware's life).
    pub fn new(
        wifi: WIFI<'a>,
        ssid: &'a [u8],
        password: &'a [u8],
        pin: AccessPointPin,
        buffers: &'a mut NetBuffers,
        watchdog: &'a Watchdog,
    ) -> Self {
        WifiNetwork {
            wifi: Some(wifi),
            ssid,
            password,
            pin,
            buffers: Some(buffers),
            rng: Trng::try_new().unwrap_or_else(|_| panic!("TRNG source")),
            controller: None,
            stack: None,
            runner: None,
            socket: None,
            tls_buffers: None,
            tls: None,
            failure: None,
            scan: None,
            watchdog,
        }
    }
}

impl Network for WifiNetwork<'_> {
    fn wifi_start(&mut self, _deadline: Deadline) -> Result<(), NetError> {
        crate::startup::mark(StartupStage::WifiStart);
        // The vendored SAE supplicant uses PSA Crypto for HMAC/key import.
        // ESP-IDF initializes it from an ESP_SYSTEM_INIT_FN startup hook;
        // esp-hal/esp-rtos do not run that hook. Without this call SAE fails
        // locally with PSA_ERROR_BAD_STATE before sending its commit.
        // SAFETY: this is the no-argument PSA C API in the vendored
        // libmbedcrypto.a, returning an int32_t status (zero is success).
        // The hub serializes attempts and calls it before creating Wi-Fi's
        // tasks; repeated initialization is supported by PSA Crypto.
        unsafe extern "C" {
            fn psa_crypto_init() -> i32;
        }
        if unsafe { psa_crypto_init() } != 0 {
            return Err(NetError::Failed);
        }
        let wifi = self.wifi.take().ok_or(NetError::Failed)?;
        let ssid = Ssid::try_from(self.ssid).map_err(|_| NetError::Failed)?;
        // WPA3-Personal only, whatever the settings say: the scan
        // threshold is WPA3, PMF is required and SAE uses hash-to-element
        // (the vendored esp-radio, PANWEAVE-PATCH.md). No WPA2 handshake is
        // ever started and no open network is joined.
        if self.password.is_empty() {
            return Err(NetError::Failed);
        }
        let authentication = AuthenticationMethodConfig::Wpa3Personal(
            Password::try_from(self.password).map_err(|_| NetError::Failed)?,
        );
        let mut station = StationConfig::default()
            .with_ssid(ssid)
            .with_authentication(authentication);
        if let Some(bssid) = self.pin.bssid {
            station = station.with_bssid(bssid);
        }
        if let Some(channel) = self.pin.channel {
            station = station.with_channel(channel);
        }
        // Starts the station (`esp_wifi_start`): a blocking driver call
        // the deadline cannot interrupt; its real duration is recorded.
        let controller = WifiController::new(
            wifi,
            ControllerConfig::default().with_initial_config(Config::Station(station)),
        )
        .map_err(|_| NetError::Failed)?;
        self.controller = Some(controller);
        Ok(())
    }

    fn associate(&mut self, deadline: Deadline) -> Result<(), NetError> {
        crate::startup::mark(StartupStage::WifiAssociate);
        /// A join that heard no access point is tried again while this much
        /// of the deadline remains: one sweep of the 13 channels takes
        /// about 1.6 s, and SAE needs time after it.
        const RETRY_MARGIN_MS: u64 = 3000;
        // The driver finds the network itself (probe requests naming the
        // SSID reach a hidden one). Handing it the BSSID and channel a
        // directed scan found, through `set_config` on the started
        // station, made every join end in reason 201 on a board. Its own
        // sweep misses an access point in range now and then (the board
        // hears 0–6 access points from one scan to the next), hence the
        // retries.
        loop {
            let controller = self.controller.as_mut().ok_or(NetError::Failed)?;
            // A timeout drops the future, abandoning the join; `wifi_stop`
            // then deinitializes the driver.
            match drive(
                None,
                controller.connect_async(),
                deadline.network_end,
                self.watchdog,
            )? {
                Ok(_) => {
                    self.failure = None;
                    return Ok(());
                }
                Err(ConnectionError::Failed(info)) => {
                    // The driver gives -128 (or 0) when it has no signal to
                    // report, e.g. no access point heard.
                    self.failure = Some(WifiFailure {
                        reason: reason_code(info.reason),
                        rssi: (info.rssi != 0 && info.rssi != i8::MIN).then_some(info.rssi),
                    });
                    let not_heard = info.reason == DisconnectReason::NoAccessPointFound;
                    if !not_heard
                        || deadline.network_remaining(crate::now().as_millis()) < RETRY_MARGIN_MS
                    {
                        return Err(NetError::Failed);
                    }
                }
                Err(_) => return Err(NetError::Failed),
            }
        }
    }

    fn scan(&mut self, deadline: Deadline) -> Result<(), NetError> {
        let start = crate::now().as_millis();
        let controller = self.controller.as_mut().ok_or(NetError::Failed)?;
        // Active, 40–80 ms per channel: about 0.5–1 s for the 13
        // channels. esp-radio's default (10–20 ms) heard a different
        // handful of access points on each run on a board. Hidden
        // networks are listed with no SSID.
        let config =
            ScanConfig::default()
                .with_show_hidden(true)
                .with_scan_type(ScanTypeConfig::Active {
                    min: esp_hal::time::Duration::from_millis(40),
                    max: esp_hal::time::Duration::from_millis(80),
                });
        let mut aps = drive(
            None,
            controller.scan_async(&config),
            deadline.network_end,
            self.watchdog,
        )?
        .map_err(|_| NetError::Failed)?;
        aps.sort_unstable_by_key(|ap| core::cmp::Reverse(ap.signal_strength));
        // The pinned access point is found by its BSSID (a hidden one
        // has no SSID in a broadcast scan). Without a pin, the directed
        // scan below finds the network by name, as the join will.
        let target = self
            .pin
            .bssid
            .and_then(|b| aps.iter().find(|ap| ap.bssid == b).map(scan_entry));
        let strongest = aps.iter().take(MAX_SCAN_ENTRIES).map(scan_entry).collect();
        let seen = u16::try_from(aps.len()).unwrap_or(u16::MAX);
        drop(aps);
        let target = if self.pin.bssid.is_none() && self.pin.channel.is_none() {
            self.find_network(deadline)?
        } else {
            target
        };
        let scan_ms = u32::try_from(crate::now().as_millis() - start).unwrap_or(u32::MAX);
        self.scan = Some(WifiScan {
            scan_ms,
            seen,
            target,
            strongest,
        });
        Ok(())
    }

    fn obtain_ip(&mut self, deadline: Deadline) -> Result<(), NetError> {
        crate::startup::mark(StartupStage::WifiAddress);
        let buffers = self.buffers.take().ok_or(NetError::Failed)?;
        let NetBuffers {
            resources,
            tcp_rx,
            tcp_tx,
            tls_read,
            tls_write,
        } = buffers;
        let interface = Interface::try_station().ok_or(NetError::Failed)?;
        let seed = u64::from(self.rng.random()) << 32 | u64::from(self.rng.random());
        let config = embassy_net::Config::dhcpv4(embassy_net::DhcpConfig::default());
        let (stack, runner) = embassy_net::new(interface, config, resources, seed);
        self.stack = Some(stack);
        self.socket = Some(TcpSocket::new(stack, tcp_rx, tcp_tx));
        self.tls_buffers = Some((tls_read, tls_write));
        let runner = self.runner.insert(runner);
        drive(
            Some(runner),
            stack.wait_config_up(),
            deadline.network_end,
            self.watchdog,
        )
    }

    fn resolve(&mut self, host: &str, deadline: Deadline) -> Result<[u8; 4], NetError> {
        crate::startup::mark(StartupStage::WifiDns);
        let stack = self.stack.ok_or(NetError::Failed)?;
        let addrs = drive(
            self.runner.as_mut(),
            stack.dns_query(host, DnsQueryType::A),
            deadline.network_end,
            self.watchdog,
        )?
        .map_err(|_| NetError::Failed)?;
        match addrs.first() {
            Some(IpAddress::Ipv4(a)) => Ok(a.octets()),
            None => Err(NetError::Failed),
        }
    }

    fn connect(&mut self, addr: [u8; 4], port: u16, deadline: Deadline) -> Result<(), NetError> {
        crate::startup::mark(StartupStage::WifiConnect);
        let socket = self.socket.as_mut().ok_or(NetError::Failed)?;
        let [a, b, c, d] = addr;
        let remote = IpEndpoint::new(IpAddress::v4(a, b, c, d), port);
        drive(
            self.runner.as_mut(),
            socket.connect(remote),
            deadline.network_end,
            self.watchdog,
        )?
        .map_err(|_| NetError::Failed)
    }

    fn tls_handshake(&mut self, host: &str, deadline: Deadline) -> Result<(), NetError> {
        crate::startup::mark(StartupStage::WifiTls);
        let socket = self.socket.take().ok_or(NetError::Failed)?;
        let (read, write) = self.tls_buffers.take().ok_or(NetError::Failed)?;
        let mut verifier = PinnedVerifier {
            inner: CertVerifier::new(Certificate::X509(ROOT_CA)),
        };
        verifier
            .set_hostname_verification(host)
            .map_err(|_| NetError::Failed)?;
        let config = TlsConfig::new().with_server_name(host);
        let provider = Provider {
            rng: &mut self.rng,
            verifier,
        };
        let tls = self.tls.insert(TlsConnection::new(socket, read, write));
        drive(
            self.runner.as_mut(),
            tls.open(TlsContext::new(&config, provider)),
            deadline.network_end,
            self.watchdog,
        )?
        .map_err(|_| NetError::Failed)
    }

    fn send(&mut self, request: &[u8], deadline: Deadline) -> Result<(), NetError> {
        crate::startup::mark(StartupStage::WifiRequest);
        let tls = self.tls.as_mut().ok_or(NetError::Failed)?;
        let write_all = async {
            let mut sent = 0;
            while sent < request.len() {
                sent += tls.write(&request[sent..]).await?;
            }
            tls.flush().await
        };
        drive(
            self.runner.as_mut(),
            write_all,
            deadline.network_end,
            self.watchdog,
        )?
        .map_err(|_| NetError::Failed)
    }

    fn receive(&mut self, buf: &mut [u8], deadline: Deadline) -> Result<usize, NetError> {
        crate::startup::mark(StartupStage::WifiResponse);
        let tls = self.tls.as_mut().ok_or(NetError::Failed)?;
        let mut n = 0;
        while n < buf.len() && !http_complete(&buf[..n]) {
            match drive(
                self.runner.as_mut(),
                tls.read(&mut buf[n..]),
                deadline.network_end,
                self.watchdog,
            )? {
                Ok(0) | Err(TlsError::ConnectionClosed) => break,
                Ok(k) => n += k,
                // What arrived is kept: the response is interpreted from
                // its beginning (status, `ok`, `message_id`).
                Err(_) if n > 0 => break,
                Err(_) => return Err(NetError::Failed),
            }
        }
        // A full buffer ends the read: the fields that matter come first.
        if n == 0 { Err(NetError::Failed) } else { Ok(n) }
    }

    fn wifi_stop(&mut self) {
        crate::startup::mark(StartupStage::WifiRestore);
        // Network first (the TLS session owns the socket, the runner owns
        // the interface), then the controller: dropping it stops and
        // deinitializes Wi-Fi (`esp_wifi_stop`, `esp_wifi_deinit`) and
        // releases the radio.
        self.tls = None;
        self.socket = None;
        self.runner = None;
        self.stack = None;
        self.tls_buffers = None;
        self.buffers = None;
        self.controller = None;
        self.wifi = None;
    }
}
