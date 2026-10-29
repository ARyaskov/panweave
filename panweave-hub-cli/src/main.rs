//! `panweave-hub-cli`: a development client for the Panweave hub over its
//! USB serial port, speaking Panweave Hub Protocol v1 with the message
//! definitions of the `panweave-hub` crate the firmware uses.
//!
//! ```text
//! panweave-hub-cli [--port PORT] [--timeout SECONDS] [--verbose] [--json] <command>
//! ```
//!
//! Run without arguments for the command list. The port defaults to the
//! `PANWEAVE_HUB_PORT` environment variable, else to the only Espressif
//! USB serial port (VID 0x303a) found.
//!
//! Exit codes: 0 success, 1 a command or test failed, 2 usage error,
//! 3 the hub could not be reached (no port, port busy, no response).
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod alertscmd;
mod capturecmd;
mod diagcmd;
mod fingerprint;
mod hil;
mod json;
mod otacmd;
mod securitycmd;
mod selftest;

use std::io::{Read, Write};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use panweave_hub::model::{
    ColorState, ContactState, DeviceState, Flag, Ieee, LeakState, level_to_brightness,
};
use panweave_hub::protocol::frame::{FrameDecoder, MAX_WIRE};
use panweave_hub::protocol::{
    CommandStage, DeviceInfo, DeviceSummary, ErrorCode, Event, GpdAddress, LightCommand, Message,
    Request, Response,
};

const USAGE: &str = "\
usage: panweave-hub-cli [--port PORT] [--timeout SECONDS] [--verbose] <command>

commands:
  ports                                   list serial ports
  info                                    hub identity and protocol version
  network                                 network parameters, permit-join window
  permit-join <seconds>                   open the network (1-254 s)
  close                                   close the network
  devices                                 list the registry
  devices watch                           list, then print events until Ctrl+C
  watch                                   print events until Ctrl+C
  device <ieee> [info]                    everything known about a device
  device <ieee> state                     its normalized state
  device <ieee> fingerprint               identifying values with their provenance
  device <ieee> interview                 run its interview again
  device <ieee> remove [--leave]          forget it (and make it leave)
  light <ieee> on|off|toggle [--endpoint N]
  light <ieee> brightness <0-100> [--transition TENTHS] [--endpoint N]
  light <ieee> color-temp <mireds> | xy <x> <y> | hs <hue 0-254> <sat 0-254>
      [--transition TENTHS] [--endpoint N]  colour (x, y: CIE 1931 × 65536)
  light <ieee> color                      its colour capabilities and current colour
  group add|remove <ieee> <group> [--endpoint N]
                                          group membership (Groups cluster)
  group light <group> on|off|toggle|brightness <0-100>|color-temp <mireds> [--transition TENTHS]
                                          one group-addressed command (no confirmation)
  scene store <ieee> <group> <scene> [--endpoint N]
  scene recall <group> <scene> [--transition TENTHS]
  ota update <file> [--ieee IEEE] [--allow-downgrade] [--wait SECONDS]
                                          offer an OTA image and serve it until a device
                                          upgrades (Admin; Ctrl+C withdraws it)
  ota status | ota cancel                 the offer and the download in progress
  gp commission [--seconds N] | gp close  Green Power commissioning window (Admin;
                                          firmware with the green-power feature)
  gp list | gp remove <srcid>             paired Green Power Devices
  read <ieee> <endpoint> <cluster> <attribute>
  bind <ieee> <endpoint> <cluster>
  report <ieee> <endpoint> <cluster> <attribute> <type> <min> <max> <change>
  diagnostics                             counters
  diagnostics system|radio|storage|runtime
                                          boot report, radio, storage, runtime metrics
  diagnostics trace                       every stored trace record
  diagnostics watch [--level L] [--category C[,C…]]
                                          follow the trace until Ctrl+C
  diagnostics device <ieee>               a device's trace records
  diagnostics interview <ieee>            its interview timeline, with a summary
  diagnostics export --output FILE [--ieee IEEE]
                                          the trace as JSONL
  diagnostics configure [--level L] [--category C[,C…]|all]
                                          what the hub keeps (Admin)
  diagnostics clear                       empty the trace (Admin)
  capture start [--seconds N] [--mode metadata|sanitized|raw [--allow-raw]]
  capture stop
  capture export --output FILE.pcap [--seconds N] [--metadata FILE.jsonl] [--mode M [--allow-raw]]
                                          capture radio frames to pcap (Admin)
  alerts [status]                         experimental Wi-Fi notifications: state, queue, timings
  alerts configure [--enable|--disable] [--wifi-ssid S] [--chat-id ID]
      [--wifi-password-stdin] [--telegram-token-stdin] [--clear-secrets]
      [--interval-ms N] [--budget-ms N] [--notify leak,contact,tamper,battery]
                                          change the settings (Admin; secrets from stdin)
  alerts configure --wifi-bssid MAC|none --wifi-channel N|none --wifi-wpa3-only|--wifi-allow-wpa2
                                          pin the access point: only this BSSID, this
                                          channel, WPA3-Personal only (Admin)
  alerts test                             queue a test notification (Admin)
  alerts probe [--count N] [--interval S] radio-switch experiment: 802.15.4 off, Wi-Fi
                                          on, scan, join, back; downtime per stage (Admin)
  alerts scan                             what the last experiment heard: access points,
                                          channels, signal, the configured SSID (Admin)
  security                                Trust Center policy, unauthorized devices, exemptions
  security exempt <ieee> [--seconds N]    let one device join without the key exchange (Admin)
  security install-code <ieee> <code>     let a device join with its install code (hex,
                                          code and CRC as printed; Admin)
  security revoke <ieee>                  withdraw its exemption (Admin)
  self-test [--allow-reboot] [--join-test [--join-seconds N]]
                                          hardware smoke test (PASS/FAIL/SKIP)
  hil light|contact|leak|aqara-leak|sber-contact|yandex-leak <ieee>
      [--report FILE] [--unattended] [--wait SECONDS]
                                          operator-driven device check
  partitions check <csv> [--flash-size BYTES] [--image FILE]
                                          validate a partition table (no hub)

Global --json prints machine-readable output (diagnostics, security, self-test,
device fingerprint).
Levels: trace debug info warning error critical. Categories: system boot
usb radio mac nwk aps trust-center commissioning zdo zcl interview ias-zone
persistence watchdog resources.
Numbers accept 0x-prefixed hex. IEEE addresses: 0011223344556677,
0x0011223344556677 or 00:11:22:33:44:55:66:77.";

/// Espressif's USB vendor identifier (USB Serial/JTAG of the ESP32-C6).
const ESPRESSIF_VID: u16 = 0x303a;

/// Set by Ctrl+C: long-running commands finish cleanly.
static STOP: AtomicBool = AtomicBool::new(false);

/// Prefix of errors that mean the hub could not be reached (exit code 3).
const UNREACHABLE: &str = "hub unreachable: ";

struct Options {
    port: Option<String>,
    timeout: Duration,
    verbose: bool,
    json: bool,
    args: Vec<String>,
}

fn parse_options() -> Result<Options, String> {
    let mut o = Options {
        port: std::env::var("PANWEAVE_HUB_PORT").ok(),
        timeout: Duration::from_secs(5),
        verbose: false,
        json: false,
        args: Vec::new(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--port" => o.port = Some(it.next().ok_or("--port needs a value")?),
            "--timeout" => {
                let s = it.next().ok_or("--timeout needs a value")?;
                o.timeout = Duration::from_secs(number(&s)?);
            }
            "--verbose" | "-v" => o.verbose = true,
            "--json" => o.json = true,
            "--help" | "-h" => return Err(String::new()),
            _ => o.args.push(a),
        }
    }
    Ok(o)
}

fn number<T: TryFrom<u64>>(s: &str) -> Result<T, String> {
    let v = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16),
        None => s.parse::<u64>(),
    }
    .map_err(|_| format!("not a number: {s}"))?;
    T::try_from(v).map_err(|_| format!("out of range: {s}"))
}

fn ieee(s: &str) -> Result<u64, String> {
    Ieee::parse(s)
        .map(|i| i.0)
        .ok_or_else(|| format!("not an IEEE address: {s}"))
}

fn flag_value<T: TryFrom<u64>>(args: &[String], name: &str, default: T) -> Result<T, String> {
    match args.iter().position(|a| a == name) {
        Some(i) => number(args.get(i + 1).ok_or(format!("{name} needs a value"))?),
        None => Ok(default),
    }
}

fn find_port() -> Result<String, String> {
    let ports = serialport::available_ports().map_err(|e| format!("listing ports: {e}"))?;
    let esp: Vec<_> = ports
        .iter()
        .filter(|p| {
            matches!(&p.port_type, serialport::SerialPortType::UsbPort(u) if u.vid == ESPRESSIF_VID)
        })
        .collect();
    match esp.as_slice() {
        [one] => Ok(one.port_name.clone()),
        [] => Err(format!(
            "{UNREACHABLE}no Espressif USB serial port found: pass --port"
        )),
        _ => Err("several Espressif ports found: pass --port".into()),
    }
}

/// A connection to the hub.
struct Hub {
    name: String,
    port: Box<dyn serialport::SerialPort>,
    rx: Receiver<Message>,
    next_id: u16,
    timeout: Duration,
    verbose: bool,
}

impl Hub {
    fn open(name: &str, timeout: Duration, verbose: bool) -> Result<Hub, String> {
        let (port, rx) = Self::connect(name, verbose)?;
        Ok(Hub {
            name: name.to_string(),
            port,
            rx,
            next_id: 1,
            timeout,
            verbose,
        })
    }

    #[allow(clippy::type_complexity)]
    fn connect(
        name: &str,
        verbose: bool,
    ) -> Result<(Box<dyn serialport::SerialPort>, Receiver<Message>), String> {
        let mut port = serialport::new(name, 115_200)
            .timeout(Duration::from_millis(50))
            .open()
            .map_err(|e| format!("{UNREACHABLE}opening {name}: {e}"))?;
        // The ESP32-C6's USB Serial/JTAG resets the chip on the RTS/DTR
        // pattern flashing tools use; keep both lines released.
        let _ = port.write_data_terminal_ready(false);
        let _ = port.write_request_to_send(false);
        let mut reader = port
            .try_clone()
            .map_err(|e| format!("cloning {name}: {e}"))?;
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut dec = FrameDecoder::new();
            let mut buf = [0u8; 256];
            let started = Instant::now();
            loop {
                let n = match reader.read(&mut buf) {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                    Err(e) => {
                        if verbose {
                            eprintln!("(serial read failed: {e})");
                        }
                        return;
                    }
                };
                if verbose && n > 0 {
                    eprintln!(
                        "(serial rx +{} ms, {n} bytes: {:02x?})",
                        started.elapsed().as_millis(),
                        &buf[..n]
                    );
                }
                for &b in &buf[..n] {
                    match dec.push(b) {
                        Some(Ok(body)) => match Message::decode(body) {
                            Ok(m) => {
                                if verbose {
                                    match &m {
                                        Message::Response { id, .. } => eprintln!(
                                            "(decoded response id={id}, {} body bytes)",
                                            body.len()
                                        ),
                                        Message::Event { seq, .. } => eprintln!(
                                            "(decoded event seq={seq}, {} body bytes)",
                                            body.len()
                                        ),
                                        Message::Request { id, .. } => {
                                            eprintln!("(unexpected request id={id})");
                                        }
                                    }
                                }
                                if tx.send(m).is_err() {
                                    return;
                                }
                            }
                            Err(e) if verbose => eprintln!("(undecodable message: {e:?})"),
                            Err(_) => {}
                        },
                        Some(Err(e)) if verbose => {
                            eprintln!("(frame dropped: {e:?})");
                        }
                        _ => {}
                    }
                }
            }
        });
        Ok((port, rx))
    }

    /// Writes octets as they are (robustness tests).
    fn send_raw(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.port
            .write_all(bytes)
            .and_then(|()| self.port.flush())
            .map_err(|e| format!("writing: {e}"))
    }

    /// Resets the chip through the USB Serial/JTAG reset line (RTS with
    /// DTR released, as flashing tools do; a "USB-JTAG reset" in the boot
    /// report afterwards), waits for the port to come back and reconnects.
    fn reset_and_reconnect(&mut self) -> Result<(), String> {
        let _ = self.port.write_data_terminal_ready(false);
        self.port
            .write_request_to_send(true)
            .map_err(|e| format!("asserting RTS: {e}"))?;
        thread::sleep(Duration::from_millis(100));
        let _ = self.port.write_request_to_send(false);
        // The USB device disappears while the chip restarts.
        let deadline = Instant::now() + Duration::from_secs(15);
        thread::sleep(Duration::from_millis(500));
        loop {
            match Self::connect(&self.name, self.verbose) {
                Ok((port, rx)) => {
                    self.port = port;
                    self.rx = rx;
                    break;
                }
                Err(e) if Instant::now() >= deadline => return Err(e),
                Err(_) => thread::sleep(Duration::from_millis(250)),
            }
        }
        // Wait until the firmware answers (boot takes a moment).
        let wait = self.timeout;
        self.timeout = Duration::from_millis(500);
        let mut answered = false;
        while Instant::now() < deadline && !answered {
            answered = matches!(self.call(Request::GetHubInfo), Ok(Response::HubInfo(_)));
        }
        self.timeout = wait;
        if answered {
            Ok(())
        } else {
            Err(format!(
                "{UNREACHABLE}the hub did not answer after the reset"
            ))
        }
    }

    fn send(&mut self, request: Request) -> Result<u16, String> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let mut wire = [0u8; MAX_WIRE];
        let n = Message::Request { id, request }
            .encode_frame(&mut wire)
            .map_err(|e| format!("encoding: {e:?}"))?;
        if self.verbose {
            eprintln!(
                "(serial tx request id={id}, {n} bytes: {:02x?})",
                &wire[..n]
            );
        }
        self.port
            .write_all(&wire[..n])
            .and_then(|()| self.port.flush())
            .map_err(|e| format!("writing: {e}"))?;
        Ok(id)
    }

    /// Sends a request and waits for its response; events that arrive
    /// meanwhile go to `on_event`.
    fn call_with(
        &mut self,
        request: Request,
        on_event: &mut dyn FnMut(&Event),
    ) -> Result<Response, String> {
        let id = self.send(request)?;
        let deadline = Instant::now() + self.timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.rx.recv_timeout(left) {
                Ok(Message::Response { id: rid, response }) if rid == id => return Ok(response),
                Ok(Message::Event { event, .. }) => on_event(&event),
                Ok(other) if self.verbose => eprintln!("(ignored {other:?})"),
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout) => {
                    if self.verbose {
                        eprintln!("(response timeout for request id={id})");
                    }
                    return Err(format!(
                        "{UNREACHABLE}no response from the hub (is the hub firmware running?)"
                    ));
                }
                Err(RecvTimeoutError::Disconnected) => return Err("serial port closed".into()),
            }
        }
    }

    fn call(&mut self, request: Request) -> Result<Response, String> {
        self.call_with(request, &mut |_| {})
    }

    /// Waits for the outcome of an accepted command.
    fn outcome(&mut self, command: u16, wait: Duration) -> Result<Event, String> {
        let deadline = Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.rx.recv_timeout(left) {
                Ok(Message::Event { event, .. }) => match &event {
                    Event::CommandCompleted { command: c, .. }
                    | Event::CommandFailed { command: c, .. }
                        if *c == command =>
                    {
                        return Ok(event);
                    }
                    e if self.verbose => println!("{}", describe_event(e)),
                    _ => {}
                },
                Ok(_) => {}
                Err(_) => return Err(format!("command {command}: no outcome reported")),
            }
        }
    }

    fn watch(&mut self) -> Result<(), String> {
        while !STOP.load(Ordering::SeqCst) {
            match self.rx.recv_timeout(Duration::from_millis(250)) {
                Ok(Message::Event { seq, event }) => {
                    println!("[{seq:5}] {}", describe_event(&event));
                }
                Ok(_) | Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err("serial port closed".into()),
            }
        }
        Ok(())
    }
}

fn expect_done(r: Response) -> Result<(), String> {
    match r {
        Response::Done => Ok(()),
        Response::Error(e) => Err(error_text(e)),
        r => Err(format!("unexpected response: {r:?}")),
    }
}

fn error_text(e: ErrorCode) -> String {
    format!("hub error: {} ({:#04x})", e.name(), e.code())
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn seen(s: Option<u32>) -> String {
    s.map_or_else(|| "never".into(), |s| format!("{s} s after boot"))
}

fn describe_state(s: &DeviceState) -> String {
    let mut parts = Vec::new();
    if let Some(on) = s.on {
        parts.push(format!("on={on}"));
    }
    if let Some(l) = s.level {
        let pct = level_to_brightness(l).map_or_else(String::new, |p| format!(" ({p} %)"));
        parts.push(format!("level={l}{pct}"));
    }
    match s.contact {
        ContactState::Unknown => {}
        ContactState::Open => parts.push("contact=open".into()),
        ContactState::Closed => parts.push("contact=closed".into()),
    }
    match s.water_leak {
        LeakState::Unknown => {}
        LeakState::Leak => parts.push("water=LEAK".into()),
        LeakState::Dry => parts.push("water=dry".into()),
    }
    for (name, f) in [
        ("motion", s.motion),
        ("tamper", s.tamper),
        ("battery-low", s.battery_low),
        ("trouble", s.trouble),
    ] {
        match f {
            Flag::Unknown => {}
            Flag::Set => parts.push(format!("{name}=yes")),
            Flag::Clear => parts.push(format!("{name}=no")),
        }
    }
    if let Some(p) = s.battery_percent {
        parts.push(format!("battery={p} %"));
    }
    if let Some(mv) = s.battery_mv {
        parts.push(format!("battery={mv} mV"));
    }
    if let Some(t) = s.temperature_centi {
        parts.push(format!("temperature={:.2} C", f64::from(t) / 100.0));
    }
    if let Some(h) = s.humidity_centi {
        parts.push(format!("humidity={:.2} %", f64::from(h) / 100.0));
    }
    if let Some(z) = s.zone_status {
        parts.push(format!("zone-status={z:#06x}"));
    }
    if parts.is_empty() {
        "unknown".into()
    } else {
        parts.join(" ")
    }
}

fn describe_event(e: &Event) -> String {
    match e {
        Event::NetworkStarted(n) => format!(
            "network started: PAN {:#06x}, extended PAN {}, channel {}",
            n.pan_id,
            Ieee(n.extended_pan_id),
            n.channel
        ),
        Event::NetworkRestored(n) => format!(
            "network restored: PAN {:#06x}, extended PAN {}, channel {}",
            n.pan_id,
            Ieee(n.extended_pan_id),
            n.channel
        ),
        Event::PermitJoinChanged { seconds: 0 } => "network closed for joining".into(),
        Event::PermitJoinChanged { seconds } => format!("network open for joining for {seconds} s"),
        Event::DeviceJoined {
            ieee,
            short,
            rejoin,
        } => format!(
            "{} {} at {short:#06x}",
            Ieee(*ieee),
            if *rejoin { "rejoined" } else { "joined" }
        ),
        Event::DeviceLeft { ieee } => format!("{} left the network", Ieee(*ieee)),
        Event::DeviceInterviewCompleted {
            ieee,
            category,
            capabilities,
            partial,
        } => format!(
            "{} interviewed{}: {} [{}]",
            Ieee(*ieee),
            if *partial { " (partially)" } else { "" },
            category.name(),
            capabilities.names().collect::<Vec<_>>().join(", ")
        ),
        Event::DeviceInterviewFailed { ieee, stage, error } => format!(
            "{} interview stalled at {}: {} (resumes when the device is heard)",
            Ieee(*ieee),
            stage.name(),
            error.name()
        ),
        Event::DeviceStateChanged { ieee, state } => {
            format!("{} state: {}", Ieee(*ieee), describe_state(state))
        }
        Event::Sensor { ieee, event } => format!("{} {}", Ieee(*ieee), event.name()),
        Event::AttributeReport {
            ieee,
            endpoint,
            cluster,
            attribute,
            value,
        } => format!(
            "{} report {endpoint}/{cluster:#06x}/{attribute:#06x} = {value}",
            Ieee(*ieee)
        ),
        Event::CommandCompleted {
            command,
            ieee,
            stage,
            value,
        } => match value {
            Some(v) => format!("command {command} to {} {}: {v}", Ieee(*ieee), stage.name()),
            None => format!("command {command} to {} {}", Ieee(*ieee), stage.name()),
        },
        Event::CommandFailed {
            command,
            ieee,
            stage,
            error,
            status,
        } => format!(
            "command {command} to {} failed after '{}': {} (status {status:#04x})",
            Ieee(*ieee),
            stage.name(),
            error.name()
        ),
        Event::HubError { error, detail } => format!("hub error: {} ({detail})", error.name()),
        Event::EventsDropped { count } => {
            format!("{count} events were dropped while nobody was reading")
        }
        Event::LightColorChanged { ieee, color } => {
            format!("{} colour: {}", Ieee(*ieee), describe_color(color))
        }
        Event::OtaDataWanted { offset, length } => {
            format!("OTA: the hub wants {length} octets from offset {offset}")
        }
        Event::OtaProgress { ieee, offset, size } => {
            format!("{} OTA download: {offset}/{size} octets", Ieee(*ieee))
        }
        Event::OtaFinished { ieee, status } => {
            format!("{} OTA download ended (status {status:#04x})", Ieee(*ieee))
        }
        Event::GreenPowerCommissioning { seconds: 0 } => {
            "Green Power commissioning closed".to_string()
        }
        Event::GreenPowerCommissioning { seconds } => {
            format!("Green Power commissioning open for {seconds} s")
        }
        Event::GreenPowerPaired { gpd, device_id } => {
            format!("{} paired (device id {device_id:#04x})", describe_gpd(gpd))
        }
        Event::GreenPowerRemoved { gpd } => format!("{} removed", describe_gpd(gpd)),
        Event::GreenPowerCommand {
            gpd,
            command,
            payload,
        } => format!(
            "{}: {} ({command:#04x}){}",
            describe_gpd(gpd),
            panweave_hub::protocol::gp::command_name(*command).unwrap_or("command"),
            if payload.is_empty() {
                String::new()
            } else {
                format!(" payload {payload:02x?}")
            }
        ),
    }
}

/// A light command from its CLI words.
fn light_command(args: &[String], action: &str, rest: &[&str]) -> Result<LightCommand, String> {
    let transition_ds = flag_value(args, "--transition", 0u16)?;
    Ok(match (action, rest) {
        ("on", _) => LightCommand::TurnOn,
        ("off", _) => LightCommand::TurnOff,
        ("toggle", _) => LightCommand::Toggle,
        ("brightness", [pct, ..]) => LightCommand::SetBrightness {
            percent: number(pct)?,
            transition_ds,
        },
        ("color-temp", [mireds, ..]) => LightCommand::SetColorTemperature {
            mireds: number(mireds)?,
            transition_ds,
        },
        ("xy", [x, y, ..]) => LightCommand::SetColorXy {
            x: number(x)?,
            y: number(y)?,
            transition_ds,
        },
        ("hs", [hue, sat, ..]) => LightCommand::SetHueSaturation {
            hue: number(hue)?,
            saturation: number(sat)?,
            transition_ds,
        },
        _ => return Err(USAGE.into()),
    })
}

fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map_or_else(|| "?".into(), |v| v.to_string())
}

fn describe_color(c: &ColorState) -> String {
    let mut caps = Vec::new();
    for (bit, name) in [
        (ColorState::HUE_SATURATION, "hs"),
        (ColorState::ENHANCED_HUE, "enhanced-hue"),
        (ColorState::COLOR_LOOP, "loop"),
        (ColorState::XY, "xy"),
        (ColorState::TEMPERATURE, "color-temp"),
    ] {
        if c.supports(bit) {
            caps.push(name);
        }
    }
    format!(
        "capabilities {} (mireds {}–{}); mode {}; xy {}/{}; {} mireds; hue {} sat {}",
        if c.capabilities.is_some() {
            caps.join(",")
        } else {
            "?".into()
        },
        opt(c.mireds_min),
        opt(c.mireds_max),
        c.mode.map_or("?", |m| m.name()),
        opt(c.x),
        opt(c.y),
        opt(c.mireds),
        opt(c.hue),
        opt(c.saturation),
    )
}

fn describe_gpd(g: &GpdAddress) -> String {
    match g {
        GpdAddress::SrcId(id) => format!("GPD {id:#010x}"),
        GpdAddress::Ieee { ieee, endpoint } => format!("GPD {} endpoint {endpoint}", Ieee(*ieee)),
    }
}

fn print_summary(d: &DeviceSummary) {
    println!(
        "{}  {:#06x}  {:<18} {:<11} {:<8} last seen {:<20} {}",
        Ieee(d.ieee),
        d.short,
        d.category.name(),
        d.interview.name(),
        if d.present { "present" } else { "left" },
        seen(d.last_seen_s),
        text(&d.model)
    );
}

fn print_device(d: &DeviceInfo) {
    let s = &d.summary;
    println!("device        {}", Ieee(s.ieee));
    println!(
        "network addr  {:#06x}{}",
        s.short,
        if s.present { "" } else { " (left)" }
    );
    println!("manufacturer  {}", text(&d.manufacturer));
    println!("model         {}", text(&s.model));
    println!("sw build      {}", text(&d.sw_build));
    if let Some(m) = d.manufacturer_code {
        println!("mfr code      {m:#06x}");
    }
    if let Some(t) = d.logical_type {
        println!("type          {}", t.name());
    }
    if let Some(rx) = d.rx_on_when_idle {
        println!("rx on idle    {}", if rx { "yes" } else { "no (sleepy)" });
    }
    println!("power         {}", d.power_source.name());
    println!("category      {}", s.category.name());
    println!(
        "capabilities  {}",
        s.capabilities.names().collect::<Vec<_>>().join(", ")
    );
    println!(
        "interview     {} ({})",
        s.interview.name(),
        d.interview_stage.name()
    );
    for e in &d.endpoints {
        let list = |l: &[u16]| {
            l.iter()
                .map(|c| format!("{c:#06x}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        println!(
            "endpoint {:<4} profile {:#06x} device {:#06x}\n  in:  {}\n  out: {}",
            e.endpoint,
            e.profile,
            e.device_id,
            list(&e.inputs),
            list(&e.outputs)
        );
    }
    if let Some(z) = d.zone {
        println!(
            "ias zone      endpoint {}, type {}, zone id {}, {}",
            z.endpoint,
            z.zone_type
                .map_or_else(|| "unknown".into(), |t| format!("{t:#06x}")),
            z.zone_id.map_or_else(|| "none".into(), |i| i.to_string()),
            if z.enrolled {
                "enrolled"
            } else {
                "not enrolled"
            }
        );
    }
    if let Some(l) = d.lqi {
        println!("lqi           {l}");
    }
    println!("last seen     {}", seen(s.last_seen_s));
    println!("state         {}", describe_state(&d.state));
}

fn list_devices(hub: &mut Hub) -> Result<(), String> {
    let mut start = 0u8;
    loop {
        match hub.call(Request::ListDevices { start })? {
            Response::DeviceList(l) => {
                if start == 0 {
                    println!("{} device(s)", l.total);
                }
                for d in &l.devices {
                    print_summary(d);
                }
                let n = u8::try_from(l.devices.len()).unwrap_or(u8::MAX);
                start = start.saturating_add(n);
                if n == 0 || start >= l.total {
                    return Ok(());
                }
            }
            Response::Error(e) => return Err(error_text(e)),
            r => return Err(format!("unexpected response: {r:?}")),
        }
    }
}

/// Runs a request that the hub accepts and completes over the radio.
fn run_command(hub: &mut Hub, request: Request) -> Result<(), String> {
    match hub.call(request)? {
        Response::Accepted { command } => {
            println!("command {command} accepted");
            match hub.outcome(command, Duration::from_mins(1))? {
                Event::CommandCompleted { stage, value, .. } => {
                    let what = match stage {
                        CommandStage::Confirmed => "done, state confirmed",
                        CommandStage::Responded => "done, the device answered",
                        _ => "done",
                    };
                    match value {
                        Some(v) => println!("{what}: {v}"),
                        None => println!("{what}"),
                    }
                    Ok(())
                }
                e => Err(describe_event(&e)),
            }
        }
        Response::Error(e) => Err(error_text(e)),
        r => Err(format!("unexpected response: {r:?}")),
    }
}

fn run(o: &Options) -> Result<(), String> {
    let args: Vec<&str> = o.args.iter().map(String::as_str).collect();
    if args.first() == Some(&"ports") {
        for p in serialport::available_ports().map_err(|e| e.to_string())? {
            let kind = match p.port_type {
                serialport::SerialPortType::UsbPort(u) => format!(
                    "USB {:04x}:{:04x} {}",
                    u.vid,
                    u.pid,
                    u.product.unwrap_or_default()
                ),
                other => format!("{other:?}"),
            };
            println!("{}  {kind}", p.port_name);
        }
        return Ok(());
    }
    if args.is_empty() {
        return Err(String::new());
    }
    if let ["partitions", "check", csv, ..] = args.as_slice() {
        return partitions_check(csv, &o.args, o.json);
    }
    let port = match &o.port {
        Some(p) => p.clone(),
        None => find_port()?,
    };
    let mut hub = Hub::open(&port, o.timeout, o.verbose)?;
    let as_json = o.json;
    let unexpected = |r: Response| match r {
        Response::Error(e) => Err(error_text(e)),
        r => Err(format!("unexpected response: {r:?}")),
    };
    match args.as_slice() {
        ["info"] => match hub.call(Request::GetHubInfo)? {
            Response::HubInfo(h) => {
                println!("hub           {}", Ieee(h.ieee));
                println!("firmware      {}", text(&h.firmware));
                println!("protocol      v{}", h.protocol_version);
                println!(
                    "registry      {} devices max, {}",
                    h.max_devices,
                    if h.persistent {
                        "persistent"
                    } else {
                        "RAM only (no storage partition)"
                    }
                );
                println!("uptime        {} s", h.uptime_s);
                Ok(())
            }
            r => unexpected(r),
        },
        ["network"] => match hub.call(Request::GetNetworkStatus)? {
            Response::NetworkStatus(s) => {
                println!("state         {}", s.state.name());
                println!("PAN id        {:#06x}", s.network.pan_id);
                println!("extended PAN  {}", Ieee(s.network.extended_pan_id));
                println!("channel       {}", s.network.channel);
                println!("coordinator   {:#06x}", s.short);
                println!(
                    "permit join   {}",
                    if s.permit_join_s == 0 {
                        "closed".into()
                    } else {
                        format!("open, {} s left", s.permit_join_s)
                    }
                );
                println!("devices       {}", s.devices);
                Ok(())
            }
            r => unexpected(r),
        },
        ["permit-join", secs] => {
            expect_done(hub.call(Request::PermitJoin {
                seconds: number(secs)?,
            })?)?;
            println!("network open for joining for {secs} s");
            Ok(())
        }
        ["close"] => {
            expect_done(hub.call(Request::CloseNetwork)?)?;
            println!("network closed");
            Ok(())
        }
        ["devices"] => list_devices(&mut hub),
        ["devices", "watch"] => {
            list_devices(&mut hub)?;
            println!("-- events (Ctrl+C to stop) --");
            hub.watch()
        }
        ["watch"] => hub.watch(),
        ["device", id] | ["device", id, "info"] => {
            match hub.call(Request::GetDevice { ieee: ieee(id)? })? {
                Response::Device(d) => {
                    print_device(&d);
                    Ok(())
                }
                r => unexpected(r),
            }
        }
        ["device", id, "fingerprint"] => match hub.call(Request::GetDevice { ieee: ieee(id)? })? {
            Response::Device(d) => {
                fingerprint::print(&d, as_json);
                Ok(())
            }
            r => unexpected(r),
        },
        ["device", id, "state"] => match hub.call(Request::GetDeviceState { ieee: ieee(id)? })? {
            Response::DeviceState {
                state, last_seen_s, ..
            } => {
                println!("{}", describe_state(&state));
                println!("last seen {}", seen(last_seen_s));
                Ok(())
            }
            r => unexpected(r),
        },
        ["device", id, "interview"] => {
            let target = ieee(id)?;
            expect_done(hub.call(Request::InterviewDevice { ieee: target })?)?;
            println!("interview restarted; waiting (a sleepy device answers when it wakes up)");
            let deadline = Instant::now() + Duration::from_mins(2);
            while Instant::now() < deadline {
                match hub.rx.recv_timeout(Duration::from_secs(1)) {
                    Ok(Message::Event { event, .. }) => {
                        println!("{}", describe_event(&event));
                        if matches!(event, Event::DeviceInterviewCompleted { ieee, .. } if ieee == target)
                        {
                            return Ok(());
                        }
                    }
                    Ok(_) | Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => return Err("serial port closed".into()),
                }
            }
            Err("the interview did not finish within 120 s; `watch` shows its progress".into())
        }
        ["device", id, "remove", rest @ ..] => {
            let leave = rest.contains(&"--leave");
            expect_done(hub.call(Request::RemoveDevice {
                ieee: ieee(id)?,
                leave,
            })?)?;
            println!(
                "{}",
                if leave {
                    "leave requested, device removed"
                } else {
                    "removed from the registry (still on the network)"
                }
            );
            Ok(())
        }
        ["light", id, "color"] => match hub.call(Request::GetLightColor { ieee: ieee(id)? })? {
            Response::LightColor { color, .. } => {
                println!("{}", describe_color(&color));
                Ok(())
            }
            Response::Error(e) => Err(error_text(e)),
            other => Err(format!("unexpected response {other:?}")),
        },
        ["group", op @ ("add" | "remove"), id, group] => {
            let (ieee, endpoint, group) = (
                ieee(id)?,
                flag_value(&o.args, "--endpoint", 0u8)?,
                number(group)?,
            );
            run_command(
                &mut hub,
                if *op == "add" {
                    Request::AddGroup {
                        ieee,
                        endpoint,
                        group,
                    }
                } else {
                    Request::RemoveGroup {
                        ieee,
                        endpoint,
                        group,
                    }
                },
            )
        }
        ["group", "light", group, action, rest @ ..] => {
            let command = light_command(&o.args, action, rest)?;
            expect_done(hub.call(Request::GroupLight {
                group: number(group)?,
                command,
            })?)?;
            println!("sent to group {group}");
            Ok(())
        }
        ["scene", "store", id, group, scene] => run_command(
            &mut hub,
            Request::StoreScene {
                ieee: ieee(id)?,
                endpoint: flag_value(&o.args, "--endpoint", 0u8)?,
                group: number(group)?,
                scene: number(scene)?,
            },
        ),
        ["scene", "recall", group, scene] => {
            expect_done(hub.call(Request::RecallScene {
                group: number(group)?,
                scene: number(scene)?,
                transition_ds: flag_value(&o.args, "--transition", 0u16)?,
            })?)?;
            println!("recalled scene {scene} of group {group}");
            Ok(())
        }
        ["light", id, action, rest @ ..] => {
            let endpoint = flag_value(&o.args, "--endpoint", 0u8)?;
            let command = light_command(&o.args, action, rest)?;
            run_command(
                &mut hub,
                Request::Light {
                    ieee: ieee(id)?,
                    endpoint,
                    command,
                },
            )
        }
        ["read", id, ep, cluster, attribute] => run_command(
            &mut hub,
            Request::ReadAttribute {
                ieee: ieee(id)?,
                endpoint: number(ep)?,
                cluster: number(cluster)?,
                attribute: number(attribute)?,
            },
        ),
        ["bind", id, ep, cluster] => run_command(
            &mut hub,
            Request::Bind {
                ieee: ieee(id)?,
                endpoint: number(ep)?,
                cluster: number(cluster)?,
            },
        ),
        ["report", id, ep, cluster, attribute, ty, min, max, change] => run_command(
            &mut hub,
            Request::ConfigureReporting {
                ieee: ieee(id)?,
                endpoint: number(ep)?,
                cluster: number(cluster)?,
                attribute: number(attribute)?,
                data_type: number(ty)?,
                min_interval: number(min)?,
                max_interval: number(max)?,
                change: number(change)?,
            },
        ),
        ["diagnostics"] => match hub.call(Request::GetDiagnostics)? {
            Response::Diagnostics(d) => {
                println!("{d:#?}");
                Ok(())
            }
            r => unexpected(r),
        },
        ["diagnostics", rest @ ..] => diagcmd::run(&mut hub, rest, as_json),
        ["capture", rest @ ..] => capturecmd::run(&mut hub, rest),
        ["security", rest @ ..] => securitycmd::run(&mut hub, rest, as_json),
        ["ota", rest @ ..] => otacmd::run(&mut hub, rest, &o.args),
        ["gp", "commission", ..] => {
            let seconds = flag_value(&o.args, "--seconds", 180u16)?;
            expect_done(hub.call(Request::GreenPowerCommission { seconds })?)?;
            println!(
                "Green Power commissioning open for {seconds} s: press the switch's commissioning button"
            );
            Ok(())
        }
        ["gp", "close"] => {
            expect_done(hub.call(Request::GreenPowerCommission { seconds: 0 })?)?;
            println!("Green Power commissioning closed");
            Ok(())
        }
        ["gp", "list"] => {
            let mut start = 0u8;
            loop {
                match hub.call(Request::ListGreenPowerDevices { start })? {
                    Response::GreenPowerDevices(l) => {
                        for d in &l.devices {
                            println!("{}  device id {:#04x}", describe_gpd(&d.gpd), d.device_id);
                        }
                        let next = usize::from(l.start) + l.devices.len();
                        if l.devices.is_empty() || next >= usize::from(l.total) {
                            if l.total == 0 {
                                println!("no Green Power Device paired");
                            }
                            return Ok(());
                        }
                        start = u8::try_from(next).unwrap_or(u8::MAX);
                    }
                    Response::Error(e) => return Err(error_text(e)),
                    r => return Err(format!("unexpected response {r:?}")),
                }
            }
        }
        ["gp", "remove", id] => {
            let gpd = GpdAddress::SrcId(number(id)?);
            expect_done(hub.call(Request::RemoveGreenPowerDevice { gpd })?)?;
            println!("{} removed", describe_gpd(&gpd));
            Ok(())
        }
        ["alerts", rest @ ..] => alertscmd::run(&mut hub, rest, as_json),
        ["self-test", rest @ ..] => {
            let options = selftest::Options {
                allow_reboot: rest.contains(&"--allow-reboot"),
                join_test: rest.contains(&"--join-test"),
                join_seconds: flag_value(&o.args, "--join-seconds", 120u8)?,
            };
            let results = selftest::run(&mut hub, &port, &options);
            if selftest::print(&results, as_json) {
                Ok(())
            } else {
                Err(FAILED.into())
            }
        }
        ["hil", kind, id, rest @ ..] => {
            let options = hil::Options {
                unattended: rest.contains(&"--unattended"),
                wait: Duration::from_secs(flag_value(&o.args, "--wait", 60u64)?),
            };
            let report = rest
                .iter()
                .position(|a| *a == "--report")
                .and_then(|i| rest.get(i + 1).copied());
            if hil::run(&mut hub, kind, ieee(id)?, &options, report)? {
                Ok(())
            } else {
                Err(FAILED.into())
            }
        }
        _ => Err(USAGE.into()),
    }
}

/// A failure already reported on stdout (exit code 1, nothing more to print).
const FAILED: &str = "\u{0}failed";

fn partitions_check(csv_path: &str, args: &[String], as_json: bool) -> Result<(), String> {
    use panweave_hub::partitions::{parse_csv, validate};
    let csv = std::fs::read_to_string(csv_path).map_err(|e| format!("{csv_path}: {e}"))?;
    let table = parse_csv(&csv).map_err(|e| format!("{csv_path} line {}: {}", e.line, e.what))?;
    let flash: u32 = flag_value(args, "--flash-size", 0x40_0000u32)?;
    let image = match args.iter().position(|a| a == "--image") {
        Some(i) => {
            let path = args.get(i + 1).ok_or("--image needs a value")?;
            let len = std::fs::metadata(path)
                .map_err(|e| format!("{path}: {e}"))?
                .len();
            Some(u32::try_from(len).map_err(|_| format!("{path}: too large"))?)
        }
        None => None,
    };
    let findings = validate(&table, flash, image);
    if as_json {
        let items: Vec<String> = findings
            .iter()
            .map(|f| {
                json::Obj::new()
                    .int("code", f.code().into())
                    .str("description", f.describe())
                    .opt("partition", f.partition().map(i128::from))
                    .bool("fatal", f.is_fatal())
                    .finish()
            })
            .collect();
        println!(
            "{}",
            json::Obj::new()
                .int("partitions", i128::try_from(table.len()).unwrap_or(0))
                .raw("findings", &json::array(&items))
                .finish()
        );
    } else {
        for (i, p) in table.iter().enumerate() {
            println!(
                "{i:>2}: {:<10} type {:#04x} subtype {:#04x} offset {:#08x} size {:#08x}",
                p.label, p.kind, p.subtype, p.offset, p.size
            );
        }
        for f in &findings {
            println!(
                "{} {}{}",
                if f.is_fatal() { "error:  " } else { "warning:" },
                f.describe(),
                f.partition()
                    .map_or_else(String::new, |p| format!(" (partition {p})"))
            );
        }
        if findings.is_empty() {
            println!("valid hub layout for {} KiB of flash", flash / 1024);
        }
    }
    if findings.iter().any(|f| f.is_fatal()) {
        Err(FAILED.into())
    } else {
        Ok(())
    }
}

fn main() -> ExitCode {
    // Ctrl+C asks long-running commands to stop; a second one ends the
    // process at once.
    let _ = ctrlc::set_handler(|| {
        if STOP.swap(true, Ordering::SeqCst) {
            std::process::exit(130);
        }
    });
    let options = match parse_options() {
        Ok(o) => o,
        Err(e) => {
            if e.is_empty() {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    match run(&options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e.is_empty() => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
        Err(e) if e == FAILED => ExitCode::FAILURE,
        Err(e) => {
            if let Some(rest) = e.strip_prefix(UNREACHABLE) {
                eprintln!("{rest}");
                return ExitCode::from(3);
            }
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn numbers_and_addresses_parse() {
        assert_eq!(number::<u16>("0x0500").unwrap(), 0x0500);
        assert_eq!(number::<u8>("180").unwrap(), 180);
        assert!(number::<u8>("300").is_err());
        assert!(number::<u8>("abc").is_err());
        assert_eq!(
            ieee("00:11:22:33:44:55:66:77").unwrap(),
            0x0011_2233_4455_6677
        );
        let args: Vec<String> = ["light", "x", "brightness", "50", "--transition", "20"]
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(flag_value(&args, "--transition", 0u16).unwrap(), 20);
        assert_eq!(flag_value(&args, "--endpoint", 0u8).unwrap(), 0);
    }

    #[test]
    fn states_describe_only_what_is_known() {
        assert_eq!(describe_state(&DeviceState::default()), "unknown");
        let s = DeviceState {
            water_leak: LeakState::Leak,
            battery_percent: Some(40),
            ..DeviceState::default()
        };
        assert_eq!(describe_state(&s), "water=LEAK battery=40 %");
    }
}
