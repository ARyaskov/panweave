//! `panweave-mqtt`: the Panweave hub's devices on an MQTT broker, with
//! Home Assistant discovery.
//!
//! ```text
//! panweave-mqtt [--port PORT] [--broker HOST:PORT] [--username NAME]
//!               [--password-env VAR] [--client-id ID] [--base-topic T]
//!               [--discovery-prefix P] [--no-admin] [--verbose]
//! ```
//!
//! The port defaults to `PANWEAVE_HUB_PORT`, else to the only Espressif
//! USB serial port found; the broker to `127.0.0.1:1883`. The password is
//! read from the environment variable named by `--password-env`, never
//! from the command line. The connection is plain TCP: run the broker on
//! the same host or reach it through a TLS tunnel. Both connections are
//! re-established when lost. See `docs/mqtt.md`.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use panweave_hub::protocol::frame::{FrameDecoder, MAX_WIRE};
use panweave_hub::protocol::{Message, Request};
use panweave_mqtt::mqtt::{self, Connect, Decoder, Packet};
use panweave_mqtt::{Action, Bridge, Config};

const ESPRESSIF_VID: u16 = 0x303a;
const KEEP_ALIVE: u16 = 60;
/// Hub requests without a response after this long are forgotten.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const USAGE: &str = "usage: panweave-mqtt [--port PORT] [--broker HOST:PORT] [--username NAME]
                     [--password-env VAR] [--client-id ID] [--base-topic TOPIC]
                     [--discovery-prefix PREFIX] [--no-admin] [--verbose]";

struct Options {
    port: Option<String>,
    broker: String,
    username: Option<String>,
    password: Option<Vec<u8>>,
    client_id: String,
    config: Config,
    verbose: bool,
}

fn parse_options() -> Result<Options, String> {
    let mut o = Options {
        port: std::env::var("PANWEAVE_HUB_PORT").ok(),
        broker: "127.0.0.1:1883".into(),
        username: None,
        password: None,
        client_id: "panweave-mqtt".into(),
        config: Config::default(),
        verbose: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "--port" => o.port = Some(value()?),
            "--broker" => o.broker = value()?,
            "--username" => o.username = Some(value()?),
            "--password-env" => {
                let var = value()?;
                let p = std::env::var(&var)
                    .map_err(|_| format!("environment variable {var} is not set"))?;
                o.password = Some(p.into_bytes());
            }
            "--client-id" => o.client_id = value()?,
            "--base-topic" => o.config.base_topic = value()?,
            "--discovery-prefix" => o.config.discovery_prefix = value()?,
            "--no-admin" => o.config.admin = false,
            "--verbose" => o.verbose = true,
            "--help" | "-h" => return Err(USAGE.into()),
            other => return Err(format!("unknown option {other}\n{USAGE}")),
        }
    }
    if o.password.is_some() && o.username.is_none() {
        return Err("--password-env needs --username".into());
    }
    Ok(o)
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
        [] => Err("no Espressif USB serial port found: pass --port".into()),
        _ => Err("several Espressif ports found: pass --port".into()),
    }
}

/// What the I/O threads hand the main loop.
// A hub message is large; inputs are moved once through the channel.
#[allow(clippy::large_enum_variant)]
enum Input {
    Hub(Message),
    HubClosed,
    Mqtt(Packet),
    MqttClosed(String),
}

fn open_hub(name: &str, tx: Sender<Input>) -> Result<Box<dyn serialport::SerialPort>, String> {
    let mut port = serialport::new(name, 115_200)
        .timeout(Duration::from_millis(50))
        .open()
        .map_err(|e| format!("opening {name}: {e}"))?;
    // The ESP32-C6's USB Serial/JTAG resets the chip on the RTS/DTR
    // pattern flashing tools use; keep both lines released.
    let _ = port.write_data_terminal_ready(false);
    let _ = port.write_request_to_send(false);
    let mut reader = port
        .try_clone()
        .map_err(|e| format!("cloning {name}: {e}"))?;
    thread::spawn(move || {
        let mut dec = FrameDecoder::new();
        let mut buf = [0u8; 256];
        loop {
            let n = match reader.read(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                Err(_) => {
                    let _ = tx.send(Input::HubClosed);
                    return;
                }
            };
            for &b in buf.get(..n).unwrap_or_default() {
                if let Some(Ok(body)) = dec.push(b)
                    && let Ok(m) = Message::decode(body)
                    && tx.send(Input::Hub(m)).is_err()
                {
                    return;
                }
            }
        }
    });
    Ok(port)
}

fn open_mqtt(o: &Options, will_topic: &str, tx: Sender<Input>) -> Result<TcpStream, String> {
    let mut stream =
        TcpStream::connect(&o.broker).map_err(|e| format!("connecting to {}: {e}", o.broker))?;
    stream
        .write_all(&mqtt::connect(&Connect {
            client_id: &o.client_id,
            keep_alive: KEEP_ALIVE,
            will: Some((will_topic, b"offline")),
            username: o.username.as_deref(),
            password: o.password.as_deref(),
        }))
        .map_err(|e| format!("writing to {}: {e}", o.broker))?;
    let mut reader = stream
        .try_clone()
        .map_err(|e| format!("cloning the socket: {e}"))?;
    thread::spawn(move || {
        let mut dec = Decoder::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = match reader.read(&mut buf) {
                Ok(0) => {
                    let _ = tx.send(Input::MqttClosed("closed by the broker".into()));
                    return;
                }
                Ok(n) => n,
                Err(e) => {
                    let _ = tx.send(Input::MqttClosed(e.to_string()));
                    return;
                }
            };
            dec.push(buf.get(..n).unwrap_or_default());
            loop {
                match dec.next_packet() {
                    Ok(Some(p)) => {
                        if tx.send(Input::Mqtt(p)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        let _ = tx.send(Input::MqttClosed(format!("protocol error: {e:?}")));
                        return;
                    }
                }
            }
        }
    });
    Ok(stream)
}

fn log(s: &str) {
    eprintln!("panweave-mqtt: {s}");
}

struct Runner {
    o: Options,
    bridge: Bridge,
    started: Instant,
    rx: Receiver<Input>,
    tx: Sender<Input>,
    hub: Option<Box<dyn serialport::SerialPort>>,
    mqtt: Option<TcpStream>,
    /// CONNACK received and subscriptions sent.
    mqtt_ready: bool,
    next_id: u16,
    pending: BTreeMap<u16, (Request, Instant)>,
    last_ping: Instant,
    /// Hub requests waiting for the serial port.
    queued: Vec<Request>,
}

impl Runner {
    fn now(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    fn act(&mut self, actions: Vec<Action>) {
        for a in actions {
            match a {
                Action::Publish(p) => {
                    if self.o.verbose {
                        log(&format!("publish {} ({} bytes)", p.topic, p.payload.len()));
                    }
                    if let Some(s) = self.mqtt.as_mut()
                        && self.mqtt_ready
                        && s.write_all(&mqtt::publish(&p.topic, &p.payload, p.retain))
                            .is_err()
                    {
                        self.mqtt = None;
                        self.mqtt_ready = false;
                    }
                }
                Action::Request(r) => self.send_hub(r),
            }
        }
    }

    fn send_hub(&mut self, request: Request) {
        let Some(port) = self.hub.as_mut() else {
            self.queued.push(request);
            return;
        };
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let mut wire = [0u8; MAX_WIRE];
        let Ok(n) = (Message::Request {
            id,
            request: request.clone(),
        })
        .encode_frame(&mut wire) else {
            return;
        };
        if port
            .write_all(wire.get(..n).unwrap_or_default())
            .and_then(|()| port.flush())
            .is_err()
        {
            self.hub = None;
            self.queued.push(request);
            return;
        }
        self.pending.insert(id, (request, Instant::now()));
    }

    fn connect_hub(&mut self) {
        let name = match self.o.port.clone().map_or_else(find_port, Ok) {
            Ok(n) => n,
            Err(e) => {
                log(&e);
                return;
            }
        };
        match open_hub(&name, self.tx.clone()) {
            Ok(p) => {
                log(&format!("hub on {name}"));
                self.hub = Some(p);
                self.pending.clear();
                for r in core::mem::take(&mut self.queued) {
                    self.send_hub(r);
                }
                if self.mqtt_ready {
                    let now = self.now();
                    let a = self.bridge.start(now);
                    self.act(a);
                }
            }
            Err(e) => log(&e),
        }
    }

    fn connect_mqtt(&mut self) {
        let will = self.bridge.state_topic();
        match open_mqtt(&self.o, &will, self.tx.clone()) {
            Ok(s) => {
                self.mqtt = Some(s);
                self.mqtt_ready = false;
                self.last_ping = Instant::now();
            }
            Err(e) => log(&e),
        }
    }

    fn on_mqtt(&mut self, p: Packet) {
        match p {
            Packet::ConnAck { code: 0, .. } => {
                log(&format!("connected to {}", self.o.broker));
                let filters = self.bridge.subscriptions();
                let refs: Vec<&str> = filters.iter().map(String::as_str).collect();
                if let Some(s) = self.mqtt.as_mut() {
                    let _ = s.write_all(&mqtt::subscribe(1, &refs));
                }
                self.mqtt_ready = true;
                let now = self.now();
                let a = self.bridge.start(now);
                self.act(a);
            }
            Packet::ConnAck { code, .. } => {
                log(&format!(
                    "the broker refused the connection: {}",
                    mqtt::connack_reason(code)
                ));
                self.mqtt = None;
            }
            Packet::Publish {
                topic,
                payload,
                qos,
                packet_id,
                ..
            } => {
                if qos == 1
                    && let (Some(id), Some(s)) = (packet_id, self.mqtt.as_mut())
                {
                    let _ = s.write_all(&mqtt::puback(id));
                }
                let now = self.now();
                let a = self.bridge.on_mqtt(&topic, &payload, now);
                self.act(a);
            }
            Packet::SubAck { codes, .. } if codes.contains(&0x80) => {
                log("the broker refused a subscription");
            }
            _ => {}
        }
    }

    fn run(&mut self, stop: &AtomicBool) {
        let mut retry_hub = Instant::now();
        let mut retry_mqtt = Instant::now();
        let mut last_tick = Instant::now();
        while !stop.load(Ordering::SeqCst) {
            if self.hub.is_none() && Instant::now() >= retry_hub {
                self.connect_hub();
                retry_hub = Instant::now() + Duration::from_secs(2);
            }
            if self.mqtt.is_none() && Instant::now() >= retry_mqtt {
                self.connect_mqtt();
                retry_mqtt = Instant::now() + Duration::from_secs(5);
            }
            match self.rx.recv_timeout(Duration::from_millis(250)) {
                Ok(Input::Hub(Message::Response { id, response })) => {
                    if let Some((request, _)) = self.pending.remove(&id) {
                        let now = self.now();
                        let a = self.bridge.on_response(&request, response, now);
                        self.act(a);
                    }
                }
                Ok(Input::Hub(Message::Event { event, .. })) => {
                    let now = self.now();
                    let a = self.bridge.on_event(event, now);
                    self.act(a);
                }
                Ok(Input::Hub(Message::Request { .. })) => {}
                Ok(Input::HubClosed) => {
                    log("hub connection lost");
                    self.hub = None;
                }
                Ok(Input::Mqtt(p)) => self.on_mqtt(p),
                Ok(Input::MqttClosed(why)) => {
                    log(&format!("broker connection lost: {why}"));
                    self.mqtt = None;
                    self.mqtt_ready = false;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            if last_tick.elapsed() >= Duration::from_secs(1) {
                last_tick = Instant::now();
                self.pending
                    .retain(|_, (_, at)| at.elapsed() < REQUEST_TIMEOUT);
                if self.mqtt_ready {
                    let now = self.now();
                    let a = self.bridge.tick(now);
                    self.act(a);
                }
            }
            if self.last_ping.elapsed() >= Duration::from_secs(u64::from(KEEP_ALIVE / 2)) {
                self.last_ping = Instant::now();
                if let Some(s) = self.mqtt.as_mut()
                    && s.write_all(&mqtt::pingreq()).is_err()
                {
                    self.mqtt = None;
                    self.mqtt_ready = false;
                }
            }
        }
        let a = self.bridge.stop();
        self.act(a);
        if let Some(s) = self.mqtt.as_mut() {
            let _ = s.write_all(&mqtt::disconnect());
        }
    }
}

fn main() -> ExitCode {
    let o = match parse_options() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        let _ = ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst));
    }
    let (tx, rx) = mpsc::channel();
    let bridge = Bridge::new(o.config.clone());
    let mut r = Runner {
        o,
        bridge,
        started: Instant::now(),
        rx,
        tx,
        hub: None,
        mqtt: None,
        mqtt_ready: false,
        next_id: 1,
        pending: BTreeMap::new(),
        last_ping: Instant::now(),
        queued: Vec::new(),
    };
    r.run(&stop);
    ExitCode::SUCCESS
}
