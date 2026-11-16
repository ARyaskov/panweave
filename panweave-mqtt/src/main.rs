//! `panweave-mqtt`: the Panweave hub's devices on an MQTT broker, with
//! Home Assistant discovery.
//!
//! ```text
//! panweave-mqtt [--port PORT] [--broker HOST:PORT] [--username NAME]
//!               [--password-env VAR] [--client-id ID] [--base-topic T]
//!               [--discovery-prefix P] [--group N=NAME]… [--no-admin] [--verbose]
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
use std::net::{TcpStream, ToSocketAddrs};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender as Sender, TrySendError};
use std::thread;
use std::time::{Duration, Instant};

use panweave_hub::protocol::frame::{FrameDecoder, MAX_WIRE};
use panweave_hub::protocol::{ErrorCode, Message, Request, Response};
use panweave_mqtt::mqtt::{self, Connect, Decoder, Packet};
use panweave_mqtt::{Action, Bridge, Config};

const ESPRESSIF_VID: u16 = 0x303a;
const KEEP_ALIVE: u16 = 60;
/// Hub requests without a response after this long are forgotten.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const USAGE: &str = "usage: panweave-mqtt [--port PORT] [--broker HOST:PORT] [--username NAME]
                     [--password-env VAR] [--client-id ID] [--base-topic TOPIC]
                     [--discovery-prefix PREFIX] [--group N=NAME]... [--no-admin] [--verbose]";

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
            "--group" => {
                let v = value()?;
                let (n, name) = v
                    .split_once('=')
                    .ok_or_else(|| format!("--group {v}: expected N=NAME"))?;
                let n = n.trim();
                let group = n
                    .strip_prefix("0x")
                    .map_or_else(|| n.parse::<u16>(), |h| u16::from_str_radix(h, 16))
                    .ok()
                    .filter(|g| (1..=0xfff7).contains(g))
                    .ok_or_else(|| format!("--group {v}: group 1–0xfff7 expected"))?;
                o.config.groups.push((group, name.trim().to_string()));
            }
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

/// Maximum buffered inputs and outstanding hub requests.
const INPUT_CAPACITY: usize = 64;
const MAX_PENDING: usize = 64;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_millis(250);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

// Epochs prevent an old reader's buffered close or response from affecting a new link.
#[allow(clippy::large_enum_variant)]
enum Input {
    Hub(u64, Message),
    HubClosed(u64),
    Mqtt(u64, Packet),
    MqttClosed(u64, String),
}

struct ReaderTask {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl ReaderTask {
    fn spawn(run: impl FnOnce(Arc<AtomicBool>) + Send + 'static) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let token = stop.clone();
        Self {
            stop,
            handle: Some(thread::spawn(move || run(token))),
        }
    }
}

impl Drop for ReaderTask {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            // Reads have finite timeouts and channel delivery observes the same token.
            let _ = handle.join();
        }
    }
}

struct Connection<T> {
    io: T,
    _reader: ReaderTask,
}

impl<T> std::ops::Deref for Connection<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.io
    }
}
impl<T> std::ops::DerefMut for Connection<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.io
    }
}

fn deliver(tx: &Sender<Input>, stop: &AtomicBool, mut input: Input) -> bool {
    while !stop.load(Ordering::Acquire) {
        match tx.try_send(input) {
            Ok(()) => return true,
            Err(TrySendError::Full(value)) => {
                input = value;
                thread::sleep(Duration::from_millis(1));
            }
            Err(TrySendError::Disconnected(_)) => return false,
        }
    }
    false
}

fn open_hub(
    name: &str,
    epoch: u64,
    tx: Sender<Input>,
) -> Result<Connection<Box<dyn serialport::SerialPort>>, String> {
    let mut port = serialport::new(name, 115_200)
        .timeout(Duration::from_millis(50))
        .open()
        .map_err(|e| format!("opening {name}: {e}"))?;
    // Avoid the ESP32-C6 reset pattern used by flashing tools.
    let _ = port.write_data_terminal_ready(false);
    let _ = port.write_request_to_send(false);
    let mut reader = port
        .try_clone()
        .map_err(|e| format!("cloning {name}: {e}"))?;
    let task = ReaderTask::spawn(move |stop| {
        let mut decoder = FrameDecoder::new();
        let mut buf = [0u8; 256];
        while !stop.load(Ordering::Acquire) {
            let n = match reader.read(&mut buf) {
                Ok(0) => {
                    deliver(&tx, &stop, Input::HubClosed(epoch));
                    return;
                }
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(_) => {
                    deliver(&tx, &stop, Input::HubClosed(epoch));
                    return;
                }
            };
            for &b in &buf[..n] {
                if let Some(Ok(body)) = decoder.push(b)
                    && let Ok(message) = Message::decode(body)
                    && !deliver(&tx, &stop, Input::Hub(epoch, message))
                {
                    return;
                }
            }
        }
    });
    Ok(Connection {
        io: port,
        _reader: task,
    })
}

fn open_mqtt(
    o: &Options,
    will_topic: &str,
    epoch: u64,
    tx: Sender<Input>,
) -> Result<Connection<TcpStream>, String> {
    let addresses = o
        .broker
        .to_socket_addrs()
        .map_err(|e| format!("resolving broker: {e}"))?;
    let mut connected = None;
    let mut last_error = None;
    for address in addresses.take(4) {
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(stream) => {
                connected = Some(stream);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let mut stream = connected.ok_or_else(|| match last_error {
        Some(error) => format!("connecting to {}: {error}", o.broker),
        None => format!("no addresses for {}", o.broker),
    })?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(CONNECT_TIMEOUT))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&mqtt::connect(&Connect {
            client_id: &o.client_id,
            keep_alive: KEEP_ALIVE,
            will: Some((will_topic, b"offline")),
            username: o.username.as_deref(),
            password: o.password.as_deref(),
        }))
        .map_err(|e| format!("writing CONNECT: {e}"))?;
    let mut reader = stream.try_clone().map_err(|e| e.to_string())?;
    let task = ReaderTask::spawn(move |stop| {
        let mut decoder = Decoder::new();
        let mut buf = [0u8; 4096];
        while !stop.load(Ordering::Acquire) {
            let n = match reader.read(&mut buf) {
                Ok(0) => {
                    deliver(
                        &tx,
                        &stop,
                        Input::MqttClosed(epoch, "closed by the broker".into()),
                    );
                    return;
                }
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(e) => {
                    deliver(&tx, &stop, Input::MqttClosed(epoch, e.to_string()));
                    return;
                }
            };
            decoder.push(&buf[..n]);
            loop {
                match decoder.next_packet() {
                    Ok(Some(packet)) => {
                        if !deliver(&tx, &stop, Input::Mqtt(epoch, packet)) {
                            return;
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        deliver(
                            &tx,
                            &stop,
                            Input::MqttClosed(epoch, format!("protocol error: {error:?}")),
                        );
                        return;
                    }
                }
            }
        }
    });
    Ok(Connection {
        io: stream,
        _reader: task,
    })
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
    hub: Option<Connection<Box<dyn serialport::SerialPort>>>,
    mqtt: Option<Connection<TcpStream>>,
    /// CONNACK and successful SUBACK received.
    mqtt_ready: bool,
    next_id: u16,
    pending: BTreeMap<u16, (Request, Instant)>,
    last_ping: Instant,
    hub_epoch: u64,
    mqtt_epoch: u64,
    connected_at: Instant,
    awaiting_suback: bool,
    ping_at: Option<Instant>,
    early_publications: Vec<Packet>,
}

impl Runner {
    fn new(o: Options) -> Self {
        let (tx, rx) = mpsc::sync_channel(INPUT_CAPACITY);
        let bridge = Bridge::new(o.config.clone());
        Self {
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
            hub_epoch: 0,
            mqtt_epoch: 0,
            connected_at: Instant::now(),
            awaiting_suback: false,
            ping_at: None,
            early_publications: Vec::new(),
        }
    }

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
                        self.disconnect_mqtt();
                        self.mqtt_ready = false;
                    }
                }
                Action::Request(r) => self.send_hub(r),
            }
        }
    }

    fn fail_request(&mut self, request: &Request, error: ErrorCode) {
        let actions = self
            .bridge
            .on_response(request, Response::Error(error), self.now());
        self.act(actions);
    }

    fn disconnect_mqtt(&mut self) {
        self.mqtt_epoch = self.mqtt_epoch.wrapping_add(1);
        self.mqtt = None;
        self.mqtt_ready = false;
        self.awaiting_suback = false;
        self.ping_at = None;
        self.early_publications.clear();
    }

    fn disconnect_hub(&mut self) {
        self.hub_epoch = self.hub_epoch.wrapping_add(1);
        self.hub = None;
        for (_, (request, _)) in core::mem::take(&mut self.pending) {
            self.fail_request(&request, ErrorCode::NetworkDown);
        }
        let actions = self.bridge.hub_disconnected(self.now());
        self.act(actions);
    }

    fn send_hub(&mut self, request: Request) {
        if self.hub.is_none() {
            self.fail_request(&request, ErrorCode::NetworkDown);
            return;
        }
        if self.pending.len() >= MAX_PENDING {
            self.fail_request(&request, ErrorCode::Busy);
            return;
        }
        let mut id = self.next_id;
        while self.pending.contains_key(&id) {
            id = id.wrapping_add(1).max(1);
        }
        self.next_id = id.wrapping_add(1).max(1);
        let mut wire = [0u8; MAX_WIRE];
        let Ok(n) = (Message::Request {
            id,
            request: request.clone(),
        })
        .encode_frame(&mut wire) else {
            self.fail_request(&request, ErrorCode::Malformed);
            return;
        };
        let result = self.hub.as_mut().map(|port| port.write_all(&wire[..n]));
        if !matches!(result, Some(Ok(()))) {
            self.disconnect_hub();
            // A partial write may have executed a non-idempotent command: never replay it.
            self.fail_request(&request, ErrorCode::SendFailed);
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
        self.hub_epoch = self.hub_epoch.wrapping_add(1);
        match open_hub(&name, self.hub_epoch, self.tx.clone()) {
            Ok(p) => {
                log(&format!("hub on {name}"));
                self.hub = Some(p);
                self.pending.clear();
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
        self.mqtt_epoch = self.mqtt_epoch.wrapping_add(1);
        match open_mqtt(&self.o, &will, self.mqtt_epoch, self.tx.clone()) {
            Ok(s) => {
                self.mqtt = Some(s);
                self.mqtt_ready = false;
                self.last_ping = Instant::now();
                self.connected_at = Instant::now();
                self.awaiting_suback = false;
                self.ping_at = None;
            }
            Err(e) => log(&e),
        }
    }

    fn on_mqtt(&mut self, p: Packet) {
        // MQTT permits publications after SUBSCRIBE and before SUBACK.
        // Retain a bounded batch until the subscription result is known.
        if matches!(&p, Packet::Publish { .. }) && !self.mqtt_ready {
            if !self.awaiting_suback || self.early_publications.len() >= INPUT_CAPACITY {
                self.disconnect_mqtt();
            } else {
                self.early_publications.push(p);
            }
            return;
        }
        match p {
            Packet::ConnAck { code: 0, .. } => {
                log(&format!("connected to {}", self.o.broker));
                let filters = self.bridge.subscriptions();
                let refs: Vec<&str> = filters.iter().map(String::as_str).collect();
                if let Some(s) = self.mqtt.as_mut()
                    && s.write_all(&mqtt::subscribe(1, &refs)).is_err()
                {
                    self.disconnect_mqtt();
                    return;
                }
                self.awaiting_suback = true;
            }
            Packet::ConnAck { code, .. } => {
                log(&format!(
                    "the broker refused the connection: {}",
                    mqtt::connack_reason(code)
                ));
                self.disconnect_mqtt();
            }
            Packet::Publish {
                topic,
                payload,
                qos,
                packet_id,
                ..
            } if self.mqtt_ready => {
                if qos == 1
                    && let (Some(id), Some(s)) = (packet_id, self.mqtt.as_mut())
                    && s.write_all(&mqtt::puback(id)).is_err()
                {
                    self.disconnect_mqtt();
                    self.mqtt_ready = false;
                    return;
                }
                let now = self.now();
                let a = self.bridge.on_mqtt(&topic, &payload, now);
                self.act(a);
            }
            Packet::SubAck {
                packet_id: 1,
                codes,
            } if self.awaiting_suback => {
                if codes.len() != self.bridge.subscriptions().len()
                    || codes.iter().any(|code| *code > 1)
                {
                    log("the broker refused a subscription");
                    self.disconnect_mqtt();
                } else {
                    self.awaiting_suback = false;
                    self.mqtt_ready = true;
                    if self.hub.is_some() {
                        let actions = self.bridge.start(self.now());
                        self.act(actions);
                    }
                    for packet in core::mem::take(&mut self.early_publications) {
                        if self.mqtt.is_none() {
                            break;
                        }
                        self.on_mqtt(packet);
                    }
                }
            }
            Packet::PingResp => self.ping_at = None,
            _ => {}
        }
    }

    fn on_input(&mut self, input: Input) {
        match input {
            Input::Hub(epoch, Message::Response { id, response })
                if epoch == self.hub_epoch && self.hub.is_some() =>
            {
                if let Some((request, _)) = self.pending.remove(&id) {
                    let actions = self.bridge.on_response(&request, response, self.now());
                    self.act(actions);
                }
            }
            Input::Hub(epoch, Message::Event { event, .. })
                if epoch == self.hub_epoch && self.hub.is_some() =>
            {
                let actions = self.bridge.on_event(event, self.now());
                self.act(actions);
            }
            Input::HubClosed(epoch) if epoch == self.hub_epoch && self.hub.is_some() => {
                log("hub connection lost");
                self.disconnect_hub();
            }
            Input::Mqtt(epoch, packet) if epoch == self.mqtt_epoch && self.mqtt.is_some() => {
                self.on_mqtt(packet);
            }
            Input::MqttClosed(epoch, why) if epoch == self.mqtt_epoch && self.mqtt.is_some() => {
                log(&format!("broker connection lost: {why}"));
                self.disconnect_mqtt();
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
                Ok(input) => self.on_input(input),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            if last_tick.elapsed() >= Duration::from_secs(1) {
                last_tick = Instant::now();
                let expired: Vec<_> = self
                    .pending
                    .iter()
                    .filter(|(_, (_, at))| at.elapsed() >= REQUEST_TIMEOUT)
                    .map(|(&id, _)| id)
                    .collect();
                for id in expired {
                    if let Some((request, _)) = self.pending.remove(&id) {
                        self.fail_request(&request, ErrorCode::Timeout);
                    }
                }
                if self.mqtt_ready {
                    let now = self.now();
                    let a = self.bridge.tick(now);
                    self.act(a);
                }
            }
            if self.mqtt.is_some()
                && (!self.mqtt_ready && self.connected_at.elapsed() >= HANDSHAKE_TIMEOUT
                    || self
                        .ping_at
                        .is_some_and(|at| at.elapsed() >= HANDSHAKE_TIMEOUT))
            {
                log("broker handshake or keep-alive timed out");
                self.disconnect_mqtt();
                self.mqtt_ready = false;
                self.ping_at = None;
            }
            if self.mqtt_ready
                && self.ping_at.is_none()
                && self.last_ping.elapsed() >= Duration::from_secs(u64::from(KEEP_ALIVE / 2))
            {
                self.last_ping = Instant::now();
                if let Some(socket) = self.mqtt.as_mut() {
                    if socket.write_all(&mqtt::pingreq()).is_err() {
                        self.disconnect_mqtt();
                        self.mqtt_ready = false;
                    } else {
                        self.ping_at = Some(Instant::now());
                    }
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
    let mut r = Runner::new(o);
    r.run(&stop);
    ExitCode::SUCCESS
}

#[cfg(test)]
mod transport_tests {
    use super::*;

    #[test]
    fn a_full_input_queue_does_not_prevent_reader_cancellation_and_join() {
        let (tx, rx) = mpsc::sync_channel(1);
        assert!(tx.try_send(Input::HubClosed(1)).is_ok());
        let (finished_tx, finished_rx) = mpsc::channel();
        let task = ReaderTask::spawn(move |stop| {
            assert!(!deliver(&tx, &stop, Input::HubClosed(2)));
            assert!(finished_tx.send(()).is_ok());
        });
        drop(task);
        assert!(finished_rx.try_recv().is_ok());
        assert!(matches!(rx.try_recv(), Ok(Input::HubClosed(1))));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn closing_a_silent_tcp_connection_joins_and_releases_its_reader() -> std::io::Result<()> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let options = Options {
            port: None,
            broker: listener.local_addr()?.to_string(),
            username: None,
            password: None,
            client_id: "transport-test".into(),
            config: Config::default(),
            verbose: false,
        };
        let (tx, _rx) = mpsc::sync_channel(1);
        let connection = open_mqtt(&options, "test/state", 3, tx).map_err(std::io::Error::other)?;
        let (mut peer, _) = listener.accept()?;
        assert_eq!(connection.read_timeout()?, Some(IO_TIMEOUT));
        assert_eq!(connection.write_timeout()?, Some(CONNECT_TIMEOUT));
        peer.set_read_timeout(Some(Duration::from_secs(2)))?;
        drop(connection);
        let mut bytes = [0u8; 256];
        let mut received = 0;
        loop {
            let n = peer.read(&mut bytes)?;
            if n == 0 {
                break;
            }
            received += n;
        }
        assert!(received > 0, "the real CONNECT must reach the local peer");
        Ok(())
    }

    fn options(broker: String) -> Options {
        Options {
            port: None,
            broker,
            username: None,
            password: None,
            client_id: "transport-test".into(),
            config: Config::default(),
            verbose: false,
        }
    }

    #[test]
    fn closed_connections_cannot_deliver_buffered_events_or_subscription_answers() {
        let mut runner = Runner::new(options("127.0.0.1:1883".into()));
        let old_hub = runner.hub_epoch;
        runner.disconnect_hub();
        runner.on_input(Input::Hub(
            old_hub,
            Message::Event {
                seq: 0,
                event: panweave_hub::protocol::Event::DeviceJoined {
                    ieee: 42,
                    short: 42,
                    rejoin: false,
                },
            },
        ));
        assert!(!runner.bridge.devices().any(|ieee| ieee == 42));
        let old_mqtt = runner.mqtt_epoch;
        runner.awaiting_suback = true;
        runner.disconnect_mqtt();
        runner.on_input(Input::Mqtt(
            old_mqtt,
            Packet::SubAck {
                packet_id: 1,
                codes: vec![0; runner.bridge.subscriptions().len()],
            },
        ));
        assert!(!runner.mqtt_ready);
        runner.on_input(Input::Mqtt(
            runner.mqtt_epoch,
            Packet::ConnAck {
                code: 0,
                session_present: false,
            },
        ));
        assert!(
            !runner.awaiting_suback,
            "a live socket is required even for the current epoch"
        );
    }

    #[test]
    fn real_peer_publication_before_suback_is_delivered_after_suback() -> std::io::Result<()> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let mut runner = Runner::new(options(listener.local_addr()?.to_string()));
        runner.connect_mqtt();
        assert!(runner.mqtt.is_some(), "the local broker must connect");
        let (mut peer, _) = listener.accept()?;
        peer.set_read_timeout(Some(Duration::from_secs(2)))?;
        peer.set_write_timeout(Some(Duration::from_secs(2)))?;
        peer.write_all(&[0x20, 2, 0, 0])?;
        runner.on_input(
            runner
                .rx
                .recv_timeout(Duration::from_secs(2))
                .map_err(std::io::Error::other)?,
        );
        assert!(runner.awaiting_suback);
        peer.write_all(&mqtt::publish(
            "panweave/bridge/request/permit_join",
            b"OFF",
            false,
        ))?;
        runner.on_input(
            runner
                .rx
                .recv_timeout(Duration::from_secs(2))
                .map_err(std::io::Error::other)?,
        );
        assert_eq!(runner.early_publications.len(), 1);
        assert!(!runner.mqtt_ready);
        let filters = runner.bridge.subscriptions().len();
        let len = u8::try_from(filters + 2).map_err(std::io::Error::other)?;
        let mut suback = vec![0x90, len, 0, 1];
        suback.resize(4 + filters, 0);
        peer.write_all(&suback)?;
        runner.on_input(
            runner
                .rx
                .recv_timeout(Duration::from_secs(2))
                .map_err(std::io::Error::other)?,
        );
        assert!(runner.mqtt_ready);
        assert_eq!(runner.early_publications.len(), 0);
        runner.disconnect_mqtt();
        let mut received = Vec::new();
        peer.read_to_end(&mut received)?;
        assert!(
            received
                .windows(b"CloseNetwork".len())
                .any(|bytes| bytes == b"CloseNetwork"),
            "the early command must execute and publish its no-hub error after SUBACK"
        );
        Ok(())
    }
}
