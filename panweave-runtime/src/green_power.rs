//! Green Power integration (GP Basic 1.1.2 §A.3.5.2.3, §A.3.5.2.4): the
//! GP stub receives GPDFs straight from the MAC (protocol version 3 frames
//! never reach the NWK layer), the Green Power EndPoint 242 receives the
//! cluster commands of sinks and proxies, the Basic Proxy tunnels its
//! notifications with NWK source aliasing after their tunnelling delay,
//! and the Basic Combo sink pairs GPDs, answers them as SelectedSender,
//! announces their aliases and executes their commands on the local
//! endpoints. Proxy and Sink Tables are persisted entry by entry.

use heapless::Vec;
use panweave_aps::Destination as ApsDestination;
use panweave_aps::layer::{DataRequest, Delivery, SecurityStatus, TxOptions};
use panweave_codec::{Decode, Encode, Reader, Writer};
use panweave_green_power::cluster::{
    self as gp_cluster, CommissioningNotification, CommunicationMode, GppGpdLink, Notification,
    Pairing, ProxyCommissioningMode, ProxyTableRequest, SinkCommissioningMode, SinkSecurityLevel,
    SinkTableRequest,
};
use panweave_green_power::gpdf::{GpdId, Gpdf};
use panweave_green_power::proxy::{
    Destination, Outgoing, PairingError, Proxy, ProxyConfig, ProxyEvent,
};
use panweave_green_power::proxy_table::{ProxyEntry, ProxyTable};
use panweave_green_power::security::KeyType;
use panweave_green_power::sink::{
    GpdCommand, GpdfTx, ModeError, Refusal, Sink, SinkConfig, SinkEvent,
};
use panweave_green_power::sink_table::{SinkEntry, SinkTable};
use panweave_green_power::translation::{self, Translated};
use panweave_mac::frame::Frame as MacFrame;
use panweave_security::cipher::BlockCipher;
use panweave_storage::{Key, Kind, Storage, StorageError};
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    CryptoRng, DeviceId, Endpoint, ExtendedAddress, GroupAddress, Key128, PanId, ProfileId,
    ShortAddress,
};
use panweave_zcl::frame::{Direction, Frame as ZclFrame, Header, ZclStatus};
use panweave_zcl::global::command as global_command;
use panweave_zcl::layer::{EndpointInstance, Origin, ZclIndication};
use panweave_zcl::{Access, AttributeDef, ClusterDef, ClusterInstance, DataType, Role, Value};
use panweave_zdo::descriptor::SimpleDescriptor;

use crate::context::AddrView;
use crate::stack::{EndpointError, Phase, Stack, StackEvent};

/// Proxy Table capacity (`gppMaxProxyTableEntries`, the recommended 20).
pub const PROXY_TABLE_ENTRIES: usize = 20;
/// Sink Table capacity (`gpsMaxSinkTableEntries`, 10).
pub const SINK_TABLE_ENTRIES: usize = 10;
/// The Basic Proxy of a stack.
pub type GpProxy = Proxy<PROXY_TABLE_ENTRIES>;
/// The Basic Combo sink of a stack.
pub type GpSink<C> = Sink<C, SINK_TABLE_ENTRIES>;
/// GP Proxy Basic device identifier (Table 23).
pub const PROXY_BASIC_DEVICE: DeviceId = DeviceId(0x0061);
/// GP Combo Basic device identifier (Table 23).
pub const COMBO_BASIC_DEVICE: DeviceId = DeviceId(0x0066);
/// Local endpoints a sink executes translated GPD commands on.
pub const SINK_ENDPOINTS: usize = 4;
/// Storage record ids of Sink Table entries start here (Proxy Table
/// entries use the indices below).
const SINK_RECORD_BASE: u64 = 0x100;

/// What a Basic Combo sink is configured with.
#[derive(Clone, Debug)]
pub struct SinkOptions {
    /// `gpsSecurityLevel` (the certifiable 0x06 by default).
    pub security_level: SinkSecurityLevel,
    /// `gpsCommunicationMode` (derived groupcast by default).
    pub communication_mode: CommunicationMode,
    /// The group paired in pre-commissioned groupcast mode.
    pub commissioned_group: Option<u16>,
    /// `gpSharedSecurityKeyType`.
    pub shared_key_type: KeyType,
    /// `gpSharedSecurityKey`.
    pub shared_key: Option<Key128>,
    /// `gpsCommissioningWindow`.
    pub commissioning_window: Duration,
    /// Local endpoints paired with every GPD (all application endpoints
    /// when empty).
    pub endpoints: Vec<Endpoint, SINK_ENDPOINTS>,
}

impl Default for SinkOptions {
    fn default() -> Self {
        SinkOptions {
            security_level: SinkSecurityLevel::DEFAULT,
            communication_mode: CommunicationMode::DerivedGroupcast,
            commissioned_group: None,
            shared_key_type: KeyType::None,
            shared_key: None,
            commissioning_window: panweave_green_power::proxy::DEFAULT_COMMISSIONING_WINDOW,
            endpoints: Vec::new(),
        }
    }
}

/// Green Power state of the stack.
pub struct GreenPower<C: BlockCipher> {
    /// The proxy.
    pub proxy: GpProxy,
    /// The sink, when this device is a Basic Combo.
    pub sink: Option<GpSink<C>>,
    /// Notifications waiting for their tunnelling delay.
    pending: Vec<Outgoing, 8>,
    /// GPDFs the sink transmits after gpTxOffset.
    gpdfs: Vec<GpdfTx, 2>,
    /// Local endpoints paired with the GPDs.
    endpoints: Vec<Endpoint, SINK_ENDPOINTS>,
}

impl<C: BlockCipher> GreenPower<C> {
    /// Earliest pending transmission or timer.
    pub fn next_deadline(&self) -> Option<Instant> {
        let mut best: Option<Instant> = None;
        let mut consider = |t: Option<Instant>| {
            if let Some(t) = t
                && best.is_none_or(|b| t.as_millis() < b.as_millis())
            {
                best = Some(t);
            }
        };
        for o in &self.pending {
            consider(Some(o.not_before));
        }
        for g in &self.gpdfs {
            consider(Some(g.not_before));
        }
        consider(self.proxy.next_deadline());
        if let Some(s) = &self.sink {
            consider(s.next_deadline());
        }
        best
    }
}

/// True when a MAC data payload starts with a GP stub NWK header
/// (Zigbee Protocol Version 3, §A.1.4.1.2).
pub(crate) fn is_gpdf(payload: &[u8]) -> bool {
    payload
        .first()
        .is_some_and(|fc| (fc >> 2) & 0x0F == panweave_green_power::gpdf::PROTOCOL_VERSION)
}

fn bits(width: u8, bits: u64) -> Value<'static> {
    Value::Bits { width, bits }
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> Stack<C, R, S> {
    /// Enables the Green Power Basic Proxy: registers the Green Power
    /// EndPoint (242, profile 0xA1E0, device GP Proxy Basic) with the
    /// Green Power cluster client and restores the persisted Proxy Table.
    pub fn enable_green_power_proxy(&mut self) -> Result<(), EndpointError> {
        if self.green_power.is_some() {
            return Ok(());
        }
        self.enable_green_power(None)
    }

    /// Enables the Green Power Basic Combo: the proxy of
    /// [`Self::enable_green_power_proxy`] plus the sink (Green Power
    /// cluster server on endpoint 242, device GP Combo Basic) with the
    /// persisted Sink Table. Must be called instead of, not after, the
    /// proxy-only enabling.
    pub fn enable_green_power_sink(&mut self, options: SinkOptions) -> Result<(), EndpointError> {
        if let Some(gp) = &self.green_power {
            return if gp.sink.is_some() {
                Ok(())
            } else {
                Err(EndpointError)
            };
        }
        self.enable_green_power(Some(options))
    }

    fn enable_green_power(&mut self, sink: Option<SinkOptions>) -> Result<(), EndpointError> {
        let (device, servers): (DeviceId, &[panweave_types::ClusterId]) = if sink.is_some() {
            (COMBO_BASIC_DEVICE, &[gp_cluster::ID])
        } else {
            (PROXY_BASIC_DEVICE, &[])
        };
        let desc = SimpleDescriptor::new(
            gp_cluster::ENDPOINT,
            gp_cluster::PROFILE,
            device,
            0,
            servers,
            &[gp_cluster::ID],
        )
        .ok_or(EndpointError)?;
        let mut ep = EndpointInstance::new(gp_cluster::ENDPOINT, gp_cluster::PROFILE);
        let client: ClusterInstance<36> = ClusterInstance::new(
            ClusterDef {
                id: gp_cluster::ID,
                revision: gp_cluster::REVISION,
                received: &[
                    gp_cluster::server_cmd::PAIRING,
                    gp_cluster::server_cmd::PROXY_COMMISSIONING_MODE,
                    gp_cluster::server_cmd::PROXY_TABLE_REQUEST,
                ],
                generated: &[
                    gp_cluster::client_cmd::NOTIFICATION,
                    gp_cluster::client_cmd::COMMISSIONING_NOTIFICATION,
                    gp_cluster::client_cmd::PROXY_TABLE_RESPONSE,
                ],
            },
            Role::Client,
        );
        ep.add_instance(client).map_err(|_| EndpointError)?;
        if let Some(o) = &sink {
            let mut server: ClusterInstance<36> = ClusterInstance::new(
                ClusterDef {
                    id: gp_cluster::ID,
                    revision: gp_cluster::REVISION,
                    received: &[
                        gp_cluster::client_cmd::NOTIFICATION,
                        gp_cluster::client_cmd::COMMISSIONING_NOTIFICATION,
                        gp_cluster::client_cmd::SINK_COMMISSIONING_MODE,
                        gp_cluster::client_cmd::SINK_TABLE_REQUEST,
                    ],
                    generated: &[
                        gp_cluster::server_cmd::PAIRING,
                        gp_cluster::server_cmd::PROXY_COMMISSIONING_MODE,
                        gp_cluster::server_cmd::RESPONSE,
                        gp_cluster::server_cmd::SINK_TABLE_RESPONSE,
                    ],
                },
                Role::Server,
            );
            let ro = |id: u16, ty: DataType| AttributeDef::new(id, ty, Access::RO);
            let entries = u64::try_from(SINK_TABLE_ENTRIES).unwrap_or(0xff);
            let attrs = [
                (
                    ro(gp_cluster::attr::MAX_SINK_TABLE_ENTRIES, DataType::Uint(1)),
                    Value::Uint {
                        width: 1,
                        value: entries,
                    },
                ),
                (
                    ro(gp_cluster::attr::COMMUNICATION_MODE, DataType::Bitmap(1)),
                    bits(1, u64::from(o.communication_mode.raw())),
                ),
                (
                    ro(
                        gp_cluster::attr::COMMISSIONING_EXIT_MODE,
                        DataType::Bitmap(1),
                    ),
                    bits(1, u64::from(gp_cluster::exit_mode::ON_FIRST_PAIRING)),
                ),
                (
                    ro(gp_cluster::attr::COMMISSIONING_WINDOW, DataType::Uint(2)),
                    Value::Uint {
                        width: 2,
                        value: o.commissioning_window.as_secs().min(0xffff),
                    },
                ),
                (
                    ro(gp_cluster::attr::SECURITY_LEVEL, DataType::Bitmap(1)),
                    bits(1, u64::from(o.security_level.raw())),
                ),
                (
                    ro(gp_cluster::attr::SINK_FUNCTIONALITY, DataType::Bitmap(3)),
                    bits(3, u64::from(gp_cluster::BASIC_SINK_FUNCTIONALITY)),
                ),
                (
                    ro(
                        gp_cluster::attr::SINK_ACTIVE_FUNCTIONALITY,
                        DataType::Bitmap(3),
                    ),
                    bits(3, u64::from(gp_cluster::BASIC_SINK_ACTIVE_FUNCTIONALITY)),
                ),
            ];
            for (def, v) in attrs {
                server.add_attribute(def, &v).map_err(|_| EndpointError)?;
            }
            ep.add_instance(server).map_err(|_| EndpointError)?;
        }
        self.zdo.add_endpoint(desc).map_err(|_| EndpointError)?;
        self.zcl.add_endpoint(ep).map_err(|_| EndpointError)?;
        let mut proxy = GpProxy::new(ProxyConfig::new(
            self.nwk.nib.network_address,
            self.config.ieee,
        ));
        proxy.poll(self.now);
        let mut gp = GreenPower {
            proxy,
            sink: None,
            pending: Vec::new(),
            gpdfs: Vec::new(),
            endpoints: Vec::new(),
        };
        if let Ok(table) = restore_proxy_table(&mut self.storage) {
            gp.proxy.table = table;
        }
        if let Some(o) = sink {
            let mut cfg = SinkConfig::new(
                self.nwk.nib.network_address,
                self.config.ieee,
                self.nwk.nib.pan_id,
                self.nwk.nib.channel.raw(),
            );
            cfg.security_level = o.security_level;
            cfg.communication_mode = o.communication_mode;
            cfg.commissioned_group = o.commissioned_group;
            cfg.shared_key_type = o.shared_key_type;
            cfg.shared_key.clone_from(&o.shared_key);
            cfg.commissioning_window = o.commissioning_window;
            let mut s = GpSink::new(cfg);
            s.poll(self.now);
            if let Ok(table) = restore_sink_table(&mut self.storage) {
                s.table = table;
            }
            gp.proxy.config.shared_key_type = o.shared_key_type;
            gp.proxy.config.shared_key = o.shared_key;
            gp.endpoints = o.endpoints;
            gp.sink = Some(s);
        }
        self.green_power = Some(gp);
        self.sync_green_power_keys();
        Ok(())
    }

    /// The proxy, when enabled.
    pub fn green_power_proxy(&mut self) -> Option<&mut GpProxy> {
        self.green_power.as_mut().map(|g| &mut g.proxy)
    }

    /// The proxy, when enabled (shared access).
    pub fn green_power_proxy_ref(&self) -> Option<&GpProxy> {
        self.green_power.as_ref().map(|g| &g.proxy)
    }

    /// The sink, when enabled.
    pub fn green_power_sink(&mut self) -> Option<&mut GpSink<C>> {
        self.green_power.as_mut().and_then(|g| g.sink.as_mut())
    }

    /// The sink, when enabled (shared access).
    pub fn green_power_sink_ref(&self) -> Option<&GpSink<C>> {
        self.green_power.as_ref().and_then(|g| g.sink.as_ref())
    }

    /// Puts the sink in commissioning mode for `window` (its
    /// gpsCommissioningWindow by default), asking the proxies to join in
    /// when `involve_proxies` (multi-hop commissioning, §A.3.9.1 step 1b).
    pub fn green_power_commission(
        &mut self,
        involve_proxies: bool,
        window: Option<Duration>,
    ) -> Result<Instant, ModeError> {
        let sink = self.green_power_sink().ok_or(ModeError::NotFound)?;
        let until = sink.enter_commissioning_mode(involve_proxies, window)?;
        self.pump_green_power();
        Ok(until)
    }

    /// Takes the sink out of commissioning mode.
    pub fn green_power_stop_commissioning(&mut self) {
        if let Some(sink) = self.green_power_sink() {
            sink.exit_commissioning_mode();
        }
        self.pump_green_power();
    }

    /// Keeps the proxy's and sink's addresses and NWK key current (after
    /// joining and after key switches).
    pub(crate) fn sync_green_power_keys(&mut self) {
        let short = self.nwk.nib.network_address;
        let pan_id = self.nwk.nib.pan_id;
        let channel = self.nwk.nib.channel.raw();
        let nwk_key = self.nwk.security.keys.active().map(|s| s.key.clone());
        if let Some(gp) = self.green_power.as_mut() {
            gp.proxy.config.short = short;
            gp.proxy.config.nwk_key.clone_from(&nwk_key);
            if let Some(s) = gp.sink.as_mut() {
                s.config.short = short;
                s.config.pan_id = pan_id;
                s.config.channel = channel;
                s.config.nwk_key = nwk_key;
            }
        }
    }

    /// A GPDF received by the MAC.
    pub(crate) fn on_gpdf(&mut self, mac: &MacFrame<'_>, lqi: u8, rssi_dbm: i8) {
        if self.phase != Phase::Operating {
            return;
        }
        let Ok(gpdf) = Gpdf::decode(mac) else {
            return;
        };
        let link = GppGpdLink::new(rssi_dbm, lqi);
        if let Some(gp) = self.green_power.as_mut() {
            gp.proxy.on_gpdf::<C>(&gpdf, link);
            if let Some(s) = gp.sink.as_mut() {
                s.on_gpdf(&gpdf, link);
            }
        }
        self.pump_green_power();
    }

    /// A Green Power cluster command delivered to the Green Power
    /// EndPoint; returns true when consumed by the proxy or the sink.
    pub(crate) fn on_green_power_command(&mut self, origin: &Origin, payload: &[u8]) -> bool {
        if origin.endpoint != gp_cluster::ENDPOINT || origin.cluster != gp_cluster::ID {
            return false;
        }
        let Some(gp) = self.green_power.as_mut() else {
            return false;
        };
        let unicast = !origin.broadcast;
        let status = match origin.header.control.direction {
            Direction::ToClient => match origin.header.command {
                gp_cluster::server_cmd::PAIRING => match Pairing::decode_exact(payload) {
                    Ok(p) => {
                        gp.proxy.on_pairing(&p, unicast);
                        ZclStatus::Success
                    }
                    Err(_) => ZclStatus::MalformedCommand,
                },
                gp_cluster::server_cmd::PROXY_COMMISSIONING_MODE => {
                    match ProxyCommissioningMode::decode_exact(payload) {
                        Ok(m) => {
                            gp.proxy.on_commissioning_mode(&m, origin.src);
                            ZclStatus::Success
                        }
                        Err(_) => ZclStatus::MalformedCommand,
                    }
                }
                gp_cluster::server_cmd::PROXY_TABLE_REQUEST => {
                    match ProxyTableRequest::decode_exact(payload) {
                        Ok(r) => {
                            gp.proxy.on_proxy_table_request(&r, origin.src, unicast);
                            ZclStatus::Success
                        }
                        Err(_) => ZclStatus::MalformedCommand,
                    }
                }
                _ => ZclStatus::UnsupportedClusterCommand,
            },
            Direction::ToServer => {
                let Some(sink) = gp.sink.as_mut() else {
                    return false;
                };
                match origin.header.command {
                    gp_cluster::client_cmd::NOTIFICATION => {
                        match Notification::decode_exact(payload) {
                            Ok(n) => {
                                sink.on_notification(&n, origin.src, unicast);
                                ZclStatus::Success
                            }
                            Err(_) => ZclStatus::MalformedCommand,
                        }
                    }
                    gp_cluster::client_cmd::COMMISSIONING_NOTIFICATION => {
                        match CommissioningNotification::decode_exact(payload) {
                            Ok(n) => {
                                sink.on_commissioning_notification(&n, origin.src);
                                ZclStatus::Success
                            }
                            Err(_) => ZclStatus::MalformedCommand,
                        }
                    }
                    gp_cluster::client_cmd::SINK_COMMISSIONING_MODE => {
                        match SinkCommissioningMode::decode_exact(payload) {
                            Ok(m) => {
                                let exists = m.endpoint == 0xff
                                    || self.zcl.endpoint(Endpoint(m.endpoint)).is_some();
                                let sink = self.green_power_sink();
                                match sink.map(|s| s.on_sink_commissioning_mode(&m, exists)) {
                                    Some(Ok(())) => ZclStatus::Success,
                                    Some(Err(ModeError::NotFound)) => ZclStatus::NotFound,
                                    Some(Err(ModeError::InvalidField)) => ZclStatus::InvalidField,
                                    Some(Err(ModeError::InvolveTc)) | None => ZclStatus::Failure,
                                }
                            }
                            Err(_) => ZclStatus::MalformedCommand,
                        }
                    }
                    gp_cluster::client_cmd::SINK_TABLE_REQUEST => {
                        match SinkTableRequest::decode_exact(payload) {
                            Ok(r) => {
                                sink.on_sink_table_request(&r, origin.src, unicast);
                                ZclStatus::Success
                            }
                            Err(_) => ZclStatus::MalformedCommand,
                        }
                    }
                    _ => ZclStatus::UnsupportedClusterCommand,
                }
            }
        };
        // Pairing errors are reported as Default Responses (§A.3.5.2.3).
        let mut rejected = None;
        self.pump_green_power_events(&mut rejected);
        let status = match rejected {
            Some(PairingError::InvalidField) => ZclStatus::InvalidField,
            Some(PairingError::InsufficientSpace) => ZclStatus::InsufficientSpace,
            None => status,
        };
        let _ = self.zcl.default_response(origin, status);
        self.pump_green_power();
        true
    }

    /// Drains the proxy's and sink's events into stack events,
    /// persistence, group membership, announcements and local execution.
    fn pump_green_power_events(&mut self, rejected: &mut Option<PairingError>) {
        let mut persist_proxy = false;
        let mut persist_sink = false;
        let mut events: Vec<StackEvent, 8> = Vec::new();
        let mut commands: Vec<GpdCommand, 4> = Vec::new();
        let mut announce: Vec<ShortAddress, 4> = Vec::new();
        let mut join: Vec<u16, 4> = Vec::new();
        let mut leave: Vec<u16, 4> = Vec::new();
        if let Some(gp) = self.green_power.as_mut() {
            while let Some(e) = gp.proxy.next_event() {
                match e {
                    ProxyEvent::TableChanged => persist_proxy = true,
                    ProxyEvent::CommissioningMode(until) => {
                        let _ = events.push(StackEvent::GreenPowerCommissioningMode { until });
                    }
                    ProxyEvent::PairingRejected(err) => *rejected = Some(err),
                }
            }
            if let Some(s) = gp.sink.as_mut() {
                while let Some(e) = s.next_event() {
                    match e {
                        SinkEvent::TableChanged => persist_sink = true,
                        SinkEvent::CommissioningMode(until) => {
                            let _ = events.push(StackEvent::GreenPowerCommissioningMode { until });
                        }
                        SinkEvent::Paired {
                            gpd,
                            device_id,
                            mode,
                            alias,
                            group,
                            announce: a,
                        } => {
                            if let Some(g) = group {
                                let _ = join.push(g);
                            }
                            if a {
                                let _ = announce.push(alias);
                            }
                            let _ = events.push(StackEvent::GreenPowerPaired {
                                gpd,
                                device_id,
                                mode,
                                alias,
                            });
                        }
                        SinkEvent::Decommissioned { gpd, group } => {
                            if let Some(g) = group
                                && !s.table.iter().any(|e| {
                                    e.mode == CommunicationMode::DerivedGroupcast
                                        && panweave_green_power::proxy_table::derived_alias(&e.gpd)
                                            .0
                                            == g
                                        || e.groups.iter().any(|(x, _)| *x == g)
                                })
                            {
                                let _ = leave.push(g);
                            }
                            let _ = events.push(StackEvent::GreenPowerDecommissioned { gpd });
                        }
                        SinkEvent::Refused { gpd, reason } => {
                            let _ = events.push(StackEvent::GreenPowerRefused { gpd, reason });
                        }
                        SinkEvent::Command(c) => {
                            let _ = commands.push(c);
                        }
                    }
                }
            }
        }
        let mut groups_changed = false;
        for g in join {
            if self
                .aps
                .groups
                .add(GroupAddress(g), gp_cluster::ENDPOINT)
                .is_ok()
            {
                groups_changed = true;
            }
        }
        for g in leave {
            if self
                .aps
                .groups
                .remove(GroupAddress(g), gp_cluster::ENDPOINT)
                .is_ok()
            {
                groups_changed = true;
            }
        }
        if groups_changed {
            let _ = self.persist_groups();
        }
        for alias in announce {
            self.announce_alias(alias);
        }
        for e in events {
            self.push_event(e);
        }
        for c in commands {
            self.execute_gpd_command(&c);
        }
        if persist_proxy {
            let _ = self.persist_proxy_table();
        }
        if persist_sink {
            let _ = self.persist_sink_table();
        }
    }

    /// Device_annce on behalf of a GPD (§A.3.6.3.4.2): NWK source and
    /// NWKAddr are the alias, the IEEE address is invalid, the NWK
    /// sequence number and APS counter are 0x00.
    fn announce_alias(&mut self, alias: ShortAddress) {
        let capability = panweave_types::MacCapability(0)
            .with_security_capable(self.config.capability().security_capable());
        let mut asdu = [0u8; 12];
        asdu[0] = self.zcl.next_seq().0;
        asdu[1..3].copy_from_slice(&alias.0.to_le_bytes());
        asdu[3..11].copy_from_slice(&ExtendedAddress::BROADCAST.0.to_le_bytes());
        asdu[11] = capability.0;
        let req = DataRequest {
            destination: ApsDestination::Short {
                address: ShortAddress::BROADCAST_RX_ON,
                endpoint: Endpoint(0),
            },
            profile: ProfileId::ZDP,
            cluster: panweave_zdo::zdp::cluster::DEVICE_ANNCE,
            src_endpoint: Endpoint(0),
            asdu: &asdu,
            options: TxOptions::NONE,
            radius: None,
            alias: Some((alias, 0)),
        };
        let view = AddrView(&self.nwk);
        let _ = self.aps.data_request(&req, &view);
    }

    /// Reports an accepted GPD command and executes its generic ZCL
    /// translation on the paired local endpoints as if it had arrived
    /// from the GPD's alias.
    fn execute_gpd_command(&mut self, c: &GpdCommand) {
        let Some(gp) = self.green_power.as_ref() else {
            return;
        };
        let group = c.group.unwrap_or(0);
        let alias = gp
            .sink
            .as_ref()
            .and_then(|s| s.table.find(&c.gpd).map(SinkEntry::alias))
            .unwrap_or(ShortAddress(0xffff));
        let mut endpoints: Vec<Endpoint, SINK_ENDPOINTS> = gp.endpoints.clone();
        if endpoints.is_empty() {
            for e in self.zcl.endpoints() {
                if e.endpoint != gp_cluster::ENDPOINT {
                    let _ = endpoints.push(e.endpoint);
                }
            }
        }
        let Some(payload) = Vec::from_slice(&c.payload).ok() else {
            return;
        };
        self.push_event(StackEvent::GreenPowerCommand {
            gpd: c.gpd,
            command_id: c.command_id,
            payload,
            group: c.group,
        });
        let Some(t) = translation::translate(c.command_id, &c.payload, group) else {
            return;
        };
        let (cluster, header, body): (_, Header, &[u8]) = match &t {
            Translated::Command {
                cluster,
                command,
                payload,
            } => (
                *cluster,
                Header::cluster_specific(self.zcl.next_seq(), *command, Direction::ToServer)
                    .disable_default_response(true),
                payload,
            ),
            Translated::Report {
                cluster,
                manufacturer,
                records,
            } => {
                let mut h = Header::global(
                    self.zcl.next_seq(),
                    global_command::REPORT_ATTRIBUTES,
                    Direction::ToClient,
                )
                .disable_default_response(true);
                if let Some(m) = manufacturer {
                    h = h.with_manufacturer(panweave_types::ManufacturerCode(*m));
                }
                (*cluster, h, records)
            }
        };
        let mut buf = [0u8; 96];
        let Ok(n) = (ZclFrame {
            header,
            payload: body,
        })
        .encode_to_slice(&mut buf) else {
            return;
        };
        for ep in endpoints {
            let ind = panweave_aps::layer::DataIndication {
                src: alias,
                src_ieee: None,
                src_endpoint: gp_cluster::ENDPOINT,
                delivery: Delivery::Endpoint(ep),
                profile: ProfileId::WILDCARD,
                cluster,
                asdu: buf.get(..n).unwrap_or(&[]),
                security: SecurityStatus::NwkKey,
                lqi: 0xff,
                relayed: None,
                counter: 0,
                nwk_broadcast: false,
            };
            // Commands the layer executes itself raise their ZCL events
            // through the regular pump; the rest reach the application.
            let out = self.zcl.on_data(&ind, &mut self.aps.groups);
            if cluster == panweave_zcl::clusters::groups::ID {
                let _ = self.persist_groups();
            }
            if let Some(ZclIndication::Command { origin, payload }) = out
                && let Ok(payload) = Vec::from_slice(payload)
            {
                self.push_event(StackEvent::ZclCommand(crate::stack::ZclFrame {
                    origin,
                    payload,
                }));
            }
        }
    }

    /// Queues the proxy's and sink's outgoing frames and sends the ones
    /// whose delay elapsed.
    pub(crate) fn pump_green_power(&mut self) {
        let mut rejected = None;
        self.pump_green_power_events(&mut rejected);
        let now = self.now;
        let Some(gp) = self.green_power.as_mut() else {
            return;
        };
        while let Some(o) = gp.proxy.next_outgoing() {
            if gp.pending.push(o).is_err() {
                break;
            }
        }
        let mut sink_frames: Vec<panweave_green_power::sink::SinkFrame, 8> = Vec::new();
        if let Some(s) = gp.sink.as_mut() {
            while let Some(f) = s.next_frame() {
                if sink_frames.push(f).is_err() {
                    break;
                }
            }
            while let Some(g) = s.next_gpdf() {
                if gp.gpdfs.push(g).is_err() {
                    break;
                }
            }
        }
        let mut due: Vec<Outgoing, 8> = Vec::new();
        let mut i = 0;
        while i < gp.pending.len() {
            if gp
                .pending
                .get(i)
                .is_some_and(|o| now.has_reached(o.not_before))
            {
                let o = gp.pending.swap_remove(i);
                let _ = due.push(o);
            } else {
                i += 1;
            }
        }
        let mut due_gpdfs: Vec<GpdfTx, 2> = Vec::new();
        let mut i = 0;
        while i < gp.gpdfs.len() {
            if gp
                .gpdfs
                .get(i)
                .is_some_and(|g| now.has_reached(g.not_before))
            {
                let g = gp.gpdfs.swap_remove(i);
                let _ = due_gpdfs.push(g);
            } else {
                i += 1;
            }
        }
        for o in due {
            self.send_green_power(&o);
        }
        for f in sink_frames {
            self.send_sink_frame(&f);
        }
        for g in due_gpdfs {
            let _ = self.mac.data_request_inter_pan(
                PanId::BROADCAST,
                g.dst,
                PanId::BROADCAST,
                &g.frame,
                false,
            );
        }
    }

    /// Timers of the proxy and the sink (commissioning windows, duplicate
    /// filters, tunnelling delays, gpTxOffset).
    pub(crate) fn poll_green_power(&mut self, now: Instant) {
        if let Some(gp) = self.green_power.as_mut() {
            gp.proxy.poll(now);
            if let Some(s) = gp.sink.as_mut() {
                s.poll(now);
            }
        }
        self.pump_green_power();
    }

    fn send_green_power(&mut self, o: &Outgoing) {
        let seq = match o.alias {
            Some(a) => panweave_types::TransactionSequence(a.sequence),
            None => self.zcl.next_seq(),
        };
        let header = Header::cluster_specific(seq, o.command, Direction::ToServer)
            .disable_default_response(true);
        let mut buf = [0u8; 96];
        let Ok(n) = (ZclFrame {
            header,
            payload: &o.payload,
        })
        .encode_to_slice(&mut buf) else {
            return;
        };
        let destination = match o.destination {
            Destination::Unicast(short) => ApsDestination::Short {
                address: short,
                endpoint: gp_cluster::ENDPOINT,
            },
            Destination::Group(g) => ApsDestination::Group(GroupAddress(g)),
            Destination::Broadcast => ApsDestination::Short {
                address: ShortAddress::BROADCAST_RX_ON,
                endpoint: gp_cluster::ENDPOINT,
            },
        };
        let req = DataRequest {
            destination,
            profile: gp_cluster::PROFILE,
            cluster: gp_cluster::ID,
            src_endpoint: gp_cluster::ENDPOINT,
            asdu: buf.get(..n).unwrap_or(&[]),
            // §A.3.5.2.3: no APS acknowledgement for tunnelled frames.
            options: TxOptions::NONE,
            radius: (o.radius != 0).then_some(o.radius),
            alias: o.alias.map(|a| (a.address, a.sequence)),
        };
        let view = AddrView(&self.nwk);
        let _ = self.aps.data_request(&req, &view);
    }

    /// Sends a sink-generated command (server → client direction) with
    /// the sink's own addresses; unicasts are acknowledged.
    fn send_sink_frame(&mut self, f: &panweave_green_power::sink::SinkFrame) {
        let header = Header::cluster_specific(self.zcl.next_seq(), f.command, Direction::ToClient)
            .disable_default_response(true);
        let mut buf = [0u8; 96];
        let Ok(n) = (ZclFrame {
            header,
            payload: &f.payload,
        })
        .encode_to_slice(&mut buf) else {
            return;
        };
        let (destination, options) = match f.destination {
            Destination::Unicast(short) => (
                ApsDestination::Short {
                    address: short,
                    endpoint: gp_cluster::ENDPOINT,
                },
                TxOptions::ACKED,
            ),
            Destination::Group(g) => (ApsDestination::Group(GroupAddress(g)), TxOptions::NONE),
            Destination::Broadcast => (
                ApsDestination::Short {
                    address: ShortAddress::BROADCAST_RX_ON,
                    endpoint: gp_cluster::ENDPOINT,
                },
                TxOptions::NONE,
            ),
        };
        let req = DataRequest {
            destination,
            profile: gp_cluster::PROFILE,
            cluster: gp_cluster::ID,
            src_endpoint: gp_cluster::ENDPOINT,
            asdu: buf.get(..n).unwrap_or(&[]),
            options,
            radius: None,
            alias: None,
        };
        let view = AddrView(&self.nwk);
        let _ = self.aps.data_request(&req, &view);
    }

    /// Persists the Proxy Table (one record per entry, §A.3.4.2.2).
    pub fn persist_proxy_table(&mut self) -> Result<(), StorageError> {
        let Some(gp) = self.green_power.as_ref() else {
            return Ok(());
        };
        for i in 0..PROXY_TABLE_ENTRIES {
            self.storage
                .erase(Key::with_id(Kind::GreenPower, i as u64))?;
        }
        for (i, e) in gp.proxy.table.iter().enumerate() {
            let mut buf = [0u8; 128];
            let mut w = Writer::new(&mut buf);
            e.encode(&mut w).map_err(|_| StorageError::Full)?;
            let n = w.position();
            self.storage.store(
                Key::with_id(Kind::GreenPower, i as u64),
                buf.get(..n).unwrap_or(&[]),
            )?;
        }
        Ok(())
    }

    /// Persists the Sink Table (one record per entry, §A.3.3.2.2).
    pub fn persist_sink_table(&mut self) -> Result<(), StorageError> {
        let Some(sink) = self.green_power.as_ref().and_then(|g| g.sink.as_ref()) else {
            return Ok(());
        };
        for i in 0..SINK_TABLE_ENTRIES {
            self.storage
                .erase(Key::with_id(Kind::GreenPower, SINK_RECORD_BASE + i as u64))?;
        }
        for (i, e) in sink.table.iter().enumerate() {
            let mut buf = [0u8; 128];
            let mut w = Writer::new(&mut buf);
            e.encode(&mut w).map_err(|_| StorageError::Full)?;
            let n = w.position();
            self.storage.store(
                Key::with_id(Kind::GreenPower, SINK_RECORD_BASE + i as u64),
                buf.get(..n).unwrap_or(&[]),
            )?;
        }
        Ok(())
    }
}

fn restore_proxy_table<S: Storage>(
    storage: &mut S,
) -> Result<ProxyTable<PROXY_TABLE_ENTRIES>, StorageError> {
    let mut table = ProxyTable::new();
    for i in 0..PROXY_TABLE_ENTRIES {
        let mut buf = [0u8; 128];
        let Some(n) = storage.load(Key::with_id(Kind::GreenPower, i as u64), &mut buf)? else {
            continue;
        };
        let mut r = Reader::new(buf.get(..n).unwrap_or(&[]));
        if let Ok(e) = ProxyEntry::decode(&mut r) {
            let _ = table.insert(e);
        }
    }
    Ok(table)
}

fn restore_sink_table<S: Storage>(
    storage: &mut S,
) -> Result<SinkTable<SINK_TABLE_ENTRIES>, StorageError> {
    let mut table = SinkTable::new();
    for i in 0..SINK_TABLE_ENTRIES {
        let mut buf = [0u8; 128];
        let Some(n) = storage.load(
            Key::with_id(Kind::GreenPower, SINK_RECORD_BASE + i as u64),
            &mut buf,
        )?
        else {
            continue;
        };
        let mut r = Reader::new(buf.get(..n).unwrap_or(&[]));
        if let Ok(e) = SinkEntry::decode(&mut r) {
            let _ = table.insert(e);
        }
    }
    Ok(table)
}

/// The GPD identity of a stack event, re-exported for applications.
pub type GreenPowerDeviceId = GpdId;
/// Re-export of the sink refusal reasons.
pub type GreenPowerRefusal = Refusal;
