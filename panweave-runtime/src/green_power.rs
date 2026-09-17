//! Green Power Basic Proxy integration (GP Basic 1.1.2 §A.3.5.2.3): the
//! GP stub receives GPDFs straight from the MAC (protocol version 3 frames
//! never reach the NWK layer), the Green Power EndPoint 242 receives the
//! cluster commands of the sinks, and the proxy's notifications are
//! tunnelled with NWK source aliasing after their tunnelling delay. The
//! Proxy Table is persisted entry by entry.

use heapless::Vec;
use panweave_aps::Destination as ApsDestination;
use panweave_aps::layer::{DataRequest, TxOptions};
use panweave_codec::{Decode, Encode, Reader, Writer};
use panweave_green_power::cluster::{
    self as gp_cluster, GppGpdLink, Pairing, ProxyCommissioningMode, ProxyTableRequest,
};
use panweave_green_power::gpdf::Gpdf;
use panweave_green_power::proxy::{
    Destination, Outgoing, PairingError, Proxy, ProxyConfig, ProxyEvent,
};
use panweave_green_power::proxy_table::{ProxyEntry, ProxyTable};
use panweave_mac::frame::Frame as MacFrame;
use panweave_security::cipher::BlockCipher;
use panweave_storage::{Key, Kind, Storage, StorageError};
use panweave_types::time::Instant;
use panweave_types::{CryptoRng, DeviceId, GroupAddress, ShortAddress};
use panweave_zcl::frame::{Direction, Frame as ZclFrame, Header, ZclStatus};
use panweave_zcl::layer::{EndpointInstance, Origin};
use panweave_zcl::{ClusterDef, ClusterInstance, Role};
use panweave_zdo::descriptor::SimpleDescriptor;

use crate::context::AddrView;
use crate::stack::{EndpointError, Phase, Stack, StackEvent};

/// Proxy Table capacity (`gppMaxProxyTableEntries`, the recommended 20).
pub const PROXY_TABLE_ENTRIES: usize = 20;
/// The Basic Proxy of a stack.
pub type GpProxy = Proxy<PROXY_TABLE_ENTRIES>;
/// GP Proxy Basic device identifier (Table 23).
pub const PROXY_BASIC_DEVICE: DeviceId = DeviceId(0x0061);

/// Green Power state of the stack.
pub struct GreenPower {
    /// The proxy.
    pub proxy: GpProxy,
    /// Notifications waiting for their tunnelling delay.
    pending: Vec<Outgoing, 8>,
}

impl GreenPower {
    /// Earliest pending transmission.
    pub fn next_deadline(&self) -> Option<Instant> {
        let p = self
            .pending
            .iter()
            .map(|o| o.not_before)
            .min_by_key(|t| t.as_millis());
        match (p, self.proxy.next_deadline()) {
            (Some(a), Some(b)) => Some(if a.as_millis() < b.as_millis() { a } else { b }),
            (a, None) => a,
            (None, b) => b,
        }
    }
}

/// True when a MAC data payload starts with a GP stub NWK header
/// (Zigbee Protocol Version 3, §A.1.4.1.2).
pub(crate) fn is_gpdf(payload: &[u8]) -> bool {
    payload
        .first()
        .is_some_and(|fc| (fc >> 2) & 0x0F == panweave_green_power::gpdf::PROTOCOL_VERSION)
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> Stack<C, R, S> {
    /// Enables the Green Power Basic Proxy: registers the Green Power
    /// EndPoint (242, profile 0xA1E0, device GP Proxy Basic) with the
    /// Green Power cluster client and restores the persisted Proxy Table.
    pub fn enable_green_power_proxy(&mut self) -> Result<(), EndpointError> {
        if self.green_power.is_some() {
            return Ok(());
        }
        let desc = SimpleDescriptor::new(
            gp_cluster::ENDPOINT,
            gp_cluster::PROFILE,
            PROXY_BASIC_DEVICE,
            0,
            &[],
            &[gp_cluster::ID],
        )
        .ok_or(EndpointError)?;
        let mut ep = EndpointInstance::new(gp_cluster::ENDPOINT, gp_cluster::PROFILE);
        let client: ClusterInstance<16> = ClusterInstance::new(
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
        self.zdo.add_endpoint(desc).map_err(|_| EndpointError)?;
        self.zcl.add_endpoint(ep).map_err(|_| EndpointError)?;
        let mut proxy = GpProxy::new(ProxyConfig::new(
            self.nwk.nib.network_address,
            self.config.ieee,
        ));
        proxy.poll(self.now);
        let mut gp = GreenPower {
            proxy,
            pending: Vec::new(),
        };
        if let Ok(table) = restore_proxy_table(&mut self.storage) {
            gp.proxy.table = table;
        }
        self.green_power = Some(gp);
        self.sync_green_power_keys();
        Ok(())
    }

    /// The proxy, when enabled.
    pub fn green_power_proxy(&mut self) -> Option<&mut GpProxy> {
        self.green_power.as_mut().map(|g| &mut g.proxy)
    }

    /// Keeps the proxy's addresses and NWK key current (after joining
    /// and after key switches).
    pub(crate) fn sync_green_power_keys(&mut self) {
        let short = self.nwk.nib.network_address;
        let nwk_key = self.nwk.security.keys.active().map(|s| s.key.clone());
        if let Some(gp) = self.green_power.as_mut() {
            gp.proxy.config.short = short;
            gp.proxy.config.nwk_key = nwk_key;
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
        }
        self.pump_green_power();
    }

    /// A Green Power cluster command delivered to the Green Power
    /// EndPoint; returns true when consumed by the proxy.
    pub(crate) fn on_green_power_command(&mut self, origin: &Origin, payload: &[u8]) -> bool {
        if origin.endpoint != gp_cluster::ENDPOINT || origin.cluster != gp_cluster::ID {
            return false;
        }
        let Some(gp) = self.green_power.as_mut() else {
            return false;
        };
        let unicast = !origin.broadcast;
        let status = match origin.header.command {
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

    /// Drains the proxy's events into stack events and persistence.
    fn pump_green_power_events(&mut self, rejected: &mut Option<PairingError>) {
        let mut persist = false;
        let mut events: Vec<StackEvent, 4> = Vec::new();
        if let Some(gp) = self.green_power.as_mut() {
            while let Some(e) = gp.proxy.next_event() {
                match e {
                    ProxyEvent::TableChanged => persist = true,
                    ProxyEvent::CommissioningMode(until) => {
                        let _ = events.push(StackEvent::GreenPowerCommissioningMode { until });
                    }
                    ProxyEvent::PairingRejected(err) => *rejected = Some(err),
                }
            }
        }
        for e in events {
            self.push_event(e);
        }
        if persist {
            let _ = self.persist_proxy_table();
        }
    }

    /// Queues the proxy's outgoing frames and sends the ones whose delay
    /// elapsed.
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
        for o in due {
            self.send_green_power(&o);
        }
    }

    /// Timers of the proxy (commissioning window, duplicate filter,
    /// tunnelling delays).
    pub(crate) fn poll_green_power(&mut self, now: Instant) {
        if let Some(gp) = self.green_power.as_mut() {
            gp.proxy.poll(now);
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

    /// Persists the Proxy Table (one record per entry, §A.3.4.2.2).
    pub fn persist_proxy_table(&mut self) -> Result<(), StorageError> {
        let Some(gp) = self.green_power.as_ref() else {
            return Ok(());
        };
        self.storage.erase_kind(Kind::GreenPower)?;
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
