//! Panweave: an independent Rust implementation of IEEE 802.15.4-based
//! Zigbee protocol functionality. See `docs/architecture.md`.
//!
//! This facade re-exports the layer crates and offers [`Node`], a
//! sans-I/O device that combines the runtime [`Stack`] with the BDB 3.1
//! commissioning machine, built through [`Coordinator`], [`Router`] and
//! [`EndDevice`]. A [`Node`] holds every table of the stack inline (a
//! few hundred kilobytes): give it a `static`, a `Box` or a thread with
//! room for it rather than a small stack frame.
//!
//! ```
//! use panweave::{Coordinator, Event};
//! use panweave::security::cipher::SoftwareAes;
//! use panweave::storage::MemoryStorage;
//! use panweave::testkit::TestRng;
//! use panweave::types::ExtendedAddress;
//!
//! # std::thread::Builder::new().stack_size(8 << 20).spawn(|| {
//! let mut node = Coordinator::new(ExtendedAddress(0x1122_3344_5566_7788))
//!     .build::<SoftwareAes, _, _>(TestRng::seed(1), MemoryStorage::<32, 128>::new());
//! node.form_network().unwrap();
//! // Drive `node.poll(now)`, `node.on_radio_frame(..)`,
//! // `node.next_radio_action()` from the radio loop and consume
//! // `node.next_event()`.
//! assert!(matches!(node.next_event(), None | Some(Event::Stack(_))));
//! # }).unwrap().join().unwrap();
//! ```
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic
    )
)]

pub use panweave_aps as aps;
pub use panweave_bdb as bdb;
pub use panweave_codec as codec;
pub use panweave_device_library as device_library;
pub use panweave_mac as mac;
pub use panweave_nwk as nwk;
pub use panweave_runtime as runtime;
pub use panweave_security as security;
pub use panweave_storage as storage;
pub use panweave_testkit as testkit;
pub use panweave_types as types;
pub use panweave_zcl as zcl;
pub use panweave_zdo as zdo;

#[cfg(feature = "direct")]
pub mod direct;
pub mod endpoints;
#[cfg(feature = "smart-energy")]
pub use panweave_smart_energy as smart_energy;
#[cfg(feature = "smart-energy")]
pub mod cbke;
#[cfg(feature = "smart-energy")]
pub mod smart_energy_drivers;
#[cfg(feature = "smart-energy")]
pub mod smart_energy_endpoints;

use heapless::Deque;
use panweave_bdb::{Bdb, Config as BdbConfig, Failure, Outcome};
use panweave_mac::radio::{RadioError, RxMetadata, TxResult};
use panweave_mac::service::{MacAction, MacServiceConfig};
use panweave_runtime::{EndpointError, Restored, Stack, StackConfig, StackEvent};
use panweave_security::cipher::BlockCipher;
use panweave_security::trust_center::TrustCenterPolicy;
use panweave_storage::{Storage, StorageError};
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    ChannelMask, ClusterId, CryptoRng, Endpoint, ExtendedAddress, GroupAddress, Key128,
    LogicalDeviceType, NwkStatus,
};
use panweave_zdo::descriptor::SimpleDescriptor;

/// Events of a [`Node`].
#[derive(Clone, Debug)]
pub enum Event {
    /// A stack event (join, ZCL command, report, …).
    Stack(StackEvent),
    /// A commissioning procedure finished.
    Commissioning(Outcome),
    /// A Zigbee Direct commissioning operation completed: forward to
    /// `panweave_direct::commissioning::Commissioning::report`.
    #[cfg(feature = "direct")]
    Direct {
        /// The operation.
        domain: panweave_direct::commissioning::Domain,
        /// Its status code (0 = SUCCESS).
        status: u8,
    },
    /// An NPDU Message TLV for the ZVD behind Trusted Link `link`
    /// (ZD 1.1 §7.7.4.1): the host encrypts it for the session and
    /// sends it as a GATT indication of the tunnel NPDU characteristic.
    #[cfg(feature = "direct")]
    DirectTunnel {
        /// The link.
        link: u8,
        /// The TLV.
        tlv: heapless::Vec<u8, { panweave_direct::tunnel::MAX_VALUE_LEN + 2 }>,
    },
    /// The APSME declined forwarding a frame to the ZVD behind `link`
    /// because it conveyed an active or prospective network key (ZD 1.1
    /// §9): the host closes the BLE connection so the ZVD re-establishes
    /// its session.
    #[cfg(feature = "direct")]
    DirectTunnelDeclined {
        /// The link.
        link: u8,
    },
    /// A ZVD in an ephemeral authorization session on a legacy network
    /// showed no proof of end-to-end authentication with the Trust
    /// Center within `apsSecurityTimeOutPeriod` (ZD 1.1 §10.1): the ZDD
    /// forgot it and the host closes the BLE connection.
    #[cfg(feature = "direct")]
    DirectAuthorizationTimeout {
        /// The link.
        link: u8,
    },
    /// The Zigbee Direct advertisement is to start or stop (ZD 1.1 §6.2:
    /// the un-provisioned ZDD's provisioning window closed, the ZDD
    /// joined or left a network, or the Configuration cluster switched
    /// the interface).
    #[cfg(feature = "direct")]
    DirectAdvertising {
        /// Advertise (true) or stop advertising.
        enabled: bool,
    },
}

/// A device: the stack plus its commissioning machine.
pub struct Node<C: BlockCipher, R: CryptoRng, S: Storage> {
    /// The protocol stack.
    pub stack: Stack<C, R, S>,
    /// The BDB 3.1 commissioning machine.
    pub bdb: Bdb,
    /// Zigbee Direct device state.
    #[cfg(feature = "direct")]
    pub direct: direct::DirectState,
    events: Deque<Event, 16>,
    /// Events dropped because the queue was full.
    pub dropped_events: u32,
}

/// Common builder fields.
#[derive(Clone, Debug)]
pub struct Builder {
    stack: StackConfig,
    bdb: BdbConfig,
    mac: MacServiceConfig,
}

impl Builder {
    fn new(role: LogicalDeviceType, ieee: ExtendedAddress) -> Self {
        Builder {
            stack: StackConfig::new(role, ieee),
            bdb: BdbConfig::DEFAULT_2_4GHZ,
            mac: MacServiceConfig::default(),
        }
    }

    /// Primary and secondary channel lists for commissioning.
    #[must_use]
    pub fn channels(mut self, primary: ChannelMask, secondary: ChannelMask) -> Self {
        self.bdb.primary_channels = primary;
        self.bdb.secondary_channels = secondary;
        self.stack.channels = primary;
        self
    }

    /// Scan duration exponent (BDB `bdbcfScanDuration`).
    #[must_use]
    pub fn scan_duration(mut self, exponent: u8) -> Self {
        self.bdb.scan_duration = exponent;
        self.stack.scan_duration = exponent;
        self
    }

    /// Manufacturer and model strings of the Basic cluster.
    #[must_use]
    pub fn identity(mut self, manufacturer: &'static [u8], model: &'static [u8]) -> Self {
        self.stack.manufacturer_name = manufacturer;
        self.stack.model = model;
        self
    }

    /// Pre-configured Trust Center link key (global or install-code
    /// derived) used to join centralized networks.
    #[must_use]
    pub fn preconfigured_link_key(
        mut self,
        trust_center: ExtendedAddress,
        key: Key128,
        kind: panweave_security::material::LinkKeyKind,
    ) -> Self {
        self.stack.preconfigured_link_key = (trust_center, key, kind);
        self
    }

    /// Overrides the whole BDB configuration.
    #[must_use]
    pub fn bdb(mut self, config: BdbConfig) -> Self {
        self.bdb = config;
        self
    }

    /// Overrides the MAC service configuration.
    #[must_use]
    pub fn mac(mut self, config: MacServiceConfig) -> Self {
        self.mac = config;
        self
    }

    /// Direct access to the stack configuration.
    pub fn stack_config(&mut self) -> &mut StackConfig {
        &mut self.stack
    }

    /// Builds the node.
    pub fn build<C: BlockCipher, R: CryptoRng, S: Storage>(
        self,
        rng: R,
        storage: S,
    ) -> Node<C, R, S> {
        Node {
            stack: Stack::new(self.stack, self.mac, rng, storage),
            bdb: Bdb::new(self.bdb, false),
            #[cfg(feature = "direct")]
            direct: direct::DirectState::default(),
            events: Deque::new(),
            dropped_events: 0,
        }
    }
}

/// Builder for a Zigbee coordinator (Trust Center of a centralized
/// network).
pub struct Coordinator;

impl Coordinator {
    /// Coordinator with `ieee` as its IEEE address.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(ieee: ExtendedAddress) -> Builder {
        let mut b = Builder::new(LogicalDeviceType::Coordinator, ieee);
        b.stack.trust_center_policy.allow_joins = false;
        b
    }

    /// Coordinator with an explicit Trust Center policy.
    pub fn with_policy(ieee: ExtendedAddress, policy: TrustCenterPolicy) -> Builder {
        let mut b = Builder::new(LogicalDeviceType::Coordinator, ieee);
        b.stack.trust_center_policy = policy;
        b
    }
}

/// Builder for a Zigbee router.
pub struct Router;

impl Router {
    /// Router with `ieee` as its IEEE address.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(ieee: ExtendedAddress) -> Builder {
        Builder::new(LogicalDeviceType::Router, ieee)
    }

    /// Router that forms / joins distributed networks.
    pub fn distributed(ieee: ExtendedAddress) -> Builder {
        let mut b = Builder::new(LogicalDeviceType::Router, ieee);
        b.stack.distributed = true;
        b
    }
}

/// Builder for a Zigbee end device.
pub struct EndDevice;

impl EndDevice {
    /// Receiver-on end device.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(ieee: ExtendedAddress) -> Builder {
        Builder::new(LogicalDeviceType::EndDevice, ieee)
    }

    /// Sleepy end device polling its parent every `poll_interval`.
    pub fn sleepy(ieee: ExtendedAddress, poll_interval: Duration) -> Builder {
        let mut b = Builder::new(LogicalDeviceType::EndDevice, ieee);
        b.stack.sleepy = true;
        b.stack.poll_interval = poll_interval;
        b
    }
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> Node<C, R, S> {
    fn push(&mut self, e: Event) {
        if self.events.push_back(e).is_err() {
            self.dropped_events = self.dropped_events.saturating_add(1);
        }
    }

    /// Drains stack events, feeding the commissioning machine.
    fn collect(&mut self) {
        while let Some(e) = self.stack.next_event() {
            if let Some(b) = Stack::<C, R, S>::bdb_event(&e)
                && let Some(o) = self.bdb.on_event(&mut self.stack, &b)
            {
                #[cfg(feature = "direct")]
                if let Some(d) = self.direct_bdb_outcome(o) {
                    self.push(d);
                }
                self.push(Event::Commissioning(o));
            }
            #[cfg(feature = "direct")]
            if let Some(d) = self.direct_outcome(&e) {
                self.push(d);
            }
            #[cfg(feature = "direct")]
            if let Some(t) = self.direct_tunnel_out(&e) {
                self.push(t);
            }
            #[cfg(feature = "direct")]
            {
                self.direct_on_configured(&e);
                self.direct_on_aware_answer(&e);
                self.direct_on_tclk_update(&e);
                self.direct_on_security_event(&e);
            }
            #[cfg(feature = "direct")]
            if let StackEvent::NetworkKeySwitched { previous, .. } = &e {
                self.direct_on_key_switched(*previous);
            }
            match &e {
                StackEvent::NetworkFormed { .. } | StackEvent::Joined { .. } => {
                    self.bdb.set_on_network(true);
                }
                StackEvent::Left { .. } => self.bdb.set_on_network(false),
                _ => {}
            }
            self.push(Event::Stack(e));
        }
    }

    /// Registers an application endpoint.
    pub fn add_endpoint(
        &mut self,
        descriptor: SimpleDescriptor,
        instance: panweave_runtime::StackEndpoint,
    ) -> Result<(), EndpointError> {
        self.stack.add_endpoint(descriptor, instance)
    }

    /// BDB 3.1 §7.1 initialization: restores persistent data and, when
    /// the node was on a network, resumes (routers, coordinator) or
    /// starts the Rejoin procedure (end devices).
    pub fn initialize(&mut self) -> Result<Restored, StorageError> {
        let restored = self.stack.restore()?;
        #[cfg(feature = "direct")]
        self.restore_direct_past_keys()?;
        #[cfg(feature = "direct")]
        self.restore_direct_config()?;
        #[cfg(feature = "direct")]
        self.restore_direct_admin_key()?;
        #[cfg(feature = "direct")]
        self.direct_power_up();
        if restored == Restored::OnNetwork {
            self.bdb.set_on_network(true);
            if self.stack.config.role == LogicalDeviceType::EndDevice {
                let _ = self.bdb.rejoin(&mut self.stack, false);
            } else {
                let _ = self.stack.resume();
            }
        }
        self.collect();
        Ok(restored)
    }

    /// Network formation (BDB 3.1 §8.1).
    pub fn form_network(&mut self) -> Result<(), Failure> {
        let r = self.bdb.form_network(&mut self.stack);
        self.collect();
        r
    }

    /// Formation with a fixed network key over the configured primary
    /// channels (tests and provisioning).
    pub fn form_network_with_key(&mut self, key: Key128) -> Result<(), NwkStatus> {
        let r = self.stack.form_network_with_key(key);
        self.collect();
        r
    }

    /// Off-network steering (BDB 3.1 §9.8): find and join an open network.
    pub fn steer(&mut self) -> Result<(), Failure> {
        let r = self.bdb.steer(&mut self.stack);
        self.collect();
        r
    }

    /// On-network steering (BDB 3.1 §9.7): opens the network for joining.
    pub fn open_network(&mut self) -> Result<(), Failure> {
        let r = self.bdb.steer_on_network(&mut self.stack);
        self.collect();
        r
    }

    /// Closes the network (BDB 3.1 §9.7.1).
    pub fn close_network(&mut self) -> Result<(), Failure> {
        let r = self.bdb.close_network(&mut self.stack);
        self.collect();
        r
    }

    /// Rejoin procedure (BDB 3.1 §10.1).
    pub fn rejoin(&mut self, lost_trust_center: bool) -> Result<(), Failure> {
        let r = self.bdb.rejoin(&mut self.stack, lost_trust_center);
        self.collect();
        r
    }

    /// Finding & binding target (BDB 3.1 §11.1).
    pub fn find_and_bind_target(&mut self, endpoint: Endpoint) -> Result<(), Failure> {
        let r = self.bdb.find_and_bind_target(&mut self.stack, endpoint);
        self.collect();
        r
    }

    /// Finding & binding initiator (BDB 3.1 §11.2).
    pub fn find_and_bind_initiator(
        &mut self,
        endpoint: Endpoint,
        group: Option<GroupAddress>,
        clusters: &[ClusterId],
    ) -> Result<(), Failure> {
        let r = self
            .bdb
            .find_and_bind_initiator(&mut self.stack, endpoint, group, clusters);
        self.collect();
        r
    }

    /// Leaves the network and erases the persisted network state
    /// (BDB 3.1 §13.3 reset via a local action).
    pub fn factory_reset(&mut self) -> Result<(), StorageError> {
        let _ = self.stack.leave(false);
        self.stack.flush();
        self.bdb.set_on_network(false);
        self.stack.erase_persisted()?;
        #[cfg(feature = "direct")]
        {
            self.direct = direct::DirectState::default();
        }
        self.collect();
        Ok(())
    }

    /// Next event.
    pub fn next_event(&mut self) -> Option<Event> {
        self.collect();
        self.events.pop_front()
    }

    /// A frame received by the radio.
    pub fn on_radio_frame(&mut self, bytes: &[u8], meta: RxMetadata) {
        self.stack.on_radio_frame(bytes, meta);
        self.collect();
    }

    /// Completion of the transmission requested by the last
    /// [`MacAction::Transmit`].
    pub fn on_tx_complete(&mut self, result: Result<TxResult, RadioError>) {
        self.stack.on_tx_complete(result);
        self.collect();
    }

    /// Result of an energy-detect request.
    pub fn on_energy_result(&mut self, level: u8) {
        self.stack.on_energy_result(level);
        self.collect();
    }

    /// Next radio action to execute.
    pub fn next_radio_action(&mut self) -> Option<MacAction> {
        self.stack.next_radio_action()
    }

    /// Advances time: runs every layer's timers and the commissioning
    /// timeouts.
    pub fn poll(&mut self, now: Instant) {
        // BDB 3.1 §6.6: a sleepy end device polls fast while a
        // commissioning procedure runs.
        self.stack.set_fast_polling(self.bdb.is_busy());
        self.stack.poll(now);
        #[cfg(feature = "direct")]
        self.direct_poll(now);
        if let Some(o) = self.bdb.poll(&mut self.stack, now) {
            #[cfg(feature = "direct")]
            if let Some(d) = self.direct_bdb_outcome(o) {
                self.push(d);
            }
            self.push(Event::Commissioning(o));
        }
        self.collect();
    }

    /// Earliest time [`Node::poll`] must be called again.
    pub fn next_deadline(&self) -> Option<Instant> {
        match (self.stack.next_deadline(), self.bdb.next_deadline()) {
            (Some(a), Some(b)) => Some(if a.as_millis() <= b.as_millis() { a } else { b }),
            (a, b) => a.or(b),
        }
    }

    /// Whether the receiver must stay on (routers, coordinators and
    /// non-sleepy end devices, or a sleepy device awaiting a reply).
    pub fn needs_receiver(&self) -> bool {
        self.stack.needs_receiver()
    }
}
