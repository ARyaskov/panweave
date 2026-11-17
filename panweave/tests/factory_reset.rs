//! Real queued MAC work must not cross the factory-reset ownership boundary.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use panweave::mac::{radio::TxResult, service::MacAction};
use panweave::runtime::StackEvent;
use panweave::security::cipher::SoftwareAes;
use panweave::storage::{Key, Kind, MemoryStorage, Storage, StorageError};
use panweave::testkit::TestRng;
use panweave::types::{ChannelMask, DeviceId, Endpoint, ExtendedAddress, Instant, ProfileId};
use panweave::zcl::{clusters::identify, layer::EndpointInstance};
use panweave::zdo::SimpleDescriptor;
use panweave::{Coordinator, Event, Node};

type TestNode = Node<SoftwareAes, TestRng, MemoryStorage<64, 512>>;
fn node() -> TestNode {
    Coordinator::new(ExtendedAddress(1))
        .channels(ChannelMask(1 << 11), ChannelMask::EMPTY)
        .scan_duration(0)
        .build(TestRng::seed(7), MemoryStorage::new())
}
fn large(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(8 << 20)
        .spawn(test)
        .unwrap()
        .join()
        .unwrap();
}
fn form(node: &mut TestNode, now: &mut u64) {
    node.form_network().expect("formation accepted");
    for _ in 0..200 {
        node.poll(Instant::from_millis(*now));
        for _ in 0..256 {
            let Some(action) = node.next_radio_action() else {
                break;
            };
            match action {
                MacAction::EnergyDetect { .. } => node.on_energy_result(0),
                MacAction::Transmit { .. } => node.on_tx_complete(Ok(TxResult {
                    acked: false,
                    frame_pending: false,
                    timestamp_us: None,
                })),
                MacAction::Configure(_)
                | MacAction::SetChannel { .. }
                | MacAction::SetPending { .. } => {}
            }
        }
        let mut formed = false;
        while let Some(event) = node.next_event() {
            formed |= matches!(event, Event::Stack(StackEvent::NetworkFormed { .. }));
        }
        if formed {
            return;
        }
        *now += 10;
    }
    panic!("real formation did not finish");
}

#[test]
fn queued_mac_work_and_handles_do_not_leak_into_the_next_network() {
    large(|| {
        let mut node = node();
        let counter = Key::single(Kind::NwkFrameCounter);
        node.stack
            .storage
            .store(counter, &0x1234_5000_u32.to_le_bytes())
            .unwrap();
        node.initialize().unwrap();
        let mut now = 0;
        form(&mut node, &mut now);
        for _ in 0..40 {
            node.open_network().unwrap();
            node.open_network().unwrap();
            assert!(
                node.stack.mac.tx_queue_len() > 0,
                "real old control frames are queued"
            );
            let bound_before = node.stack.nwk.security.keys.outgoing.peek();
            node.factory_reset().expect("reset with quiescent radio");
            assert_eq!(node.stack.mac.tx_queue_len(), 0);
            assert!(
                node.next_radio_action().is_none(),
                "no old frame/config/scan action survives reset"
            );
            assert!(!node.bdb.is_busy() && !node.bdb.is_on_network());
            assert!(node.stack.nwk.security.keys.outgoing.peek() >= bound_before);
            let mut bytes = [0; 4];
            assert_eq!(node.stack.storage.load(counter, &mut bytes), Ok(Some(4)));
            assert!(u32::from_le_bytes(bytes) >= 0x1234_5000);
            now += 10;
            form(&mut node, &mut now);
        }
    });
}

#[test]
fn reset_does_not_claim_success_while_an_unfinished_scan_owns_the_network() {
    large(|| {
        let mut node = node();
        node.form_network().unwrap();
        assert_eq!(node.factory_reset(), Err(StorageError::Io));
    });
}

#[test]
fn reset_cannot_clear_a_control_event_loss_recovery_latch() {
    large(|| {
        let mut node = node();
        let mut endpoint = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
        endpoint.add_instance(identify::server().unwrap()).unwrap();
        node.add_endpoint(
            SimpleDescriptor::new(
                Endpoint(1),
                ProfileId::HOME_AUTOMATION,
                DeviceId(0x0100),
                1,
                &[identify::ID],
                &[],
            )
            .unwrap(),
            endpoint,
        )
        .unwrap();
        while node.next_event().is_some() {}
        for seconds in 1..=17 {
            node.stack
                .zcl
                .set_identify_time(Endpoint(1), seconds)
                .unwrap();
            node.poll(Instant::from_millis(0));
        }
        assert!(node.recovery_needed());
        assert_eq!(node.factory_reset(), Err(StorageError::Io));
        assert!(node.stack.cancel_radio_work_for_factory_reset().is_err());
        assert!(node.recovery_needed());
        assert!(node.next_radio_action().is_none());
    });
}

struct EraseFaultStore {
    data: MemoryStorage<64, 512>,
    fail: bool,
}
impl Storage for EraseFaultStore {
    fn store(&mut self, key: Key, data: &[u8]) -> Result<(), StorageError> {
        self.data.store(key, data)
    }
    fn load(&mut self, key: Key, data: &mut [u8]) -> Result<Option<usize>, StorageError> {
        self.data.load(key, data)
    }
    fn erase(&mut self, key: Key) -> Result<(), StorageError> {
        self.data.erase(key)
    }
    fn erase_kind(&mut self, kind: Kind) -> Result<(), StorageError> {
        if self.fail && kind == Kind::Bindings {
            return Err(StorageError::Io);
        }
        self.data.erase_kind(kind)
    }
}

#[test]
fn reset_forgets_learned_security_and_pairings_but_keeps_declared_bootstrap() {
    large(|| {
        use panweave::Router;
        use panweave::aps::tables::{BindingDestination, BindingEntry};
        use panweave::nwk::neighbor::{NeighborEntry, Relationship};
        use panweave::runtime::AdoptParams;
        use panweave::security::material::{LinkKeyEntry, LinkKeyKind};
        use panweave::types::{
            Channel, ClusterId, GroupAddress, Key128, KeySequenceNumber, LogicalDeviceType, PanId,
            ShortAddress,
        };

        const IEEE: ExtendedAddress = ExtendedAddress(1);
        const TC: ExtendedAddress = ExtendedAddress(0xaa);
        const PEER: ExtendedAddress = ExtendedAddress(0xbb);
        for fail_erase in [true, false] {
            let mut node: Node<SoftwareAes, TestRng, EraseFaultStore> = Router::new(IEEE)
                .preconfigured_link_key(TC, Key128::from_bytes([0x31; 16]), LinkKeyKind::Global)
                .build(
                    TestRng::seed(19),
                    EraseFaultStore {
                        data: MemoryStorage::new(),
                        fail: false,
                    },
                );
            let counter = Key::single(Kind::NwkFrameCounter);
            node.stack
                .storage
                .store(counter, &0x1234_5000_u32.to_le_bytes())
                .unwrap();
            node.initialize().unwrap();
            let mut endpoint = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
            endpoint.add_instance(identify::server().unwrap()).unwrap();
            node.add_endpoint(
                SimpleDescriptor::new(
                    Endpoint(1),
                    ProfileId::HOME_AUTOMATION,
                    DeviceId(0x0100),
                    1,
                    &[identify::ID],
                    &[],
                )
                .unwrap(),
                endpoint,
            )
            .unwrap();
            node.stack
                .adopt_network(&AdoptParams {
                    extended_pan_id: ExtendedAddress(0x1234),
                    pan_id: PanId(0x4567),
                    channel: Channel::DEFAULT_2_4GHZ,
                    network_address: Some(ShortAddress(0x1234)),
                    key: Key128::from_bytes([0x42; 16]),
                    key_sequence: KeySequenceNumber(0),
                    update_id: 0,
                    trust_center: TC,
                })
                .unwrap();
            node.bdb.set_on_network(true);
            node.stack
                .nwk
                .security
                .install_key(KeySequenceNumber(7), Key128::from_bytes([0x43; 16]));
            node.stack
                .nwk
                .neighbors
                .insert(
                    NeighborEntry::new(
                        PEER,
                        ShortAddress(0x2345),
                        LogicalDeviceType::Router,
                        true,
                        Relationship::Sibling,
                        200,
                    ),
                    3,
                )
                .unwrap();
            node.stack
                .aps
                .security
                .install(LinkKeyEntry::provisional(
                    PEER,
                    Key128::from_bytes([0x52; 16]),
                    LinkKeyKind::Unique,
                ))
                .unwrap();
            node.stack
                .aps
                .bindings
                .bind(BindingEntry {
                    src_endpoint: Endpoint(1),
                    cluster: ClusterId(6),
                    destination: BindingDestination::Unicast {
                        address: PEER,
                        endpoint: Endpoint(1),
                    },
                })
                .unwrap();
            node.stack
                .aps
                .groups
                .add(GroupAddress(7), Endpoint(1))
                .unwrap();
            node.stack.aps.aib.use_extended_pan_id = ExtendedAddress(0x1234);
            assert!(node.stack.aps.security.entry(PEER).is_some());
            assert!(!node.stack.aps.bindings.is_empty() && !node.stack.aps.groups.is_empty());
            assert_eq!(
                node.stack.aps.aib.use_extended_pan_id,
                ExtendedAddress(0x1234)
            );
            node.stack.storage.fail = fail_erase;
            if fail_erase {
                assert_eq!(node.factory_reset(), Err(StorageError::Io));
                assert!(
                    node.stack.persistence_pending(),
                    "failed erase remains pending"
                );
                assert!(
                    !node.stack.is_operating(),
                    "failed reset cannot claim an operational network"
                );
                continue;
            }
            node.factory_reset().unwrap();
            assert!(node.stack.aps.security.entry(PEER).is_none());
            let bootstrap = node
                .stack
                .aps
                .security
                .entry(TC)
                .expect("declared bootstrap key restored");
            assert_eq!(bootstrap.key, Key128::from_bytes([0x31; 16]));
            assert!(node.stack.aps.bindings.is_empty() && node.stack.aps.groups.is_empty());
            assert_eq!(node.stack.aps.aib.use_extended_pan_id, ExtendedAddress(0));
            assert_eq!(node.stack.aps.aib.trust_center_address, TC);
            assert!(
                node.stack.nwk.security.keys.iter().next().is_none(),
                "no old active or alternate NWK key"
            );
            assert_eq!(node.stack.nwk.neighbors.len(), 0);
            assert_eq!(node.stack.config().ieee, IEEE);
            assert!(node.stack.zdo.endpoint(Endpoint(1)).is_some());
            assert!(node.stack.zcl.endpoint(Endpoint(1)).is_some());
            assert!(node.stack.nwk.security.keys.outgoing.peek() >= 0x1234_5000);
        }
    });
}
