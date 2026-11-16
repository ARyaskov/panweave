//! Public event producers must expose an unrecoverable control gap before
//! any stale transition can be observed or further radio work can run.

#![allow(clippy::unwrap_used, clippy::panic)]

use panweave_mac::radio::{RadioError, RxMetadata};
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{AdoptParams, EVENT_CAPACITY, JoinMode, StackConfig, StackEvent};
use panweave_security::cipher::SoftwareAes;
use panweave_security::material::LinkKeyKind;
use panweave_sim::SimStack;
use panweave_storage::{Key, Kind, MemoryStorage, Storage, StorageError};
use panweave_testkit::TestRng;
use panweave_types::{
    Channel, DeviceId, Duration, Endpoint, ExtendedAddress, Key128, KeySequenceNumber,
    LogicalDeviceType, NwkStatus, PanId, ProfileId, ShortAddress,
};
use panweave_zcl::clusters::identify;
use panweave_zcl::layer::EndpointInstance;
use panweave_zdo::descriptor::SimpleDescriptor;

const IEEE: ExtendedAddress = ExtendedAddress(0x00EA_0000_0000_0011);
const PEER: ExtendedAddress = ExtendedAddress(0x00EA_0000_0000_0012);

#[test]
fn a_real_control_event_overflow_stops_the_stack_until_reconstruction() {
    let mut stack = SimStack::new(
        StackConfig::new(LogicalDeviceType::Coordinator, IEEE),
        MacServiceConfig::default(),
        TestRng::seed(11),
        MemoryStorage::new(),
    );
    let descriptor = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0100),
        1,
        &[identify::ID],
        &[],
    )
    .unwrap();
    let mut endpoint = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    endpoint.add_instance(identify::server().unwrap()).unwrap();
    stack.add_endpoint(descriptor, endpoint).unwrap();
    stack
        .adopt_network(&AdoptParams {
            extended_pan_id: IEEE,
            pan_id: PanId(0x1234),
            channel: Channel::DEFAULT_2_4GHZ,
            network_address: Some(ShortAddress::COORDINATOR),
            key: Key128::from_bytes([0x44; 16]),
            key_sequence: KeySequenceNumber(0),
            update_id: 0,
            trust_center: IEEE,
        })
        .unwrap();
    stack.install_link_key(
        PEER,
        Key128::from_bytes([0x55; 16]),
        LinkKeyKind::Unique,
        false,
    );
    while stack.next_event().is_some() {}
    while stack.next_radio_action().is_some() {}
    assert!(stack.is_operating());
    let original_key = stack.aps.security.entry(PEER).unwrap().key.clone();
    let original_sequence = stack.network_key_sequence();
    // Every call traverses the real ZCL -> pump -> Stack event boundary.
    // Flush each event, so a smaller upstream queue cannot hide overflow.
    for _ in 0..=EVENT_CAPACITY {
        stack.zcl.set_identify_time(Endpoint(1), 60).unwrap();
        stack.flush();
    }
    assert!(stack.recovery_needed());
    assert!(!stack.is_operating());
    assert!(!stack.needs_receiver());
    assert!(matches!(
        stack.next_event(),
        Some(StackEvent::EventQueueLoss { control, .. }) if control > 0
    ));
    assert!(
        stack.next_event().is_none(),
        "stale controls must be purged"
    );
    assert!(
        stack.recovery_needed(),
        "reading a gap cannot resume the owner"
    );
    assert!(stack.next_radio_action().is_none());
    assert!(stack.next_deadline().is_none());
    assert_eq!(stack.resume(), Err(NwkStatus::InvalidRequest));
    assert_eq!(
        stack.join(JoinMode::SecuredRejoin),
        Err(NwkStatus::InvalidRequest)
    );
    assert_eq!(
        stack.permit_join_network(30),
        Err(NwkStatus::InvalidRequest)
    );
    assert_eq!(
        stack.leave_with(false, true),
        Err(NwkStatus::InvalidRequest)
    );
    assert_eq!(
        stack.request_application_link_key(PEER),
        Err(NwkStatus::InvalidRequest)
    );
    assert_eq!(
        stack.update_network_key(Key128::from_bytes([0x66; 16])),
        Err(NwkStatus::InvalidRequest)
    );
    stack.install_link_key(
        PEER,
        Key128::from_bytes([0x77; 16]),
        LinkKeyKind::Unique,
        false,
    );
    assert!(!stack.remove_link_key(PEER));
    assert_eq!(stack.aps.security.entry(PEER).unwrap().key, original_key);
    assert_eq!(stack.network_key_sequence(), original_sequence);
    let now = stack.now();
    stack.poll(now + Duration::from_secs(60));
    stack.on_radio_frame(&[], RxMetadata::default());
    stack.on_tx_complete(Err(RadioError::NoAck));
    stack.on_energy_result(255);
    stack.flush();
    assert_eq!(stack.now(), now);
    assert!(stack.next_event().is_none());
    assert!(stack.next_radio_action().is_none());
    assert!(stack.next_deadline().is_none());
    // Restoration on the same object cannot clear the event-loss latch.
    stack.restore().unwrap();
    assert_eq!(stack.resume(), Err(NwkStatus::InvalidRequest));
    assert!(stack.recovery_needed());
    assert!(!stack.is_operating());
}

#[derive(Default)]
struct RetryStorage {
    inner: MemoryStorage<64, 128>,
    retry: bool,
    children_attempts: usize,
}

impl Storage for RetryStorage {
    fn store(&mut self, key: Key, data: &[u8]) -> Result<(), StorageError> {
        match key.kind {
            Kind::Nib => Err(if self.retry {
                StorageError::Full
            } else {
                StorageError::Io
            }),
            Kind::Children => {
                self.children_attempts += 1;
                if self.retry {
                    self.inner.store(key, data)
                } else {
                    Err(StorageError::Io)
                }
            }
            _ => self.inner.store(key, data),
        }
    }

    fn load(&mut self, key: Key, buf: &mut [u8]) -> Result<Option<usize>, StorageError> {
        self.inner.load(key, buf)
    }

    fn erase(&mut self, key: Key) -> Result<(), StorageError> {
        self.inner.erase(key)
    }

    fn erase_kind(&mut self, kind: Kind) -> Result<(), StorageError> {
        self.inner.erase_kind(kind)
    }
}

#[test]
fn a_gap_during_persistence_retry_stops_later_writes_and_timers_in_that_call() {
    let mut stack = panweave_runtime::Stack::<SoftwareAes, _, _>::new(
        StackConfig::new(LogicalDeviceType::Coordinator, IEEE),
        MacServiceConfig::default(),
        TestRng::seed(12),
        RetryStorage::default(),
    );
    let descriptor = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0100),
        1,
        &[identify::ID],
        &[],
    )
    .unwrap();
    let mut endpoint = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    endpoint.add_instance(identify::server().unwrap()).unwrap();
    stack.add_endpoint(descriptor, endpoint).unwrap();
    assert_eq!(stack.persist_nib(), Err(StorageError::Io));
    assert_eq!(stack.persist_children(), Err(StorageError::Io));
    for _ in 2..EVENT_CAPACITY {
        stack.zcl.set_identify_time(Endpoint(1), 60).unwrap();
        stack.flush();
    }
    assert!(!stack.recovery_needed());
    stack.storage.retry = true;
    // A different write error emits a new control event into the full
    // queue. The next dirty record must not be written after that gap.
    stack.poll(stack.now() + Duration::from_secs(1));
    assert!(stack.recovery_needed());
    assert_eq!(stack.storage.children_attempts, 1);
    assert_eq!(
        identify::identify_time(
            stack
                .zcl
                .cluster(Endpoint(1), identify::ID, panweave_zcl::Role::Server)
                .unwrap()
        ),
        60
    );
    assert!(
        matches!(stack.next_event(), Some(StackEvent::EventQueueLoss { control, .. }) if control > 0)
    );
    assert!(stack.next_radio_action().is_none());
}
