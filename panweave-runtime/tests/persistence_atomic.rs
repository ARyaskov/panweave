//! Persistence failures must preserve unrelated peers and never execute a
//! Green Power command before its replay state is durable.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use panweave_codec::{Encode, Reader, Writer};
use panweave_green_power::cluster::CommunicationMode;
use panweave_green_power::gpdf::{
    self, ApplicationId, ExtendedFrameControl, FrameType, GpdId, NwkFrameControl, SecurityLevel,
};
use panweave_green_power::proxy_table::{ProxyEntry, SecurityOptions};
use panweave_green_power::security::{self, Direction, KeyType};
use panweave_green_power::sink_table::SinkEntry;
use panweave_mac::frame::{Frame, MacAddress};
use panweave_mac::radio::RxMetadata;
use panweave_mac::service::MacServiceConfig;
use panweave_runtime::green_power::SinkOptions;
use panweave_runtime::{AdoptParams, Restored, Stack, StackConfig, StackEvent};
use panweave_security::cipher::SoftwareAes;
use panweave_security::material::{LinkKeyEntry, LinkKeyKind};
use panweave_storage::{Key, Kind, MemoryStorage, Storage, StorageError};
use panweave_testkit::TestRng;
use panweave_types::{
    Channel, DeviceId, Endpoint, ExtendedAddress, Instant, Key128, KeyAttributes,
    KeySequenceNumber, LogicalDeviceType, PanId, ProfileId, ShortAddress,
};
use panweave_zcl::clusters::on_off;
use panweave_zcl::layer::EndpointInstance;
use panweave_zdo::descriptor::SimpleDescriptor;

const IEEE: ExtendedAddress = ExtendedAddress(0x00AB_0000_0000_0001);
const PEER: ExtendedAddress = ExtendedAddress(0x00AB_0000_0000_0002);
const OTHER: ExtendedAddress = ExtendedAddress(0x00AB_0000_0000_0003);
const GPD: GpdId = GpdId::SrcId(0x1234_5678);
const OTHER_GPD: GpdId = GpdId::SrcId(0x2345_6789);
const GPD_KEY: Key128 = Key128::from_bytes([0x55; 16]);

#[derive(Clone, Default)]
struct FaultStorage {
    inner: MemoryStorage<96, 512>,
    remaining: Option<usize>,
    operations: usize,
    fail_gp: bool,
    limit: Option<(Kind, usize)>,
    nib_attempts: usize,
}

impl FaultStorage {
    fn mutation(&mut self, kind: Kind) -> Result<(), StorageError> {
        if kind == Kind::Nib {
            self.nib_attempts += 1;
        }
        if self.fail_gp && kind == Kind::GreenPower {
            return Err(StorageError::Io);
        }
        if let Some((limited, remaining)) = &mut self.limit
            && *limited == kind
        {
            if *remaining == 0 {
                return Err(StorageError::Io);
            }
            *remaining -= 1;
        }
        if let Some(remaining) = &mut self.remaining {
            if *remaining == 0 {
                return Err(StorageError::Io);
            }
            *remaining -= 1;
        }
        self.operations += 1;
        Ok(())
    }
}

impl Storage for FaultStorage {
    fn store(&mut self, key: Key, data: &[u8]) -> Result<(), StorageError> {
        self.mutation(key.kind)?;
        self.inner.store(key, data)
    }
    fn load(&mut self, key: Key, buf: &mut [u8]) -> Result<Option<usize>, StorageError> {
        self.inner.load(key, buf)
    }
    fn erase(&mut self, key: Key) -> Result<(), StorageError> {
        self.mutation(key.kind)?;
        self.inner.erase(key)
    }
    fn erase_kind(&mut self, kind: Kind) -> Result<(), StorageError> {
        self.mutation(kind)?;
        self.inner.erase_kind(kind)
    }
}

type Node = Stack<SoftwareAes, TestRng, FaultStorage>;

fn restart(storage: FaultStorage) -> Node {
    let mut stack = Node::new(
        StackConfig::new(LogicalDeviceType::Coordinator, IEEE),
        MacServiceConfig::default(),
        TestRng::seed(1),
        storage,
    );
    let desc = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0100),
        1,
        &[on_off::ID],
        &[],
    )
    .unwrap();
    let mut endpoint = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    endpoint.add_instance(on_off::server().unwrap()).unwrap();
    stack.add_endpoint(desc, endpoint).unwrap();
    stack
}

fn node(storage: FaultStorage) -> Node {
    let mut stack = restart(storage);
    stack
        .adopt_network(&AdoptParams {
            extended_pan_id: IEEE,
            pan_id: PanId(0x1234),
            channel: Channel::DEFAULT_2_4GHZ,
            network_address: Some(ShortAddress::COORDINATOR),
            key: Key128::from_bytes([0x33; 16]),
            key_sequence: KeySequenceNumber(0),
            update_id: 0,
            trust_center: IEEE,
        })
        .unwrap();
    stack
}

fn install_key(stack: &mut Node, partner: ExtendedAddress, value: u8) {
    let mut entry = LinkKeyEntry::provisional(
        partner,
        Key128::from_bytes([value; 16]),
        LinkKeyKind::Unique,
    );
    entry.attributes = KeyAttributes::VerifiedKey;
    entry.outgoing = panweave_security::frame_counter::OutgoingCounter::restore(1024);
    stack.aps.security.keys_mut().insert(entry).unwrap();
    stack
        .storage
        .store(
            Key::with_id(Kind::ApsFrameCounter, partner.0),
            &1024u32.to_le_bytes(),
        )
        .unwrap();
}

fn readable_storage(mut storage: FaultStorage) -> FaultStorage {
    storage.remaining = None;
    storage.fail_gp = false;
    storage.limit = None;
    storage
}

#[test]
fn changing_one_link_key_never_erases_an_unrelated_partner() {
    let mut original = node(FaultStorage::default());
    install_key(&mut original, PEER, 1);
    install_key(&mut original, OTHER, 2);
    original.persist_link_keys().unwrap();
    let image = original.storage;
    for cut in 0..=1 {
        let mut stack = node(image.clone());
        stack.restore().unwrap();
        install_key(&mut stack, PEER, 3);
        stack.storage.remaining = Some(cut);
        let result = stack.persist_link_keys();
        let mut fresh = restart(readable_storage(stack.storage));
        assert_eq!(fresh.restore().unwrap(), Restored::OnNetwork);
        assert_eq!(
            fresh.aps.security.entry(OTHER).unwrap().key,
            Key128::from_bytes([2; 16])
        );
        assert_eq!(
            fresh.aps.security.entry(PEER).unwrap().key,
            Key128::from_bytes([if result.is_ok() { 3 } else { 1 }; 16])
        );
    }
}

#[test]
fn removing_a_partner_never_revives_it_or_erases_an_unrelated_key() {
    let mut original = node(FaultStorage::default());
    install_key(&mut original, PEER, 1);
    install_key(&mut original, OTHER, 2);
    original.persist_link_keys().unwrap();
    for cut in 0..=3 {
        let mut stack = node(original.storage.clone());
        stack.restore().unwrap();
        stack.aps.security.keys_mut().remove(PEER);
        stack.storage.remaining = Some(cut);
        let result = stack.persist_link_keys();
        let mut fresh = restart(readable_storage(stack.storage));
        assert_eq!(fresh.restore().unwrap(), Restored::OnNetwork);
        assert_eq!(
            fresh.aps.security.entry(OTHER).unwrap().key,
            Key128::from_bytes([2; 16])
        );
        if result.is_ok() || cut > 0 {
            assert!(fresh.aps.security.entry(PEER).is_none());
        }
        fresh.aps.security.keys_mut().remove(PEER);
        fresh.persist_link_keys().unwrap();
        let mut again = restart(fresh.storage);
        again.restore().unwrap();
        assert!(again.aps.security.entry(PEER).is_none());
    }
}

#[test]
fn a_new_link_key_is_visible_only_after_its_index_is_committed() {
    let mut original = node(FaultStorage::default());
    install_key(&mut original, OTHER, 2);
    original.persist_link_keys().unwrap();
    for cut in 0..=4 {
        let mut stack = node(original.storage.clone());
        stack.restore().unwrap();
        install_key(&mut stack, PEER, 1);
        stack.storage.remaining = Some(cut);
        let result = stack.persist_link_keys();
        let mut storage = readable_storage(stack.storage);
        let mut buf = [0u8; 512];
        let n = storage
            .load(Key::single(Kind::Aib), &mut buf)
            .unwrap()
            .unwrap();
        let mut index = Reader::new(&buf[..n]);
        let _format = index.u8().unwrap();
        let _tc = index.u64_le().unwrap();
        let count = index.u8().unwrap();
        let indexed = (0..count).any(|_| index.u64_le().unwrap() == PEER.0);
        if result.is_ok() {
            assert!(indexed);
        }
        let mut fresh = restart(storage);
        assert_eq!(fresh.restore().unwrap(), Restored::OnNetwork);
        assert_eq!(
            fresh.aps.security.entry(OTHER).unwrap().key,
            Key128::from_bytes([2; 16])
        );
        assert_eq!(fresh.aps.security.entry(PEER).is_some(), indexed);
    }
}

#[test]
fn interrupted_additions_reclaim_unindexed_records_in_bounded_storage() {
    let mut original = node(FaultStorage::default());
    install_key(&mut original, OTHER, 2);
    original.persist_link_keys().unwrap();
    let baseline = original.storage.inner.len();
    let mut image = original.storage;
    for iteration in 0..120u64 {
        let mut stack = restart(image);
        stack.restore().unwrap();
        let partner = ExtendedAddress(0x00AB_0000_0000_1000 + iteration);
        let entry =
            LinkKeyEntry::provisional(partner, Key128::from_bytes([9; 16]), LinkKeyKind::Unique);
        stack.aps.security.keys_mut().insert(entry).unwrap();
        // The prior journal's two cleanup operations precede the next
        // journal and key write; cut before the new AIB index commits.
        stack.storage.remaining = Some(if iteration == 0 { 2 } else { 4 });
        assert_eq!(stack.persist_link_keys(), Err(StorageError::Io));
        assert!(
            stack.storage.inner.len() <= baseline + 2,
            "unindexed keys must not accumulate"
        );
        image = readable_storage(stack.storage);
    }
    let mut fresh = restart(image);
    fresh.restore().unwrap();
    fresh.persist_link_keys().unwrap();
    assert_eq!(fresh.storage.inner.len(), baseline);
    assert_eq!(fresh.aps.security.keys().iter().count(), 1);
}

#[test]
fn failed_state_saves_retry_on_the_clock_without_spinning_the_pump() {
    let mut stack = node(FaultStorage::default());
    events(&mut stack);
    stack.nwk.nib.update_id = 42;
    stack.storage.nib_attempts = 0;
    stack.storage.limit = Some((Kind::Nib, 0));
    assert_eq!(stack.persist_nib(), Err(StorageError::Io));
    assert!(stack.persistence_pending());
    assert_eq!(stack.persistence_error(Kind::Nib), Some(StorageError::Io));
    stack.flush();
    stack.flush();
    stack.poll(Instant::from_millis(99));
    assert_eq!(stack.storage.nib_attempts, 1, "a retry needs its deadline");
    stack.storage.limit = None;
    stack.poll(Instant::from_millis(100));
    assert_eq!(stack.storage.nib_attempts, 2);
    assert!(!stack.persistence_pending());
    assert_eq!(stack.persistence_error(Kind::Nib), None);
    let mut fresh = restart(stack.storage);
    assert_eq!(fresh.restore().unwrap(), Restored::OnNetwork);
    assert_eq!(fresh.update_id(), 42);
}

fn proxy_entry(gpd: GpdId, counter: u32) -> ProxyEntry {
    let mut entry = ProxyEntry::new(gpd);
    entry.sequence_number_capable = true;
    entry.frame_counter = counter;
    entry
}

#[test]
fn proxy_slots_survive_counter_update_failure_and_ram_reordering() {
    let mut original = node(FaultStorage::default());
    original.enable_green_power_proxy().unwrap();
    original
        .green_power_proxy()
        .unwrap()
        .table
        .insert(proxy_entry(GPD, 7))
        .unwrap();
    original
        .green_power_proxy()
        .unwrap()
        .table
        .insert(proxy_entry(OTHER_GPD, 8))
        .unwrap();
    original.persist_proxy_table().unwrap();
    for cut in 0..=1 {
        let mut stack = restart(original.storage.clone());
        stack.enable_green_power_proxy().unwrap();
        stack
            .green_power_proxy()
            .unwrap()
            .table
            .find_mut(&GPD)
            .unwrap()
            .frame_counter = 9;
        stack.storage.remaining = Some(cut);
        let result = stack.persist_proxy_table();
        let mut fresh = restart(readable_storage(stack.storage));
        fresh.enable_green_power_proxy().unwrap();
        let table = &fresh.green_power_proxy_ref().unwrap().table;
        assert_eq!(table.find(&OTHER_GPD).unwrap().frame_counter, 8);
        assert_eq!(
            table.find(&GPD).unwrap().frame_counter,
            if result.is_ok() { 9 } else { 7 }
        );
        fresh.green_power_proxy().unwrap().table.remove(&GPD);
        fresh.storage.operations = 0;
        fresh.persist_proxy_table().unwrap();
        assert_eq!(fresh.storage.operations, 1, "only the removed slot changes");
        fresh.persist_proxy_table().unwrap();
        assert_eq!(fresh.storage.operations, 1, "unchanged saves do not write");
        let mut again = restart(fresh.storage);
        again.enable_green_power_proxy().unwrap();
        assert!(
            again
                .green_power_proxy_ref()
                .unwrap()
                .table
                .find(&GPD)
                .is_none()
        );
        assert_eq!(
            again
                .green_power_proxy_ref()
                .unwrap()
                .table
                .find(&OTHER_GPD)
                .unwrap()
                .frame_counter,
            8
        );
    }
}

#[test]
fn a_damaged_gp_record_fails_before_registering_the_endpoint() {
    let mut stack = restart(FaultStorage::default());
    stack
        .storage
        .store(Key::single(Kind::GreenPower), &[0xff])
        .unwrap();
    assert!(stack.enable_green_power_proxy().is_err());
    assert!(events(&mut stack).iter().any(|e| matches!(
        e,
        StackEvent::PersistenceFailed {
            kind: Kind::GreenPower,
            error: StorageError::Corrupt
        }
    )));
    stack.storage.erase(Key::single(Kind::GreenPower)).unwrap();
    stack.enable_green_power_proxy().unwrap();
    assert_eq!(stack.green_power_proxy_ref().unwrap().table.len(), 0);
}

fn toggle(counter: u32) -> Vec<u8> {
    let mut header = [0; 16];
    let mut writer = Writer::new(&mut header);
    gpdf::write_header(
        &mut writer,
        NwkFrameControl {
            frame_type: FrameType::Data,
            auto_commissioning: false,
            extension: true,
        },
        Some(ExtendedFrameControl {
            application_id: ApplicationId::SrcId,
            security_level: SecurityLevel::Mic,
            individual_key: true,
            rx_after_tx: false,
            from_proxy: false,
        }),
        Some(&GPD),
        Some(counter),
    )
    .unwrap();
    let n = writer.position();
    let mut payload = vec![panweave_green_power::command::TOGGLE];
    let mic = security::protect::<SoftwareAes>(
        &GPD_KEY,
        SecurityLevel::Mic,
        &GPD,
        counter,
        Direction::FromGpd,
        &header[..n],
        &mut payload,
    )
    .unwrap();
    let mut body = header[..n].to_vec();
    body.extend(payload);
    body.extend(mic);
    let mut bytes = [0; 127];
    let n = Frame {
        header: gpdf::mac_header(
            u8::try_from(counter).unwrap(),
            MacAddress::Short(ShortAddress::BROADCAST_ALL),
            MacAddress::None,
        ),
        payload: &body,
    }
    .encode_to_slice(&mut bytes)
    .unwrap();
    bytes[..n].to_vec()
}

fn events(stack: &mut Node) -> Vec<StackEvent> {
    core::iter::from_fn(|| stack.next_event()).collect()
}

#[test]
fn sink_executes_only_after_a_durable_retry_and_rejects_the_replay_after_reboot() {
    let mut stack = node(FaultStorage::default());
    stack
        .enable_green_power_sink(SinkOptions::default())
        .unwrap();
    let mut entry = SinkEntry::new(GPD, CommunicationMode::DerivedGroupcast, 2);
    entry.security = Some(SecurityOptions {
        level: SecurityLevel::Mic,
        key_type: KeyType::Individual,
        key: Some(GPD_KEY),
    });
    entry.frame_counter = 7;
    stack
        .green_power_sink()
        .unwrap()
        .table
        .insert(entry)
        .unwrap();
    stack.persist_sink_table().unwrap();
    events(&mut stack);
    stack.storage.fail_gp = true;
    let frame = toggle(8);
    stack.on_radio_frame(
        &frame,
        RxMetadata {
            lqi: 200,
            rssi_dbm: -40,
            ..RxMetadata::default()
        },
    );
    let failed = events(&mut stack);
    assert!(failed.iter().any(|e| matches!(
        e,
        StackEvent::PersistenceFailed {
            kind: Kind::GreenPower,
            error: StorageError::Io
        }
    )));
    assert!(!failed.iter().any(|e| matches!(
        e,
        StackEvent::GreenPowerCommand { .. } | StackEvent::OnOff { .. }
    )));
    assert!(stack.green_power_persistence_pending());
    assert_eq!(
        stack.green_power_persistence_error(),
        Some(StorageError::Io)
    );
    stack.storage.fail_gp = false;
    stack.poll(Instant::from_millis(1000));
    let recovered = events(&mut stack);
    assert!(!stack.green_power_persistence_pending());
    assert_eq!(stack.green_power_persistence_error(), None);
    assert_eq!(
        recovered
            .iter()
            .filter(|e| matches!(e, StackEvent::GreenPowerCommand { .. }))
            .count(),
        1
    );
    assert_eq!(
        recovered
            .iter()
            .filter(|e| matches!(e, StackEvent::OnOff { on: true, .. }))
            .count(),
        1
    );
    let mut fresh = restart(stack.storage);
    assert_eq!(fresh.restore().unwrap(), Restored::OnNetwork);
    fresh
        .enable_green_power_sink(SinkOptions::default())
        .unwrap();
    assert_eq!(
        fresh
            .green_power_sink_ref()
            .unwrap()
            .table
            .find(&GPD)
            .unwrap()
            .frame_counter,
        8
    );
    events(&mut fresh);
    fresh.on_radio_frame(&frame, RxMetadata::default());
    assert!(!events(&mut fresh).iter().any(|e| matches!(
        e,
        StackEvent::GreenPowerCommand { .. } | StackEvent::OnOff { .. }
    )));
}

#[test]
fn a_group_membership_retry_commits_once_and_releases_pairing_effects() {
    use panweave_green_power::cluster::{
        ConfigurationAction, PairedEndpoints, PairingConfiguration,
    };
    use panweave_types::GroupAddress;

    let mut stack = node(FaultStorage::default());
    stack
        .enable_green_power_sink(SinkOptions::default())
        .unwrap();
    events(&mut stack);
    let mut entry = SinkEntry::new(GPD, CommunicationMode::DerivedGroupcast, 2);
    entry.security = Some(SecurityOptions {
        level: SecurityLevel::Mic,
        key_type: KeyType::Individual,
        key: Some(GPD_KEY),
    });
    stack
        .green_power_sink()
        .unwrap()
        .on_pairing_configuration(
            &PairingConfiguration {
                action: ConfigurationAction::Extend,
                send_pairing: false,
                entry,
                paired_endpoints: PairedEndpoints::All,
                application_info: None,
                reports: None,
            },
            true,
        )
        .unwrap();
    stack.storage.limit = Some((Kind::Groups, 0));
    stack.poll(Instant::from_millis(0));
    assert!(stack.green_power_persistence_pending());
    assert!(
        !events(&mut stack)
            .iter()
            .any(|e| matches!(e, StackEvent::GreenPowerPaired { .. }))
    );
    let group = GroupAddress(panweave_green_power::proxy_table::derived_alias(&GPD).0);
    assert!(stack.aps.groups.contains(group, Endpoint(242)));
    stack.storage.limit = Some((Kind::Groups, 1));
    stack.poll(Instant::from_millis(1000));
    assert!(
        !stack.green_power_persistence_pending(),
        "one durable group write must release the batch"
    );
    assert_eq!(
        events(&mut stack)
            .iter()
            .filter(|e| matches!(e, StackEvent::GreenPowerPaired { .. }))
            .count(),
        1
    );
}
