//! What `Stack::restore` reports for every state the stack's storage can
//! be in, and that restoring never writes: an unusable or unreadable
//! network is reported (`RestoreDetail`) and left untouched, so the
//! application can refuse to form a replacement network
//! (`panweave_hub::protocol::NetworkRestore::decide`).

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use panweave_mac::service::MacServiceConfig;
use panweave_runtime::{
    Authorization, JoinMode, RestoreDetail, Restored, Stack, StackConfig, StackEvent,
};
use panweave_security::cipher::SoftwareAes;
use panweave_sim::{OnOffApp, SimStack, Simulator};
use panweave_storage::{Key, Kind, MemoryStorage, Storage, StorageError};
use panweave_testkit::TestRng;
use panweave_types::time::Duration;
use panweave_types::{ExtendedAddress, Key128, LogicalDeviceType};

const TC: ExtendedAddress = ExtendedAddress(0x00C1_0000_0000_0001);
const DEV: ExtendedAddress = ExtendedAddress(0x00C1_0000_0000_0002);
const NETWORK_KEY: Key128 = Key128::from_bytes([0x2B; 16]);

type Mem = MemoryStorage<64, 128>;

/// Storage whose reads can be made to fail, counting writes.
#[derive(Clone, Default)]
struct Flaky {
    inner: Mem,
    fail_reads: Arc<AtomicBool>,
}

impl Storage for Flaky {
    fn store(&mut self, key: Key, data: &[u8]) -> Result<(), StorageError> {
        self.inner.store(key, data)
    }
    fn load(&mut self, key: Key, buf: &mut [u8]) -> Result<Option<usize>, StorageError> {
        if self.fail_reads.load(Ordering::SeqCst) {
            return Err(StorageError::Io);
        }
        self.inner.load(key, buf)
    }
    fn erase(&mut self, key: Key) -> Result<(), StorageError> {
        self.inner.erase(key)
    }
    fn erase_kind(&mut self, kind: Kind) -> Result<(), StorageError> {
        self.inner.erase_kind(kind)
    }
}

fn tc_config() -> StackConfig {
    let mut cfg = StackConfig::new(LogicalDeviceType::Coordinator, TC);
    cfg.trust_center_policy.allow_joins = true;
    cfg
}

/// A formed network with one authorized device, and its storage.
fn formed() -> Mem {
    let mut sim = Simulator::new();
    let c = sim.add_stack(
        "tc",
        SimStack::new(
            tc_config(),
            MacServiceConfig::default(),
            TestRng::seed(1),
            Mem::new(),
        ),
        Box::new(OnOffApp::default()),
    );
    sim.stack(c).form_network_with_key(NETWORK_KEY).unwrap();
    assert!(sim.run_until(Duration::from_secs(30), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    }));
    sim.stack(c).permit_join_network(120).unwrap();
    let d = sim.add_stack(
        "dev",
        SimStack::new(
            StackConfig::new(LogicalDeviceType::Router, DEV),
            MacServiceConfig::default(),
            TestRng::seed(2),
            Mem::new(),
        ),
        Box::new(OnOffApp::default()),
    );
    sim.stack(d).join(JoinMode::Association).unwrap();
    assert!(sim.run_until(Duration::from_secs(60), |x| {
        x.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::DeviceAuthorized { ieee, .. } if *ieee == DEV))
    }));
    sim.run_for(Duration::from_secs(3));
    sim.stack(c).flush();
    sim.stack(c).storage.clone()
}

fn restart<S: Storage>(storage: S) -> Stack<SoftwareAes, TestRng, S> {
    Stack::new(
        tc_config(),
        MacServiceConfig::default(),
        TestRng::seed(9),
        storage,
    )
}

fn record(s: &mut Mem, kind: Kind) -> Vec<u8> {
    let mut buf = [0u8; 128];
    let n = s.load(Key::single(kind), &mut buf).unwrap().unwrap();
    buf[..n].to_vec()
}

#[test]
fn a_clean_store_is_empty_and_a_valid_one_restores() {
    let mut empty = restart(Mem::new());
    assert_eq!(empty.restore_detail(), RestoreDetail::NotRun);
    assert_eq!(empty.restore().unwrap(), Restored::FactoryNew);
    assert_eq!(empty.restore_detail(), RestoreDetail::Empty);
    assert!(empty.restore_detail().is_empty());

    let storage = formed();
    let mut tc = restart(storage);
    assert_eq!(tc.restore().unwrap(), Restored::OnNetwork);
    assert_eq!(tc.restore_detail(), RestoreDetail::Restored);
    assert_eq!(tc.device_authorization(DEV), Authorization::Authorized);
}

#[test]
fn an_unknown_format_is_reported_and_left_untouched() {
    let mut storage = formed();
    let mut nib = record(&mut storage, Kind::Nib);
    nib[0] = 0x7f; // a format from a newer firmware
    storage.store(Key::single(Kind::Nib), &nib).unwrap();
    let writes = storage.writes;
    let mut tc = restart(storage);
    assert_eq!(tc.restore().unwrap(), Restored::FactoryNew);
    assert_eq!(tc.restore_detail(), RestoreDetail::UnknownFormat);
    assert!(!tc.restore_detail().is_empty());
    assert_eq!(tc.storage.writes, writes, "restoring never writes");
    assert_eq!(record(&mut tc.storage, Kind::Nib), nib);
}

#[test]
fn a_half_written_network_is_incomplete() {
    // Power lost between the NIB and the network-key records (formation
    // or factory reset interrupted).
    let mut storage = formed();
    storage.erase(Key::single(Kind::NetworkKeys)).unwrap();
    let mut tc = restart(storage);
    assert_eq!(tc.restore().unwrap(), Restored::FactoryNew);
    assert_eq!(tc.restore_detail(), RestoreDetail::Incomplete);

    let mut storage = formed();
    storage.erase(Key::single(Kind::Nib)).unwrap();
    let mut tc = restart(storage);
    assert_eq!(tc.restore().unwrap(), Restored::FactoryNew);
    assert_eq!(tc.restore_detail(), RestoreDetail::Incomplete);
}

#[test]
fn a_damaged_network_record_is_malformed() {
    let mut storage = formed();
    let keys = record(&mut storage, Kind::NetworkKeys);
    storage
        .store(Key::single(Kind::NetworkKeys), &keys[..keys.len() / 2])
        .unwrap();
    let mut tc = restart(storage);
    assert_eq!(tc.restore().unwrap(), Restored::FactoryNew);
    assert_eq!(tc.restore_detail(), RestoreDetail::Malformed);

    let mut storage = formed();
    let nib = record(&mut storage, Kind::Nib);
    storage.store(Key::single(Kind::Nib), &nib[..5]).unwrap();
    let mut tc = restart(storage);
    assert_eq!(tc.restore().unwrap(), Restored::FactoryNew);
    assert_eq!(tc.restore_detail(), RestoreDetail::Malformed);
}

#[test]
fn an_unreadable_store_fails_and_recovers_when_reads_work_again() {
    let flaky = Flaky {
        inner: formed(),
        fail_reads: Arc::new(AtomicBool::new(true)),
    };
    let fail = flaky.fail_reads.clone();
    let mut tc = restart(flaky);
    assert_eq!(tc.restore(), Err(StorageError::Io));
    assert_eq!(tc.restore_detail(), RestoreDetail::NotRun);
    // A transient fault: the next attempt restores the same network.
    fail.store(false, Ordering::SeqCst);
    assert_eq!(tc.restore().unwrap(), Restored::OnNetwork);
    assert_eq!(tc.restore_detail(), RestoreDetail::Restored);
    assert_eq!(tc.device_authorization(DEV), Authorization::Authorized);
}

#[test]
fn a_restart_during_a_join_keeps_the_network_and_denies_the_unfinished_device() {
    // The device's link-key record was never written (power lost while
    // it joined): the network restores, the device has no key-pair entry
    // and no application access until it joins again.
    let mut storage = formed();
    storage.erase(Key::with_id(Kind::LinkKey, DEV.0)).unwrap();
    let mut tc = restart(storage);
    assert_eq!(tc.restore().unwrap(), Restored::OnNetwork);
    assert!(tc.aps.security.entry(DEV).is_none());
    assert_eq!(tc.device_authorization(DEV), Authorization::Unknown);
    assert!(!tc.device_authorization(DEV).grants_application_access());
}
