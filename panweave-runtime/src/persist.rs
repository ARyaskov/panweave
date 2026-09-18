//! Persistent stack state (R23.2 §2.2.8.1 APS persistent data, §3.6.1
//! NIB items retained across resets, §4.3.4 / §4.4.12 security material)
//! serialized into [`Storage`] records, and the warm-start restore.
//!
//! Layout is versioned; every record starts with a format octet so that
//! a later layout can migrate or reject old data instead of misreading
//! it. Keys are stored as raw octets: the storage backend is expected to
//! be the device's protected non-volatile memory (`docs/storage-model.md`).

use heapless::Vec;
use panweave_aps::layer::DeviceState;
use panweave_aps::tables::{BindingDestination, BindingEntry};
use panweave_codec::{Reader, Writer};
use panweave_nwk::neighbor::{NeighborEntry, Relationship};
use panweave_security::cipher::BlockCipher;
use panweave_security::material::{LinkKeyEntry, LinkKeyKind};
use panweave_storage::{Key, Kind, Storage, StorageError};
use panweave_types::{
    Channel, ChannelMask, ChannelPage, ClusterId, CryptoRng, Endpoint, ExtendedAddress,
    GroupAddress, Key128, KeyAttributes, KeySequenceNumber, LogicalDeviceType, NwkStatus, PanId,
    ShortAddress,
};

use panweave_zcl::Role;

use crate::stack::{Phase, Stack};

/// Format version of the NIB record.
const NIB_FORMAT: u8 = 1;
/// Format version of the network keys record.
const KEYS_FORMAT: u8 = 1;
/// Format version of link key records.
const LINK_KEY_FORMAT: u8 = 1;
/// Format version of the binding record.
const BINDINGS_FORMAT: u8 = 1;
/// Format version of the group record.
const GROUPS_FORMAT: u8 = 1;
/// Format version of the AIB record.
const AIB_FORMAT: u8 = 3;
/// Format version of the children record.
const CHILDREN_FORMAT: u8 = 1;

/// Largest serialized record.
const RECORD: usize = 512;

/// Outcome of [`Stack::restore`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Restored {
    /// No network data was stored: the device is factory new.
    FactoryNew,
    /// Network parameters and keys were restored; the runtime should
    /// rejoin (end devices) or resume (routers / coordinator).
    OnNetwork,
}

fn record<S: Storage>(storage: &mut S, key: Key) -> Result<Option<Vec<u8, RECORD>>, StorageError> {
    let mut buf = [0u8; RECORD];
    let Some(n) = storage.load(key, &mut buf)? else {
        return Ok(None);
    };
    Ok(Vec::from_slice(buf.get(..n).unwrap_or(&[])).ok())
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> Stack<C, R, S> {
    /// Stores the saved startup sets of the Commissioning server on
    /// `endpoint` (ZCL8 §13.2.2.3.2: non-volatile).
    pub fn persist_startup_sets(&mut self, endpoint: Endpoint) -> Result<(), StorageError> {
        use panweave_zcl::clusters::commissioning;
        let Some(state) = self
            .zcl
            .cluster(endpoint, commissioning::ID, Role::Server)
            .and_then(commissioning::saved_state)
        else {
            return Ok(());
        };
        let mut buf = [0u8; commissioning::State::ENCODED_LEN];
        let n = state.encode(&mut buf).unwrap_or(0);
        self.storage.store(
            Key::with_id(Kind::StartupSets, u64::from(endpoint.0)),
            buf.get(..n).unwrap_or(&[]),
        )
    }

    /// Restores the saved startup sets of every Commissioning server
    /// (part of [`Self::restore`]).
    pub fn restore_startup_sets(&mut self) -> Result<(), StorageError> {
        use panweave_zcl::clusters::commissioning;
        let endpoints: Vec<Endpoint, 8> = self
            .zcl
            .endpoints()
            .iter()
            .filter(|e| e.cluster(commissioning::ID, Role::Server).is_some())
            .map(|e| e.endpoint)
            .collect();
        for endpoint in endpoints {
            let mut buf = [0u8; commissioning::State::ENCODED_LEN];
            let Some(n) = self.storage.load(
                Key::with_id(Kind::StartupSets, u64::from(endpoint.0)),
                &mut buf,
            )?
            else {
                continue;
            };
            let saved = commissioning::State::decode(buf.get(..n).unwrap_or(&[]));
            if let Some(c) = self
                .zcl
                .cluster_mut(endpoint, commissioning::ID, Role::Server)
            {
                commissioning::restore_saved(c, saved);
            }
        }
        Ok(())
    }

    /// Persists the NIB items needed to resume the network.
    pub fn persist_nib(&mut self) -> Result<(), StorageError> {
        let nib = &self.nwk.nib;
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        let r = (|| -> Result<(), panweave_codec::CodecError> {
            w.u8(NIB_FORMAT)?;
            w.u16_le(nib.pan_id.0)?;
            w.u64_le(nib.extended_pan_id.0)?;
            w.u16_le(nib.network_address.0)?;
            w.u8(nib.channel_page.raw())?;
            w.u8(nib.channel.raw())?;
            w.u8(nib.update_id)?;
            w.u8(nib.depth)?;
            w.u16_le(nib.parent_address.0)?;
            w.u64_le(nib.parent_ieee.0)?;
            w.u16_le(nib.manager_addr.0)?;
            w.u8(match nib.device_type {
                LogicalDeviceType::Coordinator => 0,
                LogicalDeviceType::Router => 1,
                LogicalDeviceType::EndDevice => 2,
            })?;
            w.u8(u8::from(nib.router_started))?;
            w.u8(u8::from(self.aps.aib.is_distributed()))?;
            w.u8(nib.parent_information.0)?;
            w.u8(nib.stack_profile)?;
            Ok(())
        })();
        if r.is_err() {
            return Err(StorageError::Full);
        }
        let n = w.position();
        self.storage.store(Key::single(Kind::Nib), &buf[..n])
    }

    /// Persists the end-device children (R23.2 §3.6.9: IEEE and network
    /// address, End Device Configuration and Device Timeout of every
    /// end-device neighbor).
    pub fn persist_children(&mut self) -> Result<(), StorageError> {
        let mut buf = [0u8; RECORD];
        let mut w = Writer::new(&mut buf);
        let _ = w.u8(CHILDREN_FORMAT);
        for e in self.nwk.neighbors.end_device_children() {
            let r = (|| -> Result<(), panweave_codec::CodecError> {
                w.u64_le(e.extended.0)?;
                w.u16_le(e.short.0)?;
                w.u8(e.end_device_configuration)?;
                w.u32_le(e.device_timeout_secs)?;
                w.u8(u8::from(e.rx_on_when_idle))
            })();
            if r.is_err() {
                return Err(StorageError::Full);
            }
        }
        let n = w.position();
        self.storage.store(Key::single(Kind::Children), &buf[..n])
    }

    /// Persists the network keys and the active sequence number.
    pub fn persist_network_keys(&mut self) -> Result<(), StorageError> {
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        let keys = &self.nwk.security.keys;
        let r = (|| -> Result<(), panweave_codec::CodecError> {
            w.u8(KEYS_FORMAT)?;
            w.u8(keys.active_sequence().map_or(0xff, |s| s.0))?;
            let n = keys.iter().count();
            #[allow(clippy::cast_possible_truncation)]
            w.u8(n as u8)?;
            for slot in keys.iter() {
                w.u8(slot.sequence.0)?;
                w.bytes(slot.key.as_bytes())?;
            }
            Ok(())
        })();
        if r.is_err() {
            return Err(StorageError::Full);
        }
        let n = w.position();
        self.storage
            .store(Key::single(Kind::NetworkKeys), &buf[..n])
    }

    /// Persists every link-key entry (one record per partner) and the
    /// scalar AIB attributes.
    pub fn persist_link_keys(&mut self) -> Result<(), StorageError> {
        self.storage.erase_kind(Kind::LinkKey)?;
        let mut records: Vec<(u64, [u8; 48], usize), 8> = Vec::new();
        for e in self.aps.security.keys().iter() {
            let mut buf = [0u8; 48];
            let mut w = Writer::new(&mut buf);
            let r = (|| -> Result<(), panweave_codec::CodecError> {
                w.u8(LINK_KEY_FORMAT)?;
                w.u64_le(e.partner.0)?;
                w.bytes(e.key.as_bytes())?;
                w.u8(u8::from(e.kind == LinkKeyKind::Global))?;
                w.u8(e.attributes.raw())?;
                w.u32_le(e.incoming)?;
                w.u32_le(e.outgoing.reserved_until())?;
                w.u8(u8::from(e.frame_counter_sync))?;
                Ok(())
            })();
            if r.is_err() {
                return Err(StorageError::Full);
            }
            let n = w.position();
            let _ = records.push((e.partner.0, buf, n));
        }
        for (partner, buf, n) in &records {
            self.storage
                .store(Key::with_id(Kind::LinkKey, *partner), &buf[..*n])?;
        }
        // The AIB record doubles as the index of link-key records: the
        // storage trait has no enumeration. Format 2 appends the startup
        // attributes of Table 2-24 (apsDesignatedCoordinator,
        // apsChannelMaskList, apsUseExtendedPANID, apsUseInsecureJoin).
        let mut buf = [0u8; 16 + 8 * 8 + 16 + 16];
        let mut w = Writer::new(&mut buf);
        let _ = w.u8(AIB_FORMAT);
        let _ = w.u64_le(self.aps.aib.trust_center_address.0);
        #[allow(clippy::cast_possible_truncation)]
        let _ = w.u8(records.len() as u8);
        for (partner, _, _) in &records {
            let _ = w.u64_le(*partner);
        }
        let aib = &self.aps.aib;
        let _ = w.u8(u8::from(aib.designated_coordinator));
        let _ = w.u32_le(aib.channel_mask.0);
        let _ = w.u64_le(aib.use_extended_pan_id.0);
        let _ = w.u8(u8::from(aib.use_insecure_join));
        // Format 3: the other channel pages of apsChannelMaskList.
        #[allow(clippy::cast_possible_truncation)]
        let _ = w.u8(aib.channel_mask_pages.len() as u8);
        for m in &aib.channel_mask_pages {
            let _ = w.u32_le(m.0);
        }
        let n = w.position();
        self.storage.store(Key::single(Kind::Aib), &buf[..n])
    }

    /// Persists the binding table.
    pub fn persist_bindings(&mut self) -> Result<(), StorageError> {
        let mut buf = [0u8; RECORD];
        let mut w = Writer::new(&mut buf);
        let _ = w.u8(BINDINGS_FORMAT);
        for b in self.aps.bindings.iter() {
            let r = (|| -> Result<(), panweave_codec::CodecError> {
                w.u8(b.src_endpoint.0)?;
                w.u16_le(b.cluster.0)?;
                match b.destination {
                    BindingDestination::Group(g) => {
                        w.u8(1)?;
                        w.u16_le(g.0)
                    }
                    BindingDestination::Unicast { address, endpoint } => {
                        w.u8(3)?;
                        w.u64_le(address.0)?;
                        w.u8(endpoint.0)
                    }
                }
            })();
            if r.is_err() {
                return Err(StorageError::Full);
            }
        }
        let n = w.position();
        self.storage.store(Key::single(Kind::Bindings), &buf[..n])
    }

    /// Persists the group table.
    pub fn persist_groups(&mut self) -> Result<(), StorageError> {
        let mut buf = [0u8; RECORD];
        let mut w = Writer::new(&mut buf);
        let _ = w.u8(GROUPS_FORMAT);
        for g in self.aps.groups.iter() {
            for ep in g.endpoints.iter() {
                if w.u16_le(g.group.0).is_err() || w.u8(ep.0).is_err() {
                    return Err(StorageError::Full);
                }
            }
        }
        let n = w.position();
        self.storage.store(Key::single(Kind::Groups), &buf[..n])
    }

    /// Persists everything.
    pub fn persist_all(&mut self) -> Result<(), StorageError> {
        self.persist_nib()?;
        self.persist_children()?;
        self.persist_network_keys()?;
        self.persist_link_keys()?;
        self.persist_bindings()?;
        self.persist_groups()
    }

    /// Erases all persisted network state (factory reset).
    pub fn erase_persisted(&mut self) -> Result<(), StorageError> {
        // BDB 3.1 §13: every reset preserves the single outgoing NWK
        // frame counter (`Kind::NwkFrameCounter`), so a later join never
        // reuses counter values under a key the network still knows.
        for k in [
            Kind::Nib,
            Kind::Children,
            Kind::NetworkKeys,
            Kind::LinkKey,
            Kind::ApsFrameCounter,
            Kind::Aib,
            Kind::Bindings,
            Kind::Groups,
            Kind::GreenPower,
            Kind::DirectPastKeys,
            Kind::DirectConfig,
            Kind::DirectAdminKey,
            Kind::StartupSets,
        ] {
            self.storage.erase_kind(k)?;
        }
        Ok(())
    }

    /// Restores persisted state after a reset (BDB 3.1 §7.1 initialization
    /// procedure, step "restore persistent data"). On success the NWK
    /// layer is marked joined with the frame counter continuing past the
    /// last persisted reservation; the caller then calls
    /// [`Stack::resume`].
    pub fn restore(&mut self) -> Result<Restored, StorageError> {
        // The outgoing NWK frame counter outlives a factory reset (BDB
        // 3.1 §13): continue past the last reservation either way.
        let mut fc = [0u8; 4];
        if self
            .storage
            .load(Key::single(Kind::NwkFrameCounter), &mut fc)?
            .is_some()
        {
            self.nwk
                .security
                .restore_outgoing_counter(u32::from_le_bytes(fc));
        }
        self.restore_startup_sets()?;
        let Some(nib) = record(&mut self.storage, Key::single(Kind::Nib))? else {
            return Ok(Restored::FactoryNew);
        };
        let Some(keys) = record(&mut self.storage, Key::single(Kind::NetworkKeys))? else {
            return Ok(Restored::FactoryNew);
        };
        let mut r = Reader::new(&nib);
        let parsed = (|| -> Result<(), panweave_codec::CodecError> {
            if r.u8()? != NIB_FORMAT {
                return Err(panweave_codec::CodecError::Unsupported { what: "NIB format" });
            }
            let n = &mut self.nwk.nib;
            n.pan_id = PanId(r.u16_le()?);
            n.extended_pan_id = ExtendedAddress(r.u64_le()?);
            n.network_address = ShortAddress(r.u16_le()?);
            n.channel_page = ChannelPage(r.u8()?);
            n.channel = Channel::new(r.u8()?).unwrap_or(Channel::DEFAULT_2_4GHZ);
            n.update_id = r.u8()?;
            n.depth = r.u8()?;
            n.parent_address = ShortAddress(r.u16_le()?);
            n.parent_ieee = ExtendedAddress(r.u64_le()?);
            n.manager_addr = ShortAddress(r.u16_le()?);
            let _device_type = r.u8()?;
            n.router_started = false;
            let distributed = r.u8()? != 0;
            self.config.distributed = distributed;
            n.parent_information = panweave_nwk::command::ParentInformation(r.u8()?);
            n.stack_profile = r.u8()?;
            Ok(())
        })();
        if parsed.is_err() {
            return Ok(Restored::FactoryNew);
        }
        let mut r = Reader::new(&keys);
        let parsed = (|| -> Result<(), panweave_codec::CodecError> {
            if r.u8()? != KEYS_FORMAT {
                return Err(panweave_codec::CodecError::Unsupported { what: "key format" });
            }
            let active = r.u8()?;
            let n = r.u8()?;
            for _ in 0..n {
                let seq = KeySequenceNumber(r.u8()?);
                let key = Key128::from_bytes(r.array::<16>()?);
                if seq.0 == active {
                    self.nwk.security.install_active_key(seq, key);
                    self.network_key_sequence = seq;
                } else {
                    self.nwk.security.install_key(seq, key);
                }
            }
            Ok(())
        })();
        if parsed.is_err() || !self.nwk.security.has_key() {
            return Ok(Restored::FactoryNew);
        }
        // Frame counter: continue after the last persisted reservation
        // (never reuse a value, §4.3.4).
        let mut partners: Vec<u64, 8> = Vec::new();
        if let Some(aib) = record(&mut self.storage, Key::single(Kind::Aib))? {
            let mut r = Reader::new(&aib);
            let format = r.u8().ok();
            if matches!(format, Some(1..=AIB_FORMAT))
                && let Ok(tc) = r.u64_le()
            {
                self.aps.aib.trust_center_address = ExtendedAddress(tc);
                let n = r.u8().unwrap_or(0);
                for _ in 0..n {
                    let Ok(p) = r.u64_le() else { break };
                    let _ = partners.push(p);
                }
                if format >= Some(2)
                    && let (Ok(dc), Ok(mask), Ok(epid), Ok(insecure)) =
                        (r.u8(), r.u32_le(), r.u64_le(), r.u8())
                {
                    self.aps.aib.designated_coordinator = dc != 0;
                    self.aps.aib.channel_mask = ChannelMask(mask);
                    self.aps.aib.use_extended_pan_id = ExtendedAddress(epid);
                    self.aps.aib.use_insecure_join = insecure != 0;
                }
                if format >= Some(3)
                    && let Ok(pages) = r.u8()
                {
                    self.aps.aib.channel_mask_pages.clear();
                    for _ in 0..pages {
                        let Ok(m) = r.u32_le() else { break };
                        let _ = self.aps.aib.channel_mask_pages.push(ChannelMask(m));
                    }
                }
            }
        }
        self.restore_link_keys(&partners)?;
        // §4.6.3.8: after a reboot every partner's incoming counter is
        // unverified until a challenge succeeds.
        self.aps.security.invalidate_frame_counters();
        self.restore_bindings_and_groups()?;
        self.restore_children()?;
        self.nwk.warm_start();
        let short = self.nwk.nib.network_address;
        self.aps
            .set_network_state(short, DeviceState::JoinedAuthorized);
        self.phase = Phase::Operating;
        Ok(Restored::OnNetwork)
    }

    fn restore_link_keys(&mut self, partners: &[u64]) -> Result<(), StorageError> {
        for &p in partners {
            let Some(rec) = record(&mut self.storage, Key::with_id(Kind::LinkKey, p))? else {
                continue;
            };
            let mut r = Reader::new(&rec);
            let parsed = (|| -> Result<LinkKeyEntry, panweave_codec::CodecError> {
                if r.u8()? != LINK_KEY_FORMAT {
                    return Err(panweave_codec::CodecError::Unsupported {
                        what: "link key format",
                    });
                }
                let partner = ExtendedAddress(r.u64_le()?);
                let key = Key128::from_bytes(r.array::<16>()?);
                let kind = if r.u8()? != 0 {
                    LinkKeyKind::Global
                } else {
                    LinkKeyKind::Unique
                };
                let attributes = KeyAttributes::from_raw(r.u8()?);
                let incoming = r.u32_le()?;
                let reserved_until = r.u32_le()?;
                let sync = r.u8()? != 0;
                let mut e = LinkKeyEntry::provisional(partner, key, kind);
                e.attributes = attributes;
                e.incoming = incoming;
                e.outgoing =
                    panweave_security::frame_counter::OutgoingCounter::restore(reserved_until);
                e.frame_counter_sync = sync;
                Ok(e)
            })();
            if let Ok(e) = parsed {
                let mut fc = [0u8; 4];
                let mut e = e;
                if self
                    .storage
                    .load(Key::with_id(Kind::ApsFrameCounter, p), &mut fc)?
                    .is_some()
                {
                    e.outgoing = panweave_security::frame_counter::OutgoingCounter::restore(
                        u32::from_le_bytes(fc),
                    );
                }
                // A persisted entry supersedes the preconfigured one.
                let _ = self.aps.security.keys_mut().insert(e);
            }
        }
        Ok(())
    }

    fn restore_children(&mut self) -> Result<(), StorageError> {
        if !self.nwk.nib.is_router_or_coordinator() {
            return Ok(());
        }
        let Some(rec) = record(&mut self.storage, Key::single(Kind::Children))? else {
            return Ok(());
        };
        let mut r = Reader::new(&rec);
        if r.u8().ok() != Some(CHILDREN_FORMAT) {
            return Ok(());
        }
        let limit = self.nwk.nib.router_age_limit;
        while r.remaining() >= 16 {
            let parsed = (|| -> Result<NeighborEntry, panweave_codec::CodecError> {
                let extended = ExtendedAddress(r.u64_le()?);
                let short = ShortAddress(r.u16_le()?);
                let configuration = r.u8()?;
                let timeout = r.u32_le()?;
                let rx_on = r.u8()? != 0;
                let mut e = NeighborEntry::new(
                    extended,
                    short,
                    LogicalDeviceType::EndDevice,
                    rx_on,
                    Relationship::Child,
                    0,
                );
                e.end_device_configuration = configuration;
                e.device_timeout_secs = timeout;
                // §3.6.10.8: a full timeout period after reboot.
                e.timeout_counter_secs = timeout;
                Ok(e)
            })();
            let Ok(e) = parsed else { break };
            let _ = self.nwk.neighbors.insert(e, limit);
        }
        Ok(())
    }

    fn restore_bindings_and_groups(&mut self) -> Result<(), StorageError> {
        if let Some(rec) = record(&mut self.storage, Key::single(Kind::Bindings))? {
            let mut r = Reader::new(&rec);
            if r.u8().ok() == Some(BINDINGS_FORMAT) {
                while r.remaining() >= 4 {
                    let Ok(ep) = r.u8() else { break };
                    let Ok(cluster) = r.u16_le() else { break };
                    let dest = match r.u8() {
                        Ok(1) => r
                            .u16_le()
                            .ok()
                            .map(|g| BindingDestination::Group(GroupAddress(g))),
                        Ok(3) => match (r.u64_le(), r.u8()) {
                            (Ok(a), Ok(e)) => Some(BindingDestination::Unicast {
                                address: ExtendedAddress(a),
                                endpoint: Endpoint(e),
                            }),
                            _ => None,
                        },
                        _ => None,
                    };
                    let Some(destination) = dest else { break };
                    let _ = self.aps.bindings.bind(BindingEntry {
                        src_endpoint: Endpoint(ep),
                        cluster: ClusterId(cluster),
                        destination,
                    });
                }
            }
        }
        if let Some(rec) = record(&mut self.storage, Key::single(Kind::Groups))? {
            let mut r = Reader::new(&rec);
            if r.u8().ok() == Some(GROUPS_FORMAT) {
                while r.remaining() >= 3 {
                    let (Ok(g), Ok(ep)) = (r.u16_le(), r.u8()) else {
                        break;
                    };
                    let _ = self.aps.groups.add(GroupAddress(g), Endpoint(ep));
                }
            }
        }
        Ok(())
    }

    /// Resumes operation after [`Stack::restore`] reported
    /// [`Restored::OnNetwork`] (BDB 3.1 §7.1 / §10.1): the coordinator and
    /// routers resume on their network (routers re-announce), end devices
    /// perform a secured rejoin.
    pub fn resume(&mut self) -> Result<(), NwkStatus> {
        if self.phase != Phase::Operating {
            return Err(NwkStatus::InvalidRequest);
        }
        let nib = &self.nwk.nib;
        let (pan, page, channel, short) = (
            nib.pan_id,
            nib.channel_page,
            nib.channel,
            nib.network_address,
        );
        match self.config.role {
            LogicalDeviceType::Coordinator | LogicalDeviceType::Router => {
                let _ = (pan, page, channel);
                self.nwk
                    .start_router()
                    .map_err(|_| NwkStatus::InvalidRequest)?;
                let _ = self
                    .zdo
                    .device_announce(short, self.config.ieee, self.config.capability());
                // §2.4.3.1.12.1: announce the end device children after
                // apsParentAnnounceBaseTimer plus jitter.
                self.schedule_parent_annce(0);
                self.pump();
                Ok(())
            }
            LogicalDeviceType::EndDevice => {
                self.mac.start(pan, page, channel, short, false, false);
                let r = self.join(crate::JoinMode::SecuredRejoin);
                self.pump();
                r
            }
        }
    }
}
