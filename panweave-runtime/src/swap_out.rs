//! Trust Center swap-out (R23.2 §4.7.4): the backup a Trust Center
//! produces for a replacement (the extended PAN ID and, per device
//! key-pair entry, the Table 4-43 items with the hashed
//! `TrustCenterSwapOutLinkKey` instead of the live key), its
//! restoration on a new Trust Center before network formation, and the
//! node side: the APS layer detects the swap-out during a Trust Center
//! rejoin, the runtime reports it and requests a fresh link key.

use heapless::Vec;
use panweave_security::cipher::BlockCipher;
use panweave_security::material::{InitialJoinAuthentication, LinkKeyEntry, LinkKeyKind};
use panweave_storage::Storage;
use panweave_types::{CryptoRng, ExtendedAddress, Key128, KeyAttributes};

use crate::stack::Stack;

/// One backed-up key-pair entry (Table 4-43).
#[derive(Clone, Debug)]
pub struct BackupEntry {
    /// DeviceAddress.
    pub device: ExtendedAddress,
    /// KeyAttributes.
    pub attributes: KeyAttributes,
    /// InitialJoinAuthentication.
    pub initial_join_authentication: InitialJoinAuthentication,
    /// KeyNegotiationMethod.
    pub negotiation_method: u8,
    /// Passphrase, when supported.
    pub passphrase: Option<Key128>,
    /// TrustCenterSwapOutLinkKey: the AES-MMO hash of the link key.
    pub swap_out_key: Key128,
}

/// A Trust Center backup (§4.7.4.1.2).
#[derive(Clone, Debug, Default)]
pub struct TrustCenterBackup<const N: usize> {
    /// `nwkExtendedPanId`.
    pub extended_pan_id: ExtendedAddress,
    /// The device key-pair set, partially.
    pub entries: Vec<BackupEntry, N>,
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> Stack<C, R, S> {
    /// Produces the backup of this Trust Center (§4.7.4.1.2.1 –
    /// §4.7.4.1.2.4): unique link keys are backed up hashed; global
    /// (well-known) keys are skipped. `None` when this device is not the
    /// Trust Center of a centralized network.
    pub fn trust_center_backup<const N: usize>(&self) -> Option<TrustCenterBackup<N>> {
        if !self.aps.config.is_trust_center || self.aps.aib.is_distributed() {
            return None;
        }
        let mut b = TrustCenterBackup {
            extended_pan_id: self.nwk.nib.extended_pan_id,
            entries: Vec::new(),
        };
        for e in self.aps.security.keys().iter() {
            if e.kind != LinkKeyKind::Unique {
                continue;
            }
            let Some(h) = self.aps.security.swap_out_key(e.partner) else {
                continue;
            };
            let _ = b.entries.push(BackupEntry {
                device: e.partner,
                attributes: e.attributes,
                initial_join_authentication: e.initial_join_authentication,
                negotiation_method: e.negotiation_method,
                passphrase: e.passphrase.clone(),
                swap_out_key: h,
            });
        }
        Some(b)
    }

    /// Imports a backup on a replacement Trust Center before it forms
    /// the network (§4.7.4.1.2.6 steps 2–3): the extended PAN ID is kept
    /// and every entry's link key is set to the backed-up
    /// `TrustCenterSwapOutLinkKey` (a new hash of it becomes the next
    /// swap-out key) with the backed-up attributes, so the device's Trust
    /// Center rejoin passes §4.7.3.2 and its link key request (step 8) is
    /// honoured. The caller then forms the network with a fresh PAN ID
    /// and network key under its own EUI64.
    pub fn restore_trust_center_backup<const N: usize>(
        &mut self,
        backup: &TrustCenterBackup<N>,
    ) -> usize {
        self.nwk.nib.extended_pan_id = backup.extended_pan_id;
        let mut n = 0;
        for b in &backup.entries {
            let mut e =
                LinkKeyEntry::provisional(b.device, b.swap_out_key.clone(), LinkKeyKind::Unique);
            e.attributes = b.attributes;
            e.initial_join_authentication = b.initial_join_authentication;
            e.negotiation_method = b.negotiation_method;
            e.passphrase.clone_from(&b.passphrase);
            if self.aps.install_link_key(e).is_ok() {
                n += 1;
            }
        }
        n
    }
}
