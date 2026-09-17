//! Trust Center policy (R23.2 §4.7.1, §4.7.3, Table 4-42) as pure
//! decision functions.
//!
//! The policy answers "may this happen?" for joins, rejoins, key requests
//! and remote policy changes. Executing the resulting actions (sending
//! Transport Key, Remove Device, starting key negotiation) is done by the
//! APS/runtime layers so that this module stays testable in isolation and
//! cannot be bypassed: every Trust Center decision path calls into it.

use panweave_types::{ExtendedAddress, KeyAttributes};

use crate::material::{KeyNegotiationState, LinkKeyEntry, LinkKeyKind};

/// `requireInstallCodesOrPresetPassphrase` (attribute 0xaf).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum InstallCodePolicy {
    /// Install codes are not supported (0x00).
    NotSupported,
    /// Supported but not required; anonymous key negotiation is NOT
    /// permitted (0x01).
    #[default]
    Optional,
    /// Install codes or preset passphrases are required; only
    /// authenticated key negotiation (0x02).
    Required,
    /// Supported but not required, and anonymous key negotiation is
    /// permitted when DLK is enabled (0x03).
    OptionalWithAnonymousNegotiation,
}

impl InstallCodePolicy {
    /// Wire/storage value.
    pub const fn raw(self) -> u8 {
        match self {
            InstallCodePolicy::NotSupported => 0,
            InstallCodePolicy::Optional => 1,
            InstallCodePolicy::Required => 2,
            InstallCodePolicy::OptionalWithAnonymousNegotiation => 3,
        }
    }

    /// Parses a value; unknown values map to the most restrictive policy.
    pub const fn from_raw(v: u8) -> Self {
        match v {
            0 => InstallCodePolicy::NotSupported,
            1 => InstallCodePolicy::Optional,
            3 => InstallCodePolicy::OptionalWithAnonymousNegotiation,
            _ => InstallCodePolicy::Required,
        }
    }
}

/// `allowTrustCenterLinkKeyRequests` (0xb7).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TclkRequestPolicy {
    /// Never (0x00).
    Never,
    /// Any device may request (0x01).
    Any,
    /// Only devices whose key-pair entry is provisional (0x02).
    #[default]
    ProvisionalOnly,
}

/// `allowApplicationKeyRequests` (0xbb).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AppKeyRequestPolicy {
    /// Never (0x00).
    Never,
    /// Any device may request a key with any other device (0x01).
    #[default]
    Any,
    /// Only pairs listed in `applicationKeyRequestList` (0x02).
    ListedOnly,
}

/// `networkKeyUpdateMethod` (0xba).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum KeyUpdateMethod {
    /// Broadcast with network encryption only (0x00).
    #[default]
    Broadcast,
    /// Unicast with network and APS (link key) encryption (0x01).
    Unicast,
}

/// Trust Center policy values (Table 4-42) plus the BDB 3.1 join
/// policy attributes that refine them.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TrustCenterPolicy {
    /// `allowJoins`: devices that have never received the network key may
    /// join.
    pub allow_joins: bool,
    /// `requireInstallCodesOrPresetPassphrase`.
    pub install_codes: InstallCodePolicy,
    /// `allowRejoinsWithWellKnownKey`: unsecured (Trust Center) rejoins may
    /// use a global/provisional key. Default FALSE.
    pub allow_rejoins_with_well_known_key: bool,
    /// `allowTrustCenterLinkKeyRequests`.
    pub tclk_requests: TclkRequestPolicy,
    /// `networkKeyUpdatePeriod` in minutes; 0 disables periodic updates.
    pub network_key_update_period_min: u32,
    /// `networkKeyUpdateMethod`.
    pub network_key_update_method: KeyUpdateMethod,
    /// `allowApplicationKeyRequests`.
    pub app_key_requests: AppKeyRequestPolicy,
    /// `allowRemoteTcPolicyChange`: a Mgmt_Permit_Joining_req with TC
    /// significance may open the network.
    pub allow_remote_policy_change: bool,
    /// `allowVirtualDevices` (Zigbee Direct ZVDs).
    pub allow_virtual_devices: bool,
    /// BDB `bdbTrustCenterRequireKeyExchange`: joiners must complete the
    /// TCLK exchange or be removed.
    pub require_key_exchange: bool,
    /// Whether dynamic link key negotiation is offered.
    pub dlk_enabled: bool,
}

impl Default for TrustCenterPolicy {
    /// Mandatory BDB 3.1 defaults for a centralized network.
    fn default() -> Self {
        TrustCenterPolicy {
            allow_joins: false,
            install_codes: InstallCodePolicy::Optional,
            allow_rejoins_with_well_known_key: false,
            tclk_requests: TclkRequestPolicy::ProvisionalOnly,
            network_key_update_period_min: 0,
            network_key_update_method: KeyUpdateMethod::Broadcast,
            app_key_requests: AppKeyRequestPolicy::Any,
            allow_remote_policy_change: true,
            allow_virtual_devices: false,
            require_key_exchange: true,
            dlk_enabled: true,
        }
    }
}

/// How a joiner announced itself (from Update Device status and TLVs).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum JoinKind {
    /// Standard device secured rejoin (status 0x00).
    SecuredRejoin,
    /// Standard device unsecured join (status 0x01).
    UnsecuredJoin,
    /// Device left (status 0x02) — not a join.
    Left,
    /// Standard device Trust Center rejoin (status 0x03).
    TrustCenterRejoin,
}

/// The Trust Center's decision for a join or rejoin.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum JoinDecision {
    /// Send the network key with the (existing or newly created) link key;
    /// `create_entry` says whether a well-known-key entry must be added
    /// first (§4.7.3.1 step 2b).
    TransportNetworkKey {
        /// A key-pair entry with the well-known key must be created.
        create_entry: bool,
    },
    /// Start key negotiation (§4.7.3.3) before transporting the network
    /// key; `create_entry` as above with the well-known passphrase.
    NegotiateKey {
        /// An entry with the well-known passphrase must be created.
        create_entry: bool,
    },
    /// Secured rejoin of a known device: nothing to send.
    Allow,
    /// Reject by leaving the device to time out (§4.7.3.6 step 1).
    Ignore,
    /// Reject by removing the device (§4.7.3.6 step 2, §4.7.3.7).
    Remove,
}

impl TrustCenterPolicy {
    /// Evaluates an Update Device indication (§4.7.3.1–§4.7.3.3).
    ///
    /// * `entry` — the joiner's existing key-pair entry, if any;
    /// * `supports_key_negotiation` — the joiner advertised an asymmetric
    ///   method in its Joiner Encapsulation TLV and the parent relayed it;
    /// * `application_authorizes` — answer of the next higher layer for
    ///   secured / TC rejoins (§4.7.3.2 step 1–2); `None` delegates to the
    ///   table contents.
    pub fn evaluate_join(
        &self,
        kind: JoinKind,
        entry: Option<&LinkKeyEntry>,
        supports_key_negotiation: bool,
        application_authorizes: Option<bool>,
    ) -> JoinDecision {
        match kind {
            JoinKind::Left => JoinDecision::Ignore,
            JoinKind::SecuredRejoin => {
                // §4.7.3.2 step 1: higher layer decides; default allow when
                // the device is known, otherwise remove.
                let authorized = application_authorizes.unwrap_or(entry.is_some());
                if authorized {
                    JoinDecision::Allow
                } else {
                    JoinDecision::Remove
                }
            }
            JoinKind::TrustCenterRejoin => {
                // §4.7.3.2 step 2: require a unique link key entry, unless
                // rejoins with the well-known key are explicitly allowed
                // and the entry is verified-or-provisional per policy.
                match entry {
                    Some(e)
                        if e.kind == LinkKeyKind::Unique
                            && (e.attributes == KeyAttributes::VerifiedKey
                                || self.allow_rejoins_with_well_known_key) =>
                    {
                        if application_authorizes.unwrap_or(true) {
                            JoinDecision::TransportNetworkKey {
                                create_entry: false,
                            }
                        } else {
                            JoinDecision::Ignore
                        }
                    }
                    Some(_) if self.allow_rejoins_with_well_known_key => {
                        JoinDecision::TransportNetworkKey {
                            create_entry: false,
                        }
                    }
                    _ => JoinDecision::Ignore,
                }
            }
            JoinKind::UnsecuredJoin => {
                if !self.allow_joins {
                    return JoinDecision::Ignore;
                }
                let known = entry.is_some();
                if !known && self.install_codes == InstallCodePolicy::Required {
                    return JoinDecision::Ignore;
                }
                if supports_key_negotiation && self.dlk_enabled {
                    // §4.7.3.3
                    if known {
                        return JoinDecision::NegotiateKey {
                            create_entry: false,
                        };
                    }
                    return match self.install_codes {
                        InstallCodePolicy::OptionalWithAnonymousNegotiation => {
                            JoinDecision::NegotiateKey { create_entry: true }
                        }
                        // 0x01: anonymous negotiation not permitted; fall
                        // back to symmetric join with the well-known key
                        // (§4.7.3.1), which the policy still allows.
                        InstallCodePolicy::Optional | InstallCodePolicy::NotSupported => {
                            JoinDecision::TransportNetworkKey { create_entry: true }
                        }
                        InstallCodePolicy::Required => JoinDecision::Ignore,
                    };
                }
                // §4.7.3.1
                JoinDecision::TransportNetworkKey {
                    create_entry: !known,
                }
            }
        }
    }

    /// Evaluates a Request Key for a Trust Center link key (§4.7.3.8).
    ///
    /// `apsc_encrypted` — the command was APS encrypted with the key of
    /// the entry `entry` whose partner equals the source address.
    pub fn allow_tclk_request(&self, entry: Option<&LinkKeyEntry>, aps_encrypted: bool) -> bool {
        if !aps_encrypted {
            return false;
        }
        let Some(e) = entry else { return false };
        if e.negotiation_method != 0 || e.negotiation_state != KeyNegotiationState::None {
            // A key negotiated by a stronger mechanism must not be
            // downgraded via Request Key.
            return false;
        }
        match self.tclk_requests {
            TclkRequestPolicy::Never => false,
            TclkRequestPolicy::Any => true,
            TclkRequestPolicy::ProvisionalOnly => e.attributes == KeyAttributes::ProvisionalKey,
        }
    }

    /// Evaluates a Request Key for an application link key (§4.7.3.9).
    ///
    /// `listed` reports whether `(initiator, partner)` appears in
    /// `applicationKeyRequestList` (evaluated by the caller because the
    /// list lives in the application AIB).
    pub fn allow_app_key_request(
        &self,
        initiator: ExtendedAddress,
        partner: ExtendedAddress,
        initiator_entry: Option<&LinkKeyEntry>,
        listed: bool,
    ) -> bool {
        if initiator == partner || !partner.is_valid_device_address() {
            return false;
        }
        // The requester must hold a verified TCLK; application keys are
        // never issued to provisional entries.
        let Some(e) = initiator_entry else {
            return false;
        };
        if e.attributes != KeyAttributes::VerifiedKey {
            return false;
        }
        match self.app_key_requests {
            AppKeyRequestPolicy::Never => false,
            AppKeyRequestPolicy::Any => true,
            AppKeyRequestPolicy::ListedOnly => listed,
        }
    }

    /// Evaluates a remote Mgmt_Permit_Joining_req with TC significance
    /// (§4.7.3.4). Returns the ZDP/APS status to report: `Ok(())`,
    /// `Err(0xA3)` (ILLEGAL_REQUEST) or `Err(0xAA)` (NOT_SUPPORTED).
    pub fn allow_remote_permit_join(&self) -> Result<(), u8> {
        if !self.allow_remote_policy_change {
            return Err(0xA3);
        }
        if self.install_codes == InstallCodePolicy::Required {
            return Err(0xAA);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_types::Key128;

    fn entry(kind: LinkKeyKind, attrs: KeyAttributes) -> LinkKeyEntry {
        let mut e = LinkKeyEntry::provisional(ExtendedAddress(1), Key128::ZERO, kind);
        e.attributes = attrs;
        e
    }

    #[test]
    fn unsecured_join_policy() {
        let mut p = TrustCenterPolicy::default();
        assert_eq!(
            p.evaluate_join(JoinKind::UnsecuredJoin, None, false, None),
            JoinDecision::Ignore,
            "joins closed by default"
        );
        p.allow_joins = true;
        assert_eq!(
            p.evaluate_join(JoinKind::UnsecuredJoin, None, false, None),
            JoinDecision::TransportNetworkKey { create_entry: true }
        );
        let ic = entry(LinkKeyKind::Unique, KeyAttributes::ProvisionalKey);
        assert_eq!(
            p.evaluate_join(JoinKind::UnsecuredJoin, Some(&ic), false, None),
            JoinDecision::TransportNetworkKey {
                create_entry: false
            }
        );
        p.install_codes = InstallCodePolicy::Required;
        assert_eq!(
            p.evaluate_join(JoinKind::UnsecuredJoin, None, false, None),
            JoinDecision::Ignore
        );
        assert_eq!(
            p.evaluate_join(JoinKind::UnsecuredJoin, Some(&ic), false, None),
            JoinDecision::TransportNetworkKey {
                create_entry: false
            }
        );
    }

    #[test]
    fn key_negotiation_join_policy() {
        let mut p = TrustCenterPolicy {
            allow_joins: true,
            ..TrustCenterPolicy::default()
        };
        // Optional (0x01): anonymous negotiation not permitted → symmetric.
        assert_eq!(
            p.evaluate_join(JoinKind::UnsecuredJoin, None, true, None),
            JoinDecision::TransportNetworkKey { create_entry: true }
        );
        p.install_codes = InstallCodePolicy::OptionalWithAnonymousNegotiation;
        assert_eq!(
            p.evaluate_join(JoinKind::UnsecuredJoin, None, true, None),
            JoinDecision::NegotiateKey { create_entry: true }
        );
        let ic = entry(LinkKeyKind::Unique, KeyAttributes::ProvisionalKey);
        p.install_codes = InstallCodePolicy::Required;
        assert_eq!(
            p.evaluate_join(JoinKind::UnsecuredJoin, Some(&ic), true, None),
            JoinDecision::NegotiateKey {
                create_entry: false
            }
        );
        p.dlk_enabled = false;
        assert_eq!(
            p.evaluate_join(JoinKind::UnsecuredJoin, Some(&ic), true, None),
            JoinDecision::TransportNetworkKey {
                create_entry: false
            }
        );
    }

    #[test]
    fn rejoin_policy() {
        let p = TrustCenterPolicy::default();
        let verified = entry(LinkKeyKind::Unique, KeyAttributes::VerifiedKey);
        let global = entry(LinkKeyKind::Global, KeyAttributes::ProvisionalKey);
        assert_eq!(
            p.evaluate_join(JoinKind::TrustCenterRejoin, Some(&verified), false, None),
            JoinDecision::TransportNetworkKey {
                create_entry: false
            }
        );
        assert_eq!(
            p.evaluate_join(JoinKind::TrustCenterRejoin, Some(&global), false, None),
            JoinDecision::Ignore
        );
        assert_eq!(
            p.evaluate_join(JoinKind::TrustCenterRejoin, None, false, None),
            JoinDecision::Ignore
        );
        assert_eq!(
            p.evaluate_join(JoinKind::SecuredRejoin, Some(&verified), false, None),
            JoinDecision::Allow
        );
        assert_eq!(
            p.evaluate_join(JoinKind::SecuredRejoin, None, false, None),
            JoinDecision::Remove
        );
        assert_eq!(
            p.evaluate_join(JoinKind::SecuredRejoin, Some(&verified), false, Some(false)),
            JoinDecision::Remove
        );
        let permissive = TrustCenterPolicy {
            allow_rejoins_with_well_known_key: true,
            ..TrustCenterPolicy::default()
        };
        assert_eq!(
            permissive.evaluate_join(JoinKind::TrustCenterRejoin, Some(&global), false, None),
            JoinDecision::TransportNetworkKey {
                create_entry: false
            }
        );
    }

    #[test]
    fn tclk_request_policy() {
        let p = TrustCenterPolicy::default();
        let prov = entry(LinkKeyKind::Global, KeyAttributes::ProvisionalKey);
        let verified = entry(LinkKeyKind::Unique, KeyAttributes::VerifiedKey);
        assert!(p.allow_tclk_request(Some(&prov), true));
        assert!(
            !p.allow_tclk_request(Some(&prov), false),
            "must be APS encrypted"
        );
        assert!(!p.allow_tclk_request(Some(&verified), true));
        assert!(!p.allow_tclk_request(None, true));
        let mut negotiated = entry(LinkKeyKind::Unique, KeyAttributes::ProvisionalKey);
        negotiated.negotiation_state = KeyNegotiationState::Complete;
        assert!(!p.allow_tclk_request(Some(&negotiated), true));
        let any = TrustCenterPolicy {
            tclk_requests: TclkRequestPolicy::Any,
            ..TrustCenterPolicy::default()
        };
        assert!(any.allow_tclk_request(Some(&verified), true));
    }

    #[test]
    fn app_key_and_remote_policy() {
        let p = TrustCenterPolicy::default();
        let verified = entry(LinkKeyKind::Unique, KeyAttributes::VerifiedKey);
        let prov = entry(LinkKeyKind::Unique, KeyAttributes::ProvisionalKey);
        let a = ExtendedAddress(1);
        let b = ExtendedAddress(2);
        assert!(p.allow_app_key_request(a, b, Some(&verified), false));
        assert!(!p.allow_app_key_request(a, b, Some(&prov), false));
        assert!(!p.allow_app_key_request(a, a, Some(&verified), false));
        let listed = TrustCenterPolicy {
            app_key_requests: AppKeyRequestPolicy::ListedOnly,
            ..TrustCenterPolicy::default()
        };
        assert!(!listed.allow_app_key_request(a, b, Some(&verified), false));
        assert!(listed.allow_app_key_request(a, b, Some(&verified), true));
        assert_eq!(p.allow_remote_permit_join(), Ok(()));
        let strict = TrustCenterPolicy {
            install_codes: InstallCodePolicy::Required,
            ..TrustCenterPolicy::default()
        };
        assert_eq!(strict.allow_remote_permit_join(), Err(0xAA));
        let closed = TrustCenterPolicy {
            allow_remote_policy_change: false,
            ..TrustCenterPolicy::default()
        };
        assert_eq!(closed.allow_remote_permit_join(), Err(0xA3));
    }
}
