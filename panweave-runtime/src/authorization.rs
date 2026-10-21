//! Trust Center authorization of joined devices (BDB 3.1
//! `bdbTrustCenterRequireKeyExchange`, `bdbTrustCenterNodeJoinTimeout`;
//! R23.2 §4.7.3).
//!
//! Receiving the network key is not full authorization. A Trust Center
//! whose policy sets [`TrustCenterPolicy::require_key_exchange`] admits a
//! new device in three steps:
//!
//! 1. the device joins (MAC association or NWK rejoin) and the Trust
//!    Center decides ([`TrustCenterPolicy::evaluate_join`]);
//! 2. the network key is delivered: the device is **pending** — it may
//!    use the network and the ZDO, which the key exchange itself needs
//!    (Node_Desc_req to the Trust Center, Security_Start_Key_Negotiation,
//!    APS Request Key / Verify Key), but its application frames (ZCL and
//!    any other non-ZDO endpoint) are dropped and the application is not
//!    told it joined;
//! 3. the device holds a unique Trust Center link key that it proved
//!    with APS Verify Key (an exchanged key, or one negotiated with a
//!    dynamic link key method): it is **authorized** and
//!    [`StackEvent::DeviceAuthorized`] is emitted.
//!
//! Smart Energy devices exchange their key with Certificate-Based Key
//! Establishment over the ZCL Key Establishment cluster (0x0800): those
//! frames reach the application from a pending device (they *are* the
//! key exchange), each one extends the window by
//! [`TrustCenterPolicy::node_join_timeout_s`] up to
//! [`KEY_ESTABLISHMENT_WINDOW_S`] after the window opened, and the
//! verified key CBKE installs ([`crate::Stack::install_link_key`])
//! completes the exchange.
//!
//! A device still pending after
//! [`TrustCenterPolicy::node_join_timeout_s`] loses its key-pair entry and
//! is removed from the network ([`StackEvent::KeyExchangeTimedOut`]).
//!
//! The authorization of a device is derived from the persisted key-pair
//! entry, never from RAM alone: after a reboot a device is authorized only
//! if its entry is a verified unique key (or an administrator exemption
//! is configured again by the application), so a pending device can never
//! become authorized by a restart.
//!
//! # Application frames
//!
//! Every APS data indication for an application endpoint (anything but
//! the ZDO) passes one decision, [`crate::Stack::authorize_application_frame`],
//! made on the **originator** of the frame — the NWK source of the APS
//! indication, not the router that relayed it:
//!
//! * the originator's IEEE address is the one the frame claims (NWK
//!   extended source) or the one the address map holds for its NWK
//!   source; a claim that contradicts the map is denied
//!   ([`DenyReason::InconsistentSource`]);
//! * an originator whose IEEE address is not known at all is **not**
//!   admitted: the frame is held (at most [`RESOLUTION_HOLD`] frames, for
//!   [`RESOLUTION_TIMEOUT_MS`]) while an IEEE_addr_req resolves the
//!   address, then decided again; unresolved, it is dropped
//!   ([`DenyReason::UnresolvedSource`]);
//! * a resolved originator gets application access only when
//!   [`Authorization::grants_application_access`].
//!
//! Group and broadcast frames are decided the same way, on their
//! originator. ZDO traffic and APS commands are not application traffic:
//! the key exchange itself needs them. Network-key possession is not
//! authorization; note that NWK-level identities (short address, NWK
//! extended source, IEEE_addr_rsp) are protected by the network key only,
//! so a device that holds the network key can still claim another
//! device's identity — per-device cryptographic attribution of
//! application frames would need APS link-key security, which consumer
//! devices do not use for application traffic.
//!
//! # Exemptions
//!
//! The only relaxation, always an administrator decision configured by
//! the application, bounded in number ([`KEY_EXCHANGE_EXEMPTIONS`]):
//!
//! * a **commissioning exemption**
//!   ([`crate::Stack::grant_commissioning_exemption`]) lets one IEEE
//!   address complete *one* initial join without the key exchange, within
//!   a bounded window; it is consumed by that join and expires unused;
//! * an **admitted exemption** ([`crate::Stack::set_key_exchange_exemption`])
//!   keeps an already admitted device authorized (the application
//!   persists it and applies it after a restart). It covers secured
//!   rejoins with the network key, but not a new initial join: a device
//!   that joins again through the unauthenticated path loses it and needs
//!   a new commissioning exemption.
//!
//! Neither waives encryption or MIC checks, joining still needs the open
//! network, and an IEEE address is only what a joiner claims: an
//! exemption bounds *when* the weaker path may be used, it does not
//! authenticate the device. Zigbee Direct Virtual Devices are authorized
//! by their Basic authorization key (R23.2 §4.6.3.2.2.4) and never verify
//! a link key; they are authorized by construction.
//!
//! [`TrustCenterPolicy::require_key_exchange`]:
//!     panweave_security::trust_center::TrustCenterPolicy::require_key_exchange
//! [`TrustCenterPolicy::evaluate_join`]:
//!     panweave_security::trust_center::TrustCenterPolicy::evaluate_join
//! [`TrustCenterPolicy::node_join_timeout_s`]:
//!     panweave_security::trust_center::TrustCenterPolicy::node_join_timeout_s
//! [`StackEvent::DeviceAuthorized`]: crate::StackEvent::DeviceAuthorized
//! [`StackEvent::KeyExchangeTimedOut`]: crate::StackEvent::KeyExchangeTimedOut

use heapless::Vec;
use panweave_aps::layer::NwkView;
use panweave_security::cipher::BlockCipher;
use panweave_security::material::{KeyNegotiationState, LinkKeyEntry, LinkKeyKind};
use panweave_security::trust_center::TclkRequestPolicy;
use panweave_storage::Storage;
use panweave_types::time::{Duration, Instant};
use panweave_types::{ApsStatus, CryptoRng, ExtendedAddress, KeyAttributes, ShortAddress};

use crate::context::AddrView;
use crate::join_trace::JoinStage;
use crate::{Stack, StackEvent};

/// Devices that can be inside their key-exchange window at once. A
/// joiner that does not fit is removed instead of being left pending
/// without a deadline.
pub const KEY_EXCHANGE_PENDING_CAPACITY: usize = 8;

/// Administrator exemptions from the key-exchange requirement
/// (commissioning and admitted together).
pub const KEY_EXCHANGE_EXEMPTIONS: usize = 8;

/// Longest commissioning-exemption window, seconds.
pub const MAX_COMMISSIONING_EXEMPTION_S: u64 = 3600;

/// Application frames held while their originator's IEEE address is
/// resolved.
pub const RESOLUTION_HOLD: usize = 2;

/// How long a held frame waits for its originator to be resolved.
pub const RESOLUTION_TIMEOUT_MS: u64 = 10_000;

/// Outstanding IEEE address resolutions (one per NWK address, not
/// repeated within [`RESOLUTION_TIMEOUT_MS`]).
const RESOLUTIONS: usize = 4;

/// Longest a key-exchange window can be stretched by Key Establishment
/// traffic (Smart Energy CBKE), seconds after it opened.
pub const KEY_ESTABLISHMENT_WINDOW_S: u64 = 300;

/// The ZCL Key Establishment cluster (Smart Energy CBKE).
const KEY_ESTABLISHMENT_CLUSTER: u16 = 0x0800;

/// The Trust Center's view of a device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Authorization {
    /// The policy is satisfied: a verified unique link key, or a policy
    /// that does not require the exchange, or a Zigbee Direct Virtual
    /// Device.
    Authorized,
    /// Authorized only because the application exempted this device
    /// from the key exchange.
    Exempt,
    /// The device holds the network key and is inside its key-exchange
    /// window.
    PendingKeyExchange,
    /// The device has a key-pair entry but never completed the required
    /// exchange (its window passed, or it was pending when the Trust
    /// Center restarted).
    KeyExchangeIncomplete,
    /// The Trust Center has no key-pair entry for the device.
    Unknown,
}

impl Authorization {
    /// Whether the device's application frames reach the application.
    pub const fn grants_application_access(self) -> bool {
        matches!(self, Authorization::Authorized | Authorization::Exempt)
    }

    /// A short name.
    pub const fn name(self) -> &'static str {
        match self {
            Authorization::Authorized => "authorized",
            Authorization::Exempt => "exempt",
            Authorization::PendingKeyExchange => "pending-key-exchange",
            Authorization::KeyExchangeIncomplete => "key-exchange-incomplete",
            Authorization::Unknown => "unknown",
        }
    }
}

/// Why an application frame was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DenyReason {
    /// The originator's IEEE address could not be resolved in time.
    UnresolvedSource,
    /// The frame's claimed IEEE address contradicts the address map.
    InconsistentSource,
    /// The originator has no key-pair entry at the Trust Center.
    UnknownSource,
    /// The originator is inside its key-exchange window.
    PendingKeyExchange,
    /// The originator never completed the required key exchange.
    KeyExchangeIncomplete,
}

impl DenyReason {
    /// A short name.
    pub const fn name(self) -> &'static str {
        match self {
            DenyReason::UnresolvedSource => "unresolved-source",
            DenyReason::InconsistentSource => "inconsistent-source",
            DenyReason::UnknownSource => "unknown-source",
            DenyReason::PendingKeyExchange => "pending-key-exchange",
            DenyReason::KeyExchangeIncomplete => "key-exchange-incomplete",
        }
    }
}

/// Application frames refused, by reason.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeniedFrames {
    /// [`DenyReason::UnresolvedSource`].
    pub unresolved: u32,
    /// [`DenyReason::InconsistentSource`].
    pub inconsistent: u32,
    /// [`DenyReason::UnknownSource`].
    pub unknown: u32,
    /// [`DenyReason::PendingKeyExchange`].
    pub pending: u32,
    /// [`DenyReason::KeyExchangeIncomplete`].
    pub incomplete: u32,
}

impl DeniedFrames {
    /// All refusals.
    pub const fn total(&self) -> u32 {
        self.unresolved
            .saturating_add(self.inconsistent)
            .saturating_add(self.unknown)
            .saturating_add(self.pending)
            .saturating_add(self.incomplete)
    }

    fn count(&mut self, reason: DenyReason) {
        let c = match reason {
            DenyReason::UnresolvedSource => &mut self.unresolved,
            DenyReason::InconsistentSource => &mut self.inconsistent,
            DenyReason::UnknownSource => &mut self.unknown,
            DenyReason::PendingKeyExchange => &mut self.pending,
            DenyReason::KeyExchangeIncomplete => &mut self.incomplete,
        };
        *c = c.saturating_add(1);
    }
}

/// The decision on one application frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum FrameVerdict {
    /// Deliver it.
    Admit,
    /// Hold it until the originator is resolved.
    Hold,
    /// Drop it.
    Deny(DenyReason),
}

/// An exemption from the key-exchange requirement.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ExemptionKind {
    /// One initial join may skip the exchange until this instant.
    Commissioning { until: Instant },
    /// The device was admitted; it stays authorized.
    Admitted,
}

/// An exemption of one IEEE address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Exemption {
    pub device: ExtendedAddress,
    pub kind: ExemptionKind,
}

/// Whether `entry` satisfies the key-exchange requirement: a unique key
/// the device proved it holds.
pub(crate) fn exchanged(entry: Option<&LinkKeyEntry>) -> bool {
    entry.is_some_and(|e| {
        e.kind == LinkKeyKind::Unique && e.attributes == KeyAttributes::VerifiedKey
    })
}

/// A device inside its key-exchange window.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PendingKeyExchange {
    pub device: ExtendedAddress,
    pub short: ShortAddress,
    /// The router it joined through (`None`: a child of this node).
    pub parent: Option<ShortAddress>,
    /// When the window opened.
    pub opened: Instant,
    pub deadline: Instant,
}

/// Authorization bookkeeping of a Trust Center.
#[derive(Debug, Default)]
pub(crate) struct AuthorizationState {
    pub pending: Vec<PendingKeyExchange, KEY_EXCHANGE_PENDING_CAPACITY>,
    pub exempt: Vec<Exemption, KEY_EXCHANGE_EXEMPTIONS>,
    /// Devices restored from a Trust Center swap-out backup that have not
    /// renewed their (hashed) link key yet: R23.2 §4.7.4.1.2.6 step 8
    /// has them request a new one, which a verified entry would otherwise
    /// not be granted under `TclkRequestPolicy::ProvisionalOnly`.
    pub swap_out_renewals: Vec<ExtendedAddress, { crate::stack::LINK_KEYS }>,
    /// Application frames refused, by reason.
    pub denied: DeniedFrames,
    /// Devices removed because their key-exchange window passed.
    pub timed_out: u32,
    /// Application frames waiting for their originator to be resolved.
    pub held: Vec<(crate::pump::OwnedIndication, Instant), RESOLUTION_HOLD>,
    /// IEEE address resolutions in progress, with their deadline.
    pub resolving: Vec<(ShortAddress, Instant), RESOLUTIONS>,
    /// Commissioning exemptions consumed / expired unused.
    pub exemptions_used: u32,
    pub exemptions_expired: u32,
}

impl AuthorizationState {
    pub(crate) fn pending_index(&self, device: ExtendedAddress) -> Option<usize> {
        self.pending.iter().position(|p| p.device == device)
    }

    pub(crate) fn forget_pending(&mut self, device: ExtendedAddress) -> Option<PendingKeyExchange> {
        self.pending_index(device)
            .map(|i| self.pending.swap_remove(i))
    }

    /// An admitted exemption (not a commissioning grant).
    pub(crate) fn is_exempt(&self, device: ExtendedAddress) -> bool {
        self.exempt
            .iter()
            .any(|e| e.device == device && e.kind == ExemptionKind::Admitted)
    }

    fn commissioning(&self, device: ExtendedAddress, now: Instant) -> Option<usize> {
        self.exempt.iter().position(|e| {
            e.device == device
                && matches!(e.kind, ExemptionKind::Commissioning { until } if !now.has_reached(until))
        })
    }

    pub(crate) fn deadline(&self) -> Option<Instant> {
        let windows = self.pending.iter().map(|p| p.deadline);
        let grants = self.exempt.iter().filter_map(|e| match e.kind {
            ExemptionKind::Commissioning { until } => Some(until),
            ExemptionKind::Admitted => None,
        });
        let held = self.held.iter().map(|(_, t)| *t);
        windows
            .chain(grants)
            .chain(held)
            .min_by_key(|t| t.as_millis())
    }
}

impl<C: BlockCipher, R: CryptoRng, S: Storage> Stack<C, R, S> {
    /// How this Trust Center regards `device` (see the module
    /// documentation). Any device is [`Authorization::Authorized`] on a
    /// node that is not the Trust Center, or when the policy does not
    /// require the key exchange.
    pub fn device_authorization(&self, device: ExtendedAddress) -> Authorization {
        if !self.aps.config.is_trust_center || device == self.config.ieee {
            return Authorization::Authorized;
        }
        if self.authorization.pending_index(device).is_some() {
            return Authorization::PendingKeyExchange;
        }
        if !self.config.trust_center_policy.require_key_exchange
            || self.virtual_devices.iter().any(|(d, _)| *d == device)
        {
            return Authorization::Authorized;
        }
        let entry = self.aps.security.entry(device);
        if exchanged(entry) {
            Authorization::Authorized
        } else if self.authorization.is_exempt(device) {
            Authorization::Exempt
        } else if entry.is_some() {
            Authorization::KeyExchangeIncomplete
        } else {
            Authorization::Unknown
        }
    }

    /// Marks `device` as admitted without the key exchange (an
    /// *admitted exemption*), or withdraws every exemption it has. An
    /// administrator decision the application makes explicitly — for a
    /// device it admitted earlier through a commissioning exemption
    /// (re-applied after every restart: the stack does not persist it), or
    /// for a device already on the network that never exchanged its key.
    /// A pending device that is exempted is authorized at once;
    /// withdrawing stops the device's application frames until it
    /// completes a key exchange. `Err(ApsStatus::TableFull)` when
    /// [`KEY_EXCHANGE_EXEMPTIONS`] exemptions exist already.
    pub fn set_key_exchange_exemption(
        &mut self,
        device: ExtendedAddress,
        exempt: bool,
    ) -> Result<(), ApsStatus> {
        if !exempt {
            self.authorization.exempt.retain(|e| e.device != device);
            return Ok(());
        }
        self.authorization.exempt.retain(|e| e.device != device);
        self.authorization
            .exempt
            .push(Exemption {
                device,
                kind: ExemptionKind::Admitted,
            })
            .map_err(|_| ApsStatus::TableFull)?;
        if let Some(p) = self.authorization.forget_pending(device) {
            self.trace_join(device, Some(p.short), JoinStage::Authorized, 1);
            self.push_event(StackEvent::DeviceAuthorized {
                ieee: device,
                short: p.short,
            });
        }
        Ok(())
    }

    /// Lets `device` complete **one** initial join without the key
    /// exchange within `window` (at most
    /// [`MAX_COMMISSIONING_EXEMPTION_S`]): a *commissioning exemption*.
    /// The join consumes it and turns it into an admitted exemption
    /// ([`Self::key_exchange_exempt`]); unused, it expires. Granting again
    /// replaces the window (it never extends past `window` from now).
    /// `Err(ApsStatus::InvalidParameter)` for a zero or too long window,
    /// `Err(ApsStatus::TableFull)` when [`KEY_EXCHANGE_EXEMPTIONS`]
    /// exemptions exist already.
    pub fn grant_commissioning_exemption(
        &mut self,
        device: ExtendedAddress,
        window: Duration,
    ) -> Result<(), ApsStatus> {
        if window.as_millis() == 0
            || window.as_secs() > MAX_COMMISSIONING_EXEMPTION_S
            || !device.is_valid_device_address()
        {
            return Err(ApsStatus::InvalidParameter);
        }
        if self.authorization.is_exempt(device) {
            return Ok(());
        }
        let until = self.now.saturating_add(window);
        self.authorization.exempt.retain(|e| e.device != device);
        self.authorization
            .exempt
            .push(Exemption {
                device,
                kind: ExemptionKind::Commissioning { until },
            })
            .map_err(|_| ApsStatus::TableFull)
    }

    /// When `device`'s unused commissioning exemption expires.
    pub fn commissioning_exemption(&self, device: ExtendedAddress) -> Option<Instant> {
        self.authorization
            .commissioning(device, self.now)
            .and_then(|i| self.authorization.exempt.get(i))
            .and_then(|e| match e.kind {
                ExemptionKind::Commissioning { until } => Some(until),
                ExemptionKind::Admitted => None,
            })
    }

    /// Withdraws every exemption (the application re-applies the ones it
    /// keeps, for example after a factory reset of its own data).
    pub fn clear_key_exchange_exemptions(&mut self) {
        self.authorization.exempt.clear();
    }

    /// Whether `device` holds an admitted exemption from the key exchange.
    pub fn key_exchange_exempt(&self, device: ExtendedAddress) -> bool {
        self.authorization.is_exempt(device)
    }

    /// Commissioning exemptions consumed by a join, and expired unused.
    pub fn commissioning_exemptions(&self) -> (u32, u32) {
        (
            self.authorization.exemptions_used,
            self.authorization.exemptions_expired,
        )
    }

    /// Application frames refused, all reasons.
    pub fn unauthorized_frames_dropped(&self) -> u32 {
        self.authorization.denied.total()
    }

    /// Application frames held while their originator is resolved.
    pub fn held_application_frames(&self) -> usize {
        self.authorization.held.len()
    }

    /// Application frames refused, by reason.
    pub fn denied_frames(&self) -> DeniedFrames {
        self.authorization.denied
    }

    /// The Trust Center forgets `device`'s authorization: its link key,
    /// window and exemptions (the device was removed).
    pub(crate) fn revoke_device(&mut self, device: ExtendedAddress) {
        let _ = self.authorization.forget_pending(device);
        self.authorization.exempt.retain(|e| e.device != device);
        if self.aps.security.remove(device) {
            self.aps.request_link_key_persistence();
        }
    }

    /// Devices removed because they did not complete the key exchange in
    /// time.
    pub fn key_exchange_timeouts(&self) -> u32 {
        self.authorization.timed_out
    }

    /// Devices inside their key-exchange window.
    pub fn pending_key_exchanges(&self) -> usize {
        self.authorization.pending.len()
    }

    /// A device received the network key (or was allowed back by a
    /// secured rejoin): authorize it now when the policy is satisfied,
    /// otherwise open its key-exchange window.
    pub(crate) fn admit_or_hold(
        &mut self,
        device: ExtendedAddress,
        short: ShortAddress,
        parent: Option<ShortAddress>,
        initial_join: bool,
    ) {
        self.nwk.authenticate_child(device);
        if initial_join && self.aps.config.is_trust_center {
            let now = self.now;
            if let Some(i) = self.authorization.commissioning(device, now) {
                // A commissioning exemption is consumed by this join.
                if let Some(e) = self.authorization.exempt.get_mut(i) {
                    e.kind = ExemptionKind::Admitted;
                }
                self.authorization.exemptions_used =
                    self.authorization.exemptions_used.saturating_add(1);
            } else if self.authorization.is_exempt(device)
                && !exchanged(self.aps.security.entry(device))
            {
                // A new initial join through the unauthenticated path: an
                // earlier admission does not cover it.
                self.authorization.exempt.retain(|e| e.device != device);
                self.trace_join(device, Some(short), JoinStage::ExemptionWithdrawn, 0);
            }
        }
        let policy = &self.config.trust_center_policy;
        let timeout = policy.node_join_timeout_s.max(1);
        let needs_exchange = self.aps.config.is_trust_center
            && policy.require_key_exchange
            && !exchanged(self.aps.security.entry(device))
            && !self.authorization.is_exempt(device);
        if !needs_exchange {
            let exempt = self.authorization.is_exempt(device);
            let _ = self.authorization.forget_pending(device);
            self.trace_join(device, Some(short), JoinStage::Authorized, u8::from(exempt));
            self.push_event(StackEvent::DeviceAuthorized {
                ieee: device,
                short,
            });
            return;
        }
        let pending = PendingKeyExchange {
            device,
            short,
            parent,
            opened: self.now,
            deadline: self
                .now
                .saturating_add(Duration::from_secs(u64::from(timeout))),
        };
        match self.authorization.pending_index(device) {
            // A rejoin during the window: a new window, the new address.
            Some(i) => {
                if let Some(p) = self.authorization.pending.get_mut(i) {
                    *p = pending;
                }
            }
            None => {
                if self.authorization.pending.push(pending).is_err() {
                    // No room to track a deadline: never leave a device
                    // pending without one.
                    self.expire_key_exchange(pending);
                    return;
                }
            }
        }
        self.trace_join(device, Some(short), JoinStage::KeyExchangePending, 0);
        self.push_event(StackEvent::KeyExchangePending {
            ieee: device,
            short,
        });
    }

    /// The Trust Center verified `device`'s link key (APS Verify Key):
    /// a pending device whose entry is now a verified unique key is
    /// authorized. A duplicate or replayed verification changes nothing.
    pub(crate) fn on_link_key_verified(&mut self, device: ExtendedAddress) {
        if !exchanged(self.aps.security.entry(device)) {
            return;
        }
        self.authorization
            .swap_out_renewals
            .retain(|d| *d != device);
        let Some(p) = self.authorization.forget_pending(device) else {
            return;
        };
        let short = AddrView(&self.nwk).short_of(device).unwrap_or(p.short);
        self.trace_join(device, Some(short), JoinStage::Authorized, 0);
        self.push_event(StackEvent::DeviceAuthorized {
            ieee: device,
            short,
        });
    }

    /// The device left the network: its window closes (its key-pair
    /// entry stays; a rejoin is decided by the policy again).
    pub(crate) fn forget_key_exchange(&mut self, device: ExtendedAddress) {
        let _ = self.authorization.forget_pending(device);
    }

    /// Whether a TCLK Request Key from `src` is honoured: the Table 4-42
    /// policy, a device inside its key-exchange window repeating its
    /// request (a lost Transport Key) for a key it has not verified yet,
    /// or a device renewing the key a swap-out backup restored.
    pub(crate) fn tclk_request_allowed(&self, src: ExtendedAddress) -> bool {
        let policy = &self.config.trust_center_policy;
        let entry = self.aps.security.entry(src);
        if policy.tclk_requests != TclkRequestPolicy::Never
            && self.authorization.swap_out_renewals.contains(&src)
            && entry.is_some_and(|e| e.negotiation_state == KeyNegotiationState::None)
        {
            return true;
        }
        policy.allow_tclk_request(entry, true)
            || (policy.tclk_requests != TclkRequestPolicy::Never
                && self.authorization.pending_index(src).is_some()
                && entry.is_some_and(|e| {
                    e.attributes == KeyAttributes::UnverifiedKey
                        && e.negotiation_method == 0
                        && e.negotiation_state == KeyNegotiationState::None
                }))
    }

    /// The authorization decision on an application frame from the
    /// originator `src` (NWK source) claiming `src_ieee` (see the module
    /// documentation). Refusals are counted here.
    pub(crate) fn authorize_application_frame(
        &mut self,
        src: ShortAddress,
        src_ieee: Option<ExtendedAddress>,
        cluster: u16,
    ) -> FrameVerdict {
        if !self.aps.config.is_trust_center
            || !self.config.trust_center_policy.require_key_exchange
            || src == self.nwk.nib.network_address
        {
            return FrameVerdict::Admit;
        }
        let mapped = AddrView(&self.nwk).ieee_of(src);
        let ieee = match (src_ieee, mapped) {
            (Some(claimed), Some(known)) if claimed != known => {
                self.authorization
                    .denied
                    .count(DenyReason::InconsistentSource);
                return FrameVerdict::Deny(DenyReason::InconsistentSource);
            }
            (Some(i), _) | (None, Some(i)) => i,
            (None, None) => return FrameVerdict::Hold,
        };
        let verdict = self.authorize_device_frame(ieee, cluster);
        if let FrameVerdict::Deny(r) = verdict {
            self.authorization.denied.count(r);
        }
        verdict
    }

    /// The decision for a frame whose originator is `ieee`.
    fn authorize_device_frame(&mut self, ieee: ExtendedAddress, cluster: u16) -> FrameVerdict {
        let a = self.device_authorization(ieee);
        if a.grants_application_access() {
            return FrameVerdict::Admit;
        }
        if cluster == KEY_ESTABLISHMENT_CLUSTER
            && let Some(i) = self.authorization.pending_index(ieee)
        {
            let timeout = Duration::from_secs(u64::from(
                self.config.trust_center_policy.node_join_timeout_s.max(1),
            ));
            let now = self.now;
            if let Some(p) = self.authorization.pending.get_mut(i) {
                let cap = p
                    .opened
                    .saturating_add(Duration::from_secs(KEY_ESTABLISHMENT_WINDOW_S));
                let wanted = now.saturating_add(timeout);
                p.deadline = if wanted.as_millis() < cap.as_millis() {
                    wanted
                } else {
                    cap
                };
            }
            return FrameVerdict::Admit;
        }
        FrameVerdict::Deny(match a {
            Authorization::PendingKeyExchange => DenyReason::PendingKeyExchange,
            Authorization::KeyExchangeIncomplete => DenyReason::KeyExchangeIncomplete,
            _ => DenyReason::UnknownSource,
        })
    }

    /// Holds an application frame whose originator is not known and asks
    /// it (or its parent) for its IEEE address; a full hold refuses the
    /// frame as unresolved.
    pub(crate) fn hold_for_resolution(&mut self, ind: &crate::pump::OwnedIndication) {
        let now = self.now;
        let deadline = now.saturating_add(Duration::from_millis(RESOLUTION_TIMEOUT_MS));
        if self
            .authorization
            .held
            .push((ind.clone(), deadline))
            .is_err()
        {
            self.authorization
                .denied
                .count(DenyReason::UnresolvedSource);
            return;
        }
        let src = ind.src();
        self.authorization
            .resolving
            .retain(|(_, t)| !now.has_reached(*t));
        if self.authorization.resolving.iter().any(|(s, _)| *s == src) {
            return;
        }
        if self.authorization.resolving.push((src, deadline)).is_ok() {
            let _ = self.zdo.request(
                src,
                panweave_zdo::zdp::cluster::IEEE_ADDR_REQ,
                &panweave_zdo::zdp::IeeeAddrReq {
                    addr: src,
                    request_type: panweave_zdo::zdp::AddrRequestType::Single,
                    start_index: 0,
                },
            );
        }
    }

    /// An IEEE_addr_rsp / NWK_addr_rsp resolved `short`: frames held for it
    /// are decided again.
    pub(crate) fn on_address_resolved(&mut self, ieee: ExtendedAddress, short: ShortAddress) {
        if !ieee.is_valid_device_address() || short == self.nwk.nib.network_address {
            return;
        }
        let _ = self.nwk.address_map.record(ieee, short);
        self.authorization.resolving.retain(|(s, _)| *s != short);
        let mut i = 0;
        while i < self.authorization.held.len() {
            if self
                .authorization
                .held
                .get(i)
                .is_some_and(|(ind, _)| ind.src() == short)
            {
                let (ind, _) = self.authorization.held.swap_remove(i);
                self.dispatch_held(&ind);
            } else {
                i += 1;
            }
        }
    }

    /// Removes the devices whose key-exchange window passed, expires
    /// unused commissioning exemptions and unresolved held frames.
    pub(crate) fn poll_authorization(&mut self, now: Instant) {
        let before = self.authorization.exempt.len();
        self.authorization.exempt.retain(
            |e| !matches!(e.kind, ExemptionKind::Commissioning { until } if now.has_reached(until)),
        );
        let expired = before - self.authorization.exempt.len();
        self.authorization.exemptions_expired = self
            .authorization
            .exemptions_expired
            .saturating_add(u32::try_from(expired).unwrap_or(u32::MAX));
        while let Some(i) = self
            .authorization
            .held
            .iter()
            .position(|(_, t)| now.has_reached(*t))
        {
            let _ = self.authorization.held.swap_remove(i);
            self.authorization
                .denied
                .count(DenyReason::UnresolvedSource);
        }
        self.authorization
            .resolving
            .retain(|(_, t)| !now.has_reached(*t));
        while let Some(i) = self
            .authorization
            .pending
            .iter()
            .position(|p| now.has_reached(p.deadline))
        {
            let p = self.authorization.pending.swap_remove(i);
            self.expire_key_exchange(p);
        }
    }

    /// BDB 3.1 `bdbTrustCenterNodeJoinTimeout`: the device's link key is
    /// removed and so is the device (a NWK Leave to our own child, an APS
    /// Remove Device through its parent).
    fn expire_key_exchange(&mut self, p: PendingKeyExchange) {
        self.authorization.timed_out = self.authorization.timed_out.saturating_add(1);
        let _ = self.aps.security.remove(p.device);
        self.aps.request_link_key_persistence();
        match p.parent {
            Some(parent) if parent != self.nwk.nib.network_address => {
                if let Some(parent_ieee) = AddrView(&self.nwk).ieee_of(parent) {
                    let _ = self.aps.remove_device(parent_ieee, parent, p.device);
                }
            }
            _ => {
                let _ = self.nwk.leave(Some(p.device), false, false);
            }
        }
        self.trace_join(p.device, Some(p.short), JoinStage::KeyExchangeTimedOut, 0);
        self.push_event(StackEvent::KeyExchangeTimedOut { ieee: p.device });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StackConfig;
    use panweave_mac::service::MacServiceConfig;
    use panweave_security::cipher::SoftwareAes;
    use panweave_storage::MemoryStorage;
    use panweave_testkit::TestRng;
    use panweave_types::{Key128, LogicalDeviceType};

    type TestStack = Stack<SoftwareAes, TestRng, MemoryStorage<16, 128>>;

    const X: ExtendedAddress = ExtendedAddress(0x00D0_0000_0000_0001);
    const Y: ExtendedAddress = ExtendedAddress(0x00D0_0000_0000_0002);

    fn trust_center() -> TestStack {
        Stack::new(
            StackConfig::new(
                LogicalDeviceType::Coordinator,
                ExtendedAddress(0x00D0_0000_0000_00FF),
            ),
            MacServiceConfig::default(),
            TestRng::seed(1),
            MemoryStorage::new(),
        )
    }

    fn entry(device: ExtendedAddress, verified: bool) -> LinkKeyEntry {
        let mut e =
            LinkKeyEntry::provisional(device, Key128::from_bytes([0x11; 16]), LinkKeyKind::Unique);
        if verified {
            e.attributes = KeyAttributes::VerifiedKey;
        }
        e
    }

    #[test]
    fn the_originator_decides_and_contradictions_are_refused() {
        let mut tc = trust_center();
        assert!(tc.aps.config.is_trust_center);
        let s1 = ShortAddress(0x1111);
        let _ = tc.nwk.address_map.record(X, s1);
        tc.aps.security.install(entry(X, true)).unwrap();
        assert_eq!(
            tc.authorize_application_frame(s1, None, 6),
            FrameVerdict::Admit
        );
        assert_eq!(
            tc.authorize_application_frame(s1, Some(X), 6),
            FrameVerdict::Admit
        );
        // A frame from X's address claiming another identity: refused.
        assert_eq!(
            tc.authorize_application_frame(s1, Some(Y), 6),
            FrameVerdict::Deny(DenyReason::InconsistentSource)
        );
        // An address nobody is known at: held for resolution, never
        // admitted on the spot.
        assert_eq!(
            tc.authorize_application_frame(ShortAddress(0x2222), None, 6),
            FrameVerdict::Hold
        );
        // X moved (a rejoin): its new address is X, the old one unknown.
        let _ = tc.nwk.address_map.record(X, ShortAddress(0x3333));
        assert_eq!(
            tc.authorize_application_frame(ShortAddress(0x3333), None, 6),
            FrameVerdict::Admit
        );
        assert_eq!(
            tc.authorize_application_frame(s1, None, 6),
            FrameVerdict::Hold
        );
        // Never exchanged: refused as incomplete; unknown: as unknown.
        tc.aps.security.install(entry(Y, false)).unwrap();
        let _ = tc.nwk.address_map.record(Y, ShortAddress(0x4444));
        assert_eq!(
            tc.authorize_application_frame(ShortAddress(0x4444), None, 6),
            FrameVerdict::Deny(DenyReason::KeyExchangeIncomplete)
        );
        let z = ExtendedAddress(0x00D0_0000_0000_0003);
        let _ = tc.nwk.address_map.record(z, ShortAddress(0x5555));
        assert_eq!(
            tc.authorize_application_frame(ShortAddress(0x5555), None, 6),
            FrameVerdict::Deny(DenyReason::UnknownSource)
        );
        let d = tc.denied_frames();
        assert_eq!((d.inconsistent, d.incomplete, d.unknown), (1, 1, 1));
        assert_eq!(d.total(), 3);
        // Without the requirement, possession of the network key is the
        // policy: everything is admitted.
        tc.config.trust_center_policy.require_key_exchange = false;
        assert_eq!(
            tc.authorize_application_frame(ShortAddress(0x2222), None, 6),
            FrameVerdict::Admit
        );
    }

    #[test]
    fn commissioning_exemptions_are_bounded_single_use_and_expire() {
        let mut tc = trust_center();
        assert_eq!(
            tc.grant_commissioning_exemption(X, Duration::from_secs(0)),
            Err(ApsStatus::InvalidParameter)
        );
        assert_eq!(
            tc.grant_commissioning_exemption(X, Duration::from_secs(3601)),
            Err(ApsStatus::InvalidParameter)
        );
        assert_eq!(
            tc.grant_commissioning_exemption(ExtendedAddress(0), Duration::from_secs(60)),
            Err(ApsStatus::InvalidParameter)
        );
        tc.grant_commissioning_exemption(X, Duration::from_secs(60))
            .unwrap();
        // A grant is not an admission.
        assert!(!tc.key_exchange_exempt(X));
        tc.aps.security.install(entry(X, false)).unwrap();
        assert_eq!(
            tc.device_authorization(X),
            Authorization::KeyExchangeIncomplete
        );
        // A secured rejoin does not consume it; an initial join does.
        tc.admit_or_hold(X, ShortAddress(0x1111), None, false);
        assert!(tc.commissioning_exemption(X).is_some());
        assert_eq!(
            tc.device_authorization(X),
            Authorization::PendingKeyExchange
        );
        tc.admit_or_hold(X, ShortAddress(0x1111), None, true);
        assert!(tc.commissioning_exemption(X).is_none());
        assert_eq!(tc.device_authorization(X), Authorization::Exempt);
        assert_eq!(tc.commissioning_exemptions(), (1, 0));
        // A later initial join through the same weak path is not covered.
        tc.admit_or_hold(X, ShortAddress(0x1112), None, true);
        assert!(!tc.key_exchange_exempt(X));
        assert_eq!(
            tc.device_authorization(X),
            Authorization::PendingKeyExchange
        );
        // Unused grants expire; the table is bounded.
        tc.grant_commissioning_exemption(Y, Duration::from_secs(5))
            .unwrap();
        let later = tc.now.saturating_add(Duration::from_secs(6));
        tc.poll_authorization(later);
        assert!(tc.commissioning_exemption(Y).is_none());
        assert_eq!(tc.commissioning_exemptions().1, 1);
        for i in 0..KEY_EXCHANGE_EXEMPTIONS as u64 {
            tc.grant_commissioning_exemption(
                ExtendedAddress(0x00E0_0000_0000_0000 + i),
                Duration::from_secs(600),
            )
            .unwrap();
        }
        assert_eq!(
            tc.grant_commissioning_exemption(Y, Duration::from_secs(600)),
            Err(ApsStatus::TableFull)
        );
    }

    #[test]
    fn only_a_verified_unique_key_counts_as_exchanged() {
        let mut e = LinkKeyEntry::provisional(
            ExtendedAddress(1),
            Key128::WELL_KNOWN_GLOBAL_TCLK,
            LinkKeyKind::Global,
        );
        assert!(!exchanged(Some(&e)));
        e.attributes = KeyAttributes::VerifiedKey;
        assert!(!exchanged(Some(&e)), "a global key is never exchanged");
        e.kind = LinkKeyKind::Unique;
        e.attributes = KeyAttributes::UnverifiedKey;
        assert!(!exchanged(Some(&e)), "transported but not proven");
        e.attributes = KeyAttributes::VerifiedKey;
        assert!(exchanged(Some(&e)));
        assert!(!exchanged(None));
        assert!(Authorization::Exempt.grants_application_access());
        assert!(!Authorization::PendingKeyExchange.grants_application_access());
        assert!(!Authorization::Unknown.grants_application_access());
    }
}
