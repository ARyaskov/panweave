//! The ZDD's security state (ZD 1.1 §6.2, Figure 4) and the admission
//! of sessions (§6.3.1, §6.6): an un-provisioned ZDD is *Open to be
//! provisioned* for `NewZddProvisioningTimeout` and then switches its
//! Zigbee Direct interface off until a power cycle or a user action; a
//! provisioned ZDD is *Open to connect ZVD* unless the Zigbee Direct
//! Configuration cluster turned the interface off; leaving the network
//! reopens provisioning. A provisioning session is refused while the
//! same ZVD holds an authorization session, and, on a provisioned ZDD,
//! unless the network is open (the anonymous secret also needs the
//! Anonymous Join Countdown Timer).

use heapless::Vec;
use panweave_types::{Duration, ExtendedAddress, Instant};

use crate::auth::Level;
use crate::tlv::Psk;

/// The smallest `NewZddProvisioningTimeout` a manufacturer may choose
/// (§6.2.2).
pub const MIN_NEW_ZDD_PROVISIONING_TIMEOUT: Duration = Duration::from_secs(60);

/// Sessions the ZDD tracks per peer.
pub const SESSIONS: usize = 4;

/// The Zigbee Direct interface state (Figure 4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Interface {
    /// Un-provisioned and advertising: any ZVD may provision the ZDD
    /// until `until`, unless a provisioning session opened meanwhile.
    OpenToBeProvisioned {
        /// When, with no provisioning session, the interface goes off.
        until: Instant,
    },
    /// The Zigbee Direct advertisement is off (no provisioning session
    /// in time, or the Configuration cluster turned it off).
    Off,
    /// Provisioned and advertising: authorized ZVDs connect, new ones
    /// may be provisioned while the network is open.
    OpenToConnect,
}

/// Why a session is not admitted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Refusal {
    /// The interface is off.
    InterfaceOff,
    /// An authorization key on an un-provisioned ZDD (no network, no
    /// keys).
    NotProvisioned,
    /// A new ZVD may only be provisioned while the network is open
    /// (§6.6).
    NetworkClosed,
    /// The Anonymous Join Countdown Timer is 0 (§6.3.1, §6.6): the
    /// connection is closed.
    AnonymousJoinExpired,
    /// The ZVD holds an authorization session (§6.3.1 last paragraph).
    AuthorizationSessionActive,
}

/// What changed in a state transition, for the host.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Transition {
    /// Start (or resume) the Zigbee Direct advertisement.
    Advertise,
    /// Stop the Zigbee Direct advertisement (§6.2.2: manufacturer
    /// extensions may stay, at the lowest frequency).
    StopAdvertising,
}

/// The ZDD's security state machine.
#[derive(Clone, Debug)]
pub struct SecurityState {
    interface: Interface,
    provisioned: bool,
    timeout: Duration,
    /// A provisioning session is open on an un-provisioned ZDD, which
    /// holds the timeout.
    provisioning_open: bool,
    sessions: Vec<(ExtendedAddress, Level), SESSIONS>,
}

impl SecurityState {
    /// A state machine with `NewZddProvisioningTimeout` `timeout`
    /// (raised to the 60 s minimum), before power-up.
    pub fn new(timeout: Duration) -> Self {
        let timeout = if timeout.as_millis() < MIN_NEW_ZDD_PROVISIONING_TIMEOUT.as_millis() {
            MIN_NEW_ZDD_PROVISIONING_TIMEOUT
        } else {
            timeout
        };
        SecurityState {
            interface: Interface::Off,
            provisioned: false,
            timeout,
            provisioning_open: false,
            sessions: Vec::new(),
        }
    }

    /// The interface state.
    pub const fn interface(&self) -> Interface {
        self.interface
    }

    /// Whether the ZDD is provisioned (on a network).
    pub const fn is_provisioned(&self) -> bool {
        self.provisioned
    }

    /// Whether the Zigbee Direct advertisement is on.
    pub const fn advertising(&self) -> bool {
        !matches!(self.interface, Interface::Off)
    }

    /// Power-up (or a user action that reopens provisioning, §6.2.2):
    /// a provisioned ZDD is open to connect, an un-provisioned one open
    /// to be provisioned until `now + timeout`.
    pub fn power_up(&mut self, now: Instant, provisioned: bool) -> Transition {
        self.provisioned = provisioned;
        self.provisioning_open = false;
        self.sessions.clear();
        self.interface = if provisioned {
            Interface::OpenToConnect
        } else {
            Interface::OpenToBeProvisioned {
                until: now + self.timeout,
            }
        };
        Transition::Advertise
    }

    /// The ZDD joined or formed a network (§6.2.3): open to connect.
    pub fn on_joined(&mut self) -> Option<Transition> {
        self.provisioned = true;
        self.provisioning_open = false;
        let was_off = !self.advertising();
        self.interface = Interface::OpenToConnect;
        was_off.then_some(Transition::Advertise)
    }

    /// The ZDD left the network (§6.2.3 last paragraph): open to be
    /// provisioned again, authorization sessions void.
    pub fn on_left(&mut self, now: Instant) -> Transition {
        self.power_up(now, false)
    }

    /// The Zigbee Direct Configuration cluster turned the interface off
    /// or on (§11.3.5.4.3); only meaningful once provisioned.
    pub fn on_interface_configured(&mut self, enabled: bool) -> Option<Transition> {
        if !self.provisioned {
            return None;
        }
        match (enabled, self.advertising()) {
            (true, false) => {
                self.interface = Interface::OpenToConnect;
                Some(Transition::Advertise)
            }
            (false, true) => {
                self.interface = Interface::Off;
                self.sessions.clear();
                Some(Transition::StopAdvertising)
            }
            _ => None,
        }
    }

    /// Time passes: an un-provisioned ZDD with no provisioning session
    /// by the deadline switches its interface off.
    pub fn poll(&mut self, now: Instant) -> Option<Transition> {
        if let Interface::OpenToBeProvisioned { until } = self.interface
            && !self.provisioning_open
            && now.has_reached(until)
        {
            self.interface = Interface::Off;
            return Some(Transition::StopAdvertising);
        }
        None
    }

    /// Whether a session `peer` wants to establish with `psk` is
    /// admitted, and at which level (§6.3.1, §6.6). `network_open` is
    /// whether the network permits joining, `anonymous_allowed` whether
    /// the Anonymous Join Countdown Timer is running (both only matter
    /// on a provisioned ZDD).
    pub fn admit(
        &self,
        peer: ExtendedAddress,
        psk: Psk,
        network_open: bool,
        anonymous_allowed: bool,
    ) -> Result<Level, Refusal> {
        if !self.advertising() {
            return Err(Refusal::InterfaceOff);
        }
        match psk {
            Psk::BasicAuthorization | Psk::AdminAuthorization => {
                if !self.provisioned {
                    return Err(Refusal::NotProvisioned);
                }
                Ok(if psk == Psk::AdminAuthorization {
                    Level::Admin
                } else {
                    Level::Basic
                })
            }
            Psk::SymmetricToken | Psk::InstallCode | Psk::Passcode | Psk::Anonymous => {
                if self
                    .sessions
                    .iter()
                    .any(|(p, l)| *p == peer && *l != Level::Provisioning)
                {
                    return Err(Refusal::AuthorizationSessionActive);
                }
                if self.provisioned {
                    if !network_open {
                        return Err(Refusal::NetworkClosed);
                    }
                    if psk == Psk::Anonymous && !anonymous_allowed {
                        return Err(Refusal::AnonymousJoinExpired);
                    }
                }
                Ok(Level::Provisioning)
            }
        }
    }

    /// A session with `peer` was established at `level`; a provisioning
    /// session on an un-provisioned ZDD holds the provisioning timeout.
    pub fn session_opened(&mut self, peer: ExtendedAddress, level: Level) {
        self.sessions.retain(|(p, _)| *p != peer);
        if self.sessions.is_full() {
            self.sessions.remove(0);
        }
        let _ = self.sessions.push((peer, level));
        if level == Level::Provisioning && !self.provisioned {
            self.provisioning_open = true;
        }
    }

    /// The session with `peer` ended (connection closed).
    pub fn session_closed(&mut self, peer: ExtendedAddress, now: Instant) {
        self.sessions.retain(|(p, _)| *p != peer);
        if self.provisioning_open && !self.sessions.iter().any(|(_, l)| *l == Level::Provisioning) {
            // The un-provisioned ZDD's window restarts.
            self.provisioning_open = false;
            if !self.provisioned && self.advertising() {
                self.interface = Interface::OpenToBeProvisioned {
                    until: now + self.timeout,
                };
            }
        }
    }

    /// The level of the session with `peer`, if any.
    pub fn session_level(&self, peer: ExtendedAddress) -> Option<Level> {
        self.sessions
            .iter()
            .find(|(p, _)| *p == peer)
            .map(|(_, l)| *l)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZVD: ExtendedAddress = ExtendedAddress(0x00AA_0000_0000_0001);
    const T0: Instant = Instant::from_millis(0);

    #[test]
    fn an_unprovisioned_zdd_times_out_unless_provisioning_starts() {
        let mut s = SecurityState::new(Duration::from_secs(10));
        assert_eq!(s.power_up(T0, false), Transition::Advertise);
        assert_eq!(
            s.interface(),
            Interface::OpenToBeProvisioned {
                until: T0 + Duration::from_secs(60)
            }
        );
        // Authorization keys mean nothing yet; any provisioning secret
        // is welcome, the network state being irrelevant.
        assert_eq!(
            s.admit(ZVD, Psk::BasicAuthorization, false, false),
            Err(Refusal::NotProvisioned)
        );
        assert_eq!(
            s.admit(ZVD, Psk::Anonymous, false, false),
            Ok(Level::Provisioning)
        );
        assert_eq!(s.poll(T0 + Duration::from_secs(59)), None);
        // A provisioning session holds the window; closing it restarts.
        s.session_opened(ZVD, Level::Provisioning);
        assert_eq!(s.poll(T0 + Duration::from_secs(120)), None);
        s.session_closed(ZVD, T0 + Duration::from_secs(120));
        assert_eq!(s.poll(T0 + Duration::from_secs(150)), None);
        assert_eq!(
            s.poll(T0 + Duration::from_secs(180)),
            Some(Transition::StopAdvertising)
        );
        assert_eq!(s.interface(), Interface::Off);
        assert_eq!(
            s.admit(ZVD, Psk::InstallCode, true, true),
            Err(Refusal::InterfaceOff)
        );
        // A user action reopens it.
        assert_eq!(
            s.power_up(T0 + Duration::from_secs(200), false),
            Transition::Advertise
        );
        assert!(s.advertising());
    }

    #[test]
    fn a_provisioned_zdd_admits_by_the_network_state_and_the_cluster() {
        let mut s = SecurityState::new(Duration::from_secs(60));
        s.power_up(T0, false);
        s.session_opened(ZVD, Level::Provisioning);
        assert_eq!(s.on_joined(), None);
        assert_eq!(s.interface(), Interface::OpenToConnect);
        assert!(s.is_provisioned());
        // Authorized ZVDs always; new ones only while the network is
        // open, anonymous ones only while the countdown runs.
        assert_eq!(
            s.admit(ZVD, Psk::AdminAuthorization, false, false),
            Ok(Level::Admin)
        );
        assert_eq!(
            s.admit(ZVD, Psk::BasicAuthorization, false, false),
            Ok(Level::Basic)
        );
        assert_eq!(
            s.admit(ZVD, Psk::InstallCode, false, true),
            Err(Refusal::NetworkClosed)
        );
        assert_eq!(
            s.admit(ZVD, Psk::InstallCode, true, false),
            Ok(Level::Provisioning)
        );
        assert_eq!(
            s.admit(ZVD, Psk::Anonymous, true, false),
            Err(Refusal::AnonymousJoinExpired)
        );
        assert_eq!(
            s.admit(ZVD, Psk::Anonymous, true, true),
            Ok(Level::Provisioning)
        );
        // No provisioning session while the same ZVD holds an
        // authorization session; another ZVD is unaffected.
        s.session_opened(ZVD, Level::Basic);
        assert_eq!(
            s.admit(ZVD, Psk::Anonymous, true, true),
            Err(Refusal::AuthorizationSessionActive)
        );
        assert_eq!(
            s.admit(
                ExtendedAddress(0x00AA_0000_0000_0002),
                Psk::Anonymous,
                true,
                true
            ),
            Ok(Level::Provisioning)
        );
        s.session_closed(ZVD, T0);
        assert_eq!(
            s.admit(ZVD, Psk::Anonymous, true, true),
            Ok(Level::Provisioning)
        );
        // The Configuration cluster switches the interface.
        assert_eq!(
            s.on_interface_configured(false),
            Some(Transition::StopAdvertising)
        );
        assert_eq!(
            s.admit(ZVD, Psk::BasicAuthorization, true, true),
            Err(Refusal::InterfaceOff)
        );
        assert_eq!(s.on_interface_configured(false), None);
        assert_eq!(s.on_interface_configured(true), Some(Transition::Advertise));
        assert_eq!(s.poll(T0 + Duration::from_secs(3600)), None);
        // Leaving reopens provisioning.
        assert_eq!(
            s.on_left(T0 + Duration::from_secs(10)),
            Transition::Advertise
        );
        assert!(!s.is_provisioned());
        assert_eq!(
            s.interface(),
            Interface::OpenToBeProvisioned {
                until: T0 + Duration::from_secs(70)
            }
        );
    }
}
