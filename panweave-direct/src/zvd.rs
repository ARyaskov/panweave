//! The ZVD side (ZD 1.1 §8): what a Zigbee Virtual Device does around
//! the BLE transport, the session layer and the Tunnel Service, as a
//! sans-I/O state machine. The host scans, connects, runs the session
//! exchange of [`crate::session::Initiator`] and writes to the tunnel;
//! [`TunnelClient`] tells it what to do next and keeps the connection
//! re-establishment rules of §8.3.3 and the tunnel client steps of
//! §8.4.3.3. EUI-64 and short address allocation follow §8.5 and R23.2
//! §3.6.1.8.

use heapless::Vec;
use panweave_types::{CryptoRng, ExtendedAddress, PanId, ShortAddress};

use crate::advertisement::Advertisement;

/// A BLE device address as the host reports it (6 octets, little
/// endian as on the air).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BleAddress(pub [u8; 6]);

/// ZDDs the client may reconnect to (§8.3.1: "the ZVD MAY reconnect to
/// a ZDD using a previously obtained BLE address").
pub const KNOWN_ZDDS: usize = 4;

/// A randomly generated, locally administered EUI-64 (§8.5, \[R7\]): the
/// U/L bit of the first octet on the air (bit 1 of the most significant
/// octet) set, the I/G bit clear.
pub fn random_eui64<R: CryptoRng>(rng: &mut R) -> ExtendedAddress {
    let mut bytes = [0u8; 8];
    rng.fill_bytes(&mut bytes);
    // Octet 0 on the air is the most significant octet of the value.
    bytes[0] = (bytes[0] | 0x02) & !0x01;
    ExtendedAddress(u64::from_be_bytes(bytes))
}

/// A short address chosen at random per R23.2 §3.6.1.8 (stochastic
/// address assignment): unicast, not reserved, outside the range a
/// coordinator holds; `in_use` rejects addresses the ZVD already knows.
/// `None` when 64 draws found nothing.
pub fn random_short_address<R: CryptoRng>(
    rng: &mut R,
    mut in_use: impl FnMut(ShortAddress) -> bool,
) -> Option<ShortAddress> {
    for _ in 0..64 {
        let mut b = [0u8; 2];
        rng.fill_bytes(&mut b);
        let candidate = ShortAddress(u16::from_le_bytes(b));
        if candidate.is_assignable() && !in_use(candidate) {
            return Some(candidate);
        }
    }
    None
}

/// What the client is doing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum State {
    /// Not connected to any ZDD.
    Idle,
    /// Scanning for a ZDD of the network (§8.3.1), or reconnecting to a
    /// known one; `attempt` counts the discovery rounds of this
    /// re-establishment.
    Discovering {
        /// The discovery round (1-based).
        attempt: u8,
    },
    /// A BLE connection to `zdd` is being set up.
    Connecting {
        /// The ZDD.
        zdd: BleAddress,
    },
    /// The secure session with `zdd` is being established (§8.3.2).
    EstablishingSession {
        /// The ZDD.
        zdd: BleAddress,
    },
    /// The Network Commissioning Request went through the tunnel; the
    /// response is awaited (§8.4.3.3 steps 1–2).
    Joining {
        /// The ZDD.
        zdd: BleAddress,
    },
    /// On the network through `zdd`'s tunnel (§8.4.3.3 step 3).
    Operating {
        /// The ZDD.
        zdd: BleAddress,
    },
    /// Every discovery round the application allowed failed.
    Failed,
}

/// The kind of Network Commissioning Request the client sends
/// (§7.7.4.3, §7.7.4.6).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum JoinRequest {
    /// An initial join over a provisioning session, unsecured.
    InitialJoin,
    /// A secure rejoin over an authorization session (the ZVD holds the
    /// current Basic key): NWK-secured.
    SecureRejoin,
    /// A Trust Center rejoin over a Limited Authorization session (the
    /// network key rotated, §9.1): unsecured.
    TrustCenterRejoin,
}

/// What the host does next.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Action {
    /// Scan for Zigbee Direct advertisements (§8.3.1); feed each to
    /// [`TunnelClient::on_advertisement`].
    Scan,
    /// Connect to the ZDD.
    Connect(BleAddress),
    /// Run the session establishment of §6.5 with the secret the client
    /// holds (Basic authorization once provisioned, the provisioning
    /// secret before), announcing `key_sequence` when it is a Basic key
    /// (§9.1).
    EstablishSession {
        /// The ZDD.
        zdd: BleAddress,
    },
    /// Tunnel a Network Commissioning Request of this kind with the
    /// ZVD's short address (§8.4.3.3 step 1).
    SendCommissioningRequest(JoinRequest),
    /// Disconnect from the ZDD (a session that could not be established
    /// with it, §8.3.3 step 2) before looking for another one.
    Disconnect(BleAddress),
    /// The ZVD gave up (the application's retry budget is spent).
    GiveUp,
}

/// The ZVD's tunnel client (§8.3.3, §8.4.3.3).
#[derive(Clone, Debug)]
pub struct TunnelClient {
    /// The network the ZVD belongs to (its PAN ID filters
    /// advertisements, §8.3.3 step 1).
    pan_id: Option<PanId>,
    /// The short address the ZVD uses (§3.6.1.8).
    short: ShortAddress,
    /// ZDDs of the network the ZVD connected to before, most recent
    /// last.
    known: Vec<BleAddress, KNOWN_ZDDS>,
    /// ZDDs tried and rejected in this re-establishment (no session).
    rejected: Vec<BleAddress, KNOWN_ZDDS>,
    /// Discovery rounds the application allows per re-establishment
    /// (at least one retry after the first, §8.3.3 step 1).
    max_attempts: u8,
    /// The ZVD holds a Basic authorization key derived from network key
    /// sequence number `.0`, so it rejoins rather than joins.
    provisioned: Option<u8>,
    /// The ZDD announced this active key sequence number in the last
    /// session (Message 2), to tell a rotation.
    zdd_key_sequence: Option<u8>,
    state: State,
    pending: Vec<Action, 4>,
}

impl TunnelClient {
    /// A client for the network `pan_id` (None: any ZDD, the first
    /// commissioning) with `short` as its address and `max_attempts`
    /// discovery rounds per re-establishment (clamped to at least 2:
    /// the ZVD "SHALL retry the discovery process at least once").
    pub fn new(pan_id: Option<PanId>, short: ShortAddress, max_attempts: u8) -> Self {
        TunnelClient {
            pan_id,
            short,
            known: Vec::new(),
            rejected: Vec::new(),
            max_attempts: max_attempts.max(2),
            provisioned: None,
            zdd_key_sequence: None,
            state: State::Idle,
            pending: Vec::new(),
        }
    }

    /// The state.
    pub const fn state(&self) -> State {
        self.state
    }

    /// The short address.
    pub const fn short_address(&self) -> ShortAddress {
        self.short
    }

    /// The ZVD received its Basic authorization key derived from
    /// network key `sequence` (a Transport Key over the tunnel): later
    /// sessions use it and the ZVD rejoins instead of joining.
    pub fn set_basic_key_sequence(&mut self, sequence: u8) {
        self.provisioned = Some(sequence);
    }

    /// The network key sequence number the ZVD's Basic key derives
    /// from, once provisioned.
    pub const fn basic_key_sequence(&self) -> Option<u8> {
        self.provisioned
    }

    /// Next action for the host.
    pub fn next_action(&mut self) -> Option<Action> {
        if self.pending.is_empty() {
            None
        } else {
            Some(self.pending.remove(0))
        }
    }

    fn push(&mut self, a: Action) {
        let _ = self.pending.push(a);
    }

    /// Starts (or restarts) connecting to the network: a known ZDD is
    /// reconnected to directly, otherwise a scan starts (§8.3.1,
    /// §8.3.3 step 1).
    pub fn start(&mut self) {
        self.rejected.clear();
        self.discover(1);
    }

    fn discover(&mut self, attempt: u8) {
        if attempt > self.max_attempts {
            self.state = State::Failed;
            self.push(Action::GiveUp);
            return;
        }
        self.state = State::Discovering { attempt };
        if let Some(zdd) = self
            .known
            .iter()
            .rev()
            .copied()
            .find(|z| !self.rejected.contains(z))
        {
            self.connect(zdd);
        } else {
            self.push(Action::Scan);
        }
    }

    fn connect(&mut self, zdd: BleAddress) {
        self.state = State::Connecting { zdd };
        self.push(Action::Connect(zdd));
    }

    /// A Zigbee Direct advertisement from `zdd` was heard while
    /// discovering: a ZDD of the ZVD's network with the Tunnel Service
    /// (any joined ZDD before the ZVD has a network) is connected to.
    /// Returns whether it was selected.
    pub fn on_advertisement(&mut self, zdd: BleAddress, ad: &Advertisement) -> bool {
        let State::Discovering { .. } = self.state else {
            return false;
        };
        if !ad.tunnel_service || !ad.joined() || self.rejected.contains(&zdd) {
            return false;
        }
        if self.pan_id.is_some_and(|p| p != ad.pan_id) {
            return false;
        }
        if self.pan_id.is_none() {
            self.pan_id = Some(ad.pan_id);
        }
        self.connect(zdd);
        true
    }

    /// The scan the host ran ended without a usable ZDD: the next
    /// discovery round, or giving up.
    pub fn on_scan_finished(&mut self) {
        if let State::Discovering { attempt } = self.state {
            self.discover(attempt.saturating_add(1));
        }
    }

    /// The BLE connection to the ZDD is up: the session follows
    /// (§8.3.3 step 2).
    pub fn on_connected(&mut self) {
        if let State::Connecting { zdd } = self.state {
            self.state = State::EstablishingSession { zdd };
            self.push(Action::EstablishSession { zdd });
        }
    }

    /// The BLE connection attempt failed: another ZDD, or another
    /// round.
    pub fn on_connect_failed(&mut self) {
        if let State::Connecting { zdd } = self.state {
            let _ = self.rejected.push(zdd);
            self.discover(1);
        }
    }

    /// The secure session is up; `zdd_key_sequence` is what the ZDD
    /// announced in Message 2. The Network Commissioning Request
    /// follows: an initial join before provisioning, a Trust Center
    /// rejoin when the ZDD's active key sequence number differs from
    /// the one the Basic key derives from (a rotation, §9.1), a secure
    /// rejoin otherwise (§7.7.4.6).
    pub fn on_session_established(&mut self, zdd_key_sequence: Option<u8>) {
        let State::EstablishingSession { zdd } = self.state else {
            return;
        };
        self.zdd_key_sequence = zdd_key_sequence;
        if !self.known.contains(&zdd) {
            if self.known.is_full() {
                self.known.remove(0);
            }
            let _ = self.known.push(zdd);
        }
        let request = match self.provisioned {
            None => JoinRequest::InitialJoin,
            Some(mine) => {
                if zdd_key_sequence.is_some_and(|s| s != mine) {
                    JoinRequest::TrustCenterRejoin
                } else {
                    JoinRequest::SecureRejoin
                }
            }
        };
        self.state = State::Joining { zdd };
        self.push(Action::SendCommissioningRequest(request));
    }

    /// Session establishment with the ZDD failed: it is left alone and
    /// an alternative ZDD discovered (§8.3.3 step 2).
    pub fn on_session_failed(&mut self) {
        if let State::EstablishingSession { zdd } = self.state {
            let _ = self.rejected.push(zdd);
            self.push(Action::Disconnect(zdd));
            self.discover(1);
        }
    }

    /// The Network Commissioning Response arrived: `success` with the
    /// address the ZDD assigned (0xF0 "address conflict" responses give
    /// `assigned` and no success; the client adopts the address and
    /// asks again).
    pub fn on_commissioning_response(&mut self, success: bool, assigned: ShortAddress) {
        let State::Joining { zdd } = self.state else {
            return;
        };
        if success {
            self.short = assigned;
            self.state = State::Operating { zdd };
        } else if assigned != self.short && assigned.is_assignable() {
            self.short = assigned;
            let request = match self.provisioned {
                None => JoinRequest::InitialJoin,
                Some(mine) if self.zdd_key_sequence.is_some_and(|s| s != mine) => {
                    JoinRequest::TrustCenterRejoin
                }
                Some(_) => JoinRequest::SecureRejoin,
            };
            self.push(Action::SendCommissioningRequest(request));
        } else {
            let _ = self.rejected.push(zdd);
            self.push(Action::Disconnect(zdd));
            self.discover(1);
        }
    }

    /// The BLE connection or the secure session to the ZDD was lost:
    /// re-establishment starts (§8.3.3), from the known ZDDs first.
    pub fn on_disconnected(&mut self) {
        match self.state {
            State::Idle | State::Failed | State::Discovering { .. } => {}
            _ => {
                self.rejected.clear();
                self.discover(1);
            }
        }
    }

    /// The application stops: nothing further.
    pub fn stop(&mut self) {
        self.state = State::Idle;
        self.pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic generator for tests only (never cryptographic).
    struct Rng(panweave_types::rng::DeterministicRng);
    impl panweave_types::rng::Rng for Rng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.fill_bytes(dest);
        }
    }
    impl CryptoRng for Rng {}

    const A: BleAddress = BleAddress([1, 2, 3, 4, 5, 6]);
    const B: BleAddress = BleAddress([9, 9, 9, 9, 9, 9]);

    fn ad(pan: u16) -> Advertisement {
        Advertisement {
            tunnel_service: true,
            permit_join: true,
            pan_id: PanId(pan),
            nwk_address: ShortAddress(0x1234),
        }
    }

    #[test]
    fn allocated_identifiers_follow_the_rules() {
        let mut rng = Rng(panweave_types::rng::DeterministicRng::seed(7));
        for _ in 0..32 {
            let e = random_eui64(&mut rng);
            let first = e.0.to_be_bytes()[0];
            assert_eq!(first & 0x03, 0x02, "locally administered, unicast");
        }
        let taken = ShortAddress(0x1234);
        for _ in 0..32 {
            let s = random_short_address(&mut rng, |c| c == taken).unwrap();
            assert!(s.is_assignable() && s != taken);
        }
    }

    #[test]
    fn the_client_joins_reconnects_and_rejoins() {
        let mut c = TunnelClient::new(None, ShortAddress(0x4E21), 3);
        c.start();
        assert_eq!(c.next_action(), Some(Action::Scan));
        // A ZDD without the Tunnel Service is ignored; one with it on
        // any network is taken (no network yet).
        let mut no_ts = ad(0x1A62);
        no_ts.tunnel_service = false;
        assert!(!c.on_advertisement(A, &no_ts));
        assert!(c.on_advertisement(A, &ad(0x1A62)));
        assert_eq!(c.next_action(), Some(Action::Connect(A)));
        c.on_connected();
        assert_eq!(c.next_action(), Some(Action::EstablishSession { zdd: A }));
        c.on_session_established(Some(0));
        assert_eq!(
            c.next_action(),
            Some(Action::SendCommissioningRequest(JoinRequest::InitialJoin))
        );
        // Address conflict: the assigned address is adopted and the
        // request repeated.
        c.on_commissioning_response(false, ShortAddress(0x4E22));
        assert_eq!(c.short_address(), ShortAddress(0x4E22));
        assert_eq!(
            c.next_action(),
            Some(Action::SendCommissioningRequest(JoinRequest::InitialJoin))
        );
        c.on_commissioning_response(true, ShortAddress(0x4E22));
        assert_eq!(c.state(), State::Operating { zdd: A });
        c.set_basic_key_sequence(0);

        // Connection lost: the known ZDD is reconnected to directly, a
        // secure rejoin follows (same key sequence).
        c.on_disconnected();
        assert_eq!(c.next_action(), Some(Action::Connect(A)));
        c.on_connected();
        assert_eq!(c.next_action(), Some(Action::EstablishSession { zdd: A }));
        c.on_session_established(Some(0));
        assert_eq!(
            c.next_action(),
            Some(Action::SendCommissioningRequest(JoinRequest::SecureRejoin))
        );
        c.on_commissioning_response(true, ShortAddress(0x4E22));

        // Lost again; the known ZDD refuses the session: it is left,
        // another ZDD of the same network found by scanning; the key
        // rotated meanwhile, so a Trust Center rejoin.
        c.on_disconnected();
        assert_eq!(c.next_action(), Some(Action::Connect(A)));
        c.on_connected();
        assert_eq!(c.next_action(), Some(Action::EstablishSession { zdd: A }));
        c.on_session_failed();
        assert_eq!(c.next_action(), Some(Action::Disconnect(A)));
        assert_eq!(c.next_action(), Some(Action::Scan));
        assert!(!c.on_advertisement(B, &ad(0x2222)), "another network");
        assert!(!c.on_advertisement(A, &ad(0x1A62)), "rejected this round");
        assert!(c.on_advertisement(B, &ad(0x1A62)));
        assert_eq!(c.next_action(), Some(Action::Connect(B)));
        c.on_connected();
        let _ = c.next_action();
        c.on_session_established(Some(1));
        assert_eq!(
            c.next_action(),
            Some(Action::SendCommissioningRequest(
                JoinRequest::TrustCenterRejoin
            ))
        );
        c.on_commissioning_response(true, ShortAddress(0x4E22));
        assert_eq!(c.state(), State::Operating { zdd: B });
    }

    #[test]
    fn discovery_is_retried_at_least_once_then_given_up() {
        let mut c = TunnelClient::new(Some(PanId(0x1A62)), ShortAddress(0x0001), 0);
        c.start();
        assert_eq!(c.next_action(), Some(Action::Scan));
        c.on_scan_finished();
        assert_eq!(c.state(), State::Discovering { attempt: 2 });
        assert_eq!(c.next_action(), Some(Action::Scan));
        c.on_scan_finished();
        assert_eq!(c.state(), State::Failed);
        assert_eq!(c.next_action(), Some(Action::GiveUp));
        assert_eq!(c.next_action(), None);
    }
}
