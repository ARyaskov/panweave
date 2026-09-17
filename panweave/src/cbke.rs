//! A certificate-based key establishment driver (SE 1.4a §5.4.6,
//! Annex C; BDB 3.1 §8.7 step for CBKE-capable nodes): runs the Key
//! Establishment cluster exchange over a [`Stack`] on both sides — the
//! initiator (client) after joining, the responder (server) whenever a
//! peer initiates — and installs the derived link key with the partner.
//! The elliptic-curve primitive is the host's ([`Ecmqv`], ADR-0012).
//!
//! The application owns the driver and feeds it every [`StackEvent`]:
//!
//! ```ignore
//! let mut cbke = CbkeDriver::new(my_ecmqv, endpoint, issuer, timing).start_after_join();
//! while let Some(event) = node.next_event() {
//!     if let Some(outcome) = cbke.on_event(&mut node.stack, &event) { /* key established or failed */ }
//! }
//! ```

use panweave_aps::layer::Destination;
use panweave_runtime::{Stack, StackEvent};
use panweave_security::cipher::BlockCipher;
use panweave_security::material::LinkKeyKind;
use panweave_smart_energy::PROFILE_ID;
use panweave_smart_energy::key_establishment::{
    self as ke, Ecmqv, Initiate, Initiator, IssuerPolicy, Outgoing, Responder, Status,
    TRANSMISSION_ALLOWANCE_SECS, Terminate, Timing,
};
use panweave_storage::Storage;
use panweave_types::time::{Duration, Instant};
use panweave_types::{
    CommandId, CryptoRng, Endpoint, ExtendedAddress, Key128, LogicalDeviceType, ShortAddress,
};
use panweave_zcl::frame::{Direction, FrameType};
use panweave_zcl::layer::Origin;

/// Why an exchange could not be started.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CbkeError {
    /// Another exchange is in progress (or the primitive is out).
    Busy,
    /// The Initiate request could not be encoded or sent.
    Send,
}

/// How an exchange ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CbkeOutcome {
    /// The link key with `partner` was derived and installed.
    Established {
        /// The partner.
        partner: ExtendedAddress,
    },
    /// The exchange failed or was terminated.
    Failed {
        /// The partner.
        partner: ExtendedAddress,
        /// The Terminate status (`None` on a timeout).
        status: Option<Status>,
    },
}

enum Active<E: Ecmqv> {
    Initiator {
        machine: Initiator<E>,
        remote_cert: heapless::Vec<u8, { ke::MAX_CERTIFICATE_LEN }>,
        dst: ShortAddress,
    },
    Responder {
        machine: Responder<E>,
    },
}

/// The driver: one exchange at a time on `endpoint`.
pub struct CbkeDriver<E: Ecmqv, I: IssuerPolicy = ExtendedAddress> {
    ecmqv: Option<E>,
    active: Option<(ExtendedAddress, Active<E>)>,
    endpoint: Endpoint,
    issuers: I,
    timing: Timing,
    deadline: Option<Instant>,
    auto: bool,
}

impl<E: Ecmqv, I: IssuerPolicy> CbkeDriver<E, I> {
    /// A driver over `endpoint`'s Key Establishment client and server,
    /// trusting `issuers`, advertising `timing`.
    pub fn new(ecmqv: E, endpoint: Endpoint, issuers: I, timing: Timing) -> Self {
        CbkeDriver {
            ecmqv: Some(ecmqv),
            active: None,
            endpoint,
            issuers,
            timing,
            deadline: None,
            auto: false,
        }
    }

    /// Starts the exchange with the Trust Center by itself once the
    /// device has joined (BDB 3.1: CBKE follows the join on a node that
    /// supports it).
    #[must_use]
    pub fn start_after_join(mut self) -> Self {
        self.auto = true;
        self
    }

    /// Whether an exchange is in progress.
    pub fn is_busy(&self) -> bool {
        self.active.is_some()
    }

    /// Initiates an exchange with `partner` at `dst` (the Trust Center
    /// as a rule). `Err` while another exchange runs or without the
    /// primitive.
    pub fn start<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        dst: ShortAddress,
        partner: ExtendedAddress,
    ) -> Result<(), CbkeError> {
        if self.active.is_some() {
            return Err(CbkeError::Busy);
        }
        let ecmqv = self.ecmqv.take().ok_or(CbkeError::Busy)?;
        let machine = Initiator::new(ecmqv, stack.config.ieee, partner);
        let mut buf = [0u8; 96];
        let Some(n) = machine.initiate(self.timing).encode(&mut buf) else {
            self.ecmqv = Some(machine.into_ecmqv());
            return Err(CbkeError::Send);
        };
        self.send(
            stack,
            dst,
            ke::command::INITIATE_KEY_ESTABLISHMENT,
            Direction::ToServer,
            buf.get(..n).unwrap_or(&[]),
        );
        // C.3.1.1: the partner's generate times plus the allowance, not
        // yet known — allow the longest first step.
        self.deadline =
            Some(stack.now() + Duration::from_secs(255 + u64::from(TRANSMISSION_ALLOWANCE_SECS)));
        self.active = Some((
            partner,
            Active::Initiator {
                machine,
                remote_cert: heapless::Vec::new(),
                dst,
            },
        ));
        Ok(())
    }

    /// Feeds a stack event; returns the outcome when an exchange ends.
    pub fn on_event<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        event: &StackEvent,
    ) -> Option<CbkeOutcome> {
        match event {
            StackEvent::Joined { rejoin: false, .. } if self.auto => {
                if stack.config.role != LogicalDeviceType::Coordinator
                    && !stack.aps.aib.is_distributed()
                {
                    let tc = stack.aps.aib.trust_center_address;
                    let dst = stack.trust_center_short();
                    let _ = self.start(stack, dst, tc);
                }
                None
            }
            StackEvent::ZclCommand(f)
                if f.origin.cluster == ke::ID && f.origin.endpoint == self.endpoint =>
            {
                let origin = f.origin;
                let command = f.origin.header.command.0;
                match f.origin.header.control.direction {
                    Direction::ToClient => self.on_response(stack, &origin, command, &f.payload),
                    Direction::ToServer => self.on_request(stack, &origin, command, &f.payload),
                }
            }
            _ => None,
        }
    }

    /// Times an exchange out (C.3.1.1): the peer is sent Terminate and
    /// the application told.
    pub fn poll<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        now: Instant,
    ) -> Option<CbkeOutcome> {
        if !self.deadline.is_some_and(|t| now.has_reached(t)) {
            return None;
        }
        let (partner, active) = self.active.take()?;
        self.deadline = None;
        let terminate = Terminate {
            status: Status::NoResources,
            wait_time: 0,
            suites: Self::suites_of(&active),
        };
        match active {
            Active::Initiator { machine, dst, .. } => {
                self.ecmqv = Some(machine.into_ecmqv());
                self.send(
                    stack,
                    dst,
                    ke::command::TERMINATE_KEY_ESTABLISHMENT,
                    Direction::ToServer,
                    &terminate.encode(),
                );
            }
            Active::Responder { machine } => {
                self.ecmqv = Some(machine.into_ecmqv());
            }
        }
        Some(CbkeOutcome::Failed {
            partner,
            status: None,
        })
    }

    fn suites_of(active: &Active<E>) -> u16 {
        match active {
            Active::Initiator { machine, .. } => machine.suite().bit(),
            Active::Responder { machine } => machine.suite().bit(),
        }
    }

    /// The earliest instant [`Self::poll`] has something to do.
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    fn send<C: BlockCipher, R: CryptoRng, S: Storage>(
        &self,
        stack: &mut Stack<C, R, S>,
        dst: ShortAddress,
        cmd: u8,
        direction: Direction,
        payload: &[u8],
    ) {
        let _ = stack.zcl.send_command(
            Destination::Short {
                address: dst,
                endpoint: self.endpoint,
            },
            PROFILE_ID,
            ke::ID,
            self.endpoint,
            CommandId(cmd),
            direction,
            None,
            payload,
        );
        stack.flush();
    }

    fn reply<C: BlockCipher, R: CryptoRng, S: Storage>(
        stack: &mut Stack<C, R, S>,
        origin: &Origin,
        cmd: u8,
        payload: &[u8],
    ) {
        let _ = stack
            .zcl
            .respond(origin, CommandId(cmd), FrameType::ClusterSpecific, payload);
        stack.flush();
    }

    fn finish_initiator<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        partner: ExtendedAddress,
        machine: Initiator<E>,
        dst: ShortAddress,
        out: Outgoing,
        key: Option<Key128>,
    ) -> Option<CbkeOutcome> {
        let step = |secs: u8| {
            Duration::from_secs(u64::from(secs.saturating_add(TRANSMISSION_ALLOWANCE_SECS)))
        };
        match (out, key) {
            (Outgoing::EphemeralData(p), _) => {
                self.deadline = Some(stack.now() + step(machine.partner_timing.ephemeral_data));
                self.send(
                    stack,
                    dst,
                    ke::command::EPHEMERAL_DATA,
                    Direction::ToServer,
                    &p,
                );
                self.active = Some((
                    partner,
                    Active::Initiator {
                        machine,
                        remote_cert: heapless::Vec::new(),
                        dst,
                    },
                ));
                None
            }
            (Outgoing::ConfirmKey(mac), _) => {
                self.deadline = Some(stack.now() + step(machine.partner_timing.confirm_key));
                self.send(
                    stack,
                    dst,
                    ke::command::CONFIRM_KEY,
                    Direction::ToServer,
                    &mac,
                );
                self.active = Some((
                    partner,
                    Active::Initiator {
                        machine,
                        remote_cert: heapless::Vec::new(),
                        dst,
                    },
                ));
                None
            }
            (Outgoing::Terminate(t), _) => {
                self.send(
                    stack,
                    dst,
                    ke::command::TERMINATE_KEY_ESTABLISHMENT,
                    Direction::ToServer,
                    &t.encode(),
                );
                self.ecmqv = Some(machine.into_ecmqv());
                self.deadline = None;
                Some(CbkeOutcome::Failed {
                    partner,
                    status: Some(t.status),
                })
            }
        }
    }

    fn on_response<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        _origin: &Origin,
        command: u8,
        payload: &[u8],
    ) -> Option<CbkeOutcome> {
        let (partner, active) = self.active.take()?;
        let Active::Initiator {
            mut machine,
            mut remote_cert,
            dst,
        } = active
        else {
            self.active = Some((partner, active));
            return None;
        };
        match command {
            ke::command::INITIATE_KEY_ESTABLISHMENT => {
                let Ok(rsp) = Initiate::parse(payload) else {
                    self.active = Some((
                        partner,
                        Active::Initiator {
                            machine,
                            remote_cert,
                            dst,
                        },
                    ));
                    return None;
                };
                remote_cert.clear();
                let _ = remote_cert.extend_from_slice(rsp.certificate);
                let out = machine.on_initiate_response::<C>(&rsp, &self.issuers);
                let r = self.finish_initiator(stack, partner, machine, dst, out, None);
                if let Some((
                    _,
                    Active::Initiator {
                        remote_cert: rc, ..
                    },
                )) = self.active.as_mut()
                {
                    *rc = remote_cert;
                }
                r
            }
            ke::command::EPHEMERAL_DATA => {
                let out = machine.on_ephemeral_response::<C>(&remote_cert, payload);
                let r = self.finish_initiator(stack, partner, machine, dst, out, None);
                if let Some((
                    _,
                    Active::Initiator {
                        remote_cert: rc, ..
                    },
                )) = self.active.as_mut()
                {
                    *rc = remote_cert;
                }
                r
            }
            ke::command::CONFIRM_KEY => match machine.on_confirm_response::<C>(payload) {
                Ok(key) => {
                    stack.install_link_key(partner, key, LinkKeyKind::Unique, false);
                    self.ecmqv = Some(machine.into_ecmqv());
                    self.deadline = None;
                    Some(CbkeOutcome::Established { partner })
                }
                Err(out) => self.finish_initiator(stack, partner, machine, dst, out, None),
            },
            ke::command::TERMINATE_KEY_ESTABLISHMENT => {
                let status = Terminate::parse(payload).map(|t| t.status);
                machine.on_terminate();
                self.ecmqv = Some(machine.into_ecmqv());
                self.deadline = None;
                Some(CbkeOutcome::Failed { partner, status })
            }
            _ => {
                self.active = Some((
                    partner,
                    Active::Initiator {
                        machine,
                        remote_cert,
                        dst,
                    },
                ));
                None
            }
        }
    }

    fn on_request<C: BlockCipher, R: CryptoRng, S: Storage>(
        &mut self,
        stack: &mut Stack<C, R, S>,
        origin: &Origin,
        command: u8,
        payload: &[u8],
    ) -> Option<CbkeOutcome> {
        let step = |secs: u8| {
            Duration::from_secs(u64::from(secs.saturating_add(TRANSMISSION_ALLOWANCE_SECS)))
        };
        if command == ke::command::INITIATE_KEY_ESTABLISHMENT {
            // A new exchange from the peer; a busy driver refuses with
            // NO_RESOURCES (C.3.1.2.3.1.2).
            let Ok(req) = Initiate::parse(payload) else {
                return None;
            };
            let partner = match origin_ieee(stack, origin) {
                Some(p) => p,
                None => {
                    Self::reply(
                        stack,
                        origin,
                        ke::command::TERMINATE_KEY_ESTABLISHMENT,
                        &Terminate {
                            status: Status::InvalidCertificate,
                            wait_time: 0,
                            suites: req.suite.bit(),
                        }
                        .encode(),
                    );
                    return None;
                }
            };
            let Some(ecmqv) = self.ecmqv.take().filter(|_| self.active.is_none()) else {
                Self::reply(
                    stack,
                    origin,
                    ke::command::TERMINATE_KEY_ESTABLISHMENT,
                    &Terminate {
                        status: Status::NoResources,
                        wait_time: u8::try_from(
                            self.deadline
                                .map_or(0, |d| d.saturating_duration_since(stack.now()).as_secs()),
                        )
                        .unwrap_or(u8::MAX),
                        suites: req.suite.bit(),
                    }
                    .encode(),
                );
                return None;
            };
            let mut machine = Responder::new(ecmqv, stack.config.ieee, partner);
            match machine.on_initiate(&req, &self.issuers, self.timing) {
                Ok(rsp) => {
                    let mut buf = [0u8; 96];
                    let n = rsp.encode(&mut buf).unwrap_or(0);
                    Self::reply(
                        stack,
                        origin,
                        ke::command::INITIATE_KEY_ESTABLISHMENT,
                        buf.get(..n).unwrap_or(&[]),
                    );
                    self.deadline = Some(stack.now() + step(machine.partner_timing.ephemeral_data));
                    self.active = Some((partner, Active::Responder { machine }));
                    None
                }
                Err(t) => {
                    Self::reply(
                        stack,
                        origin,
                        ke::command::TERMINATE_KEY_ESTABLISHMENT,
                        &t.encode(),
                    );
                    self.ecmqv = Some(machine.into_ecmqv());
                    Some(CbkeOutcome::Failed {
                        partner,
                        status: Some(t.status),
                    })
                }
            }
        } else {
            let (partner, active) = self.active.take()?;
            let Active::Responder { mut machine } = active else {
                self.active = Some((partner, active));
                return None;
            };
            match command {
                ke::command::EPHEMERAL_DATA => match machine.on_ephemeral::<C>(payload) {
                    Outgoing::EphemeralData(p) => {
                        Self::reply(stack, origin, ke::command::EPHEMERAL_DATA, &p);
                        self.deadline =
                            Some(stack.now() + step(machine.partner_timing.confirm_key));
                        self.active = Some((partner, Active::Responder { machine }));
                        None
                    }
                    Outgoing::Terminate(t) => {
                        Self::reply(
                            stack,
                            origin,
                            ke::command::TERMINATE_KEY_ESTABLISHMENT,
                            &t.encode(),
                        );
                        self.ecmqv = Some(machine.into_ecmqv());
                        self.deadline = None;
                        Some(CbkeOutcome::Failed {
                            partner,
                            status: Some(t.status),
                        })
                    }
                    Outgoing::ConfirmKey(_) => {
                        self.ecmqv = Some(machine.into_ecmqv());
                        self.deadline = None;
                        Some(CbkeOutcome::Failed {
                            partner,
                            status: Some(Status::BadMessage),
                        })
                    }
                },
                ke::command::CONFIRM_KEY => match machine.on_confirm::<C>(payload) {
                    Ok((Outgoing::ConfirmKey(mac), key)) => {
                        stack.install_link_key(partner, key, LinkKeyKind::Unique, false);
                        Self::reply(stack, origin, ke::command::CONFIRM_KEY, &mac);
                        self.ecmqv = Some(machine.into_ecmqv());
                        self.deadline = None;
                        Some(CbkeOutcome::Established { partner })
                    }
                    Err(Outgoing::Terminate(t)) => {
                        Self::reply(
                            stack,
                            origin,
                            ke::command::TERMINATE_KEY_ESTABLISHMENT,
                            &t.encode(),
                        );
                        self.ecmqv = Some(machine.into_ecmqv());
                        self.deadline = None;
                        Some(CbkeOutcome::Failed {
                            partner,
                            status: Some(t.status),
                        })
                    }
                    _ => {
                        self.ecmqv = Some(machine.into_ecmqv());
                        self.deadline = None;
                        Some(CbkeOutcome::Failed {
                            partner,
                            status: Some(Status::BadMessage),
                        })
                    }
                },
                ke::command::TERMINATE_KEY_ESTABLISHMENT => {
                    let status = Terminate::parse(payload).map(|t| t.status);
                    self.ecmqv = Some(machine.into_ecmqv());
                    self.deadline = None;
                    Some(CbkeOutcome::Failed { partner, status })
                }
                _ => {
                    self.active = Some((partner, Active::Responder { machine }));
                    None
                }
            }
        }
    }
}

/// The IEEE address behind a frame's source (the neighbour table or
/// address map).
fn origin_ieee<C: BlockCipher, R: CryptoRng, S: Storage>(
    stack: &Stack<C, R, S>,
    origin: &Origin,
) -> Option<ExtendedAddress> {
    stack.ieee_of(origin.src)
}
