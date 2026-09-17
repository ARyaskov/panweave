//! Smart Energy cluster drivers (SE 1.4a Annex D): the sans-I/O cluster
//! models of `panweave_smart_energy::clusters` bound to a [`Stack`] —
//! each driver decodes the cluster's commands from the stack's events,
//! applies them to the model, sends the responses the cluster requires
//! (APS link-key protected, as Table 5-12 mandates) and reports what the
//! application needs to act on. The application owns the drivers and
//! feeds them every [`StackEvent`], the way it does with
//! [`crate::cbke::CbkeDriver`].
//!
//! UTC time comes from the Time cluster server on the driver's endpoint
//! when there is one, otherwise from [`UtcClock`] set by the application.

pub mod commissioning;
pub mod drlc;
pub mod messaging;
pub mod metering;
pub mod price;

use panweave_aps::layer::{Destination, TxOptions};
use panweave_runtime::{Stack, StackEvent};
use panweave_security::cipher::BlockCipher;
use panweave_smart_energy::PROFILE_ID;
use panweave_storage::Storage;
use panweave_types::time::Instant;
use panweave_types::{ClusterId, CommandId, CryptoRng, Endpoint};
use panweave_zcl::clusters::time;
use panweave_zcl::frame::{Direction, FrameType, Header};
use panweave_zcl::layer::Origin;
use panweave_zcl::{Role, ZclStatus};

/// A UTC reference the application sets when no Time server is at hand.
#[derive(Clone, Copy, Debug, Default)]
pub struct UtcClock {
    base: Option<(u32, Instant)>,
}

impl UtcClock {
    /// Unset.
    pub const fn new() -> Self {
        UtcClock { base: None }
    }

    /// Records that it was `utc` seconds at `at`.
    pub fn set(&mut self, utc: u32, at: Instant) {
        self.base = Some((utc, at));
    }

    /// UTC seconds at `now` (`None` while unset).
    pub fn now(&self, now: Instant) -> Option<u32> {
        let (base, at) = self.base?;
        let elapsed = now.as_millis().saturating_sub(at.as_millis()) / 1000;
        Some(base.saturating_add(u32::try_from(elapsed).unwrap_or(u32::MAX)))
    }
}

/// UTC seconds now: the Time server on `endpoint`, else `clock`, else 0
/// (the ZCL "unknown" time).
pub fn utc_now<C: BlockCipher, R: CryptoRng, S: Storage>(
    stack: &Stack<C, R, S>,
    endpoint: Endpoint,
    clock: &UtcClock,
) -> u32 {
    let now = stack.now();
    stack
        .zcl
        .endpoint(endpoint)
        .and_then(|e| e.cluster(time::ID, Role::Server))
        .and_then(|c| time::now(c, now))
        .or_else(|| clock.now(now))
        .unwrap_or(0)
}

/// The frame of a cluster-specific command on `cluster` received on the
/// driver's `endpoint`, in `direction`.
pub(crate) fn command_for<'a>(
    event: &'a StackEvent,
    endpoint: Endpoint,
    cluster: ClusterId,
    direction: Direction,
) -> Option<(&'a Origin, &'a [u8])> {
    match event {
        StackEvent::ZclCommand(f)
            if f.origin.endpoint == endpoint
                && f.origin.cluster == cluster
                && f.origin.header.control.direction == direction
                && f.origin.header.control.frame_type == FrameType::ClusterSpecific =>
        {
            Some((&f.origin, &f.payload))
        }
        _ => None,
    }
}

/// Sends a cluster-specific command from `endpoint` with APS link-key
/// security and an acknowledgement for unicasts.
pub(crate) fn send<C: BlockCipher, R: CryptoRng, S: Storage>(
    stack: &mut Stack<C, R, S>,
    endpoint: Endpoint,
    destination: Destination,
    cluster: ClusterId,
    command: CommandId,
    direction: Direction,
    payload: &[u8],
) -> bool {
    let header = Header::cluster_specific(stack.zcl.next_seq(), command, direction)
        .disable_default_response(true);
    let ok = stack
        .zcl
        .send(
            destination,
            PROFILE_ID,
            cluster,
            endpoint,
            &header,
            payload,
            TxOptions {
                security: true,
                ..TxOptions::ACKED
            },
        )
        .is_ok();
    stack.flush();
    ok
}

/// Answers a received command with a cluster-specific response.
pub(crate) fn reply<C: BlockCipher, R: CryptoRng, S: Storage>(
    stack: &mut Stack<C, R, S>,
    origin: &Origin,
    command: CommandId,
    payload: &[u8],
) -> bool {
    let ok = stack
        .zcl
        .respond(origin, command, FrameType::ClusterSpecific, payload)
        .is_ok();
    stack.flush();
    ok
}

/// Answers a received command with a Default Response.
pub(crate) fn default_response<C: BlockCipher, R: CryptoRng, S: Storage>(
    stack: &mut Stack<C, R, S>,
    origin: &Origin,
    status: ZclStatus,
) {
    let _ = stack.zcl.default_response(origin, status);
    stack.flush();
}
