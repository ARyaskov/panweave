//! Storage profiles of the ZCL tables.
//!
//! Every cluster instance, endpoint and dispatcher is generic over a
//! [`ZclProfile`] that chooses, at compile time:
//!
//! * the cluster-specific state an instance can carry ([`StateStore`]):
//!   [`Full`] carries [`ClusterState`], an enum of every implemented
//!   cluster's state whose largest variant (the Door Lock user table)
//!   is close to a kilobyte; [`Sensor`] carries only the IAS Zone and
//!   Poll Control states;
//! * the octets a cluster's wide attributes (strings, composites, keys)
//!   share ([`ZclProfile::Pool`]);
//! * the reporting slots of a cluster ([`ZclProfile::Reports`]): an
//!   attribute holds one while it is configured to report or has a
//!   default reporting configuration;
//! * whether an endpoint has a scene table ([`SceneStore`]);
//! * the dispatcher's action and event queues.
//!
//! The profile is a type, not a Cargo feature: a [`Full`] coordinator and
//! a [`Sensor`] end device coexist in one binary. [`Full`] is the default
//! of every generic type, so `ClusterInstance<36>` and `Zcl<2, 12, 36>`
//! keep their meaning.
//!
//! A profile that cannot hold a cluster's state refuses to build it:
//! the cluster's builder fails with `INSUFFICIENT_SPACE` (or the
//! instance is left without state, and its commands fail), it never
//! answers as if the state were there.

use panweave_types::capacity::{Cap, Capacity};

use crate::cluster::ClusterState;
use crate::clusters::{
    alarms, appliance, color_control, commissioning, configuration, direct_configuration,
    door_lock, hvac, ias_ace, ias_zone, level, poll_control, power_configuration, power_profile,
    rssi_location, scenes, time,
};

/// Access to one kind of cluster-specific state in a state store.
pub trait Holds<T> {
    /// The state, when the store holds this kind.
    fn get(&self) -> Option<&T>;
    /// The state, mutably, when the store holds this kind.
    fn get_mut(&mut self) -> Option<&mut T>;
    /// Replaces the store's content with `state`; hands it back when the
    /// store cannot hold this kind.
    fn put(&mut self, state: T) -> Result<(), T>;
}

/// The transient-state reset of Reset to Factory Defaults (§3.2.2.3.1)
/// for one kind of cluster state.
pub trait ResetState: Sized {
    /// The state after the reset (configuration kept, work in progress
    /// dropped).
    fn reset(self) -> Self;
}

/// The cluster-specific state of one instance: one of the states it
/// [`Holds`], or none.
pub trait StateStore:
    Default
    + Clone
    + core::fmt::Debug
    + 'static
    + Holds<level::Transition>
    + Holds<poll_control::State>
    + Holds<time::Clock>
    + Holds<alarms::Table>
    + Holds<ias_zone::State>
    + Holds<color_control::Engine>
    + Holds<door_lock::State>
    + Holds<ias_ace::Panel>
    + Holds<commissioning::State>
    + Holds<hvac::thermostat::Schedule>
    + Holds<power_configuration::MainsDwell>
    + Holds<configuration::Dwell>
    + Holds<appliance::control::State>
    + Holds<appliance::events_alerts::Alerts>
    + Holds<appliance::statistics::LogQueue>
    + Holds<power_profile::Profiles>
    + Holds<rssi_location::State>
    + Holds<direct_configuration::State>
{
    /// Applies [`ResetState::reset`] to the state held.
    fn reset(&mut self);
}

/// The scene table of an endpoint, when the profile has one.
pub trait SceneStore: Default + core::fmt::Debug + 'static {
    /// The table.
    fn table(&self) -> Option<&scenes::SceneTable>;
    /// The table, mutably.
    fn table_mut(&mut self) -> Option<&mut scenes::SceneTable>;
}

impl SceneStore for scenes::SceneTable {
    fn table(&self) -> Option<&scenes::SceneTable> {
        Some(self)
    }

    fn table_mut(&mut self) -> Option<&mut scenes::SceneTable> {
        Some(self)
    }
}

/// No scene table: endpoints of the profile cannot host a Scenes server
/// (its commands fail with `INSUFFICIENT_SPACE`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct NoScenes;

impl SceneStore for NoScenes {
    fn table(&self) -> Option<&scenes::SceneTable> {
        None
    }

    fn table_mut(&mut self) -> Option<&mut scenes::SceneTable> {
        None
    }
}

/// The compile-time dimensions of the ZCL storage (see the module
/// documentation).
pub trait ZclProfile: 'static {
    /// Cluster-specific state of an instance.
    type State: StateStore;
    /// Octets of wide-attribute storage per cluster instance; each wide
    /// attribute takes [`crate::attribute::MAX_ATTRIBUTE_BYTES`] twice
    /// (value and factory default). Read-only strings given as `'static`
    /// data take none.
    type Pool: Capacity;
    /// Reporting slots of a cluster instance of `A` attributes.
    type Reports<const A: usize>: Capacity;
    /// The scene table of an endpoint.
    type Scenes: SceneStore;
    /// Outgoing frames the dispatcher queues for the runtime.
    type Actions: Capacity;
    /// Events the dispatcher queues for the application.
    type Events: Capacity;
}

/// Every implemented cluster: the profile of coordinators, routers, hubs
/// and full-featured devices, and the default of every generic type.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Full;

impl ZclProfile for Full {
    type State = ClusterState;
    type Pool = Cap<{ crate::attribute::ATTRIBUTE_POOL }>;
    // Every attribute can report at once.
    type Reports<const A: usize> = Cap<A>;
    type Scenes = scenes::SceneTable;
    type Actions = Cap<{ crate::layer::QUEUE_CAPACITY }>;
    type Events = Cap<{ crate::layer::QUEUE_CAPACITY }>;
}

/// A battery sensor (Panweave Lite): Basic, Identify, Power
/// Configuration, IAS Zone, Poll Control and the measurement servers.
/// No scene table, no wide writable attributes (the Basic strings are
/// `'static`), four reporting slots per cluster, and the IAS Zone and
/// Poll Control states only.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Sensor;

crate::cluster_state! {
    /// The cluster states of the [`Sensor`] profile.
    pub enum SensorState {
        /// IAS Zone server state (§8.2).
        IasZone(ias_zone::State),
        /// Poll Control server / client state (§3.16).
        PollControl(poll_control::State),
    }
    unsupported {
        level::Transition,
        time::Clock,
        alarms::Table,
        color_control::Engine,
        door_lock::State,
        ias_ace::Panel,
        commissioning::State,
        hvac::thermostat::Schedule,
        power_configuration::MainsDwell,
        configuration::Dwell,
        appliance::control::State,
        appliance::events_alerts::Alerts,
        appliance::statistics::LogQueue,
        power_profile::Profiles,
        rssi_location::State,
        direct_configuration::State,
    }
}

impl ZclProfile for Sensor {
    type State = SensorState;
    type Pool = Cap<0>;
    type Reports<const A: usize> = Cap<4>;
    type Scenes = NoScenes;
    // A response, a report and a notification in one turn.
    type Actions = Cap<3>;
    type Events = Cap<4>;
}

/// Defines a cluster-state enum for a [`ZclProfile`]: a `None` variant
/// plus the listed variants, [`Holds`] for each listed state, a refusing
/// [`Holds`] for every state in `unsupported`, and [`StateStore`]. Every
/// state [`StateStore`] names must appear in one of the two lists.
#[macro_export]
macro_rules! cluster_state {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident($ty:ty), )*
        }
        unsupported { $( $unsupported:ty ),* $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Default)]
        $vis enum $name {
            /// No state.
            #[default]
            None,
            $( $(#[$vmeta])* $variant($ty), )*
        }

        $(
            impl $crate::profile::Holds<$ty> for $name {
                fn get(&self) -> ::core::option::Option<&$ty> {
                    match self {
                        $name::$variant(s) => ::core::option::Option::Some(s),
                        #[allow(unreachable_patterns)]
                        _ => ::core::option::Option::None,
                    }
                }

                fn get_mut(&mut self) -> ::core::option::Option<&mut $ty> {
                    match self {
                        $name::$variant(s) => ::core::option::Option::Some(s),
                        #[allow(unreachable_patterns)]
                        _ => ::core::option::Option::None,
                    }
                }

                fn put(&mut self, state: $ty) -> ::core::result::Result<(), $ty> {
                    *self = $name::$variant(state);
                    ::core::result::Result::Ok(())
                }
            }
        )*

        $(
            impl $crate::profile::Holds<$unsupported> for $name {
                fn get(&self) -> ::core::option::Option<&$unsupported> {
                    ::core::option::Option::None
                }

                fn get_mut(&mut self) -> ::core::option::Option<&mut $unsupported> {
                    ::core::option::Option::None
                }

                fn put(&mut self, state: $unsupported) -> ::core::result::Result<(), $unsupported> {
                    ::core::result::Result::Err(state)
                }
            }
        )*

        impl $crate::profile::StateStore for $name {
            fn reset(&mut self) {
                *self = match ::core::mem::take(self) {
                    $name::None => $name::None,
                    $( $name::$variant(s) => $name::$variant($crate::profile::ResetState::reset(s)), )*
                };
            }
        }
    };
}

impl ResetState for level::Transition {
    fn reset(self) -> Self {
        level::Transition::default()
    }
}

impl ResetState for poll_control::State {
    fn reset(self) -> Self {
        poll_control::State::default()
    }
}

impl ResetState for time::Clock {
    fn reset(self) -> Self {
        time::Clock {
            base: None,
            published: time::INVALID,
            ..self
        }
    }
}

impl ResetState for alarms::Table {
    fn reset(self) -> Self {
        alarms::Table::default()
    }
}

impl ResetState for ias_zone::State {
    fn reset(self) -> Self {
        ias_zone::State {
            cie: None,
            cie_address: 0,
            enroll_request_due: false,
            notify_due: None,
            test_until: None,
            ..self
        }
    }
}

impl ResetState for color_control::Engine {
    fn reset(self) -> Self {
        color_control::Engine::default()
    }
}

impl ResetState for door_lock::State {
    fn reset(self) -> Self {
        // The PIN users are wiped, the slot count is kept.
        let mut users = heapless::Vec::new();
        for _ in 0..self.users.len() {
            let _ = users.push(door_lock::User::default());
        }
        door_lock::State {
            users,
            ..door_lock::State::default()
        }
    }
}

impl ResetState for ias_ace::Panel {
    fn reset(self) -> Self {
        // The zone table and code are wiped; the panel is disarmed.
        ias_ace::Panel {
            audible: self.audible,
            ready: true,
            ..ias_ace::Panel::default()
        }
    }
}

impl ResetState for commissioning::State {
    fn reset(self) -> Self {
        commissioning::State::default()
    }
}

impl ResetState for hvac::thermostat::Schedule {
    fn reset(self) -> Self {
        // The transitions are wiped, the capacities kept.
        hvac::thermostat::Schedule {
            weekly: self.weekly,
            daily: self.daily,
            dirty: true,
            ..hvac::thermostat::Schedule::default()
        }
    }
}

impl ResetState for power_configuration::MainsDwell {
    fn reset(self) -> Self {
        power_configuration::MainsDwell::default()
    }
}

impl ResetState for configuration::Dwell {
    fn reset(self) -> Self {
        configuration::Dwell::default()
    }
}

impl ResetState for appliance::control::State {
    fn reset(self) -> Self {
        appliance::control::State::default()
    }
}

impl ResetState for appliance::events_alerts::Alerts {
    fn reset(self) -> Self {
        appliance::events_alerts::Alerts::default()
    }
}

impl ResetState for appliance::statistics::LogQueue {
    fn reset(self) -> Self {
        appliance::statistics::LogQueue::default()
    }
}

impl ResetState for direct_configuration::State {
    fn reset(self) -> Self {
        self
    }
}

impl ResetState for rssi_location::State {
    fn reset(self) -> Self {
        // The identity is kept; pending work is dropped.
        rssi_location::State {
            pending_responses: 0,
            requester: None,
            pending_pings: 0,
            collected: heapless::Vec::new(),
            report_at: None,
            next_response: None,
            next_ping: None,
            next_report: None,
            calculated_at: None,
            ..self
        }
    }
}

impl ResetState for power_profile::Profiles {
    fn reset(self) -> Self {
        // The profile slots are kept; forecasts, schedules and
        // constraints are wiped.
        let mut wiped = power_profile::Profiles::default();
        for e in &self.entries {
            let _ = wiped.entries.push(power_profile::Entry {
                phases: heapless::Vec::new(),
                record: power_profile::ProfileRecord {
                    energy_phase: power_profile::NO_PHASE,
                    state: power_profile::state::IDLE,
                    ..e.record
                },
                schedule: heapless::Vec::new(),
                constraints: power_profile::Constraints {
                    id: e.record.id,
                    start_after: 0,
                    stop_before: power_profile::NO_STOP,
                },
            });
        }
        wiped
    }
}
