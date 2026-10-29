//! Low-power operation of a sleepy sensor.
//!
//! The stack is sans-I/O: it never sleeps or busy-waits itself. After
//! every input (a radio frame, a transmission completing, a GPIO edge,
//! a deadline) the platform drains the radio actions and asks
//! [`plan`] how it may sleep. The plan names the next protocol deadline
//! (poll the parent, retransmit, report, a commissioning timeout) and the
//! deepest [`SleepMode`] that keeps the protocol correct:
//!
//! * [`SleepMode::Awake`]: a transmission is queued or the receiver must
//!   stay on (a data poll waits for its frame); do not sleep.
//! * [`SleepMode::RamRetained`]: CPU and radio off, RAM and the RTC kept
//!   (EFR32 EM2). All protocol state survives; wake at `until` or on a
//!   sensor GPIO.
//! * [`SleepMode::Off`]: RAM may be lost (EFR32 EM4, or power removed).
//!   Only offered when the device is not on a network and has nothing
//!   to do: there is no protocol deadline to keep, and what a later
//!   commissioning needs is in storage. Waking from it is a reset: the
//!   firmware builds a new [`crate::LiteDevice`] and calls
//!   [`crate::LiteDevice::initialize`], which restores the network,
//!   keys, frame counters and IAS enrolment from storage and rejoins.
//!
//! Waking from RAM-retained sleep needs no restoration: the platform
//! passes the RTC time to [`crate::LiteDevice::poll`] (time must be
//! monotonic across sleep; the stack compares instants, so the RTC must
//! not be reset while RAM is retained). A sensor GPIO edge is delivered
//! with [`crate::LiteDevice::set_inputs`] before polling, which notifies
//! the CIE at once instead of at the next routine report.
//!
//! [`EnergyModel`] estimates the average current of a configuration for
//! battery-life planning; its figures are inputs, not measurements.

use panweave_types::time::{Duration, Instant};

/// How deeply the platform may sleep (see the module documentation).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SleepMode {
    /// Keep running (radio activity in progress).
    Awake,
    /// CPU and radio off, RAM and RTC retained.
    RamRetained,
    /// RAM may be lost: a wake is a reset.
    Off,
}

/// What the platform should do until the next input.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SleepPlan {
    /// The deepest allowed mode.
    pub mode: SleepMode,
    /// Wake no later than this (the next protocol deadline); `None`
    /// when only an external event (GPIO, button) needs to wake it.
    pub until: Option<Instant>,
    /// The radio receiver must stay on.
    pub receiver: bool,
}

/// The state [`plan`] decides from (what [`crate::LiteDevice`] reports).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Activity {
    /// The current time.
    pub now: Instant,
    /// The next protocol or application deadline.
    pub deadline: Option<Instant>,
    /// Radio actions are queued.
    pub radio_busy: bool,
    /// The receiver must stay on (routers never sleep; a sleepy device
    /// waiting for indirect data after a poll).
    pub receiver: bool,
    /// The device is on a network or (re)joining it.
    pub on_network: bool,
    /// A commissioning procedure runs.
    pub commissioning: bool,
}

/// Sleep shorter than this is not worth entering (wake-up and
/// clock-restart costs); the platform idles instead.
pub const MIN_SLEEP: Duration = Duration::from_millis(2);

/// The sleep plan for `a`.
pub fn plan(a: &Activity) -> SleepPlan {
    if a.radio_busy || a.receiver {
        return SleepPlan {
            mode: SleepMode::Awake,
            until: a.deadline,
            receiver: a.receiver,
        };
    }
    if let Some(d) = a.deadline
        && d.saturating_duration_since(a.now).as_millis() < MIN_SLEEP.as_millis()
    {
        return SleepPlan {
            mode: SleepMode::Awake,
            until: Some(d),
            receiver: false,
        };
    }
    let off = !a.on_network && !a.commissioning && a.deadline.is_none();
    SleepPlan {
        mode: if off {
            SleepMode::Off
        } else {
            SleepMode::RamRetained
        },
        until: a.deadline,
        receiver: false,
    }
}

/// The platform below a Lite device (the board support of a product).
/// Implementations are hardware specific; the trait fixes what the
/// device logic relies on.
pub trait Platform {
    /// Monotonic time, continuous across RAM-retained sleep.
    fn now(&self) -> Instant;
    /// Enters `plan.mode` until `plan.until` or a wake-up source (sensor
    /// GPIO, button, radio interrupt while the receiver is on) and
    /// returns what woke it. [`SleepMode::Off`] does not return on
    /// hardware that resets on wake.
    fn sleep(&mut self, plan: &SleepPlan) -> Wake;
}

/// Why the platform woke.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Wake {
    /// The deadline passed.
    Deadline,
    /// A sensor input changed (read the inputs and call
    /// [`crate::LiteDevice::set_inputs`]).
    Input,
    /// The radio has an event (frame received, transmission done).
    Radio,
}

/// Inputs of a battery estimate (datasheet or measured figures; nothing
/// here is a measurement of a Panweave device).
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct EnergyModel {
    /// Sleep current with RAM retention and the RTC, µA.
    pub sleep_ua: f32,
    /// Average current while awake with the radio receiving, mA.
    pub rx_ma: f32,
    /// Average current while transmitting, mA.
    pub tx_ma: f32,
    /// Awake time of one data poll without pending data (wake, CSMA,
    /// data request, acknowledgement, short receive window), ms.
    pub poll_ms: f32,
    /// Of which transmitting, ms.
    pub poll_tx_ms: f32,
    /// Awake time of one acknowledged report (frame, APS ack through the
    /// parent, fast polls), ms.
    pub report_ms: f32,
    /// Of which transmitting, ms.
    pub report_tx_ms: f32,
}

impl EnergyModel {
    /// Average current in µA for one data poll every `poll_interval` and
    /// `reports_per_day` acknowledged reports.
    pub fn average_ua(&self, poll_interval: Duration, reports_per_day: f32) -> f32 {
        const DAY_MS: f32 = 86_400_000.0;
        #[allow(clippy::cast_precision_loss)]
        let polls = DAY_MS / (poll_interval.as_millis().max(1) as f32);
        let charge = |ms: f32, tx_ms: f32| (ms - tx_ms) * self.rx_ma + tx_ms * self.tx_ma;
        // mA·ms per day.
        let active = polls * charge(self.poll_ms, self.poll_tx_ms)
            + reports_per_day * charge(self.report_ms, self.report_tx_ms);
        let awake_ms = polls * self.poll_ms + reports_per_day * self.report_ms;
        let asleep_ms = (DAY_MS - awake_ms).max(0.0);
        // Average over the day, µA.
        (active * 1000.0 + asleep_ms * self.sleep_ua) / DAY_MS
    }

    /// Battery life in days for `capacity_mah` (no self-discharge or
    /// pulse-current derating: apply those to `capacity_mah`).
    pub fn days(&self, capacity_mah: f32, poll_interval: Duration, reports_per_day: f32) -> f32 {
        let ua = self.average_ua(poll_interval, reports_per_day);
        if ua <= 0.0 {
            return f32::INFINITY;
        }
        capacity_mah * 1000.0 / ua / 24.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn activity() -> Activity {
        Activity {
            now: Instant::from_millis(1000),
            deadline: Some(Instant::from_millis(8000)),
            radio_busy: false,
            receiver: false,
            on_network: true,
            commissioning: false,
        }
    }

    #[test]
    fn plans_follow_the_activity() {
        let a = activity();
        assert_eq!(
            plan(&a),
            SleepPlan {
                mode: SleepMode::RamRetained,
                until: Some(Instant::from_millis(8000)),
                receiver: false
            }
        );
        assert_eq!(
            plan(&Activity {
                receiver: true,
                ..a
            })
            .mode,
            SleepMode::Awake
        );
        assert_eq!(
            plan(&Activity {
                radio_busy: true,
                ..a
            })
            .mode,
            SleepMode::Awake
        );
        assert_eq!(
            plan(&Activity {
                deadline: Some(Instant::from_millis(1001)),
                ..a
            })
            .mode,
            SleepMode::Awake
        );
        // Off the network with nothing to do: RAM may go.
        let idle = Activity {
            on_network: false,
            deadline: None,
            ..a
        };
        assert_eq!(plan(&idle).mode, SleepMode::Off);
        // Commissioning keeps RAM.
        assert_eq!(
            plan(&Activity {
                commissioning: true,
                ..idle
            })
            .mode,
            SleepMode::RamRetained
        );
    }

    #[test]
    fn energy_model_is_dominated_by_polling() {
        let m = EnergyModel {
            sleep_ua: 1.5,
            rx_ma: 4.5,
            tx_ma: 4.5,
            poll_ms: 3.0,
            poll_tx_ms: 0.5,
            report_ms: 40.0,
            report_tx_ms: 2.0,
        };
        let fast = m.average_ua(Duration::from_secs(1), 24.0);
        let slow = m.average_ua(Duration::from_secs(60), 24.0);
        assert!(fast > 5.0 * slow, "{fast} vs {slow}");
        assert!(slow > m.sleep_ua);
        let days = m.days(220.0, Duration::from_secs(60), 24.0);
        assert!(days > 365.0, "{days}");
    }
}
