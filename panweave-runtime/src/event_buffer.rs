//! Bounded event delivery with explicit loss and a fail-closed control
//! boundary. Reconstruct the owner after control loss; draining a gap
//! notification never re-enables protocol progress.

use panweave_types::capacity::{Capacity, DequeLen, DequeOf};

/// Events that drive protocol or security state take precedence over
/// replaceable observations. Unknown event kinds should default to control.
pub trait Prioritized {
    /// Whether losing this event invalidates a consumer's control state.
    fn is_control(&self) -> bool;
}

/// Loss since the last notification. The notification is stored outside
/// the bounded queue, so a full queue cannot hide it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EventLoss {
    /// Replaceable observations discarded or evicted.
    pub telemetry: u32,
    /// Control transitions discarded, including stale transitions purged
    /// when their stream became incomplete.
    pub control: u32,
}

/// One bounded FIFO, with priority admission rather than priority
/// delivery: retained events keep their original order.
pub struct EventBuffer<E: Prioritized, K: Capacity> {
    queue: DequeOf<E, K>,
    loss: EventLoss,
    recovery_needed: bool,
}

impl<E: Prioritized, K: Capacity> Default for EventBuffer<E, K> {
    fn default() -> Self {
        Self {
            queue: K::deque(),
            loss: EventLoss::default(),
            recovery_needed: false,
        }
    }
}

impl<E: Prioritized, K: Capacity> EventBuffer<E, K> {
    /// Returns the number of discarded events. A control-only overflow
    /// discards stale queued transitions and permanently latches recovery.
    pub fn push(&mut self, event: E) -> u32 {
        if self.recovery_needed {
            self.record_loss(&event);
            return 1;
        }
        let event = match self.queue.push_back(event) {
            Ok(()) => return 0,
            Err(event) => event,
        };
        if !event.is_control() {
            self.record_loss(&event);
            return 1;
        }
        let replace = self.queue.iter().position(|queued| !queued.is_control());
        if let Some(index) = replace {
            let count = self.queue.len();
            for position in 0..count {
                let Some(queued) = self.queue.pop_front() else {
                    break;
                };
                if position == index {
                    self.record_loss(&queued);
                } else {
                    // Removing before reinserting always leaves a slot.
                    let _ = self.queue.push_back(queued);
                }
            }
            // One telemetry entry was removed above.
            let _ = self.queue.push_back(event);
            return 1;
        }
        self.recovery_needed = true;
        let mut discarded = 1u32;
        self.record_loss(&event);
        while let Some(queued) = self.queue.pop_front() {
            self.record_loss(&queued);
            discarded = discarded.saturating_add(1);
        }
        discarded
    }

    fn record_loss(&mut self, event: &E) {
        let count = if event.is_control() {
            &mut self.loss.control
        } else {
            &mut self.loss.telemetry
        };
        *count = count.saturating_add(1);
    }

    /// Next retained event in its original order. Owners should deliver
    /// [`Self::take_loss`] before exposing retained observations.
    pub fn pop(&mut self) -> Option<E> {
        self.queue.pop_front()
    }

    /// Takes a latched loss notification without clearing recovery state.
    pub fn take_loss(&mut self) -> Option<EventLoss> {
        if self.loss == EventLoss::default() {
            None
        } else {
            Some(core::mem::take(&mut self.loss))
        }
    }

    /// Whether the owner must stop protocol progress and be reconstructed.
    pub const fn recovery_needed(&self) -> bool {
        self.recovery_needed
    }

    /// Records loss in an upstream stream. Critical loss also invalidates
    /// queued transitions; a consumer must not replay them after the gap.
    /// Returns the total newly discarded or reported event count.
    pub fn observe_loss(&mut self, loss: EventLoss) -> u32 {
        self.loss.telemetry = self.loss.telemetry.saturating_add(loss.telemetry);
        self.loss.control = self.loss.control.saturating_add(loss.control);
        let purged = if loss.control > 0 { self.halt() } else { 0 };
        loss.telemetry
            .saturating_add(loss.control)
            .saturating_add(purged)
    }

    /// Permanently stops admission and purges queued events. The caller
    /// owns the external failure notification that caused this halt.
    pub fn halt(&mut self) -> u32 {
        self.recovery_needed = true;
        let mut discarded = 0u32;
        while let Some(queued) = self.queue.pop_front() {
            self.record_loss(&queued);
            discarded = discarded.saturating_add(1);
        }
        discarded
    }
}

impl Prioritized for crate::StackEvent {
    fn is_control(&self) -> bool {
        // Keep commands, commissioning, persistence and security events
        // conservative: every new kind remains control by default.
        !matches!(
            self,
            Self::ZclReport(_) | Self::LinkPowerDelta { .. } | Self::InterferenceReported { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_types::capacity::Cap;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        Telemetry(u8),
        Control(u8),
    }

    impl Prioritized for Event {
        fn is_control(&self) -> bool {
            matches!(self, Self::Control(_))
        }
    }

    #[test]
    fn control_admission_evicts_oldest_telemetry_without_reordering() {
        let mut buffer = EventBuffer::<Event, Cap<4>>::default();
        for event in [
            Event::Telemetry(1),
            Event::Control(2),
            Event::Telemetry(3),
            Event::Control(4),
        ] {
            assert_eq!(buffer.push(event), 0);
        }
        assert_eq!(buffer.push(Event::Control(5)), 1);
        assert_eq!(buffer.push(Event::Telemetry(6)), 1);
        assert_eq!(
            buffer.take_loss(),
            Some(EventLoss {
                telemetry: 2,
                control: 0
            })
        );
        assert_eq!(buffer.take_loss(), None);
        for event in [
            Event::Control(2),
            Event::Telemetry(3),
            Event::Control(4),
            Event::Control(5),
        ] {
            assert_eq!(buffer.pop(), Some(event));
        }
        assert_eq!(buffer.pop(), None);
        assert!(!buffer.recovery_needed());
    }

    #[test]
    fn control_only_exhaustion_latches_recovery_and_discards_stale_transitions() {
        let mut buffer = EventBuffer::<Event, Cap<2>>::default();
        assert_eq!(buffer.push(Event::Control(1)), 0);
        assert_eq!(buffer.push(Event::Control(2)), 0);
        assert_eq!(buffer.push(Event::Control(3)), 3);
        assert!(buffer.recovery_needed());
        assert_eq!(
            buffer.take_loss(),
            Some(EventLoss {
                telemetry: 0,
                control: 3
            })
        );
        assert_eq!(buffer.pop(), None);
        assert!(
            buffer.recovery_needed(),
            "observing loss must not resume the owner"
        );
        assert_eq!(buffer.push(Event::Control(4)), 1);
        assert_eq!(buffer.push(Event::Telemetry(5)), 1);
        assert_eq!(
            buffer.take_loss(),
            Some(EventLoss {
                telemetry: 1,
                control: 1
            })
        );
        assert_eq!(buffer.pop(), None);
    }

    #[test]
    fn telemetry_cannot_displace_a_full_control_queue() {
        let mut buffer = EventBuffer::<Event, Cap<1>>::default();
        assert_eq!(buffer.push(Event::Control(1)), 0);
        assert_eq!(buffer.push(Event::Telemetry(2)), 1);
        assert_eq!(buffer.pop(), Some(Event::Control(1)));
        assert_eq!(
            buffer.take_loss(),
            Some(EventLoss {
                telemetry: 1,
                control: 0
            })
        );
        assert!(!buffer.recovery_needed());
    }

    #[test]
    fn upstream_control_loss_invalidates_pending_observer_transitions() {
        let mut buffer = EventBuffer::<Event, Cap<2>>::default();
        buffer.push(Event::Control(1));
        buffer.push(Event::Telemetry(2));
        assert_eq!(
            buffer.observe_loss(EventLoss {
                telemetry: 3,
                control: 1
            }),
            6
        );
        assert_eq!(
            buffer.take_loss(),
            Some(EventLoss {
                telemetry: 4,
                control: 2
            })
        );
        assert!(buffer.recovery_needed());
        assert_eq!(buffer.pop(), None);
    }
}
