//! Network restoration at boot, after the first attempt.
//!
//! [`NetworkRestore::decide`] settles the first boot attempt. When the
//! stack's storage could not be read at all ([`NetworkRestore::ReadFailed`])
//! the failure may be transient (a flash glitch): [`RestoreRetry`] tries
//! again, read-only, with a growing interval, and brings the stored
//! network back when a later read succeeds. It never forms a network: a
//! storage that failed and later reads *empty* is not trusted to be
//! factory new, so the hub stays without a network until an operator
//! decides (a deliberate factory reset). Other outcomes are not retried —
//! damaged or unusable records do not heal by being read again.

use crate::protocol::{NetworkRestore, StoredNetwork};

/// First retry this long after the failed boot attempt.
pub const RESTORE_RETRY_FIRST_MS: u64 = 10_000;
/// Longest interval between retries.
pub const RESTORE_RETRY_MAX_MS: u64 = 300_000;

/// What a retry led to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RetryOutcome {
    /// The stored network was read: resume it.
    Restored,
    /// Still unreadable: the next retry is scheduled.
    Retrying,
    /// Readable now but not usable as the network: stop retrying and stay
    /// without a network, reporting this outcome.
    GaveUp(NetworkRestore),
}

/// Retries of an unreadable stack storage.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RestoreRetry {
    next_ms: Option<u64>,
    interval_ms: u64,
    attempts: u32,
}

impl RestoreRetry {
    /// Retries after a boot whose outcome was `outcome` (only
    /// [`NetworkRestore::ReadFailed`] is retried).
    pub const fn after_boot(outcome: NetworkRestore, now_ms: u64) -> Self {
        let armed = matches!(outcome, NetworkRestore::ReadFailed);
        RestoreRetry {
            next_ms: if armed {
                Some(now_ms.saturating_add(RESTORE_RETRY_FIRST_MS))
            } else {
                None
            },
            interval_ms: RESTORE_RETRY_FIRST_MS,
            attempts: 0,
        }
    }

    /// Whether a retry is due at `now_ms`.
    pub const fn due(&self, now_ms: u64) -> bool {
        match self.next_ms {
            Some(t) => now_ms >= t,
            None => false,
        }
    }

    /// Whether retries continue.
    pub const fn active(&self) -> bool {
        self.next_ms.is_some()
    }

    /// Retries made so far.
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Records the result of a retry made at `now_ms`.
    pub fn on_attempt(&mut self, now_ms: u64, stored: StoredNetwork) -> RetryOutcome {
        self.attempts = self.attempts.saturating_add(1);
        match stored {
            StoredNetwork::Present => {
                self.next_ms = None;
                RetryOutcome::Restored
            }
            StoredNetwork::Unreadable => {
                self.interval_ms = self.interval_ms.saturating_mul(2).min(RESTORE_RETRY_MAX_MS);
                self.next_ms = Some(now_ms.saturating_add(self.interval_ms));
                RetryOutcome::Retrying
            }
            StoredNetwork::Empty => {
                self.next_ms = None;
                RetryOutcome::GaveUp(NetworkRestore::ReadFailed)
            }
            StoredNetwork::Unusable => {
                self.next_ms = None;
                RetryOutcome::GaveUp(NetworkRestore::StoredUnusable)
            }
        }
    }
}

/// What a stack restore found, for [`NetworkRestore::decide`] and
/// [`RestoreRetry`].
#[cfg(feature = "engine")]
pub fn stored_network(
    result: Result<panweave_runtime::Restored, panweave_storage::StorageError>,
    detail: panweave_runtime::RestoreDetail,
) -> StoredNetwork {
    use panweave_runtime::{RestoreDetail, Restored};
    match result {
        Err(_) => StoredNetwork::Unreadable,
        Ok(Restored::OnNetwork) => StoredNetwork::Present,
        Ok(Restored::FactoryNew) if detail == RestoreDetail::Empty => StoredNetwork::Empty,
        Ok(Restored::FactoryNew) => StoredNetwork::Unusable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_read_failures_are_retried_with_backoff() {
        assert!(!RestoreRetry::after_boot(NetworkRestore::Restored, 0).active());
        assert!(!RestoreRetry::after_boot(NetworkRestore::CorruptNotFormed, 0).active());
        let mut r = RestoreRetry::after_boot(NetworkRestore::ReadFailed, 1000);
        assert!(!r.due(10_999));
        assert!(r.due(11_000));
        assert_eq!(
            r.on_attempt(11_000, StoredNetwork::Unreadable),
            RetryOutcome::Retrying
        );
        assert!(!r.due(30_999));
        assert!(r.due(31_000), "20 s later");
        let mut t = 31_000;
        for _ in 0..10 {
            assert_eq!(
                r.on_attempt(t, StoredNetwork::Unreadable),
                RetryOutcome::Retrying
            );
            t += RESTORE_RETRY_MAX_MS;
            assert!(r.due(t), "never longer than the maximum");
        }
        assert_eq!(
            r.on_attempt(t, StoredNetwork::Present),
            RetryOutcome::Restored
        );
        assert!(!r.active());
        assert_eq!(r.attempts(), 12);
    }

    #[test]
    fn a_failed_store_that_reads_empty_later_is_not_trusted() {
        let mut r = RestoreRetry::after_boot(NetworkRestore::ReadFailed, 0);
        assert_eq!(
            r.on_attempt(10_000, StoredNetwork::Empty),
            RetryOutcome::GaveUp(NetworkRestore::ReadFailed)
        );
        assert!(!r.active());
        let mut r = RestoreRetry::after_boot(NetworkRestore::ReadFailed, 0);
        assert_eq!(
            r.on_attempt(10_000, StoredNetwork::Unusable),
            RetryOutcome::GaveUp(NetworkRestore::StoredUnusable)
        );
    }

    #[cfg(feature = "engine")]
    #[test]
    fn restore_results_map_to_what_was_stored() {
        use panweave_runtime::{RestoreDetail, Restored};
        use panweave_storage::StorageError;
        assert_eq!(
            stored_network(Err(StorageError::Io), RestoreDetail::NotRun),
            StoredNetwork::Unreadable
        );
        assert_eq!(
            stored_network(Ok(Restored::OnNetwork), RestoreDetail::Restored),
            StoredNetwork::Present
        );
        assert_eq!(
            stored_network(Ok(Restored::FactoryNew), RestoreDetail::Empty),
            StoredNetwork::Empty
        );
        for d in [
            RestoreDetail::Incomplete,
            RestoreDetail::UnknownFormat,
            RestoreDetail::Malformed,
        ] {
            assert_eq!(
                stored_network(Ok(Restored::FactoryNew), d),
                StoredNetwork::Unusable
            );
        }
    }
}
