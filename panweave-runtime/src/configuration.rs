//! Read-only startup configuration and the policies that may change at runtime.

use panweave_security::cipher::BlockCipher;
use panweave_security::trust_center::TrustCenterPolicy;
use panweave_storage::Storage;
use panweave_types::CryptoRng;
use panweave_types::time::Duration;

use crate::profile::StackProfile;
use crate::stack::{Phase, Stack, StackConfig};

/// The runtime polling policy of a sleepy end device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollingPolicy {
    /// Normal data-request interval. Products normally keep this within
    /// the parent's indirect-message retention window.
    pub interval: Duration,
    /// Interval used while waiting for responses.
    pub fast_interval: Duration,
    /// Number of fast polls scheduled after a transmission.
    pub fast_polls: u8,
}

/// A runtime policy update was refused without changing the stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigurationError {
    /// Polling intervals must be at least one millisecond.
    ZeroPollInterval,
}

impl core::fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("polling intervals must be at least one millisecond")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ConfigurationError {}

impl<
    C: BlockCipher,
    R: CryptoRng,
    S: Storage,
    P: StackProfile,
    const E: usize,
    const CL: usize,
    const A: usize,
> Stack<C, R, S, P, E, CL, A>
{
    /// Reads the effective stack settings. Set startup identity and role
    /// before constructing the stack; runtime policies have their own
    /// mutation methods so dependent state stays synchronized.
    ///
    /// ```compile_fail
    /// fn change_role<C: panweave_security::cipher::BlockCipher,
    ///     R: panweave_types::CryptoRng, S: panweave_storage::Storage>(
    ///     stack: &mut panweave_runtime::Stack<C, R, S>) {
    ///     stack.config().role = panweave_types::LogicalDeviceType::Router;
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// fn change_sleep_mode<C: panweave_security::cipher::BlockCipher,
    ///     R: panweave_types::CryptoRng, S: panweave_storage::Storage>(
    ///     stack: &mut panweave_runtime::Stack<C, R, S>) {
    ///     stack.config().sleepy = true;
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// fn change_identity<C: panweave_security::cipher::BlockCipher,
    ///     R: panweave_types::CryptoRng, S: panweave_storage::Storage>(
    ///     stack: &mut panweave_runtime::Stack<C, R, S>) {
    ///     stack.config().ieee = panweave_types::ExtendedAddress(2);
    /// }
    /// ```
    ///
    /// The stored configuration is private as well, so callers cannot
    /// bypass the shared accessor.
    ///
    /// ```compile_fail
    /// fn bypass_accessor<C: panweave_security::cipher::BlockCipher,
    ///     R: panweave_types::CryptoRng, S: panweave_storage::Storage>(
    ///     stack: &mut panweave_runtime::Stack<C, R, S>) {
    ///     stack.config.sleepy = true;
    /// }
    /// ```
    pub const fn config(&self) -> &StackConfig {
        &self.config
    }

    /// Updates Trust Center policy for subsequent admission and key
    /// requests. Existing authorization deadlines and the MAC permit-join
    /// window remain unchanged; use [`Self::permit_join_network`] for the
    /// network's joining window.
    pub fn trust_center_policy_mut(&mut self) -> &mut TrustCenterPolicy {
        &mut self.config.trust_center_policy
    }

    /// Current polling intervals and the after-transmission burst size.
    pub const fn polling_policy(&self) -> PollingPolicy {
        PollingPolicy {
            interval: self.config.poll_interval,
            fast_interval: self.config.fast_poll_interval,
            fast_polls: self.config.fast_polls,
        }
    }

    /// Changes polling intervals and reschedules the next poll of an
    /// operating sleepy end device. Poll Control fast mode retains its
    /// negotiated interval; an already scheduled burst is bounded by the
    /// new burst size. Zero intervals leave the policy and timer unchanged.
    pub fn set_polling_policy(&mut self, policy: PollingPolicy) -> Result<(), ConfigurationError> {
        if policy.interval.as_millis() == 0 || policy.fast_interval.as_millis() == 0 {
            return Err(ConfigurationError::ZeroPollInterval);
        }
        self.config.poll_interval = policy.interval;
        self.config.fast_poll_interval = policy.fast_interval;
        self.config.fast_polls = policy.fast_polls;
        self.fast_polls_left = self.fast_polls_left.min(policy.fast_polls);
        if self.config.sleepy && matches!(self.phase, Phase::Operating | Phase::AwaitingKey) {
            let interval = if self.fast_polls_left > 0 {
                policy.fast_interval
            } else if let Some(interval) = self.fast_poll_mode {
                interval
            } else if self.fast_polling {
                policy.fast_interval
            } else {
                policy.interval
            };
            self.next_poll = Some(self.now.saturating_add(interval));
        }
        Ok(())
    }
}
