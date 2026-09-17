//! APS constants (R23.2 §2.2.7.1, Table 2-23) and the scalar attributes of
//! the APS information base (§2.2.7.2, Table 2-24; security attributes
//! §4.4.12, Table 4-35).

use panweave_types::{ChannelMask, ExtendedAddress, time::Duration};

/// APS sub-layer constants (Table 2-23).
pub mod constants {
    use panweave_types::time::Duration;

    /// `apscMaxDescriptorSize`: maximum octets in a non-complex
    /// descriptor.
    pub const MAX_DESCRIPTOR_SIZE: usize = 64;
    /// `apscMaxFrameRetries`.
    pub const MAX_FRAME_RETRIES: u8 = 3;
    /// `apscAckWaitDuration`: 0.05 × (2 × nwkcMaxDepth) + 0.1 s = 1.6 s.
    pub const ACK_WAIT_DURATION: Duration = Duration::from_millis(1600);
    /// `apscMinDuplicateRejectionTableSize`.
    pub const MIN_DUPLICATE_REJECTION_TABLE_SIZE: usize = 1;
    /// `apscMinHeaderOverhead`: minimum octets the APS adds to an ASDU.
    pub const MIN_HEADER_OVERHEAD: usize = 12;
    /// `apsParentAnnounceBaseTimer`.
    pub const PARENT_ANNOUNCE_BASE_TIMER: Duration = Duration::from_secs(10);
    /// `apsParentAnnounceJitterMax`.
    pub const PARENT_ANNOUNCE_JITTER_MAX: Duration = Duration::from_secs(10);
    /// `apscJoinerTLVsUnfragmentedMaxSize`: maximum joiner TLV payload a
    /// parent passes to the Trust Center in an Update Device command.
    pub const JOINER_TLVS_UNFRAGMENTED_MAX_SIZE: usize = 79;
    /// `apscMaxWindowSize`: the stack-wide fragmentation window (window
    /// size 1 is the only interoperable value, §2.2.8.4.5).
    pub const MAX_WINDOW_SIZE: u8 = 1;
    /// `apscInterframeDelay` (unused with window size 1).
    pub const INTERFRAME_DELAY: Duration = Duration::from_millis(0);
    /// Time the receiver of a fragmented transaction waits for the
    /// window to advance: `apscAckWaitDuration × (1 + apscMaxFrameRetries)`
    /// (§2.2.8.4.5.4).
    pub const FRAGMENT_RECEIVE_TIMEOUT: Duration =
        Duration::from_millis(1600 * (1 + MAX_FRAME_RETRIES as u64));
    /// Persistence of a completed reassembly so that a retransmitted last
    /// block is acknowledged again (§2.2.8.4.5.4 recommends
    /// `apscAckWaitDuration`).
    pub const FRAGMENT_PERSISTENCE: Duration = ACK_WAIT_DURATION;
    /// Lifetime of a duplicate rejection entry. The specification requires
    /// "timing information" without a value; the sender's worst case is
    /// `apscAckWaitDuration × (1 + apscMaxFrameRetries)`, so entries live
    /// for that long.
    pub const DUPLICATE_REJECTION_TIMEOUT: Duration = FRAGMENT_RECEIVE_TIMEOUT;
    /// Minimum `apsMaxSizeASDU` every R23 device supports (Table 2-28).
    pub const MIN_MAX_ASDU: usize = 128;
}

/// `apsMaxSizeASDU` as advertised in descriptors.
const MAX_ASDU_U16: u16 = {
    assert!(crate::MAX_ASDU <= u16::MAX as usize);
    #[allow(clippy::cast_possible_truncation)]
    {
        crate::MAX_ASDU as u16
    }
};

/// Scalar AIB attributes. Tables (bindings, groups, key pairs) live in
/// their own modules.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Aib {
    /// `apsDesignatedCoordinator` (0xc2).
    pub designated_coordinator: bool,
    /// `apsChannelMaskList` (0xc3), the page 0 entry.
    pub channel_mask: ChannelMask,
    /// `apsChannelMaskList` (0xc3) entries for other channel pages
    /// (each mask carries its page in the top bits).
    pub channel_mask_pages: heapless::Vec<ChannelMask, 3>,
    /// `apsUseExtendedPANID` (0xc4); zero means "any".
    pub use_extended_pan_id: ExtendedAddress,
    /// `apsUseInsecureJoin` (0xc8).
    pub use_insecure_join: bool,
    /// `apsInterframeDelay` (0xc9) in milliseconds.
    pub interframe_delay_ms: u8,
    /// `apsLastChannelEnergy` (0xca).
    pub last_channel_energy: Option<u8>,
    /// `apsLastChannelFailureRate` (0xcb), percent.
    pub last_channel_failure_rate: Option<u8>,
    /// `apsChannelTimer` (0xcc), hours until the next permitted channel
    /// change; `None` when the channel has never been changed.
    pub channel_timer_hours: Option<u8>,
    /// `apsParentAnnounceTimer` (0xce).
    pub parent_announce_timer: Duration,
    /// `apsZdoRestrictedMode` (0xcf).
    pub zdo_restricted_mode: bool,
    /// `apsMaxSizeASDU` (0xd3).
    pub max_size_asdu: u16,
    /// `apsZdoResponseTimeout` (0xd4) in seconds.
    pub zdo_response_timeout_secs: u8,
    /// `apsApplicationFragmentationSupport` (0xd5).
    pub application_fragmentation_support: bool,
    /// `apsTrustCenterAddress` (0xab); all ones in a distributed
    /// security network.
    pub trust_center_address: ExtendedAddress,
    /// `apsSecurityTimeOutPeriod` (0xac).
    pub security_timeout_period: Duration,
    /// `apsSupportedKeyNegotiationMethods` (0xaf) bitmask (Table I-?
    /// Supported Key Negotiation Methods global TLV). Bit 0 is the Key
    /// Request method and is always set.
    pub supported_key_negotiation_methods: u8,
    /// `apsChallengePeriodTimeoutSeconds` (0xb0).
    pub challenge_period_timeout_secs: u8,
    /// `apsDeviceInterviewTimeoutPeriod` (0xb4) in seconds.
    pub device_interview_timeout_secs: u8,
}

impl Aib {
    /// Sets `apsChannelMaskList` from a Channel List Structure: the
    /// page 0 entry becomes [`Aib::channel_mask`], the others are kept
    /// beside it (at most three).
    pub fn set_channel_mask_list(&mut self, list: &[ChannelMask]) {
        self.channel_mask = ChannelMask(0);
        self.channel_mask_pages.clear();
        for m in list {
            if m.page().0 == 0 {
                self.channel_mask = *m;
            } else {
                let _ = self.channel_mask_pages.push(*m);
            }
        }
    }

    /// The distributed-security marker for `apsTrustCenterAddress`.
    pub const NO_TRUST_CENTER: ExtendedAddress = ExtendedAddress(u64::MAX);

    /// Defaults from Tables 2-24 and 4-35.
    pub const fn new() -> Self {
        Aib {
            designated_coordinator: false,
            channel_mask_pages: heapless::Vec::new(),
            channel_mask: ChannelMask::ALL_2_4GHZ,
            use_extended_pan_id: ExtendedAddress::ZERO,
            use_insecure_join: false,
            interframe_delay_ms: 0,
            last_channel_energy: None,
            last_channel_failure_rate: None,
            channel_timer_hours: None,
            parent_announce_timer: Duration::from_millis(0),
            zdo_restricted_mode: false,
            max_size_asdu: MAX_ASDU_U16,
            zdo_response_timeout_secs: 3,
            application_fragmentation_support: false,
            trust_center_address: Self::NO_TRUST_CENTER,
            security_timeout_period: Duration::from_secs(10),
            supported_key_negotiation_methods: 0x01,
            challenge_period_timeout_secs: 5,
            device_interview_timeout_secs: 12,
        }
    }

    /// True when `apsTrustCenterAddress` denotes a distributed security
    /// network (§4.6.3.2.1).
    #[inline]
    pub const fn is_distributed(&self) -> bool {
        self.trust_center_address.0 == u64::MAX
    }
}

impl Default for Aib {
    fn default() -> Self {
        Self::new()
    }
}
