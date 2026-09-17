//! Sub-GHz cluster (SE 1.4a Annex D.14): the channel-mask attributes of
//! pages 28–31, the Suspend ZCL Messages / Get Suspend ZCL Messages
//! Status commands and a client-side [`Suspension`] that blocks ZCL
//! traffic to the server for the announced period.
//!
//! Sub-GHz radio operation itself (the 863–876 MHz and 915–921 MHz
//! pages, duty-cycle limits) needs a matching PHY and is outside this
//! crate; the cluster is exposed so a Trust Center or BOMD can carry
//! the coordination messages.

use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{ClusterId, CommandId};
use panweave_zcl::attribute::{Access, AttributeDef};
use panweave_zcl::cluster::ClusterDef;
use panweave_zcl::types::DataType;

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x070B);

/// `ChannelChange`: the channel (bits 0–26) and page (bits 27–31) the
/// network manager intends to move to.
pub const CHANNEL_CHANGE: AttributeDef = AttributeDef::new(0x0000, DataType::Bitmap(4), Access::RO);
/// `Page28ChannelMask` (863 MHz channels 0–26).
pub const PAGE_28_CHANNEL_MASK: AttributeDef =
    AttributeDef::new(0x0001, DataType::Bitmap(4), Access::RO);
/// `Page29ChannelMask` (863 MHz channels 27–34 and 62).
pub const PAGE_29_CHANNEL_MASK: AttributeDef =
    AttributeDef::new(0x0002, DataType::Bitmap(4), Access::RO);
/// `Page30ChannelMask` (863 MHz channels 35–61).
pub const PAGE_30_CHANNEL_MASK: AttributeDef =
    AttributeDef::new(0x0003, DataType::Bitmap(4), Access::RO);
/// `Page31ChannelMask` (915 MHz channels 0–26).
pub const PAGE_31_CHANNEL_MASK: AttributeDef =
    AttributeDef::new(0x0004, DataType::Bitmap(4), Access::RO);

/// Default `Page28ChannelMask`: every channel.
pub const DEFAULT_PAGE_28_MASK: u32 = 0xE7FF_FFFF;
/// Default `Page29ChannelMask`.
pub const DEFAULT_PAGE_29_MASK: u32 = 0xE800_01FF;
/// Default `Page30ChannelMask`.
pub const DEFAULT_PAGE_30_MASK: u32 = 0xF7FF_FFFF;
/// Default `Page31ChannelMask`.
pub const DEFAULT_PAGE_31_MASK: u32 = 0xFFFF_FFFF;

/// Server → client: SuspendZclMessages.
pub const CMD_SUSPEND_ZCL_MESSAGES: CommandId = CommandId(0x00);
/// Client → server: GetSuspendZclMessagesStatus (no payload).
pub const CMD_GET_SUSPEND_ZCL_MESSAGES_STATUS: CommandId = CommandId(0x00);

/// Server cluster definition.
pub const SERVER_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[CMD_GET_SUSPEND_ZCL_MESSAGES_STATUS],
    generated: &[CMD_SUSPEND_ZCL_MESSAGES],
};

/// Client cluster definition.
pub const CLIENT_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: SERVER_DEF.generated,
    generated: SERVER_DEF.received,
};

/// Builds a page channel mask attribute value from a page (28–31) and
/// the channel bits (bits 0–26).
pub const fn channel_mask(page: u8, channels: u32) -> u32 {
    ((page as u32 & 0x1f) << 27) | (channels & 0x07ff_ffff)
}

/// Splits a channel mask attribute value into its page and channel
/// bits.
pub const fn split_channel_mask(mask: u32) -> (u8, u32) {
    ((mask >> 27) as u8, mask & 0x07ff_ffff)
}

/// SuspendZclMessages (D.14.2.3.1): minutes to suspend, 0 when not
/// suspended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SuspendZclMessages {
    /// Suspension period in minutes.
    pub minutes: u8,
}

impl SuspendZclMessages {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(SuspendZclMessages { minutes: r.u8()? })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.minutes)
    }
}

/// Client-side suspension state towards one server (D.14.2.3.1.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Suspension {
    until: Option<u32>,
}

impl Suspension {
    /// Not suspended.
    pub const fn new() -> Self {
        Suspension { until: None }
    }

    /// Applies a SuspendZclMessages received at `now` (seconds).
    pub fn apply(&mut self, cmd: &SuspendZclMessages, now: u32) {
        self.until = if cmd.minutes == 0 {
            None
        } else {
            Some(now.saturating_add(u32::from(cmd.minutes) * 60))
        };
    }

    /// Whether ZCL traffic to the server must be held at `now`.
    pub fn is_suspended(&self, now: u32) -> bool {
        self.until.is_some_and(|t| now < t)
    }

    /// When normal operation may resume, while suspended.
    pub fn resumes_at(&self, now: u32) -> Option<u32> {
        self.until.filter(|t| now < *t)
    }

    /// The remaining period as the server would report it, rounded up
    /// to whole minutes.
    pub fn remaining_minutes(&self, now: u32) -> u8 {
        self.resumes_at(now).map_or(0, |t| {
            u8::try_from((t - now).div_ceil(60)).unwrap_or(u8::MAX)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_and_codec() {
        assert_eq!(split_channel_mask(DEFAULT_PAGE_28_MASK), (28, 0x07ff_ffff));
        assert_eq!(split_channel_mask(DEFAULT_PAGE_29_MASK), (29, 0x1ff));
        assert_eq!(split_channel_mask(DEFAULT_PAGE_30_MASK), (30, 0x07ff_ffff));
        assert_eq!(split_channel_mask(DEFAULT_PAGE_31_MASK), (31, 0x07ff_ffff));
        assert_eq!(channel_mask(29, 0x1ff), DEFAULT_PAGE_29_MASK);
        let mut buf = [0u8; 1];
        let mut w = Writer::new(&mut buf);
        SuspendZclMessages { minutes: 5 }.encode(&mut w).unwrap();
        assert_eq!(SuspendZclMessages::parse(&buf).unwrap().minutes, 5);
        assert!(SuspendZclMessages::parse(&[]).is_err());
    }

    #[test]
    fn suspension_holds_traffic_for_the_period() {
        let mut s = Suspension::new();
        assert!(!s.is_suspended(0));
        s.apply(&SuspendZclMessages { minutes: 2 }, 100);
        assert!(s.is_suspended(100));
        assert!(s.is_suspended(219));
        assert!(!s.is_suspended(220));
        assert_eq!(s.resumes_at(100), Some(220));
        assert_eq!(s.remaining_minutes(100), 2);
        assert_eq!(s.remaining_minutes(161), 1);
        assert_eq!(s.remaining_minutes(220), 0);
        s.apply(&SuspendZclMessages { minutes: 0 }, 150);
        assert!(!s.is_suspended(150));
    }
}
