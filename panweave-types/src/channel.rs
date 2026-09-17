//! Channel pages, channel numbers and channel masks.
//!
//! Spec: R23.2 §3.2.2.2 (ScanChannels), BDB3.1 §5.1 (primary/secondary
//! channel sets), R23.2 Annex D.12–D.14 (sub-GHz pages).

use core::fmt;

/// An IEEE 802.15.4 channel page.
///
/// Page 0 is the 2.4 GHz O-QPSK band used by Zigbee PRO. Other pages exist
/// for sub-GHz PHYs (R23.2 Annex D.12–D.14) and are carried but not
/// otherwise interpreted by the core stack.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ChannelPage(pub u8);

impl ChannelPage {
    /// The 2.4 GHz page.
    pub const PAGE_0: ChannelPage = ChannelPage(0);

    /// Returns the raw page number.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }
}

impl fmt::Debug for ChannelPage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChannelPage({})", self.0)
    }
}

crate::impl_defmt_via_debug!(ChannelPage);

/// A logical channel number.
///
/// On page 0 the valid Zigbee channels are `11..=26`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Channel(u8);

impl Channel {
    /// Lowest 2.4 GHz channel.
    pub const MIN_2_4GHZ: u8 = 11;
    /// Highest 2.4 GHz channel.
    pub const MAX_2_4GHZ: u8 = 26;

    /// Builds a channel, accepting any value `0..=31` (the range a 32-bit
    /// channel mask can express). Returns `None` otherwise.
    #[inline]
    pub const fn new(n: u8) -> Option<Channel> {
        if n <= 31 { Some(Channel(n)) } else { None }
    }

    /// Builds a 2.4 GHz channel (`11..=26`).
    #[inline]
    pub const fn new_2_4ghz(n: u8) -> Option<Channel> {
        if n >= Self::MIN_2_4GHZ && n <= Self::MAX_2_4GHZ {
            Some(Channel(n))
        } else {
            None
        }
    }

    /// Returns the raw channel number.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// True for a 2.4 GHz channel.
    #[inline]
    pub const fn is_2_4ghz(self) -> bool {
        self.0 >= Self::MIN_2_4GHZ && self.0 <= Self::MAX_2_4GHZ
    }
}

impl fmt::Debug for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Channel({})", self.0)
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

crate::impl_defmt_via_debug!(Channel);

/// A 32-bit channel mask; bit `n` selects channel `n`.
///
/// The top 5 bits are a channel page in the ZDP Mgmt_NWK_Update and
/// Enhanced Update encodings; helper methods below operate on the plain
/// 27-bit channel portion. Page handling is explicit via
/// [`ChannelMask::with_page`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ChannelMask(pub u32);

impl ChannelMask {
    /// All 2.4 GHz channels `11..=26`.
    pub const ALL_2_4GHZ: ChannelMask = ChannelMask(0x07FF_F800);
    /// BDB 3.1 primary channel set on page 0: channels 11, 15, 20, 25
    /// (BDB3.1 §5.1, `bdbcTLPrimaryChannelSet` / primary steering set).
    pub const BDB_PRIMARY: ChannelMask = ChannelMask(0x0210_8800);
    /// BDB 3.1 secondary channel set on page 0: the remaining 2.4 GHz
    /// channels.
    pub const BDB_SECONDARY: ChannelMask = ChannelMask(0x07FF_F800 & !0x0210_8800);
    /// Empty mask.
    pub const EMPTY: ChannelMask = ChannelMask(0);

    const CHANNEL_BITS: u32 = 0x07FF_FFFF;

    /// Returns the raw value.
    #[inline]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Mask with only the channel bits (page bits cleared).
    #[inline]
    pub const fn channels_only(self) -> ChannelMask {
        ChannelMask(self.0 & Self::CHANNEL_BITS)
    }

    /// Page encoded in the top 5 bits (ZDP encoding).
    #[inline]
    pub const fn page(self) -> ChannelPage {
        // The shift leaves at most 5 significant bits, so the narrowing is
        // lossless.
        #[allow(clippy::cast_possible_truncation)]
        ChannelPage((self.0 >> 27) as u8)
    }

    /// Returns a copy with the page bits set.
    #[inline]
    pub const fn with_page(self, page: ChannelPage) -> ChannelMask {
        ChannelMask((self.0 & Self::CHANNEL_BITS) | ((page.0 as u32 & 0x1F) << 27))
    }

    /// True when channel `c` is selected.
    #[inline]
    pub const fn contains(self, c: Channel) -> bool {
        self.0 & (1u32 << c.0) != 0
    }

    /// Returns a copy with channel `c` added.
    #[inline]
    pub const fn with(self, c: Channel) -> ChannelMask {
        ChannelMask(self.0 | (1u32 << c.0))
    }

    /// Returns a copy with channel `c` removed.
    #[inline]
    pub const fn without(self, c: Channel) -> ChannelMask {
        ChannelMask(self.0 & !(1u32 << c.0))
    }

    /// True when no channel is selected.
    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 & Self::CHANNEL_BITS == 0
    }

    /// Number of selected channels.
    #[inline]
    pub const fn len(self) -> u32 {
        (self.0 & Self::CHANNEL_BITS).count_ones()
    }

    /// Iterates selected channels in ascending order.
    pub fn iter(self) -> impl Iterator<Item = Channel> {
        let bits = self.0 & Self::CHANNEL_BITS;
        (0u8..27)
            .filter(move |n| bits & (1u32 << n) != 0)
            .map(Channel)
    }

    /// The lowest selected channel, if any.
    pub fn first(self) -> Option<Channel> {
        self.iter().next()
    }

    /// Intersection.
    #[inline]
    pub const fn and(self, other: ChannelMask) -> ChannelMask {
        ChannelMask(self.0 & other.0)
    }

    /// Union.
    #[inline]
    pub const fn or(self, other: ChannelMask) -> ChannelMask {
        ChannelMask(self.0 | other.0)
    }
}

impl fmt::Debug for ChannelMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChannelMask(0x{:08x})", self.0)
    }
}

crate::impl_defmt_via_debug!(ChannelMask);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_construction() {
        assert_eq!(Channel::new_2_4ghz(11).map(Channel::raw), Some(11));
        assert_eq!(Channel::new_2_4ghz(26).map(Channel::raw), Some(26));
        assert!(Channel::new_2_4ghz(10).is_none());
        assert!(Channel::new_2_4ghz(27).is_none());
        assert!(Channel::new(31).is_some());
        assert!(Channel::new(32).is_none());
    }

    #[test]
    fn bdb_channel_sets_partition_2_4ghz() {
        let p = ChannelMask::BDB_PRIMARY;
        let s = ChannelMask::BDB_SECONDARY;
        assert_eq!(p.or(s), ChannelMask::ALL_2_4GHZ);
        assert!(p.and(s).is_empty());
        let primary: [u8; 4] = [11, 15, 20, 25];
        for c in primary {
            assert!(p.contains(Channel(c)));
        }
        assert_eq!(p.len(), 4);
        assert_eq!(s.len(), 12);
        assert_eq!(ChannelMask::ALL_2_4GHZ.first(), Some(Channel(11)));
    }

    #[test]
    fn page_bits_round_trip() {
        let m = ChannelMask::ALL_2_4GHZ.with_page(ChannelPage(28));
        assert_eq!(m.page(), ChannelPage(28));
        assert_eq!(m.channels_only(), ChannelMask::ALL_2_4GHZ);
        assert_eq!(m.iter().count(), 16);
    }
}
