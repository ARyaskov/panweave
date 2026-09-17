//! Discovery table (R23.2 §3.6.1.6.1.4, Table 3-74) and parent ranking
//! (§3.6.1.5.2).

use heapless::Vec;
use panweave_types::{Channel, ChannelPage, ExtendedAddress, PanId, ShortAddress};

use crate::tlv::RouterInformation;

/// Maximum beacon appendix bytes retained per candidate.
pub const MAX_APPENDIX: usize = 24;

/// A potential parent / network learnt from a beacon.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Candidate {
    /// Extended PAN identifier.
    pub extended_pan_id: ExtendedAddress,
    /// PAN identifier.
    pub pan_id: PanId,
    /// Channel page.
    pub page: ChannelPage,
    /// Logical channel.
    pub channel: Channel,
    /// Short address of the potential parent.
    pub short: ShortAddress,
    /// Extended address of the potential parent, if the beacon source
    /// used extended addressing (rare) or is otherwise known.
    pub extended: Option<ExtendedAddress>,
    /// LQA/LQI of the beacon.
    pub lqa: u8,
    /// `nwkUpdateId` advertised.
    pub update_id: u8,
    /// Router capacity advertised.
    pub router_capacity: bool,
    /// End device capacity advertised.
    pub end_device_capacity: bool,
    /// Association permit from the MAC superframe specification.
    pub permit_joining: bool,
    /// The beacon source is the PAN coordinator.
    pub pan_coordinator: bool,
    /// Router Information TLV from the beacon appendix, if any.
    pub router_info: Option<RouterInformation>,
    /// True when the beacon carried an R23 appendix (Network Commissioning
    /// attach mechanism available).
    pub r23: bool,
    /// Raw beacon appendix bytes (truncated to [`MAX_APPENDIX`]).
    pub appendix: Vec<u8, MAX_APPENDIX>,
    /// Number of join attempts already made to this candidate.
    pub attempts: u8,
}

impl Candidate {
    /// Ranking key per §3.6.1.5.2: higher is better. Tie-breaking beyond
    /// the listed criteria uses LQA.
    ///
    /// * hub connectivity
    /// * preferred parent
    /// * long uptime
    /// * newest update id (relative to `current_update_id`, with wrap)
    /// * current parent when rejoining (`current_parent`)
    pub fn rank(&self, current_update_id: u8, current_parent: Option<ShortAddress>) -> u32 {
        let ri = self.router_info.unwrap_or_default();
        let hub = u32::from(ri.hub_connectivity());
        let preferred = u32::from(ri.preferred_parent());
        let uptime = u32::from(ri.long_uptime());
        // Newest update id: distance ahead of the current value (0..=127
        // counts as newer); map so larger is better.
        let delta = self.update_id.wrapping_sub(current_update_id);
        let newest = if delta < 0x80 { u32::from(delta) } else { 0 };
        let is_parent = u32::from(current_parent == Some(self.short));
        (hub << 28)
            | (preferred << 27)
            | (uptime << 26)
            | (newest << 18)
            | (is_parent << 17)
            | u32::from(self.lqa)
    }
}

/// Fixed-capacity discovery table.
#[derive(Clone, Debug, Default)]
pub struct DiscoveryTable<const N: usize> {
    entries: Vec<Candidate, N>,
}

impl<const N: usize> DiscoveryTable<N> {
    /// Empty table.
    pub const fn new() -> Self {
        DiscoveryTable {
            entries: Vec::new(),
        }
    }

    /// Adds or updates a candidate (keyed by PAN ID, channel and short
    /// address). When full, the lowest-ranked candidate is replaced if
    /// the new one ranks higher (§3.6.1.5.2).
    pub fn add(
        &mut self,
        c: Candidate,
        current_update_id: u8,
        current_parent: Option<ShortAddress>,
    ) {
        if let Some(e) = self
            .entries
            .iter_mut()
            .find(|e| e.pan_id == c.pan_id && e.channel == c.channel && e.short == c.short)
        {
            let attempts = e.attempts;
            *e = c;
            e.attempts = attempts;
            return;
        }
        if self.entries.is_full() {
            let new_rank = c.rank(current_update_id, current_parent);
            let (idx, worst) = match self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.rank(current_update_id, current_parent))
            {
                Some((i, e)) => (i, e.rank(current_update_id, current_parent)),
                None => return,
            };
            if new_rank > worst {
                self.entries[idx] = c;
            }
            return;
        }
        let _ = self.entries.push(c);
    }

    /// Candidates for `extended_pan_id` (or any when `None`) that permit
    /// joining and have the required capacity, best first; `good_only`
    /// restricts to candidates whose LQA is at least `good_lqa`
    /// (§3.6.1.5.2 two-pass rule).
    pub fn ranked<'a>(
        &'a self,
        extended_pan_id: Option<ExtendedAddress>,
        as_router: bool,
        require_permit: bool,
        good_lqa: u8,
        good_only: bool,
        current_update_id: u8,
        current_parent: Option<ShortAddress>,
        max_attempts: u8,
        out: &mut Vec<usize, N>,
    ) {
        out.clear();
        let mut idx: Vec<usize, N> = Vec::new();
        for (i, c) in self.entries.iter().enumerate() {
            if let Some(e) = extended_pan_id
                && c.extended_pan_id != e
            {
                continue;
            }
            if require_permit && !c.permit_joining {
                continue;
            }
            if as_router && !c.router_capacity {
                continue;
            }
            if !as_router && !c.end_device_capacity {
                continue;
            }
            if good_only && c.lqa < good_lqa {
                continue;
            }
            if !good_only && c.lqa >= good_lqa {
                continue;
            }
            if c.attempts >= max_attempts {
                continue;
            }
            let _ = idx.push(i);
        }
        // Insertion sort by descending rank (N is small).
        for i in 0..idx.len() {
            let mut j = i;
            while j > 0 {
                let a = self.entries[idx[j - 1]].rank(current_update_id, current_parent);
                let b = self.entries[idx[j]].rank(current_update_id, current_parent);
                if b > a {
                    idx.swap(j - 1, j);
                    j -= 1;
                } else {
                    break;
                }
            }
        }
        for i in idx {
            let _ = out.push(i);
        }
    }

    /// Candidate by index.
    pub fn get(&self, index: usize) -> Option<&Candidate> {
        self.entries.get(index)
    }

    /// Mutable candidate by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Candidate> {
        self.entries.get_mut(index)
    }

    /// Iterates candidates.
    pub fn iter(&self) -> impl Iterator<Item = &Candidate> {
        self.entries.iter()
    }

    /// Distinct networks discovered (first candidate per extended PAN ID).
    pub fn networks(&self) -> impl Iterator<Item = &Candidate> {
        self.entries.iter().enumerate().filter_map(|(i, c)| {
            if self.entries[..i]
                .iter()
                .any(|p| p.extended_pan_id == c.extended_pan_id)
            {
                None
            } else {
                Some(c)
            }
        })
    }

    /// Number of candidates.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clears the table.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(short: u16, lqa: u8, hub: bool, update_id: u8) -> Candidate {
        Candidate {
            extended_pan_id: ExtendedAddress(1),
            pan_id: PanId(1),
            page: ChannelPage::PAGE_0,
            channel: Channel::DEFAULT_2_4GHZ,
            short: ShortAddress(short),
            extended: None,
            lqa,
            update_id,
            router_capacity: true,
            end_device_capacity: true,
            permit_joining: true,
            pan_coordinator: short == 0,
            router_info: Some(RouterInformation(if hub {
                RouterInformation::HUB_CONNECTIVITY
            } else {
                0
            })),
            r23: true,
            appendix: Vec::new(),
            attempts: 0,
        }
    }

    #[test]
    fn ranking_prefers_hub_then_update_id_then_lqa() {
        let mut t = DiscoveryTable::<6>::new();
        t.add(cand(1, 250, false, 0), 0, None);
        t.add(cand(2, 100, true, 0), 0, None);
        t.add(cand(3, 200, false, 1), 0, None);
        let mut out = Vec::<usize, 6>::new();
        t.ranked(
            Some(ExtendedAddress(1)),
            false,
            true,
            75,
            true,
            0,
            None,
            3,
            &mut out,
        );
        let order: Vec<u16, 6> = out.iter().map(|i| t.get(*i).unwrap().short.0).collect();
        assert_eq!(order.as_slice(), &[2, 3, 1]);
        // Marginal pass yields nothing (all good).
        t.ranked(
            Some(ExtendedAddress(1)),
            false,
            true,
            75,
            false,
            0,
            None,
            3,
            &mut out,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn full_table_keeps_best() {
        let mut t = DiscoveryTable::<2>::new();
        t.add(cand(1, 50, false, 0), 0, None);
        t.add(cand(2, 60, false, 0), 0, None);
        t.add(cand(3, 255, false, 0), 0, None);
        assert_eq!(t.len(), 2);
        assert!(t.iter().any(|c| c.short == ShortAddress(3)));
        assert!(!t.iter().any(|c| c.short == ShortAddress(1)));
        // Updating an existing candidate keeps attempts.
        t.get_mut(0).unwrap().attempts = 2;
        let short0 = t.get(0).unwrap().short.0;
        t.add(cand(short0, 10, false, 0), 0, None);
        assert_eq!(t.get(0).unwrap().attempts, 2);
        assert_eq!(t.networks().count(), 1);
    }

    #[test]
    fn filters_capacity_permit_and_attempts() {
        let mut t = DiscoveryTable::<4>::new();
        let mut a = cand(1, 200, false, 0);
        a.permit_joining = false;
        let mut b = cand(2, 200, false, 0);
        b.router_capacity = false;
        let mut c = cand(3, 200, false, 0);
        c.attempts = 3;
        t.add(a, 0, None);
        t.add(b, 0, None);
        t.add(c, 0, None);
        let mut out = Vec::<usize, 4>::new();
        t.ranked(None, true, true, 75, true, 0, None, 3, &mut out);
        assert!(out.is_empty());
        t.ranked(None, false, false, 75, true, 0, None, 3, &mut out);
        let shorts: Vec<u16, 4> = out.iter().map(|i| t.get(*i).unwrap().short.0).collect();
        assert_eq!(shorts.as_slice(), &[1, 2]);
    }
}
