//! The MAC joining policy and IEEE joining list (`mibJoiningPolicy`,
//! `mibJoiningIeeeList`, R23.2 §2.4.3.3.11 / §2.4.4.3.11): which devices
//! a router or coordinator answers association requests for. The list
//! is held here, next to the network layer that services associations,
//! rather than in a per-interface MAC PIB, and applies to every enabled
//! interface alike.

use heapless::Vec;
use panweave_types::ExtendedAddress;

/// Joining policy values (Table 2-112).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum JoiningPolicy {
    /// Any device may join (ALL_JOIN).
    #[default]
    AllJoin,
    /// Only devices on the IEEE joining list may join (IEEELIST_JOIN).
    IeeeListJoin,
    /// No device may join (NO_JOIN).
    NoJoin,
}

impl JoiningPolicy {
    /// The ZDO enumeration value.
    pub const fn raw(self) -> u8 {
        match self {
            JoiningPolicy::AllJoin => 0x00,
            JoiningPolicy::IeeeListJoin => 0x01,
            JoiningPolicy::NoJoin => 0x02,
        }
    }

    /// From the ZDO enumeration value.
    pub const fn from_raw(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(JoiningPolicy::AllJoin),
            0x01 => Some(JoiningPolicy::IeeeListJoin),
            0x02 => Some(JoiningPolicy::NoJoin),
            _ => None,
        }
    }
}

/// The policy with its list and update id.
#[derive(Clone, Debug, Default)]
pub struct JoiningList<const N: usize> {
    /// Current policy.
    pub policy: JoiningPolicy,
    /// `IeeeJoiningListUpdateID`: incremented on every change, wrapping.
    pub update_id: u8,
    list: Vec<ExtendedAddress, N>,
}

impl<const N: usize> JoiningList<N> {
    /// ALL_JOIN with an empty list.
    pub const fn new() -> Self {
        JoiningList {
            policy: JoiningPolicy::AllJoin,
            update_id: 0,
            list: Vec::new(),
        }
    }

    /// The addresses.
    pub fn entries(&self) -> &[ExtendedAddress] {
        &self.list
    }

    /// Whether `device` passes the policy.
    pub fn allows(&self, device: ExtendedAddress) -> bool {
        match self.policy {
            JoiningPolicy::AllJoin => true,
            JoiningPolicy::IeeeListJoin => self.list.contains(&device),
            JoiningPolicy::NoJoin => false,
        }
    }

    /// Sets the policy (a change bumps the update id).
    pub fn set_policy(&mut self, policy: JoiningPolicy) {
        if self.policy != policy {
            self.policy = policy;
            self.update_id = self.update_id.wrapping_add(1);
        }
    }

    /// Clears the list.
    pub fn clear(&mut self) {
        if !self.list.is_empty() {
            self.list.clear();
            self.update_id = self.update_id.wrapping_add(1);
        }
    }

    /// Applies a Mgmt_NWK_IEEE_Joining_List_rsp (§2.4.4.3.11.2): the
    /// policy, then the entries from `start_index` (a total of 0 clears
    /// the list). `false` when an entry does not fit.
    pub fn apply(
        &mut self,
        policy: JoiningPolicy,
        total: u8,
        start_index: u8,
        entries: &[ExtendedAddress],
    ) -> bool {
        self.set_policy(policy);
        if total == 0 {
            self.clear();
            return true;
        }
        let mut changed = false;
        for (i, e) in entries.iter().enumerate() {
            let index = usize::from(start_index) + i;
            if let Some(slot) = self.list.get_mut(index) {
                if *slot != *e {
                    *slot = *e;
                    changed = true;
                }
            } else if index == self.list.len() {
                if self.list.push(*e).is_err() {
                    return false;
                }
                changed = true;
            } else {
                return false;
            }
        }
        if changed {
            self.update_id = self.update_id.wrapping_add(1);
        }
        true
    }

    /// Adds an address (local administration).
    pub fn add(&mut self, device: ExtendedAddress) -> bool {
        if self.list.contains(&device) {
            return true;
        }
        if self.list.push(device).is_err() {
            return false;
        }
        self.update_id = self.update_id.wrapping_add(1);
        true
    }

    /// Removes an address.
    pub fn remove(&mut self, device: ExtendedAddress) -> bool {
        let before = self.list.len();
        self.list.retain(|d| *d != device);
        if self.list.len() != before {
            self.update_id = self.update_id.wrapping_add(1);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_and_list_gate_joins() {
        let mut j: JoiningList<4> = JoiningList::new();
        let a = ExtendedAddress(1);
        let b = ExtendedAddress(2);
        assert!(j.allows(a));
        j.set_policy(JoiningPolicy::IeeeListJoin);
        assert_eq!(j.update_id, 1);
        assert!(!j.allows(a));
        assert!(j.add(a) && j.add(a));
        assert_eq!(j.update_id, 2);
        assert!(j.allows(a) && !j.allows(b));
        j.set_policy(JoiningPolicy::NoJoin);
        assert!(!j.allows(a));
        // A response replaces from an index and a zero total clears.
        assert!(j.apply(JoiningPolicy::IeeeListJoin, 2, 0, &[b, a]));
        assert_eq!(j.entries(), &[b, a]);
        assert!(!j.apply(JoiningPolicy::IeeeListJoin, 5, 4, &[b]), "gap");
        assert!(j.apply(JoiningPolicy::IeeeListJoin, 0, 0, &[]));
        assert!(j.entries().is_empty());
        assert!(!j.remove(a));
        assert_eq!(JoiningPolicy::from_raw(2), Some(JoiningPolicy::NoJoin));
        assert_eq!(JoiningPolicy::from_raw(3), None);
        assert_eq!(JoiningPolicy::IeeeListJoin.raw(), 1);
    }
}
