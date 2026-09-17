//! Enhanced inter-PAN transmission for Smart Energy (SE 1.4a Annex B):
//! the security policy of B.4 / B.8 (every SE inter-PAN frame is APS
//! secured except the Key Establishment exchange that creates the key),
//! the header builder applying it, the reception filter that drops
//! non-conforming frames, and the B.6 receiver discovery helper that
//! picks the required receiving device from the beacons heard.
//!
//! The frame format itself lives in [`panweave_aps::interpan`]; the
//! CBKE run over inter-PAN reuses [`crate::key_establishment`] with the
//! cluster frames carried unsecured, after which the resulting link key
//! secures every further frame (B.6 steps 4–6).

use heapless::Vec;
use panweave_aps::interpan::{InterPanDelivery, InterPanHeader};
use panweave_types::{Channel, ClusterId, ExtendedAddress, PanId, ShortAddress};

use crate::{PROFILE_ID, cluster};

/// Whether frames of `cluster` must be secured over inter-PAN (B.4:
/// everything but Key Establishment, whose Initiate / Ephemeral Data /
/// Confirm Key / Terminate frames precede the key; ADR-0013).
pub const fn security_required(cluster: ClusterId) -> bool {
    cluster.0 != cluster::KEY_ESTABLISHMENT.0
}

/// A stub header for an outgoing SE inter-PAN frame with the Security
/// bit set as the profile requires and the APS counter present for an
/// acknowledged unicast.
pub const fn outgoing_header(
    delivery: InterPanDelivery,
    cluster: ClusterId,
    counter: Option<u8>,
) -> InterPanHeader {
    InterPanHeader {
        delivery,
        cluster,
        profile: PROFILE_ID,
        secured: security_required(cluster),
        counter,
        fragment: None,
    }
}

/// Why a received inter-PAN frame is dropped (B.8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Rejection {
    /// Not the Smart Energy profile.
    WrongProfile,
    /// A cluster that requires security arrived unsecured.
    UnsecuredCluster,
    /// A Key Establishment frame arrived secured (no key exists yet).
    SecuredKeyEstablishment,
    /// Group addressing is not used by the profile over inter-PAN.
    GroupAddressed,
}

/// Checks a received stub header against the profile rules before the
/// payload is processed (or unsecured).
pub const fn accept(header: &InterPanHeader) -> Result<(), Rejection> {
    if header.profile.0 != PROFILE_ID.0 {
        return Err(Rejection::WrongProfile);
    }
    if matches!(header.delivery, InterPanDelivery::Group(_)) {
        return Err(Rejection::GroupAddressed);
    }
    match (security_required(header.cluster), header.secured) {
        (true, false) => Err(Rejection::UnsecuredCluster),
        (false, true) => Err(Rejection::SecuredKeyEstablishment),
        _ => Ok(()),
    }
}

/// A device heard during the B.6 channel survey (one per beacon).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Heard {
    /// Channel the beacon was received on.
    pub channel: Channel,
    /// PAN identifier.
    pub pan_id: PanId,
    /// Extended PAN identifier from the beacon payload.
    pub extended_pan_id: ExtendedAddress,
    /// Beaconing device (its short address).
    pub short: ShortAddress,
    /// Beaconing device's IEEE address, when the beacon carried it.
    pub ieee: Option<ExtendedAddress>,
    /// Link quality.
    pub lqi: u8,
}

/// The list of devices heard while surveying the channels (B.6 step 3).
#[derive(Clone, Debug, Default)]
pub struct Survey<const N: usize> {
    heard: Vec<Heard, N>,
}

impl<const N: usize> Survey<N> {
    /// An empty survey.
    pub const fn new() -> Self {
        Survey { heard: Vec::new() }
    }

    /// Records a beacon; a repeat from the same device keeps the best
    /// link quality. Returns `false` when the list is full.
    pub fn record(&mut self, h: Heard) -> bool {
        if let Some(e) = self
            .heard
            .iter_mut()
            .find(|e| e.pan_id == h.pan_id && e.short == h.short && e.channel == h.channel)
        {
            if h.lqi > e.lqi {
                *e = h;
            }
            return true;
        }
        self.heard.push(h).is_ok()
    }

    /// Everything heard, for a user interface to choose from.
    pub fn heard(&self) -> &[Heard] {
        &self.heard
    }

    /// The strongest signal, the choice without a user interface.
    pub fn strongest(&self) -> Option<&Heard> {
        self.heard.iter().max_by_key(|h| h.lqi)
    }

    /// The devices of one extended PAN.
    pub fn of_network(&self, epid: ExtendedAddress) -> impl Iterator<Item = &Heard> {
        self.heard.iter().filter(move |h| h.extended_pan_id == epid)
    }

    /// Forgets everything (the survey is repeated after a channel change
    /// that was not announced over inter-PAN, B.7).
    pub fn clear(&mut self) {
        self.heard.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_policy_follows_annex_b() {
        let price = outgoing_header(InterPanDelivery::Unicast, cluster::PRICE, Some(1));
        assert!(price.secured && price.counter == Some(1));
        assert_eq!(accept(&price), Ok(()));
        let cbke = outgoing_header(InterPanDelivery::Unicast, cluster::KEY_ESTABLISHMENT, None);
        assert!(!cbke.secured);
        assert_eq!(accept(&cbke), Ok(()));
        assert_eq!(
            accept(&InterPanHeader {
                secured: false,
                ..price
            }),
            Err(Rejection::UnsecuredCluster)
        );
        assert_eq!(
            accept(&InterPanHeader {
                secured: true,
                ..cbke
            }),
            Err(Rejection::SecuredKeyEstablishment)
        );
        assert_eq!(
            accept(&InterPanHeader {
                profile: panweave_types::ProfileId(0x0104),
                ..price
            }),
            Err(Rejection::WrongProfile)
        );
        assert_eq!(
            accept(&InterPanHeader {
                delivery: InterPanDelivery::Group(panweave_types::GroupAddress(1)),
                ..price
            }),
            Err(Rejection::GroupAddressed)
        );
    }

    #[test]
    fn survey_keeps_the_best_beacon_per_device() {
        let mut s: Survey<4> = Survey::new();
        let h = |pan: u16, short: u16, lqi: u8| Heard {
            channel: Channel::new(15).unwrap(),
            pan_id: PanId(pan),
            extended_pan_id: ExtendedAddress(u64::from(pan)),
            short: ShortAddress(short),
            ieee: None,
            lqi,
        };
        assert!(s.record(h(1, 0, 100)));
        assert!(s.record(h(1, 0, 90)));
        assert!(s.record(h(1, 0, 120)));
        assert!(s.record(h(2, 0, 110)));
        assert_eq!(s.heard().len(), 2);
        assert_eq!(s.strongest().unwrap().pan_id, PanId(1));
        assert_eq!(s.strongest().unwrap().lqi, 120);
        assert_eq!(s.of_network(ExtendedAddress(2)).count(), 1);
        assert!(s.record(h(3, 0, 1)) && s.record(h(4, 0, 1)) && !s.record(h(5, 0, 1)));
        s.clear();
        assert!(s.strongest().is_none());
    }
}
