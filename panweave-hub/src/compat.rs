//! Commercial device profiles: identification of known commercial
//! Zigbee devices and the few model-specific corrections they need.
//!
//! Generic, standards-based behaviour is the default and covers every
//! device; a profile only names a commercial product and, where evidence
//! shows a deviation, applies a narrowly scoped correction to *how its
//! data is interpreted*. Rules:
//!
//! * a profile matches an exact Basic `ManufacturerName` /
//!   `ModelIdentifier` pair (or an exact model with a documented
//!   suffix), never a manufacturer alone;
//! * the strings come from the device itself and are **not** an
//!   authenticated identity: a profile never affects security — joining,
//!   the Trust Center policy and exemptions ignore it entirely;
//! * every correction cites its evidence and has a test; every profile
//!   says whether it was verified on hardware.
//!
//! Profiles also serve the fingerprint export (`device <ieee>
//! fingerprint`), which labels each value with its provenance.

/// How a profile's claims were established.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verification {
    /// From public documentation and open-source integrations only.
    DocumentedExternally,
    /// Confirmed on a physical device with this hub.
    HardwareVerified,
}

impl Verification {
    /// A short name.
    pub const fn name(self) -> &'static str {
        match self {
            Verification::DocumentedExternally => "documented-externally",
            Verification::HardwareVerified => "hardware-verified",
        }
    }
}

/// Model-specific corrections.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Corrections {
    /// The device is battery powered although its MAC capability octet
    /// (association request, node descriptor) claims mains power: the
    /// claim is ignored.
    pub battery_despite_mac_mains_flag: bool,
}

/// A commercial device profile.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Profile {
    /// Stable profile identifier.
    pub id: &'static str,
    /// Vendor and commercial model, as sold.
    pub vendor: &'static str,
    /// Commercial model number(s).
    pub commercial_model: &'static str,
    /// Basic `ManufacturerName` to match, when the profile needs it.
    pub manufacturer: Option<&'static [u8]>,
    /// Basic `ModelIdentifier`.
    pub model: &'static [u8],
    /// Also match `model` followed by a tab and anything (a documented
    /// firmware variant of the identifier).
    pub model_tab_suffix: bool,
    /// Corrections.
    pub corrections: Corrections,
    /// Evidence for the identifiers and every correction.
    pub evidence: &'static str,
    /// Verification status.
    pub verification: Verification,
}

impl Profile {
    /// Whether the device's Basic identity matches this profile.
    pub fn matches(&self, manufacturer: &[u8], model: &[u8]) -> bool {
        let model_ok = model == self.model
            || (self.model_tab_suffix
                && model.len() > self.model.len()
                && model.starts_with(self.model)
                && model.get(self.model.len()) == Some(&b'\t'));
        model_ok && self.manufacturer.is_none_or(|m| m == manufacturer)
    }
}

/// The known profiles.
pub const PROFILES: &[Profile] = &[
    Profile {
        id: "aqara-water-leak-t1",
        vendor: "Aqara",
        commercial_model: "Water Leak Sensor T1 (WL-S02D, SJCGQ12LM; sold as Yandex YNDX-00521)",
        manufacturer: Some(b"LUMI"),
        model: b"lumi.flood.agl02",
        model_tab_suffix: true,
        corrections: Corrections {
            battery_despite_mac_mains_flag: true,
        },
        evidence: "Model identifier lumi.flood.agl02 (and the lumi.flood.agl02<TAB>... variant): \
                   zigbee-herdsman-converters (MIT) definitions SJCGQ12LM and SJCGQ12LM-ES. \
                   CR2032 battery: Aqara WL-S02D specifications. MAC capability 0x84 \
                   (mains-powered flag set, receiver off when idle) with Basic PowerSource 3 \
                   (battery): zigpy/zha-device-handlers issue #2582 device signature.",
        verification: Verification::DocumentedExternally,
    },
    Profile {
        id: "sber-opening-sensor",
        vendor: "SberDevices",
        commercial_model: "Smart Opening Sensor (SBDV-00030)",
        manufacturer: Some(b"_TYZB01_epni2jgy"),
        model: b"TS0203",
        model_tab_suffix: false,
        corrections: Corrections {
            battery_despite_mac_mains_flag: false,
        },
        evidence: "Fingerprint TS0203 / _TYZB01_epni2jgy, IAS contact with tamper and \
                   battery-low bits, Basic cluster reports ignored: zigbee-herdsman-converters \
                   (MIT) definition SBDV-00030.",
        verification: Verification::DocumentedExternally,
    },
    Profile {
        id: "yandex-water-leak-00527",
        vendor: "Yandex",
        commercial_model: "Water Leak Sensor (YNDX-00527)",
        manufacturer: None,
        model: b"YNDX-00527",
        model_tab_suffix: false,
        corrections: Corrections {
            battery_despite_mac_mains_flag: false,
        },
        evidence: "Model identifier YNDX-00527, IAS water sensor (Alarm1, battery low) and \
                   battery voltage: zigbee-herdsman-converters (MIT) definition YNDX_00527; \
                   Zigbee 3.0, CR2032: Yandex YNDX-00527 specifications. Not the same \
                   product as YNDX-00521 (an Aqara T1).",
        verification: Verification::DocumentedExternally,
    },
];

/// The profile of a device, from its Basic identity.
pub fn lookup(manufacturer: &[u8], model: &[u8]) -> Option<&'static Profile> {
    PROFILES.iter().find(|p| p.matches(manufacturer, model))
}

/// Commercial products deliberately outside the Zigbee compatibility
/// scope, with the reason (they are not Zigbee devices).
pub const OUT_OF_SCOPE: &[(&str, &str)] = &[(
    "Sber SBDV-00115 (smart LED bulb E27)",
    "Wi-Fi 802.11b/g/n and Bluetooth LE 4.2 only, per the manufacturer's \
     specifications: not a Zigbee device; no Zigbee pairing is attempted",
)];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_match_exact_identities_only() {
        let aqara = lookup(b"LUMI", b"lumi.flood.agl02").unwrap();
        assert_eq!(aqara.id, "aqara-water-leak-t1");
        assert!(aqara.corrections.battery_despite_mac_mains_flag);
        // The documented variant with a tab suffix.
        assert_eq!(
            lookup(b"LUMI", b"lumi.flood.agl02\tF\x01").map(|p| p.id),
            Some("aqara-water-leak-t1")
        );
        // Not a prefix match otherwise, not another manufacturer, not
        // another LUMI product.
        assert!(lookup(b"LUMI", b"lumi.flood.agl02x").is_none());
        assert!(lookup(b"Other", b"lumi.flood.agl02").is_none());
        assert!(lookup(b"LUMI", b"lumi.sensor_wleak.aq1").is_none());
        let sber = lookup(b"_TYZB01_epni2jgy", b"TS0203").unwrap();
        assert_eq!(sber.corrections, Corrections::default());
        // Other Tuya TS0203 sensors are not this product.
        assert!(lookup(b"_TZ3000_26fmupbb", b"TS0203").is_none());
        let yandex = lookup(b"anything", b"YNDX-00527").unwrap();
        assert_eq!(yandex.corrections, Corrections::default());
        assert!(lookup(b"", b"YNDX-00521").is_none(), "a different product");
        assert!(lookup(b"", b"").is_none());
    }

    #[test]
    fn every_profile_is_documented_and_none_is_claimed_verified() {
        for p in PROFILES {
            assert!(!p.evidence.is_empty(), "{}", p.id);
            assert!(!p.model.is_empty(), "{}", p.id);
            // Update when a device is tested on hardware, with the report.
            assert_eq!(
                p.verification,
                Verification::DocumentedExternally,
                "{}",
                p.id
            );
        }
        assert!(OUT_OF_SCOPE.iter().any(|(m, _)| m.contains("SBDV-00115")));
    }
}
