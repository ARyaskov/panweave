//! The device registry: a bounded table of the devices on the hub's
//! network, keyed by IEEE address.
//!
//! The IEEE address is the identity; the network (short) address is only
//! where the device currently is and changes on rejoins and address
//! conflicts. What a device *is* — category and capabilities — is derived
//! by [`Device::classify`] from its simple descriptors, its IAS zone type
//! and the attributes it answered for; nothing is assumed from a
//! manufacturer or model string.

use heapless::Vec;
use panweave_types::time::Instant;

use crate::model::{
    Capabilities, ColorState, DeviceCategory, DeviceState, InterviewStage, InterviewStatus,
    LogicalType, PowerSource,
};
use crate::protocol::{
    DeviceInfo, DeviceSummary, EndpointDescriptor, MAX_BUILD, MAX_ENDPOINTS, MAX_NAME, Text,
    ZoneInfo,
};

/// Registry capacity.
pub const MAX_DEVICES: usize = 32;

/// Network address not known.
pub const NO_SHORT: u16 = 0xfffe;

/// Cluster identifiers the registry interprets.
pub mod cluster {
    /// Basic.
    pub const BASIC: u16 = 0x0000;
    /// Power Configuration.
    pub const POWER_CONFIGURATION: u16 = 0x0001;
    /// Identify.
    pub const IDENTIFY: u16 = 0x0003;
    /// Groups.
    pub const GROUPS: u16 = 0x0004;
    /// Scenes.
    pub const SCENES: u16 = 0x0005;
    /// On/Off.
    pub const ON_OFF: u16 = 0x0006;
    /// Level Control.
    pub const LEVEL: u16 = 0x0008;
    /// Poll Control.
    pub const POLL_CONTROL: u16 = 0x0020;
    /// Color Control.
    pub const COLOR: u16 = 0x0300;
    /// Illuminance Measurement.
    pub const ILLUMINANCE: u16 = 0x0400;
    /// Temperature Measurement.
    pub const TEMPERATURE: u16 = 0x0402;
    /// Relative Humidity Measurement.
    pub const HUMIDITY: u16 = 0x0405;
    /// Occupancy Sensing.
    pub const OCCUPANCY: u16 = 0x0406;
    /// IAS Zone.
    pub const IAS_ZONE: u16 = 0x0500;
}

/// IAS zone types the hub normalizes (ZCL8 Table 8-5).
pub mod zone_type {
    /// Motion sensor.
    pub const MOTION_SENSOR: u16 = 0x000d;
    /// Contact switch.
    pub const CONTACT_SWITCH: u16 = 0x0015;
    /// Water sensor.
    pub const WATER_SENSOR: u16 = 0x002a;
}

/// Profiles whose endpoints the hub talks ZCL to.
const HOME_AUTOMATION: u16 = 0x0104;
const ZLL: u16 = 0xc05e;

/// Interview bookkeeping of a device (persisted: status, stage and the
/// partial flag; the rest restarts with the hub).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Interview {
    /// Status.
    pub status: InterviewStatus,
    /// Current stage.
    pub stage: InterviewStage,
    /// Step within the stage (endpoint index, attribute group, …).
    pub step: u8,
    /// Attempts made at the current step.
    pub attempts: u8,
    /// When the next step may be sent (`None`: not scheduled).
    pub due: Option<Instant>,
    /// A request of the interview is outstanding.
    pub busy: bool,
    /// Optional steps failed.
    pub partial: bool,
}

/// A device in the registry.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Device {
    /// IEEE address: the identity.
    pub ieee: u64,
    /// Current network address ([`NO_SHORT`] when unknown).
    pub short: u16,
    /// On the network (has not left).
    pub present: bool,
    /// Basic `ManufacturerName`.
    pub manufacturer: Text<MAX_NAME>,
    /// Basic `ModelIdentifier`.
    pub model: Text<MAX_NAME>,
    /// Basic `SWBuildID`.
    pub sw_build: Text<MAX_BUILD>,
    /// Node descriptor manufacturer code.
    pub manufacturer_code: Option<u16>,
    /// Node descriptor logical type.
    pub logical_type: Option<LogicalType>,
    /// Receiver on when idle.
    pub rx_on_when_idle: Option<bool>,
    /// Power source.
    pub power_source: PowerSource,
    /// Simple descriptors.
    pub endpoints: Vec<EndpointDescriptor, MAX_ENDPOINTS>,
    /// Active endpoints beyond [`MAX_ENDPOINTS`] were ignored.
    pub endpoints_truncated: bool,
    /// Category.
    pub category: DeviceCategory,
    /// Capabilities.
    pub capabilities: Capabilities,
    /// IAS Zone details.
    pub zone: Option<ZoneInfo>,
    /// Normalized state (not persisted: unknown after a reboot until the
    /// device reports or answers).
    pub state: DeviceState,
    /// Color Control server (not persisted: read again by the state
    /// synchronization after a reboot).
    pub color: ColorState,
    /// Interview bookkeeping.
    pub interview: Interview,
    /// When the device was last heard.
    pub last_seen: Option<Instant>,
    /// Link quality from the neighbor table.
    pub lqi: Option<u8>,
    /// An administrator exempted the device from the Trust Center's
    /// key-exchange requirement (persisted; applied to the stack at
    /// start-up).
    pub key_exchange_exempt: bool,
    /// The record must be written to storage.
    pub(crate) dirty: bool,
    /// The state must be read again (after a reboot or a rejoin) the next
    /// time the device is heard.
    pub(crate) needs_sync: bool,
    /// When the last state synchronization was started.
    pub(crate) last_sync: Option<Instant>,
    /// Next read of the state synchronization in progress.
    pub(crate) sync_step: u8,
    /// A synchronization read is outstanding.
    pub(crate) sync_busy: bool,
    /// When the last join (or rejoin) was reported to the host.
    pub(crate) joined_at: Option<Instant>,
    /// `IAS_CIE_Address` as read during the interview.
    pub(crate) cie_address: Option<u64>,
    /// The device sent a Zone Enroll Request that was answered.
    pub(crate) enroll_answered: bool,
    /// Unsolicited enrolments repeated in this interview.
    pub(crate) enroll_retries: u8,
}

impl Device {
    /// A device first seen at `short`.
    pub fn new(ieee: u64, short: u16) -> Self {
        Device {
            ieee,
            short,
            present: true,
            manufacturer: Vec::new(),
            model: Vec::new(),
            sw_build: Vec::new(),
            manufacturer_code: None,
            logical_type: None,
            rx_on_when_idle: None,
            power_source: PowerSource::Unknown,
            endpoints: Vec::new(),
            endpoints_truncated: false,
            category: DeviceCategory::Unknown,
            capabilities: Capabilities::default(),
            zone: None,
            state: DeviceState::default(),
            color: ColorState::default(),
            interview: Interview::default(),
            last_seen: None,
            lqi: None,
            key_exchange_exempt: false,
            dirty: true,
            needs_sync: false,
            last_sync: None,
            sync_step: 0,
            sync_busy: false,
            joined_at: None,
            cie_address: None,
            enroll_answered: false,
            enroll_retries: 0,
        }
    }

    /// The endpoint descriptor of `endpoint`.
    pub fn endpoint(&self, endpoint: u8) -> Option<&EndpointDescriptor> {
        self.endpoints.iter().find(|e| e.endpoint == endpoint)
    }

    /// The first endpoint (with a ZCL profile) serving `cluster`.
    pub fn endpoint_serving(&self, cluster: u16) -> Option<u8> {
        self.endpoints
            .iter()
            .find(|e| talks_zcl(e) && e.inputs.contains(&cluster))
            .map(|e| e.endpoint)
    }

    /// Whether any endpoint serves `cluster`.
    pub fn serves(&self, cluster: u16) -> bool {
        self.endpoint_serving(cluster).is_some()
    }

    /// The commercial profile of the device (`crate::compat`), from its
    /// Basic identity — interpretation only, never security.
    pub fn profile(&self) -> Option<&'static crate::compat::Profile> {
        crate::compat::lookup(&self.manufacturer, &self.model)
    }

    /// Whether a mains-powered claim in the device's MAC capability octet
    /// is to be ignored (a profile says it runs on a battery).
    pub fn ignores_mac_mains_claim(&self) -> bool {
        self.profile()
            .is_some_and(|p| p.corrections.battery_despite_mac_mains_flag)
    }

    /// Derives category and capabilities from the descriptors, the zone
    /// type and the attributes the device answered for.
    pub fn classify(&mut self) {
        // A profile's power-source correction, once the identity is known.
        if self.ignores_mac_mains_claim() && self.power_source == PowerSource::Mains {
            self.power_source = PowerSource::Battery;
        }
        let mut caps = Capabilities::default();
        let mut light_device = false;
        let mut outputs_only = true;
        for e in self.endpoints.iter().filter(|e| talks_zcl(e)) {
            for &c in &e.inputs {
                let flag = match c {
                    cluster::ON_OFF => Capabilities::ON_OFF,
                    cluster::LEVEL => Capabilities::LEVEL,
                    cluster::COLOR => Capabilities::COLOR,
                    cluster::IAS_ZONE => Capabilities::IAS_ZONE,
                    cluster::POWER_CONFIGURATION => Capabilities::POWER_CONFIGURATION,
                    cluster::TEMPERATURE => Capabilities::TEMPERATURE,
                    cluster::HUMIDITY => Capabilities::HUMIDITY,
                    cluster::OCCUPANCY => Capabilities::OCCUPANCY,
                    cluster::ILLUMINANCE => Capabilities::ILLUMINANCE,
                    cluster::IDENTIFY => Capabilities::IDENTIFY,
                    cluster::POLL_CONTROL => Capabilities::POLL_CONTROL,
                    _ => 0,
                };
                caps.insert(flag);
                if flag != 0 && flag != Capabilities::IDENTIFY {
                    outputs_only = false;
                }
            }
            // HA lighting device identifiers (DTL §5: 0x0100–0x010d) and
            // every ZLL endpoint carrying On/Off are lights.
            light_device |= (0x0100..=0x010d).contains(&e.device_id) || e.profile == ZLL;
        }
        let zone_type = self.zone.and_then(|z| z.zone_type);
        if caps.contains(Capabilities::IAS_ZONE) {
            match zone_type {
                Some(zone_type::CONTACT_SWITCH) => caps.insert(Capabilities::CONTACT),
                Some(zone_type::WATER_SENSOR) => caps.insert(Capabilities::WATER_LEAK),
                Some(zone_type::MOTION_SENSOR) => caps.insert(Capabilities::OCCUPANCY),
                _ => {}
            }
        }
        if self.state.battery_percent.is_some() {
            caps.insert(Capabilities::BATTERY_PERCENTAGE);
        }
        if self.state.battery_mv.is_some() {
            caps.insert(Capabilities::BATTERY_VOLTAGE);
        }
        self.capabilities = caps;
        self.category = if caps.contains(Capabilities::WATER_LEAK) {
            DeviceCategory::WaterLeakSensor
        } else if caps.contains(Capabilities::CONTACT) {
            DeviceCategory::ContactSensor
        } else if caps.contains(Capabilities::IAS_ZONE)
            && zone_type == Some(zone_type::MOTION_SENSOR)
        {
            DeviceCategory::MotionSensor
        } else if caps.contains(Capabilities::IAS_ZONE) {
            DeviceCategory::IasZone
        } else if caps.contains(Capabilities::ON_OFF | Capabilities::LEVEL | Capabilities::COLOR) {
            DeviceCategory::ColorLight
        } else if caps.contains(Capabilities::ON_OFF | Capabilities::LEVEL) {
            DeviceCategory::DimmableLight
        } else if caps.contains(Capabilities::ON_OFF) {
            if light_device {
                DeviceCategory::OnOffLight
            } else {
                DeviceCategory::OnOffOutput
            }
        } else if caps.contains(Capabilities::OCCUPANCY) {
            DeviceCategory::MotionSensor
        } else if caps.contains(Capabilities::TEMPERATURE) {
            DeviceCategory::TemperatureSensor
        } else if outputs_only
            && self
                .endpoints
                .iter()
                .any(|e| talks_zcl(e) && !e.outputs.is_empty())
        {
            DeviceCategory::Controller
        } else if self.logical_type == Some(LogicalType::Router) {
            DeviceCategory::Router
        } else {
            DeviceCategory::Unknown
        };
    }

    /// Seconds since `boot` when the device was last heard.
    pub fn last_seen_s(&self, boot: Instant) -> Option<u32> {
        self.last_seen
            .map(|t| u32::try_from(t.saturating_duration_since(boot).as_secs()).unwrap_or(u32::MAX))
    }

    /// The protocol summary.
    pub fn summary(&self, boot: Instant) -> DeviceSummary {
        DeviceSummary {
            ieee: self.ieee,
            short: self.short,
            category: self.category,
            capabilities: self.capabilities,
            interview: self.interview.status,
            present: self.present,
            last_seen_s: self.last_seen_s(boot),
            model: self.model.clone(),
        }
    }

    /// The protocol device information.
    pub fn info(&self, boot: Instant) -> DeviceInfo {
        DeviceInfo {
            summary: self.summary(boot),
            manufacturer: self.manufacturer.clone(),
            sw_build: self.sw_build.clone(),
            manufacturer_code: self.manufacturer_code,
            logical_type: self.logical_type,
            rx_on_when_idle: self.rx_on_when_idle,
            power_source: self.power_source,
            interview_stage: self.interview.stage,
            endpoints: self.endpoints.clone(),
            zone: self.zone,
            lqi: self.lqi,
            state: self.state,
        }
    }
}

/// Whether the hub speaks ZCL to an endpoint (Home Automation, or ZLL,
/// which Zigbee 3.0 devices also accept under the HA profile).
pub fn talks_zcl(e: &EndpointDescriptor) -> bool {
    e.profile == HOME_AUTOMATION || e.profile == ZLL
}

/// The registry is full.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RegistryFull;

/// The device table.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    devices: Vec<Device, MAX_DEVICES>,
}

impl Registry {
    /// An empty registry.
    pub const fn new() -> Self {
        Registry {
            devices: Vec::new(),
        }
    }

    /// Number of devices.
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// The devices, in registration order.
    pub fn iter(&self) -> impl Iterator<Item = &Device> {
        self.devices.iter()
    }

    /// The devices, mutably.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Device> {
        self.devices.iter_mut()
    }

    /// The device at `index`.
    pub fn at(&self, index: usize) -> Option<&Device> {
        self.devices.get(index)
    }

    /// The device at `index`, mutably.
    pub fn at_mut(&mut self, index: usize) -> Option<&mut Device> {
        self.devices.get_mut(index)
    }

    /// Index of the device with `ieee`.
    pub fn index_of(&self, ieee: u64) -> Option<usize> {
        self.devices.iter().position(|d| d.ieee == ieee)
    }

    /// Index of the device currently at `short`.
    pub fn index_of_short(&self, short: u16) -> Option<usize> {
        if short == NO_SHORT {
            return None;
        }
        self.devices.iter().position(|d| d.short == short)
    }

    /// The device with `ieee`.
    pub fn get(&self, ieee: u64) -> Option<&Device> {
        self.devices.iter().find(|d| d.ieee == ieee)
    }

    /// The device with `ieee`, mutably.
    pub fn get_mut(&mut self, ieee: u64) -> Option<&mut Device> {
        self.devices.iter_mut().find(|d| d.ieee == ieee)
    }

    /// Records that `ieee` is at `short`: updates a known device (a
    /// changed address marks it dirty) or adds a new one. Another entry
    /// still claiming `short` loses it (the address was reassigned).
    /// Returns the index and whether the device is new.
    pub fn upsert(&mut self, ieee: u64, short: u16) -> Result<(usize, bool), RegistryFull> {
        for d in self.devices.iter_mut() {
            if d.ieee != ieee && d.short == short {
                d.short = NO_SHORT;
                d.dirty = true;
            }
        }
        if let Some(i) = self.index_of(ieee) {
            if let Some(d) = self.devices.get_mut(i)
                && d.short != short
            {
                d.short = short;
                d.dirty = true;
            }
            return Ok((i, false));
        }
        self.devices
            .push(Device::new(ieee, short))
            .map_err(|_| RegistryFull)?;
        Ok((self.devices.len() - 1, true))
    }

    /// Inserts a restored device as is.
    pub fn restore(&mut self, device: Device) -> Result<(), RegistryFull> {
        if self.index_of(device.ieee).is_some() {
            return Ok(());
        }
        self.devices.push(device).map_err(|_| RegistryFull)
    }

    /// Removes the device with `ieee`.
    pub fn remove(&mut self, ieee: u64) -> Option<Device> {
        let i = self.index_of(ieee)?;
        Some(self.devices.remove(i))
    }

    /// Removes every device.
    pub fn clear(&mut self) {
        self.devices.clear();
    }

    /// The lowest IAS zone identifier no device uses (0–0xfe).
    pub fn free_zone_id(&self) -> Option<u8> {
        (0..=0xfeu8).find(|id| {
            !self
                .devices
                .iter()
                .any(|d| d.zone.and_then(|z| z.zone_id) == Some(*id))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(endpoint: u8, device_id: u16, inputs: &[u16], outputs: &[u16]) -> EndpointDescriptor {
        EndpointDescriptor {
            endpoint,
            profile: HOME_AUTOMATION,
            device_id,
            inputs: Vec::from_slice(inputs).unwrap(),
            outputs: Vec::from_slice(outputs).unwrap(),
        }
    }

    #[test]
    fn categories_follow_the_descriptors() {
        let mut d = Device::new(1, 0x1234);
        d.endpoints
            .push(ep(1, 0x0101, &[0, 3, 4, 5, 6, 8], &[]))
            .unwrap();
        d.classify();
        assert_eq!(d.category, DeviceCategory::DimmableLight);
        assert!(
            d.capabilities
                .contains(Capabilities::ON_OFF | Capabilities::LEVEL)
        );
        assert!(!d.capabilities.contains(Capabilities::COLOR));

        let mut plug = Device::new(2, 0x2222);
        plug.endpoints.push(ep(1, 0x0051, &[0, 6], &[])).unwrap();
        plug.classify();
        assert_eq!(plug.category, DeviceCategory::OnOffOutput);

        let mut leak = Device::new(3, 0x3333);
        leak.endpoints
            .push(ep(1, 0x0402, &[0, 1, 3, 0x0500], &[]))
            .unwrap();
        leak.classify();
        assert_eq!(leak.category, DeviceCategory::IasZone, "zone type unknown");
        leak.zone = Some(ZoneInfo {
            endpoint: 1,
            zone_type: Some(zone_type::WATER_SENSOR),
            zone_id: None,
            enrolled: false,
        });
        leak.state.battery_percent = Some(80);
        leak.classify();
        assert_eq!(leak.category, DeviceCategory::WaterLeakSensor);
        assert!(leak.capabilities.contains(
            Capabilities::WATER_LEAK | Capabilities::BATTERY_PERCENTAGE | Capabilities::IAS_ZONE
        ));
        assert!(!leak.capabilities.contains(Capabilities::BATTERY_VOLTAGE));

        let mut remote = Device::new(4, 0x4444);
        remote
            .endpoints
            .push(ep(1, 0x0820, &[0, 3], &[6, 8]))
            .unwrap();
        remote.classify();
        assert_eq!(remote.category, DeviceCategory::Controller);

        let mut gp = Device::new(5, 0x5555);
        gp.endpoints
            .push(EndpointDescriptor {
                endpoint: 242,
                profile: 0xa1e0,
                device_id: 0x0061,
                inputs: Vec::new(),
                outputs: Vec::from_slice(&[0x0021]).unwrap(),
            })
            .unwrap();
        gp.logical_type = Some(LogicalType::Router);
        gp.classify();
        assert_eq!(gp.category, DeviceCategory::Router);
    }

    #[test]
    fn upsert_tracks_address_changes_and_capacity() {
        let mut r = Registry::new();
        assert_eq!(r.upsert(10, 0x0001), Ok((0, true)));
        assert_eq!(r.upsert(11, 0x0002), Ok((1, true)));
        r.iter_mut().for_each(|d| d.dirty = false);
        // Device 10 rejoined with a new address.
        assert_eq!(r.upsert(10, 0x0003), Ok((0, false)));
        assert!(r.get(10).unwrap().dirty);
        assert_eq!(r.index_of_short(0x0003), Some(0));
        // Device 12 took device 11's old address.
        assert_eq!(r.upsert(12, 0x0002), Ok((2, true)));
        assert_eq!(r.get(11).unwrap().short, NO_SHORT);
        assert_eq!(r.index_of_short(NO_SHORT), None);
        let mut full = Registry::new();
        for i in 0..MAX_DEVICES {
            full.upsert(100 + i as u64, u16::try_from(i).unwrap())
                .unwrap();
        }
        assert_eq!(full.upsert(999, 0x7777), Err(RegistryFull));
        assert_eq!(full.len(), MAX_DEVICES);
        assert!(full.remove(100).is_some());
        assert_eq!(full.upsert(999, 0x7777), Ok((MAX_DEVICES - 1, true)));
    }
}
