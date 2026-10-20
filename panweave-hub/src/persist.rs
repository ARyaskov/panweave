//! Registry records in persistent storage.
//!
//! The registry lives in its own [`Storage`] (on the ESP32-C6 a flash
//! partition separate from the stack's), as `Kind::Application` records:
//!
//! * id 0 — the index: a format octet and the IEEE addresses of the
//!   registered devices (storage backends cannot enumerate);
//! * id = IEEE address — one device: identity, descriptors, category,
//!   capabilities, IAS zone and interview progress.
//!
//! The normalized *state* is deliberately not stored: after a reboot a
//! sensor's state is unknown until the device reports or answers again,
//! and high-rate state changes never cause flash writes. Every record
//! starts with a format octet; a record of an unknown format is left in
//! place untouched (a newer firmware's data survives a downgrade) and
//! the device is skipped.
//!
//! Writes are ordered so that an interruption never leaves the index
//! naming a device without a record: a new device's record is written
//! before the index, and a removed device leaves the index before its
//! record is erased.

use heapless::Vec;
use panweave_codec::{Reader, Writer};
use panweave_storage::{Key, Kind};

use crate::model::{
    Capabilities, DeviceCategory, InterviewStage, InterviewStatus, LogicalType, PowerSource,
};
use crate::protocol::{
    EndpointDescriptor, ProtocolError, ZoneInfo, read_bool, read_list, read_opt_u8, read_opt_u16,
    read_text, write_list, write_opt_u8, write_opt_u16, write_text,
};
use crate::registry::{Device, Interview, MAX_DEVICES};

/// Current record format.
pub(crate) const FORMAT: u8 = 1;

/// Largest record (the `panweave-storage` NOR flash store's limit).
pub(crate) const MAX_RECORD: usize = 512;

/// The index record.
pub(crate) const fn index_key() -> Key {
    Key::with_id(Kind::Application, 0)
}

/// A device record.
pub(crate) const fn device_key(ieee: u64) -> Key {
    Key::with_id(Kind::Application, ieee)
}

/// Encodes the index of `devices`.
pub(crate) fn encode_index<'a>(
    devices: impl Iterator<Item = &'a Device>,
    out: &mut [u8],
) -> Result<usize, ProtocolError> {
    let mut w = Writer::new(out);
    w.u8(FORMAT)?;
    let at = w.position();
    w.u8(0)?;
    let mut n: u8 = 0;
    for d in devices {
        w.u64_le(d.ieee)?;
        n = n.saturating_add(1);
    }
    let len = w.position();
    if let Some(b) = out.get_mut(at) {
        *b = n;
    }
    Ok(len)
}

/// Decodes an index.
pub(crate) fn decode_index(bytes: &[u8]) -> Result<Vec<u64, MAX_DEVICES>, ProtocolError> {
    let mut r = Reader::new(bytes);
    if r.u8()? != FORMAT {
        return Err(ProtocolError::UnknownKind(
            bytes.first().copied().unwrap_or(0),
        ));
    }
    let n = r.u8()?;
    let mut out = Vec::new();
    for _ in 0..n {
        let ieee = r.u64_le()?;
        if out.push(ieee).is_err() {
            break;
        }
    }
    Ok(out)
}

/// Encodes a device record.
pub(crate) fn encode_device(d: &Device, out: &mut [u8]) -> Result<usize, ProtocolError> {
    let mut w = Writer::new(out);
    w.u8(FORMAT)?;
    w.u64_le(d.ieee)?;
    w.u16_le(d.short)?;
    w.u8(u8::from(d.present)
        | (u8::from(d.endpoints_truncated) << 1)
        | (u8::from(d.interview.partial) << 2))?;
    w.u8(d.category.code())?;
    w.u32_le(d.capabilities.0)?;
    w.u8(d.interview.status.code())?;
    w.u8(d.interview.stage.code())?;
    write_opt_u16(&mut w, d.manufacturer_code)?;
    w.u8(d.logical_type.map_or(0xff, LogicalType::code))?;
    w.u8(match d.rx_on_when_idle {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    })?;
    w.u8(d.power_source.code())?;
    write_text(&mut w, &d.manufacturer)?;
    write_text(&mut w, &d.model)?;
    write_text(&mut w, &d.sw_build)?;
    match &d.zone {
        Some(z) => {
            w.u8(1)?;
            w.u8(z.endpoint)?;
            write_opt_u16(&mut w, z.zone_type)?;
            write_opt_u8(&mut w, z.zone_id)?;
            w.u8(u8::from(z.enrolled))?;
        }
        None => w.u8(0)?,
    }
    w.u8(u8::try_from(d.endpoints.len()).unwrap_or(0))?;
    for e in &d.endpoints {
        w.u8(e.endpoint)?;
        w.u16_le(e.profile)?;
        w.u16_le(e.device_id)?;
        write_list(&mut w, &e.inputs)?;
        write_list(&mut w, &e.outputs)?;
    }
    Ok(w.position())
}

/// Decodes a device record.
pub(crate) fn decode_device(bytes: &[u8]) -> Result<Device, ProtocolError> {
    let mut r = Reader::new(bytes);
    if r.u8()? != FORMAT {
        return Err(ProtocolError::UnknownKind(
            bytes.first().copied().unwrap_or(0),
        ));
    }
    let ieee = r.u64_le()?;
    let short = r.u16_le()?;
    let flags = r.u8()?;
    let mut d = Device::new(ieee, short);
    d.present = flags & 1 != 0;
    d.endpoints_truncated = flags & 2 != 0;
    d.category = DeviceCategory::from_code(r.u8()?);
    d.capabilities = Capabilities(r.u32_le()?);
    d.interview = Interview {
        status: InterviewStatus::from_code(r.u8()?),
        stage: InterviewStage::from_code(r.u8()?),
        partial: flags & 4 != 0,
        ..Interview::default()
    };
    d.manufacturer_code = read_opt_u16(&mut r)?;
    d.logical_type = LogicalType::from_code(r.u8()?);
    d.rx_on_when_idle = match r.u8()? {
        0 => None,
        1 => Some(false),
        2 => Some(true),
        _ => return Err(ProtocolError::Malformed),
    };
    d.power_source = PowerSource::from_code(r.u8()?);
    d.manufacturer = read_text(&mut r)?;
    d.model = read_text(&mut r)?;
    d.sw_build = read_text(&mut r)?;
    if read_bool(&mut r)? {
        d.zone = Some(ZoneInfo {
            endpoint: r.u8()?,
            zone_type: read_opt_u16(&mut r)?,
            zone_id: read_opt_u8(&mut r)?,
            enrolled: read_bool(&mut r)?,
        });
    }
    let n = r.u8()?;
    for _ in 0..n {
        let e = EndpointDescriptor {
            endpoint: r.u8()?,
            profile: r.u16_le()?,
            device_id: r.u16_le()?,
            inputs: read_list(&mut r)?,
            outputs: read_list(&mut r)?,
        };
        d.endpoints.push(e).map_err(|_| ProtocolError::Malformed)?;
    }
    if !r.is_empty() {
        return Err(ProtocolError::Malformed);
    }
    d.dirty = false;
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DeviceState;
    use crate::registry::zone_type;

    #[test]
    fn device_records_round_trip_without_state() {
        let mut d = Device::new(0x00aa_bbcc_ddee_ff11, 0x1234);
        d.manufacturer = Vec::from_slice(b"Maker").unwrap();
        d.model = Vec::from_slice(b"Leak sensor").unwrap();
        d.sw_build = Vec::from_slice(b"1.0.3").unwrap();
        d.manufacturer_code = Some(0x1037);
        d.logical_type = Some(LogicalType::EndDevice);
        d.rx_on_when_idle = Some(false);
        d.power_source = PowerSource::Battery;
        d.zone = Some(ZoneInfo {
            endpoint: 1,
            zone_type: Some(zone_type::WATER_SENSOR),
            zone_id: Some(3),
            enrolled: true,
        });
        d.endpoints
            .push(EndpointDescriptor {
                endpoint: 1,
                profile: 0x0104,
                device_id: 0x0402,
                inputs: Vec::from_slice(&[0, 1, 3, 0x0500]).unwrap(),
                outputs: Vec::from_slice(&[0x0019]).unwrap(),
            })
            .unwrap();
        d.interview.status = InterviewStatus::Partial;
        d.interview.stage = InterviewStage::Done;
        d.interview.partial = true;
        d.classify();
        d.state.battery_percent = Some(50);
        let mut buf = [0u8; MAX_RECORD];
        let n = encode_device(&d, &mut buf).unwrap();
        assert!(n < 200, "a typical record is small: {n}");
        let back = decode_device(&buf[..n]).unwrap();
        assert_eq!(back.state, DeviceState::default(), "state is not persisted");
        let mut expected = d.clone();
        expected.state = DeviceState::default();
        expected.dirty = false;
        assert_eq!(back, expected);
        // Another format is refused, not misread.
        buf[0] = 2;
        assert!(decode_device(&buf[..n]).is_err());
        assert!(decode_device(&buf[..n - 1]).is_err());
    }

    #[test]
    fn the_largest_device_fits_a_record() {
        let mut d = Device::new(1, 2);
        d.manufacturer = Vec::from_slice(&[b'm'; 32]).unwrap();
        d.model = Vec::from_slice(&[b'n'; 32]).unwrap();
        d.sw_build = Vec::from_slice(&[b'b'; 16]).unwrap();
        d.zone = Some(ZoneInfo {
            endpoint: 1,
            zone_type: Some(1),
            zone_id: Some(1),
            enrolled: false,
        });
        for e in 0..4 {
            d.endpoints
                .push(EndpointDescriptor {
                    endpoint: e,
                    profile: 0x0104,
                    device_id: 0,
                    inputs: Vec::from_slice(&[7; 16]).unwrap(),
                    outputs: Vec::from_slice(&[7; 8]).unwrap(),
                })
                .unwrap();
        }
        let mut buf = [0u8; MAX_RECORD];
        let n = encode_device(&d, &mut buf).unwrap();
        assert!(n <= MAX_RECORD);
        let devices = [Device::new(5, 6), Device::new(7, 8)];
        let n = encode_index(devices.iter(), &mut buf).unwrap();
        assert_eq!(decode_index(&buf[..n]).unwrap().as_slice(), &[5, 7]);
    }
}
