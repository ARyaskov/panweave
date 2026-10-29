//! OTA upgrade messages (0.4): the host offers one image and streams its
//! bytes; the hub serves it to the matching device (ZCL8 chapter 11).
//!
//! The hub holds no image: it asks for the bytes ahead of the device
//! ([`super::Event::OtaDataWanted`]) and keeps a small window of them.
//! The host reads the file and checks it (signature, hash) before
//! offering it; the device verifies the image it downloaded.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};

use super::{ProtocolError, read_bool};

/// Image octets per [`super::Request::OtaData`].
pub const MAX_OTA_CHUNK: usize = 255;

/// An OTA image's identity, from its file header (ZCL8 §11.4.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OtaImage {
    /// Manufacturer code.
    pub manufacturer_code: u16,
    /// Image type.
    pub image_type: u16,
    /// File version.
    pub file_version: u32,
    /// Total image size (the whole file, header included).
    pub size: u32,
}

/// An image offered to devices.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OtaOffer {
    /// The image.
    pub image: OtaImage,
    /// Only this device (`None`: every device that matches).
    pub target: Option<u64>,
    /// Offer it to devices running a newer version too.
    pub allow_downgrade: bool,
}

/// The OTA server's state.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct OtaStatus {
    /// The image offered.
    pub offer: Option<OtaOffer>,
    /// The device downloading it.
    pub device: Option<u64>,
    /// The next offset that device asked for.
    pub offset: u32,
    /// First offset held by the hub.
    pub window_offset: u32,
    /// Octets held.
    pub window_len: u16,
}

pub(crate) fn write_image(w: &mut Writer<'_>, i: &OtaImage) -> Result<(), CodecError> {
    w.u16_le(i.manufacturer_code)?;
    w.u16_le(i.image_type)?;
    w.u32_le(i.file_version)?;
    w.u32_le(i.size)
}

pub(crate) fn read_image(r: &mut Reader<'_>) -> Result<OtaImage, ProtocolError> {
    Ok(OtaImage {
        manufacturer_code: r.u16_le()?,
        image_type: r.u16_le()?,
        file_version: r.u32_le()?,
        size: r.u32_le()?,
    })
}

pub(crate) fn write_offer(w: &mut Writer<'_>, o: &OtaOffer) -> Result<(), CodecError> {
    write_image(w, &o.image)?;
    match o.target {
        Some(t) => {
            w.u8(1)?;
            w.u64_le(t)?;
        }
        None => w.u8(0)?,
    }
    w.u8(u8::from(o.allow_downgrade))
}

pub(crate) fn read_offer(r: &mut Reader<'_>) -> Result<OtaOffer, ProtocolError> {
    Ok(OtaOffer {
        image: read_image(r)?,
        target: if read_bool(r)? {
            Some(r.u64_le()?)
        } else {
            None
        },
        allow_downgrade: read_bool(r)?,
    })
}

pub(crate) fn write_status(w: &mut Writer<'_>, s: &OtaStatus) -> Result<(), CodecError> {
    match &s.offer {
        Some(o) => {
            w.u8(1)?;
            write_offer(w, o)?;
        }
        None => w.u8(0)?,
    }
    match s.device {
        Some(d) => {
            w.u8(1)?;
            w.u64_le(d)?;
        }
        None => w.u8(0)?,
    }
    w.u32_le(s.offset)?;
    w.u32_le(s.window_offset)?;
    w.u16_le(s.window_len)
}

pub(crate) fn read_status(r: &mut Reader<'_>) -> Result<OtaStatus, ProtocolError> {
    Ok(OtaStatus {
        offer: if read_bool(r)? {
            Some(read_offer(r)?)
        } else {
            None
        },
        device: if read_bool(r)? {
            Some(r.u64_le()?)
        } else {
            None
        },
        offset: r.u32_le()?,
        window_offset: r.u32_le()?,
        window_len: r.u16_le()?,
    })
}

pub(crate) fn write_chunk(w: &mut Writer<'_>, data: &[u8]) -> Result<(), CodecError> {
    // At most MAX_OTA_CHUNK (255) octets: the count fits an octet.
    let n = data.len().min(MAX_OTA_CHUNK);
    w.u8(u8::try_from(n).unwrap_or(u8::MAX))?;
    w.bytes(data.get(..n).unwrap_or_default())
}

pub(crate) fn read_chunk(r: &mut Reader<'_>) -> Result<Vec<u8, MAX_OTA_CHUNK>, ProtocolError> {
    let n = usize::from(r.u8()?);
    Vec::from_slice(r.bytes(n)?).map_err(|_| ProtocolError::TooLarge)
}
