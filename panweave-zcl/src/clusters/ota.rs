//! OTA Upgrade cluster (ZCL8 chapter 11): the OTA file header and
//! sub-elements (§11.4), the client attributes (§11.10), every command
//! frame of §11.13, a client download machine (Query Next Image → Image
//! Block Requests → Upgrade End, with the wait / abort / rate-limit rules)
//! that hands image bytes to the application, and a server side that
//! answers requests from an [`ImageSource`]. Signature verification
//! (§11.6–§11.7, ECDSA over the SE suites) is the host's, as for the Key
//! Establishment cluster (ADR-0012).

use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::time::{Duration, Instant};
use panweave_types::{ClusterId, CommandId, ExtendedAddress};

use crate::attribute::{Access, AttributeDef};
use crate::cluster::{ClusterDef, ClusterInstance, Role};
use crate::frame::ZclStatus;
use crate::types::{DataType, Value};

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0019);

/// `UpgradeServerID` (EUI-64).
pub const UPGRADE_SERVER_ID: AttributeDef = AttributeDef::new(0x0000, DataType::Eui64, Access::RO);
/// `FileOffset` (uint32).
pub const FILE_OFFSET: AttributeDef = AttributeDef::new(0x0001, DataType::Uint(4), Access::RO);
/// `CurrentFileVersion` (uint32).
pub const CURRENT_FILE_VERSION: AttributeDef =
    AttributeDef::new(0x0002, DataType::Uint(4), Access::RO);
/// `CurrentZigBeeStackVersion` (uint16).
pub const CURRENT_ZIGBEE_STACK_VERSION: AttributeDef =
    AttributeDef::new(0x0003, DataType::Uint(2), Access::RO);
/// `DownloadedFileVersion` (uint32).
pub const DOWNLOADED_FILE_VERSION: AttributeDef =
    AttributeDef::new(0x0004, DataType::Uint(4), Access::RO);
/// `DownloadedZigBeeStackVersion` (uint16).
pub const DOWNLOADED_ZIGBEE_STACK_VERSION: AttributeDef =
    AttributeDef::new(0x0005, DataType::Uint(2), Access::RO);
/// `ImageUpgradeStatus` (enum8).
pub const IMAGE_UPGRADE_STATUS: AttributeDef =
    AttributeDef::new(0x0006, DataType::Enum8, Access::RO);
/// `ManufacturerID` (uint16).
pub const MANUFACTURER_ID: AttributeDef = AttributeDef::new(0x0007, DataType::Uint(2), Access::RO);
/// `ImageTypeID` (uint16).
pub const IMAGE_TYPE_ID: AttributeDef = AttributeDef::new(0x0008, DataType::Uint(2), Access::RO);
/// `MinimumBlockPeriod` (uint16 ms).
pub const MINIMUM_BLOCK_PERIOD: AttributeDef =
    AttributeDef::new(0x0009, DataType::Uint(2), Access::RO);
/// `ImageStamp` (uint32).
pub const IMAGE_STAMP: AttributeDef = AttributeDef::new(0x000a, DataType::Uint(4), Access::RO);
/// `UpgradeActivationPolicy` (enum8).
pub const UPGRADE_ACTIVATION_POLICY: AttributeDef =
    AttributeDef::new(0x000b, DataType::Enum8, Access::RO);
/// `UpgradeTimeoutPolicy` (enum8).
pub const UPGRADE_TIMEOUT_POLICY: AttributeDef =
    AttributeDef::new(0x000c, DataType::Enum8, Access::RO);

/// Client → server: Query Next Image Request.
pub const CMD_QUERY_NEXT_IMAGE_REQUEST: CommandId = CommandId(0x01);
/// Client → server: Image Block Request.
pub const CMD_IMAGE_BLOCK_REQUEST: CommandId = CommandId(0x03);
/// Client → server: Image Page Request.
pub const CMD_IMAGE_PAGE_REQUEST: CommandId = CommandId(0x04);
/// Client → server: Upgrade End Request.
pub const CMD_UPGRADE_END_REQUEST: CommandId = CommandId(0x06);
/// Client → server: Query Device Specific File Request.
pub const CMD_QUERY_DEVICE_SPECIFIC_FILE_REQUEST: CommandId = CommandId(0x08);
/// Server → client: Image Notify.
pub const CMD_IMAGE_NOTIFY: CommandId = CommandId(0x00);
/// Server → client: Query Next Image Response.
pub const CMD_QUERY_NEXT_IMAGE_RESPONSE: CommandId = CommandId(0x02);
/// Server → client: Image Block Response.
pub const CMD_IMAGE_BLOCK_RESPONSE: CommandId = CommandId(0x05);
/// Server → client: Upgrade End Response.
pub const CMD_UPGRADE_END_RESPONSE: CommandId = CommandId(0x07);
/// Server → client: Query Device Specific File Response.
pub const CMD_QUERY_DEVICE_SPECIFIC_FILE_RESPONSE: CommandId = CommandId(0x09);

/// Server cluster definition.
pub const SERVER_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 3,
    received: &[
        CMD_QUERY_NEXT_IMAGE_REQUEST,
        CMD_IMAGE_BLOCK_REQUEST,
        CMD_IMAGE_PAGE_REQUEST,
        CMD_UPGRADE_END_REQUEST,
        CMD_QUERY_DEVICE_SPECIFIC_FILE_REQUEST,
    ],
    generated: &[
        CMD_IMAGE_NOTIFY,
        CMD_QUERY_NEXT_IMAGE_RESPONSE,
        CMD_IMAGE_BLOCK_RESPONSE,
        CMD_UPGRADE_END_RESPONSE,
        CMD_QUERY_DEVICE_SPECIFIC_FILE_RESPONSE,
    ],
};

/// Client cluster definition.
pub const CLIENT_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 3,
    received: &[
        CMD_IMAGE_NOTIFY,
        CMD_QUERY_NEXT_IMAGE_RESPONSE,
        CMD_IMAGE_BLOCK_RESPONSE,
        CMD_UPGRADE_END_RESPONSE,
        CMD_QUERY_DEVICE_SPECIFIC_FILE_RESPONSE,
    ],
    generated: &[
        CMD_QUERY_NEXT_IMAGE_REQUEST,
        CMD_IMAGE_BLOCK_REQUEST,
        CMD_IMAGE_PAGE_REQUEST,
        CMD_UPGRADE_END_REQUEST,
        CMD_QUERY_DEVICE_SPECIFIC_FILE_REQUEST,
    ],
};

/// `ImageUpgradeStatus` values (Table 11-11).
pub mod upgrade_status {
    /// Normal.
    pub const NORMAL: u8 = 0x00;
    /// Download in progress.
    pub const DOWNLOAD_IN_PROGRESS: u8 = 0x01;
    /// Download complete.
    pub const DOWNLOAD_COMPLETE: u8 = 0x02;
    /// Waiting to upgrade.
    pub const WAITING_TO_UPGRADE: u8 = 0x03;
    /// Count down.
    pub const COUNT_DOWN: u8 = 0x04;
    /// Wait for more images.
    pub const WAIT_FOR_MORE: u8 = 0x05;
    /// Waiting to upgrade via an external event.
    pub const WAITING_FOR_EXTERNAL_EVENT: u8 = 0x06;
}

/// `UpgradeActivationPolicy` values (Table 11-12).
pub mod activation_policy {
    /// The server's Upgrade End Response activates the image.
    pub const SERVER: u8 = 0x00;
    /// Out-of-band activation only.
    pub const OUT_OF_BAND: u8 = 0x01;
}

/// Wild-card manufacturer code / image type / file version.
pub const WILDCARD_U16: u16 = 0xffff;
/// Wild-card file version and "wait" upgrade time.
pub const WILDCARD_U32: u32 = 0xffff_ffff;
/// Image types reserved for device-specific files (Table 11-4).
pub mod image_type {
    /// Client security credentials.
    pub const CLIENT_SECURITY_CREDENTIALS: u16 = 0xffc0;
    /// Client configuration.
    pub const CLIENT_CONFIGURATION: u16 = 0xffc1;
    /// Server log.
    pub const SERVER_LOG: u16 = 0xffc2;
    /// Picture.
    pub const PICTURE: u16 = 0xffc3;
    /// Largest manufacturer-specific image type.
    pub const MAX_MANUFACTURER_SPECIFIC: u16 = 0xffbf;
}

// ------------------------------------------------------------------
// OTA file format (§11.4)
// ------------------------------------------------------------------

/// The OTA upgrade file identifier (§11.4.2.1).
pub const FILE_IDENTIFIER: u32 = 0x0BEE_F11E;
/// The header version this crate understands (§11.4.2.2).
pub const HEADER_VERSION: u16 = 0x0100;
/// Length of the mandatory header fields.
pub const MIN_HEADER_LEN: u16 = 56;

/// Header field control bits (Table 11-3).
pub mod field_control {
    /// Security credential version present.
    pub const SECURITY_CREDENTIAL_VERSION: u16 = 1 << 0;
    /// Device-specific file (upgrade file destination present).
    pub const DEVICE_SPECIFIC: u16 = 1 << 1;
    /// Hardware versions present.
    pub const HARDWARE_VERSIONS: u16 = 1 << 2;
}

/// Sub-element tags (Table 11-9).
pub mod tag {
    /// Upgrade image.
    pub const UPGRADE_IMAGE: u16 = 0x0000;
    /// ECDSA signature (Crypto Suite 1).
    pub const ECDSA_SIGNATURE_1: u16 = 0x0001;
    /// ECDSA signing certificate (Crypto Suite 1).
    pub const ECDSA_CERTIFICATE_1: u16 = 0x0002;
    /// Image integrity code.
    pub const IMAGE_INTEGRITY_CODE: u16 = 0x0003;
    /// Picture data.
    pub const PICTURE_DATA: u16 = 0x0004;
    /// ECDSA signature (Crypto Suite 2).
    pub const ECDSA_SIGNATURE_2: u16 = 0x0005;
    /// ECDSA signing certificate (Crypto Suite 2).
    pub const ECDSA_CERTIFICATE_2: u16 = 0x0006;
}

/// A parsed OTA file header (Table 11-2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Header {
    /// Header version.
    pub version: u16,
    /// Header length (the sub-elements start here).
    pub length: u16,
    /// Field control.
    pub field_control: u16,
    /// Manufacturer code.
    pub manufacturer_code: u16,
    /// Image type.
    pub image_type: u16,
    /// File version.
    pub file_version: u32,
    /// Zigbee stack version.
    pub stack_version: u16,
    /// The 32-octet header string (NUL-terminated ASCII).
    pub string: [u8; 32],
    /// Total image size including the header.
    pub total_size: u32,
    /// Security credential version.
    pub security_credential_version: Option<u8>,
    /// Upgrade file destination.
    pub destination: Option<ExtendedAddress>,
    /// Minimum and maximum hardware versions.
    pub hardware_versions: Option<(u16, u16)>,
}

impl Header {
    /// Parses the header at the start of an OTA file (`bytes` may be a
    /// prefix of the file as long as it holds the whole header).
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let id = r.u32_le()?;
        if id != FILE_IDENTIFIER {
            return Err(CodecError::InvalidField {
                field: "OTA upgrade file identifier",
                value: id,
            });
        }
        let version = r.u16_le()?;
        if version >> 8 != HEADER_VERSION >> 8 {
            return Err(CodecError::Unsupported {
                what: "OTA header version",
            });
        }
        let length = r.u16_le()?;
        if length < MIN_HEADER_LEN {
            return Err(CodecError::InvalidField {
                field: "OTA header length",
                value: u32::from(length),
            });
        }
        let field_control = r.u16_le()?;
        let manufacturer_code = r.u16_le()?;
        let image_type = r.u16_le()?;
        let file_version = r.u32_le()?;
        let stack_version = r.u16_le()?;
        let string = r.array::<32>()?;
        let total_size = r.u32_le()?;
        let security_credential_version =
            if field_control & field_control::SECURITY_CREDENTIAL_VERSION != 0 {
                Some(r.u8()?)
            } else {
                None
            };
        let destination = if field_control & field_control::DEVICE_SPECIFIC != 0 {
            Some(ExtendedAddress(r.u64_le()?))
        } else {
            None
        };
        let hardware_versions = if field_control & field_control::HARDWARE_VERSIONS != 0 {
            Some((r.u16_le()?, r.u16_le()?))
        } else {
            None
        };
        if r.position() > usize::from(length) || u32::from(length) > total_size {
            return Err(CodecError::InvalidField {
                field: "OTA header length",
                value: u32::from(length),
            });
        }
        Ok(Header {
            version,
            length,
            field_control,
            manufacturer_code,
            image_type,
            file_version,
            stack_version,
            string,
            total_size,
            security_credential_version,
            destination,
            hardware_versions,
        })
    }

    /// The header string up to its NUL terminator.
    pub fn string_text(&self) -> &[u8] {
        let end = self.string.iter().position(|b| *b == 0).unwrap_or(32);
        self.string.get(..end).unwrap_or(&[])
    }

    /// Whether the image suits a device (§11.13.4.4): manufacturer,
    /// image type, hardware version within the header's range and, for
    /// device-specific files, the destination.
    pub fn suits(
        &self,
        manufacturer_code: u16,
        image_type: u16,
        hardware: Option<u16>,
        ieee: ExtendedAddress,
    ) -> bool {
        self.manufacturer_code == manufacturer_code
            && self.image_type == image_type
            && self
                .hardware_versions
                .is_none_or(|(min, max)| hardware.is_none_or(|h| (min..=max).contains(&h)))
            && self.destination.is_none_or(|d| d == ieee)
    }

    /// Writes a header with the mandatory fields (and the optional ones
    /// present in `self`); returns the length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut w = Writer::new(out);
        let mut fc = 0u16;
        let mut len = MIN_HEADER_LEN;
        if self.security_credential_version.is_some() {
            fc |= field_control::SECURITY_CREDENTIAL_VERSION;
            len += 1;
        }
        if self.destination.is_some() {
            fc |= field_control::DEVICE_SPECIFIC;
            len += 8;
        }
        if self.hardware_versions.is_some() {
            fc |= field_control::HARDWARE_VERSIONS;
            len += 4;
        }
        w.u32_le(FILE_IDENTIFIER)?;
        w.u16_le(HEADER_VERSION)?;
        w.u16_le(len)?;
        w.u16_le(fc)?;
        w.u16_le(self.manufacturer_code)?;
        w.u16_le(self.image_type)?;
        w.u32_le(self.file_version)?;
        w.u16_le(self.stack_version)?;
        w.bytes(&self.string)?;
        w.u32_le(self.total_size)?;
        if let Some(v) = self.security_credential_version {
            w.u8(v)?;
        }
        if let Some(d) = self.destination {
            w.u64_le(d.0)?;
        }
        if let Some((min, max)) = self.hardware_versions {
            w.u16_le(min)?;
            w.u16_le(max)?;
        }
        Ok(w.position())
    }
}

/// A sub-element (§11.4.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SubElement<'a> {
    /// Tag identifier.
    pub tag: u16,
    /// Data.
    pub data: &'a [u8],
}

/// Iterates over the sub-elements after the header of a complete file.
pub struct SubElements<'a>(pub &'a [u8]);

impl<'a> Iterator for SubElements<'a> {
    type Item = Result<SubElement<'a>, CodecError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            return None;
        }
        let mut r = Reader::new(self.0);
        let item = (|| {
            let tag = r.u16_le()?;
            let len = r.u32_le()?;
            let len = usize::try_from(len).map_err(|_| CodecError::InvalidField {
                field: "sub-element length",
                value: len,
            })?;
            let data = r.bytes(len)?;
            Ok(SubElement { tag, data })
        })();
        match item {
            Ok(e) => {
                self.0 = r.take_rest();
                Some(Ok(e))
            }
            Err(e) => {
                self.0 = &[];
                Some(Err(e))
            }
        }
    }
}

// ------------------------------------------------------------------
// Command frames (§11.13)
// ------------------------------------------------------------------

/// Image Notify (§11.13.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ImageNotify {
    /// Query jitter (1–100).
    pub query_jitter: u8,
    /// Manufacturer code (payload type ≥ 1).
    pub manufacturer_code: Option<u16>,
    /// Image type (payload type ≥ 2).
    pub image_type: Option<u16>,
    /// New file version (payload type 3).
    pub file_version: Option<u32>,
}

impl ImageNotify {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let ty = r.u8()?;
        let query_jitter = r.u8()?;
        if ty > 3 || !(1..=100).contains(&query_jitter) {
            return Err(CodecError::InvalidField {
                field: "Image Notify payload type / jitter",
                value: u32::from(ty),
            });
        }
        Ok(ImageNotify {
            query_jitter,
            manufacturer_code: if ty >= 1 { Some(r.u16_le()?) } else { None },
            image_type: if ty >= 2 { Some(r.u16_le()?) } else { None },
            file_version: if ty >= 3 { Some(r.u32_le()?) } else { None },
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let ty = match (self.manufacturer_code, self.image_type, self.file_version) {
            (None, ..) => 0,
            (Some(_), None, _) => 1,
            (Some(_), Some(_), None) => 2,
            (Some(_), Some(_), Some(_)) => 3,
        };
        w.u8(ty)?;
        w.u8(self.query_jitter)?;
        if let Some(m) = self.manufacturer_code {
            w.u16_le(m)?;
        }
        if ty >= 2
            && let Some(t) = self.image_type
        {
            w.u16_le(t)?;
        }
        if ty >= 3
            && let Some(v) = self.file_version
        {
            w.u32_le(v)?;
        }
        Ok(())
    }
}

/// Query Next Image Request (§11.13.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct QueryNextImageRequest {
    /// Manufacturer code.
    pub manufacturer_code: u16,
    /// Image type.
    pub image_type: u16,
    /// Current file version.
    pub file_version: u32,
    /// Hardware version.
    pub hardware_version: Option<u16>,
}

impl QueryNextImageRequest {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let fc = r.u8()?;
        Ok(QueryNextImageRequest {
            manufacturer_code: r.u16_le()?,
            image_type: r.u16_le()?,
            file_version: r.u32_le()?,
            hardware_version: if fc & 0x01 != 0 {
                Some(r.u16_le()?)
            } else {
                None
            },
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(u8::from(self.hardware_version.is_some()))?;
        w.u16_le(self.manufacturer_code)?;
        w.u16_le(self.image_type)?;
        w.u32_le(self.file_version)?;
        if let Some(h) = self.hardware_version {
            w.u16_le(h)?;
        }
        Ok(())
    }
}

/// Query Next Image Response (§11.13.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct QueryNextImageResponse {
    /// SUCCESS, NO_IMAGE_AVAILABLE or NOT_AUTHORIZED.
    pub status: ZclStatus,
    /// The image on success.
    pub image: Option<ImageId>,
    /// Image size on success.
    pub image_size: u32,
}

/// Identity of an image.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ImageId {
    /// Manufacturer code.
    pub manufacturer_code: u16,
    /// Image type.
    pub image_type: u16,
    /// File version.
    pub file_version: u32,
}

impl ImageId {
    fn read(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(ImageId {
            manufacturer_code: r.u16_le()?,
            image_type: r.u16_le()?,
            file_version: r.u32_le()?,
        })
    }

    fn write(self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.manufacturer_code)?;
        w.u16_le(self.image_type)?;
        w.u32_le(self.file_version)
    }

    /// Whether `other` names this image, wild cards allowed.
    pub const fn matches(self, other: ImageId) -> bool {
        (other.manufacturer_code == WILDCARD_U16
            || other.manufacturer_code == self.manufacturer_code)
            && (other.image_type == WILDCARD_U16 || other.image_type == self.image_type)
            && (other.file_version == WILDCARD_U32 || other.file_version == self.file_version)
    }
}

impl QueryNextImageResponse {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let status = ZclStatus::from_raw(r.u8()?);
        if status == ZclStatus::Success {
            let image = ImageId::read(&mut r)?;
            let image_size = r.u32_le()?;
            Ok(QueryNextImageResponse {
                status,
                image: Some(image),
                image_size,
            })
        } else {
            if r.remaining() != 0 {
                return Err(CodecError::InvalidField {
                    field: "Query Next Image Response",
                    value: u32::from(status.raw()),
                });
            }
            Ok(QueryNextImageResponse {
                status,
                image: None,
                image_size: 0,
            })
        }
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.status.raw())?;
        if self.status == ZclStatus::Success {
            self.image
                .ok_or(CodecError::InvalidField {
                    field: "Query Next Image Response image",
                    value: 0,
                })?
                .write(w)?;
            w.u32_le(self.image_size)?;
        }
        Ok(())
    }
}

/// Image Block Request (§11.13.6).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ImageBlockRequest {
    /// The image.
    pub image: ImageId,
    /// File offset.
    pub file_offset: u32,
    /// Maximum data size the client accepts.
    pub max_data_size: u8,
    /// The requesting node (device-specific files).
    pub node: Option<ExtendedAddress>,
    /// The client's `MinimumBlockPeriod` (ms).
    pub minimum_block_period: Option<u16>,
}

impl ImageBlockRequest {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let fc = r.u8()?;
        let image = ImageId::read(&mut r)?;
        let file_offset = r.u32_le()?;
        let max_data_size = r.u8()?;
        let node = if fc & 0x01 != 0 {
            Some(ExtendedAddress(r.u64_le()?))
        } else {
            None
        };
        let minimum_block_period = if fc & 0x02 != 0 {
            Some(r.u16_le()?)
        } else {
            None
        };
        Ok(ImageBlockRequest {
            image,
            file_offset,
            max_data_size,
            node,
            minimum_block_period,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        let fc =
            u8::from(self.node.is_some()) | (u8::from(self.minimum_block_period.is_some()) << 1);
        w.u8(fc)?;
        self.image.write(w)?;
        w.u32_le(self.file_offset)?;
        w.u8(self.max_data_size)?;
        if let Some(n) = self.node {
            w.u64_le(n.0)?;
        }
        if let Some(p) = self.minimum_block_period {
            w.u16_le(p)?;
        }
        Ok(())
    }
}

/// Image Page Request (§11.13.7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ImagePageRequest {
    /// The image.
    pub image: ImageId,
    /// File offset.
    pub file_offset: u32,
    /// Maximum data size per block.
    pub max_data_size: u8,
    /// Page size.
    pub page_size: u16,
    /// Response spacing (ms).
    pub response_spacing: u16,
    /// The requesting node.
    pub node: Option<ExtendedAddress>,
}

impl ImagePageRequest {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let fc = r.u8()?;
        let image = ImageId::read(&mut r)?;
        Ok(ImagePageRequest {
            image,
            file_offset: r.u32_le()?,
            max_data_size: r.u8()?,
            page_size: r.u16_le()?,
            response_spacing: r.u16_le()?,
            node: if fc & 0x01 != 0 {
                Some(ExtendedAddress(r.u64_le()?))
            } else {
                None
            },
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(u8::from(self.node.is_some()))?;
        self.image.write(w)?;
        w.u32_le(self.file_offset)?;
        w.u8(self.max_data_size)?;
        w.u16_le(self.page_size)?;
        w.u16_le(self.response_spacing)?;
        if let Some(n) = self.node {
            w.u64_le(n.0)?;
        }
        Ok(())
    }
}

/// Image Block Response (§11.13.8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ImageBlockResponse<'a> {
    /// A block of image data.
    Success {
        /// The image.
        image: ImageId,
        /// File offset of `data`.
        file_offset: u32,
        /// The data.
        data: &'a [u8],
    },
    /// Come back later.
    WaitForData {
        /// Server's current time (0 = offsets).
        current_time: u32,
        /// When to retry.
        request_time: u32,
        /// Rate limit for later requests (ms).
        minimum_block_period: u16,
    },
    /// The download is cancelled.
    Abort,
}

impl<'a> ImageBlockResponse<'a> {
    /// Parses the payload.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        match ZclStatus::from_raw(r.u8()?) {
            ZclStatus::Success => {
                let image = ImageId::read(&mut r)?;
                let file_offset = r.u32_le()?;
                let size = usize::from(r.u8()?);
                let data = r.bytes(size)?;
                Ok(ImageBlockResponse::Success {
                    image,
                    file_offset,
                    data,
                })
            }
            ZclStatus::WaitForData => {
                let current_time = r.u32_le()?;
                let request_time = r.u32_le()?;
                let minimum_block_period = if r.remaining() >= 2 { r.u16_le()? } else { 0 };
                Ok(ImageBlockResponse::WaitForData {
                    current_time,
                    request_time,
                    minimum_block_period,
                })
            }
            ZclStatus::Abort => Ok(ImageBlockResponse::Abort),
            other => Err(CodecError::InvalidField {
                field: "Image Block Response status",
                value: u32::from(other.raw()),
            }),
        }
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        match self {
            ImageBlockResponse::Success {
                image,
                file_offset,
                data,
            } => {
                w.u8(ZclStatus::Success.raw())?;
                image.write(w)?;
                w.u32_le(*file_offset)?;
                w.u8(
                    u8::try_from(data.len()).map_err(|_| CodecError::InvalidField {
                        field: "Image Block Response data size",
                        value: 0,
                    })?,
                )?;
                w.bytes(data)
            }
            ImageBlockResponse::WaitForData {
                current_time,
                request_time,
                minimum_block_period,
            } => {
                w.u8(ZclStatus::WaitForData.raw())?;
                w.u32_le(*current_time)?;
                w.u32_le(*request_time)?;
                w.u16_le(*minimum_block_period)
            }
            ImageBlockResponse::Abort => w.u8(ZclStatus::Abort.raw()),
        }
    }
}

/// Upgrade End Request (§11.13.9).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct UpgradeEndRequest {
    /// SUCCESS, INVALID_IMAGE, REQUIRE_MORE_IMAGE or ABORT.
    pub status: ZclStatus,
    /// The image.
    pub image: ImageId,
}

impl UpgradeEndRequest {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(UpgradeEndRequest {
            status: ZclStatus::from_raw(r.u8()?),
            image: ImageId::read(&mut r)?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.status.raw())?;
        self.image.write(w)
    }
}

/// Upgrade End Response (§11.13.10).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct UpgradeEndResponse {
    /// The image (wild cards allowed).
    pub image: ImageId,
    /// Server's current time (0 = offsets).
    pub current_time: u32,
    /// When to upgrade (0xffffffff = wait for another command).
    pub upgrade_time: u32,
}

impl UpgradeEndResponse {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(UpgradeEndResponse {
            image: ImageId::read(&mut r)?,
            current_time: r.u32_le()?,
            upgrade_time: r.u32_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        self.image.write(w)?;
        w.u32_le(self.current_time)?;
        w.u32_le(self.upgrade_time)
    }
}

/// Seconds to wait given a `(current_time, request_time)` pair (Table
/// 11-15) for a device without UTC time: offsets when the server has no
/// clock, the difference otherwise; `None` for "wait for a command".
pub const fn wait_seconds(current_time: u32, request_time: u32) -> Option<u32> {
    if request_time == WILDCARD_U32 {
        None
    } else if current_time == 0 {
        Some(request_time)
    } else {
        Some(request_time.saturating_sub(current_time))
    }
}

// ------------------------------------------------------------------
// Client machine (§11.16)
// ------------------------------------------------------------------

/// Client identity and policy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ClientConfig {
    /// Manufacturer code.
    pub manufacturer_code: u16,
    /// Image type of the running image.
    pub image_type: u16,
    /// Running file version.
    pub file_version: u32,
    /// Hardware version, when reported.
    pub hardware_version: Option<u16>,
    /// Largest block the client accepts.
    pub max_data_size: u8,
    /// Activation policy (Table 11-12).
    pub activation_policy: u8,
}

/// Client download state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Phase {
    /// Nothing in progress.
    Normal,
    /// Query Next Image sent, awaiting the response.
    Querying,
    /// Downloading `image`: `offset` of `size` received.
    Downloading {
        /// The image.
        image: ImageId,
        /// Bytes received.
        offset: u32,
        /// Total size.
        size: u32,
    },
    /// Upgrade End Request sent, awaiting the response.
    Ending {
        /// The image.
        image: ImageId,
    },
    /// Told when to upgrade.
    WaitingToUpgrade {
        /// The image.
        image: ImageId,
        /// Upgrade at this instant (`None` = wait for a command).
        at: Option<Instant>,
    },
}

/// What the client machine asks of the host.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClientAction<'a> {
    /// Send this Query Next Image Request.
    Query(QueryNextImageRequest),
    /// Send this Image Block Request (after `not_before`).
    RequestBlock {
        /// The request.
        request: ImageBlockRequest,
        /// Earliest send time (rate limiting / wait).
        not_before: Instant,
    },
    /// Store image bytes at `offset` (the download continues).
    Store {
        /// Offset in the file.
        offset: u32,
        /// Data.
        data: &'a [u8],
    },
    /// The image is complete: verify it, then call
    /// [`Client::finish`] with the verdict.
    Verify {
        /// The image.
        image: ImageId,
        /// Total size.
        size: u32,
    },
    /// Send this Upgrade End Request.
    UpgradeEnd(UpgradeEndRequest),
    /// Apply the downloaded image at `at` (`None` = now).
    Upgrade {
        /// The image.
        image: ImageId,
        /// When.
        at: Option<Instant>,
    },
    /// Answer with a Default Response of this status.
    Default(ZclStatus),
    /// Nothing to do.
    None,
}

/// The OTA client machine.
#[derive(Clone, Copy, Debug)]
pub struct Client {
    /// Identity and policy.
    pub config: ClientConfig,
    /// Current phase.
    pub phase: Phase,
    /// `MinimumBlockPeriod` set by the server (ms).
    pub minimum_block_period: u16,
    /// Earliest next block request.
    pub not_before: Instant,
    /// Downloaded file version (kept after completion).
    pub downloaded_version: Option<u32>,
}

impl Client {
    /// A client in the Normal state.
    pub const fn new(config: ClientConfig) -> Self {
        Client {
            config,
            phase: Phase::Normal,
            minimum_block_period: 0,
            not_before: Instant::from_millis(0),
            downloaded_version: None,
        }
    }

    /// The Query Next Image Request for this device.
    pub const fn query(&self) -> QueryNextImageRequest {
        QueryNextImageRequest {
            manufacturer_code: self.config.manufacturer_code,
            image_type: self.config.image_type,
            file_version: self.config.file_version,
            hardware_version: self.config.hardware_version,
        }
    }

    /// Starts a query (periodic polling or after a notify).
    pub fn start_query(&mut self) -> ClientAction<'static> {
        if matches!(self.phase, Phase::Normal | Phase::Querying) {
            self.phase = Phase::Querying;
            ClientAction::Query(self.query())
        } else {
            ClientAction::None
        }
    }

    /// Handles an Image Notify (§11.13.3.4): `random_1_100` is a fresh
    /// draw in 1..=100 for the jitter test of broadcasts.
    pub fn on_image_notify(
        &mut self,
        n: &ImageNotify,
        unicast: bool,
        random_1_100: u8,
    ) -> ClientAction<'static> {
        if !matches!(self.phase, Phase::Normal | Phase::Querying) {
            return ClientAction::None;
        }
        if unicast {
            return self.start_query();
        }
        if n.manufacturer_code
            .is_some_and(|m| m != self.config.manufacturer_code)
            || n.image_type.is_some_and(|t| t != self.config.image_type)
        {
            return ClientAction::None;
        }
        if let Some(v) = n.file_version
            && (v == self.config.file_version || Some(v) == self.downloaded_version)
        {
            return ClientAction::None;
        }
        if random_1_100 <= n.query_jitter {
            self.start_query()
        } else {
            ClientAction::None
        }
    }

    /// Handles a Query Next Image Response (§11.13.5.4).
    pub fn on_query_response(
        &mut self,
        r: &QueryNextImageResponse,
        now: Instant,
    ) -> ClientAction<'static> {
        if self.phase != Phase::Querying {
            return ClientAction::None;
        }
        match (r.status, r.image) {
            (ZclStatus::Success, Some(image)) => {
                if image.manufacturer_code != self.config.manufacturer_code
                    || image.image_type != self.config.image_type
                {
                    self.phase = Phase::Normal;
                    return ClientAction::Default(ZclStatus::MalformedCommand);
                }
                if image.file_version == self.config.file_version
                    || Some(image.file_version) == self.downloaded_version
                {
                    self.phase = Phase::Normal;
                    return ClientAction::None;
                }
                self.phase = Phase::Downloading {
                    image,
                    offset: 0,
                    size: r.image_size,
                };
                self.not_before = now;
                self.block_request(now)
            }
            _ => {
                self.phase = Phase::Normal;
                ClientAction::None
            }
        }
    }

    fn block_request(&self, now: Instant) -> ClientAction<'static> {
        let Phase::Downloading { image, offset, .. } = self.phase else {
            return ClientAction::None;
        };
        let not_before = if now.has_reached(self.not_before) {
            now
        } else {
            self.not_before
        };
        ClientAction::RequestBlock {
            request: ImageBlockRequest {
                image,
                file_offset: offset,
                max_data_size: self.config.max_data_size,
                node: None,
                minimum_block_period: (self.minimum_block_period != 0)
                    .then_some(self.minimum_block_period),
            },
            not_before,
        }
    }

    /// Handles an Image Block Response: returns the store action (then
    /// call [`Client::next`] for the following request) or the verify /
    /// wait / abort outcome.
    pub fn on_block_response<'a>(
        &mut self,
        r: &ImageBlockResponse<'a>,
        now: Instant,
    ) -> ClientAction<'a> {
        let Phase::Downloading {
            image,
            offset,
            size,
        } = self.phase
        else {
            return ClientAction::None;
        };
        match *r {
            ImageBlockResponse::Success {
                image: got,
                file_offset,
                data,
            } => {
                if got != image || file_offset != offset {
                    // Out of order or the wrong image: ask again.
                    return self.block_request(now);
                }
                let new_offset =
                    offset.saturating_add(u32::try_from(data.len()).unwrap_or(u32::MAX));
                self.phase = Phase::Downloading {
                    image,
                    offset: new_offset.min(size),
                    size,
                };
                self.not_before = now + Duration::from_millis(u64::from(self.minimum_block_period));
                if new_offset >= size {
                    self.downloaded_version = Some(image.file_version);
                }
                ClientAction::Store {
                    offset: file_offset,
                    data,
                }
            }
            ImageBlockResponse::WaitForData {
                current_time,
                request_time,
                minimum_block_period,
            } => {
                self.minimum_block_period = minimum_block_period;
                let secs = wait_seconds(current_time, request_time).unwrap_or(3600);
                self.not_before = now + Duration::from_secs(u64::from(secs));
                self.block_request(now)
            }
            ImageBlockResponse::Abort => {
                self.phase = Phase::Normal;
                ClientAction::None
            }
        }
    }

    /// After a stored block: the next block request, or `Verify` when
    /// the file is complete.
    pub fn next(&mut self, now: Instant) -> ClientAction<'static> {
        match self.phase {
            Phase::Downloading {
                image,
                offset,
                size,
            } if offset >= size => {
                self.phase = Phase::Ending { image };
                ClientAction::Verify { image, size }
            }
            Phase::Downloading { .. } => self.block_request(now),
            _ => ClientAction::None,
        }
    }

    /// The application verified the image: `status` is SUCCESS,
    /// INVALID_IMAGE, REQUIRE_MORE_IMAGE or ABORT (§11.13.9.3).
    pub fn finish(&mut self, status: ZclStatus) -> ClientAction<'static> {
        let Phase::Ending { image } = self.phase else {
            return ClientAction::None;
        };
        if status != ZclStatus::Success {
            self.phase = Phase::Normal;
            self.downloaded_version = None;
        }
        ClientAction::UpgradeEnd(UpgradeEndRequest { status, image })
    }

    /// Aborts a download from the application's side.
    pub fn abort(&mut self) -> ClientAction<'static> {
        let image = match self.phase {
            Phase::Downloading { image, .. } | Phase::Ending { image } => image,
            _ => return ClientAction::None,
        };
        self.phase = Phase::Normal;
        self.downloaded_version = None;
        ClientAction::UpgradeEnd(UpgradeEndRequest {
            status: ZclStatus::Abort,
            image,
        })
    }

    /// Handles an Upgrade End Response (§11.13.10.4).
    pub fn on_upgrade_end_response(
        &mut self,
        r: &UpgradeEndResponse,
        now: Instant,
    ) -> ClientAction<'static> {
        let image = match self.phase {
            Phase::Ending { image } | Phase::WaitingToUpgrade { image, .. } => image,
            _ => return ClientAction::None,
        };
        if !image.matches(r.image) {
            return ClientAction::None;
        }
        if self.config.activation_policy == activation_policy::OUT_OF_BAND
            && r.upgrade_time != WILDCARD_U32
        {
            return ClientAction::Default(ZclStatus::NotAuthorized);
        }
        let at = wait_seconds(r.current_time, r.upgrade_time)
            .map(|s| now + Duration::from_secs(u64::from(s)));
        self.phase = Phase::WaitingToUpgrade { image, at };
        ClientAction::Upgrade { image, at }
    }

    /// The `ImageUpgradeStatus` value for the phase.
    pub const fn upgrade_status(&self) -> u8 {
        match self.phase {
            Phase::Normal | Phase::Querying => upgrade_status::NORMAL,
            Phase::Downloading { .. } => upgrade_status::DOWNLOAD_IN_PROGRESS,
            Phase::Ending { .. } => upgrade_status::DOWNLOAD_COMPLETE,
            Phase::WaitingToUpgrade { at: Some(_), .. } => upgrade_status::COUNT_DOWN,
            Phase::WaitingToUpgrade { at: None, .. } => {
                if self.config.activation_policy == activation_policy::OUT_OF_BAND {
                    upgrade_status::WAITING_FOR_EXTERNAL_EVENT
                } else {
                    upgrade_status::WAITING_TO_UPGRADE
                }
            }
        }
    }

    /// Mirrors the machine into a client cluster instance's attributes.
    pub fn publish<const A: usize>(&self, c: &mut ClusterInstance<A>) {
        c.set(
            IMAGE_UPGRADE_STATUS.id,
            &Value::Enum8(self.upgrade_status()),
        );
        let offset = match self.phase {
            Phase::Downloading { offset, .. } => offset,
            _ => WILDCARD_U32,
        };
        c.set(
            FILE_OFFSET.id,
            &Value::Uint {
                width: 4,
                value: u64::from(offset),
            },
        );
        c.set(
            DOWNLOADED_FILE_VERSION.id,
            &Value::Uint {
                width: 4,
                value: u64::from(self.downloaded_version.unwrap_or(WILDCARD_U32)),
            },
        );
        c.set_u16(MINIMUM_BLOCK_PERIOD.id, self.minimum_block_period);
    }
}

/// Builds a client cluster instance with the mandatory and the
/// download-tracking attributes for `config`.
pub fn client<const A: usize>(
    config: &ClientConfig,
    server: ExtendedAddress,
) -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(CLIENT_DEF, Role::Client);
    c.add_attribute(UPGRADE_SERVER_ID, &Value::Eui64(server.0))?;
    c.add_attribute(
        FILE_OFFSET,
        &Value::Uint {
            width: 4,
            value: u64::from(WILDCARD_U32),
        },
    )?;
    c.add_attribute(
        CURRENT_FILE_VERSION,
        &Value::Uint {
            width: 4,
            value: u64::from(config.file_version),
        },
    )?;
    c.add_attribute(
        DOWNLOADED_FILE_VERSION,
        &Value::Uint {
            width: 4,
            value: u64::from(WILDCARD_U32),
        },
    )?;
    c.add_attribute(IMAGE_UPGRADE_STATUS, &Value::Enum8(upgrade_status::NORMAL))?;
    c.add_attribute(
        MANUFACTURER_ID,
        &Value::Uint {
            width: 2,
            value: u64::from(config.manufacturer_code),
        },
    )?;
    c.add_attribute(
        IMAGE_TYPE_ID,
        &Value::Uint {
            width: 2,
            value: u64::from(config.image_type),
        },
    )?;
    c.add_attribute(MINIMUM_BLOCK_PERIOD, &Value::Uint { width: 2, value: 0 })?;
    c.add_attribute(
        UPGRADE_ACTIVATION_POLICY,
        &Value::Enum8(config.activation_policy),
    )?;
    Ok(c)
}

/// Builds a server cluster instance (no attributes).
pub fn server<const A: usize>() -> ClusterInstance<A> {
    ClusterInstance::new(SERVER_DEF, Role::Server)
}

// ------------------------------------------------------------------
// Server side (§11.13.4.4, §11.13.6.4, §11.13.9.4)
// ------------------------------------------------------------------

/// An image the server can serve.
pub trait ImageSource {
    /// The header of the image (identity, size, hardware range).
    fn header(&self) -> Header;
    /// Copies up to `out.len()` bytes from `offset` into `out`; returns
    /// the number copied (0 at or past the end).
    fn read(&self, offset: u32, out: &mut [u8]) -> usize;
}

/// The server's answer to a Query Next Image Request from a device
/// (`ieee`): the newest suitable image among `images` whose version
/// differs from the client's, or NO_IMAGE_AVAILABLE.
pub fn query_response(
    req: &QueryNextImageRequest,
    ieee: ExtendedAddress,
    images: &[&dyn ImageSource],
) -> QueryNextImageResponse {
    let mut best: Option<Header> = None;
    for img in images {
        let h = img.header();
        if !h.suits(
            req.manufacturer_code,
            req.image_type,
            req.hardware_version,
            ieee,
        ) || h.file_version == req.file_version
        {
            continue;
        }
        if best.is_none_or(|b| h.file_version > b.file_version) {
            best = Some(h);
        }
    }
    match best {
        Some(h) => QueryNextImageResponse {
            status: ZclStatus::Success,
            image: Some(ImageId {
                manufacturer_code: h.manufacturer_code,
                image_type: h.image_type,
                file_version: h.file_version,
            }),
            image_size: h.total_size,
        },
        None => QueryNextImageResponse {
            status: ZclStatus::NoImageAvailable,
            image: None,
            image_size: 0,
        },
    }
}

/// The server's Image Block Response for a request: the block from the
/// matching image (at most `max_block` and the client's maximum), ABORT
/// when the image is unknown. `buf` receives the data.
pub fn block_response<'a>(
    req: &ImageBlockRequest,
    images: &[&dyn ImageSource],
    max_block: u8,
    buf: &'a mut [u8],
) -> ImageBlockResponse<'a> {
    let Some(img) = images.iter().find(|i| {
        let h = i.header();
        h.manufacturer_code == req.image.manufacturer_code
            && h.image_type == req.image.image_type
            && h.file_version == req.image.file_version
    }) else {
        return ImageBlockResponse::Abort;
    };
    let want = usize::from(req.max_data_size.min(max_block)).min(buf.len());
    let n = img.read(req.file_offset, buf.get_mut(..want).unwrap_or(&mut []));
    ImageBlockResponse::Success {
        image: req.image,
        file_offset: req.file_offset,
        data: buf.get(..n).unwrap_or(&[]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MemImage {
        header: Header,
        bytes: heapless::Vec<u8, 512>,
    }

    impl ImageSource for MemImage {
        fn header(&self) -> Header {
            self.header
        }
        fn read(&self, offset: u32, out: &mut [u8]) -> usize {
            let start = usize::try_from(offset)
                .unwrap_or(usize::MAX)
                .min(self.bytes.len());
            let n = out.len().min(self.bytes.len() - start);
            out[..n].copy_from_slice(&self.bytes[start..start + n]);
            n
        }
    }

    fn image() -> MemImage {
        let mut string = [0u8; 32];
        string[..7].copy_from_slice(b"panweav");
        let payload: [u8; 100] = core::array::from_fn(|i| i as u8);
        let mut header = Header {
            version: HEADER_VERSION,
            length: 0,
            field_control: 0,
            manufacturer_code: 0x1234,
            image_type: 0x0001,
            file_version: 0x0200_0000,
            stack_version: 2,
            string,
            total_size: 0,
            security_credential_version: None,
            destination: None,
            hardware_versions: Some((0x0100, 0x01ff)),
        };
        header.total_size = 60 + 6 + 100;
        let mut bytes = heapless::Vec::new();
        let mut buf = [0u8; 64];
        let n = header.encode(&mut buf).unwrap();
        assert_eq!(n, 60);
        bytes.extend_from_slice(&buf[..n]).unwrap();
        bytes
            .extend_from_slice(&tag::UPGRADE_IMAGE.to_le_bytes())
            .unwrap();
        bytes.extend_from_slice(&100u32.to_le_bytes()).unwrap();
        bytes.extend_from_slice(&payload).unwrap();
        header.length = 60;
        header.field_control = field_control::HARDWARE_VERSIONS;
        MemImage { header, bytes }
    }

    #[test]
    fn header_and_sub_elements_round_trip() {
        let img = image();
        let h = Header::parse(&img.bytes).unwrap();
        assert_eq!(h, img.header);
        assert_eq!(h.string_text(), b"panweav");
        assert!(h.suits(0x1234, 1, Some(0x0110), ExtendedAddress(9)));
        assert!(!h.suits(0x1234, 1, Some(0x0200), ExtendedAddress(9)));
        assert!(!h.suits(0x1235, 1, None, ExtendedAddress(9)));
        let subs: heapless::Vec<_, 4> = SubElements(&img.bytes[60..]).collect();
        assert_eq!(subs.len(), 1);
        let e = subs[0].as_ref().unwrap();
        assert_eq!(e.tag, tag::UPGRADE_IMAGE);
        assert_eq!(e.data.len(), 100);
        assert!(Header::parse(&[0; 60]).is_err());
    }

    #[test]
    fn download_flow_between_client_and_server() {
        let img = image();
        let images: [&dyn ImageSource; 1] = [&img];
        let mut client = Client::new(ClientConfig {
            manufacturer_code: 0x1234,
            image_type: 1,
            file_version: 0x0100_0000,
            hardware_version: Some(0x0110),
            max_data_size: 48,
            activation_policy: activation_policy::SERVER,
        });
        let t0 = Instant::from_millis(0);
        // A broadcast notify for another manufacturer is ignored; one for
        // ours with jitter 50 passes on a draw of 30.
        let other = ImageNotify {
            query_jitter: 50,
            manufacturer_code: Some(0x9999),
            image_type: None,
            file_version: None,
        };
        assert_eq!(
            client.on_image_notify(&other, false, 30),
            ClientAction::None
        );
        let ours = ImageNotify {
            query_jitter: 50,
            manufacturer_code: Some(0x1234),
            image_type: Some(1),
            file_version: Some(0x0200_0000),
        };
        assert_eq!(client.on_image_notify(&ours, false, 80), ClientAction::None);
        let ClientAction::Query(q) = client.on_image_notify(&ours, false, 30) else {
            panic!("query expected");
        };
        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        q.encode(&mut w).unwrap();
        let n = w.position();
        let q2 = QueryNextImageRequest::parse(&buf[..n]).unwrap();
        assert_eq!(q2, q);
        // The server offers the image.
        let rsp = query_response(&q2, ExtendedAddress(1), &images);
        assert_eq!(rsp.status, ZclStatus::Success);
        assert_eq!(rsp.image_size, 166);
        let mut w = Writer::new(&mut buf);
        rsp.encode(&mut w).unwrap();
        let n = w.position();
        let rsp = QueryNextImageResponse::parse(&buf[..n]).unwrap();
        let ClientAction::RequestBlock { request, .. } = client.on_query_response(&rsp, t0) else {
            panic!("block request expected");
        };
        assert_eq!(request.file_offset, 0);
        // Blocks go back and forth until the file is complete.
        let mut received = heapless::Vec::<u8, 256>::new();
        let mut req = request;
        let mut rounds = 0;
        loop {
            rounds += 1;
            assert!(rounds < 10);
            let mut data = [0u8; 64];
            let block = block_response(&req, &images, 40, &mut data);
            let mut wire = [0u8; 80];
            let mut w = Writer::new(&mut wire);
            block.encode(&mut w).unwrap();
            let n = w.position();
            let block = ImageBlockResponse::parse(&wire[..n]).unwrap();
            let ClientAction::Store { offset, data } = client.on_block_response(&block, t0) else {
                panic!("store expected");
            };
            assert_eq!(offset as usize, received.len());
            received.extend_from_slice(data).unwrap();
            match client.next(t0) {
                ClientAction::RequestBlock { request, .. } => req = request,
                ClientAction::Verify { size, .. } => {
                    assert_eq!(size, 166);
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(rounds, 5, "40-byte blocks for 166 bytes");
        assert_eq!(received.as_slice(), img.bytes.as_slice());
        assert_eq!(client.upgrade_status(), upgrade_status::DOWNLOAD_COMPLETE);
        // Verified: the Upgrade End Request goes out; the server answers
        // "in 30 s".
        let ClientAction::UpgradeEnd(end) = client.finish(ZclStatus::Success) else {
            panic!("upgrade end expected");
        };
        assert_eq!(end.status, ZclStatus::Success);
        let rsp = UpgradeEndResponse {
            image: end.image,
            current_time: 0,
            upgrade_time: 30,
        };
        let a = client.on_upgrade_end_response(&rsp, t0);
        assert_eq!(
            a,
            ClientAction::Upgrade {
                image: end.image,
                at: Some(t0 + Duration::from_secs(30))
            }
        );
        assert_eq!(client.upgrade_status(), upgrade_status::COUNT_DOWN);
        // A wait response sets the rate limit and the retry time.
        let mut c2 = Client::new(client.config);
        c2.start_query();
        let _ = c2.on_query_response(
            &QueryNextImageResponse {
                status: ZclStatus::Success,
                image: Some(end.image),
                image_size: 166,
            },
            t0,
        );
        let wait = ImageBlockResponse::WaitForData {
            current_time: 0,
            request_time: 5,
            minimum_block_period: 250,
        };
        let ClientAction::RequestBlock {
            not_before,
            request,
        } = c2.on_block_response(&wait, t0)
        else {
            panic!();
        };
        assert_eq!(not_before, t0 + Duration::from_secs(5));
        assert_eq!(request.minimum_block_period, Some(250));
        assert_eq!(
            c2.on_block_response(&ImageBlockResponse::Abort, t0),
            ClientAction::None
        );
        assert_eq!(c2.phase, Phase::Normal);
        // Out-of-band activation refuses a timed upgrade.
        let mut c3 = Client::new(ClientConfig {
            activation_policy: activation_policy::OUT_OF_BAND,
            ..client.config
        });
        c3.phase = Phase::Ending { image: end.image };
        assert_eq!(
            c3.on_upgrade_end_response(&rsp, t0),
            ClientAction::Default(ZclStatus::NotAuthorized)
        );
        assert_eq!(
            c3.on_upgrade_end_response(
                &UpgradeEndResponse {
                    image: ImageId {
                        manufacturer_code: WILDCARD_U16,
                        image_type: WILDCARD_U16,
                        file_version: WILDCARD_U32
                    },
                    current_time: 0,
                    upgrade_time: WILDCARD_U32
                },
                t0
            ),
            ClientAction::Upgrade {
                image: end.image,
                at: None
            }
        );
        assert_eq!(
            c3.upgrade_status(),
            upgrade_status::WAITING_FOR_EXTERNAL_EVENT
        );
    }
}
