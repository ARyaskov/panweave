//! Device Management cluster (SE 1.4a Annex D.10): the supplier /
//! tenancy / backhaul / HAN control attribute identifiers, the event
//! configuration bitmap, every command codec (change of tenancy and
//! supplier, password delivery, Site ID and CIN updates, event
//! configuration set / get / report), a client-side [`EventConfig`]
//! table applying the four "apply by" selectors, and a client-side
//! [`Pending`] store that holds the timed changes, honours the
//! cancellation and provider-match rules and reports what is due.

use heapless::Vec;
use panweave_codec::{CodecError, Reader, Writer};
use panweave_types::{AttributeId, ClusterId, CommandId};
use panweave_zcl::attribute::{Access, AttributeDef};
use panweave_zcl::cluster::ClusterDef;
use panweave_zcl::types::DataType;

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0708);

/// Server attributes (Tables D-163, D-166, D-167, D-169).
pub mod server_attr {
    use super::*;

    /// `ProviderID`.
    pub const PROVIDER_ID: AttributeDef = AttributeDef::new(0x0100, DataType::Uint(4), Access::RO);
    /// `ProviderName` (octstr ≤ 16).
    pub const PROVIDER_NAME: AttributeDef =
        AttributeDef::new(0x0101, DataType::OctetString, Access::RO);
    /// `ProviderContactDetails` (octstr ≤ 19).
    pub const PROVIDER_CONTACT_DETAILS: AttributeDef =
        AttributeDef::new(0x0102, DataType::OctetString, Access::RO);
    /// `ProposedProviderID`.
    pub const PROPOSED_PROVIDER_ID: AttributeDef =
        AttributeDef::new(0x0110, DataType::Uint(4), Access::RO);
    /// `ProposedProviderName`.
    pub const PROPOSED_PROVIDER_NAME: AttributeDef =
        AttributeDef::new(0x0111, DataType::OctetString, Access::RO);
    /// `ProposedProviderChangeDate/Time`.
    pub const PROPOSED_PROVIDER_CHANGE_TIME: AttributeDef =
        AttributeDef::new(0x0112, DataType::UtcTime, Access::RO);
    /// `ProposedProviderChangeControl` (Table D-164).
    pub const PROPOSED_PROVIDER_CHANGE_CONTROL: AttributeDef =
        AttributeDef::new(0x0113, DataType::Bitmap(4), Access::RO);
    /// `ProposedProviderContactDetails`.
    pub const PROPOSED_PROVIDER_CONTACT_DETAILS: AttributeDef =
        AttributeDef::new(0x0114, DataType::OctetString, Access::RO);
    /// `ReceivedProviderID`.
    pub const RECEIVED_PROVIDER_ID: AttributeDef =
        AttributeDef::new(0x0120, DataType::Uint(4), Access::RO);
    /// `ReceivedProviderName`.
    pub const RECEIVED_PROVIDER_NAME: AttributeDef =
        AttributeDef::new(0x0121, DataType::OctetString, Access::RO);
    /// `ReceivedProviderContactDetails`.
    pub const RECEIVED_PROVIDER_CONTACT_DETAILS: AttributeDef =
        AttributeDef::new(0x0122, DataType::OctetString, Access::RO);
    /// `ReceivedProposedProviderID`.
    pub const RECEIVED_PROPOSED_PROVIDER_ID: AttributeDef =
        AttributeDef::new(0x0130, DataType::Uint(4), Access::RO);
    /// `ReceivedProposedProviderName`.
    pub const RECEIVED_PROPOSED_PROVIDER_NAME: AttributeDef =
        AttributeDef::new(0x0131, DataType::OctetString, Access::RO);
    /// `ReceivedProposedProviderChangeDate/Time`.
    pub const RECEIVED_PROPOSED_PROVIDER_CHANGE_TIME: AttributeDef =
        AttributeDef::new(0x0132, DataType::UtcTime, Access::RO);
    /// `ReceivedProposedProviderChangeControl`.
    pub const RECEIVED_PROPOSED_PROVIDER_CHANGE_CONTROL: AttributeDef =
        AttributeDef::new(0x0133, DataType::Bitmap(4), Access::RO);
    /// `ReceivedProposedProviderContactDetails`.
    pub const RECEIVED_PROPOSED_PROVIDER_CONTACT_DETAILS: AttributeDef =
        AttributeDef::new(0x0134, DataType::OctetString, Access::RO);
    /// `ChangeofTenancyUpdateDate/Time` (0xFFFFFFFF until one is known).
    pub const CHANGE_OF_TENANCY_UPDATE_TIME: AttributeDef =
        AttributeDef::new(0x0200, DataType::UtcTime, Access::RO);
    /// `ProposedTenancyChangeControl`.
    pub const PROPOSED_TENANCY_CHANGE_CONTROL: AttributeDef =
        AttributeDef::new(0x0201, DataType::Bitmap(4), Access::RO);
    /// `WANStatus` (Table D-168).
    pub const WAN_STATUS: AttributeDef = AttributeDef::new(0x0300, DataType::Enum8, Access::RO);
    /// `LowMediumThreshold`.
    pub const LOW_MEDIUM_THRESHOLD: AttributeDef =
        AttributeDef::new(0x0400, DataType::Uint(4), Access::RO);
    /// `MediumHighThreshold`.
    pub const MEDIUM_HIGH_THRESHOLD: AttributeDef =
        AttributeDef::new(0x0401, DataType::Uint(4), Access::RO);
}

/// Client attributes (Table D-175) and the event configuration sets
/// (Tables D-176 to D-184).
pub mod client_attr {
    use super::*;

    /// `ProviderID`.
    pub const PROVIDER_ID: AttributeDef = AttributeDef::new(0x0000, DataType::Uint(4), Access::RO);
    /// `ReceivedProviderID`.
    pub const RECEIVED_PROVIDER_ID: AttributeDef =
        AttributeDef::new(0x0010, DataType::Uint(4), Access::RO);

    /// Event configuration attribute sets (Table D-174).
    pub mod set {
        /// Price events.
        pub const PRICE: u8 = 0x01;
        /// Metering events.
        pub const METERING: u8 = 0x02;
        /// Messaging events.
        pub const MESSAGING: u8 = 0x03;
        /// Prepayment events.
        pub const PREPAYMENT: u8 = 0x04;
        /// Calendar events.
        pub const CALENDAR: u8 = 0x05;
        /// Device Management events.
        pub const DEVICE_MANAGEMENT: u8 = 0x06;
        /// Tunneling events.
        pub const TUNNELING: u8 = 0x07;
        /// OTA events.
        pub const OTA: u8 = 0x08;
    }

    /// The Event Group ID (`0xnnFF`) of an attribute set.
    pub const fn group_id(set: u8) -> u16 {
        ((set as u16) << 8) | 0x00ff
    }
}

/// `WANStatus` values (Table D-168).
pub mod wan_status {
    /// Connection to the WAN is not available.
    pub const NOT_AVAILABLE: u8 = 0x00;
    /// Connection to the WAN is available.
    pub const AVAILABLE: u8 = 0x01;
}

/// Change Control bits (Table D-164).
pub mod change_control {
    /// Trigger a pre-change snapshot.
    pub const PRE_SNAPSHOT: u32 = 1 << 0;
    /// Trigger a post-change snapshot.
    pub const POST_SNAPSHOT: u32 = 1 << 1;
    /// Reset the credit registers.
    pub const RESET_CREDIT_REGISTER: u32 = 1 << 2;
    /// Reset the debt registers.
    pub const RESET_DEBT_REGISTER: u32 = 1 << 3;
    /// Reset the billing periods.
    pub const RESET_BILLING_PERIOD: u32 = 1 << 4;
    /// Clear the tariff plan.
    pub const CLEAR_TARIFF_PLAN: u32 = 1 << 5;
    /// Clear the standing charge.
    pub const CLEAR_STANDING_CHARGE: u32 = 1 << 6;
    /// Stop publishing historical load profile data to the HAN.
    pub const BLOCK_HISTORICAL_LOAD_PROFILE: u32 = 1 << 7;
    /// Clear historical load profile data.
    pub const CLEAR_HISTORICAL_LOAD_PROFILE: u32 = 1 << 8;
    /// Clear consumer IHD data.
    pub const CLEAR_IHD_CONSUMER_DATA: u32 = 1 << 9;
    /// Clear supplier IHD data.
    pub const CLEAR_IHD_SUPPLIER_DATA: u32 = 1 << 10;
    /// Contactor state field mask (bits 11–12, Table D-165).
    pub const CONTACTOR_STATE_MASK: u32 = 0b11 << 11;
    /// Clear the transaction log.
    pub const CLEAR_TRANSACTION_LOG: u32 = 1 << 13;
    /// Clear the prepayment data.
    pub const CLEAR_PREPAYMENT_DATA: u32 = 1 << 14;

    /// The contactor state requested by a change control value.
    pub const fn contactor_state(control: u32) -> ContactorState {
        match (control >> 11) & 0b11 {
            0b00 => ContactorState::Off,
            0b01 => ContactorState::OffArmed,
            0b10 => ContactorState::On,
            _ => ContactorState::Unchanged,
        }
    }

    /// Contactor state after the change (Table D-165).
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub enum ContactorState {
        /// Supply off.
        Off,
        /// Supply off, armed.
        OffArmed,
        /// Supply on (where the market allows it).
        On,
        /// Unchanged.
        Unchanged,
    }
}

/// Event Configuration bits (Table D-177).
pub mod event_config {
    /// Mask of the log selection (bits 0–2).
    pub const LOG_MASK: u8 = 0x07;
    /// Do not log.
    pub const NO_LOG: u8 = 0;
    /// Log as tamper.
    pub const LOG_TAMPER: u8 = 1;
    /// Log as fault.
    pub const LOG_FAULT: u8 = 2;
    /// Log as general event.
    pub const LOG_GENERAL: u8 = 3;
    /// Log as security event.
    pub const LOG_SECURITY: u8 = 4;
    /// Log as network event.
    pub const LOG_NETWORK: u8 = 5;
    /// Push the event to the WAN.
    pub const PUSH_TO_WAN: u8 = 0x08;
    /// Push the event to the HAN.
    pub const PUSH_TO_HAN: u8 = 0x10;
    /// Raise a Zigbee alarm.
    pub const RAISE_ALARM_ZIGBEE: u8 = 0x20;
    /// Raise a physical alarm.
    pub const RAISE_ALARM_PHYSICAL: u8 = 0x40;
}

/// Password types (Table D-172).
pub mod password_type {
    /// Service menu access.
    pub const SERVICE: u8 = 0x01;
    /// Consumer menu access.
    pub const CONSUMER: u8 = 0x02;
    /// Password 3.
    pub const PASSWORD_3: u8 = 0x03;
    /// Password 4.
    pub const PASSWORD_4: u8 = 0x04;
}

/// Client → server: GetChangeOfTenancy (no payload).
pub const CMD_GET_CHANGE_OF_TENANCY: CommandId = CommandId(0x00);
/// Client → server: GetChangeOfSupplier (no payload).
pub const CMD_GET_CHANGE_OF_SUPPLIER: CommandId = CommandId(0x01);
/// Client → server: RequestNewPassword.
pub const CMD_REQUEST_NEW_PASSWORD: CommandId = CommandId(0x02);
/// Client → server: GetSiteID (no payload).
pub const CMD_GET_SITE_ID: CommandId = CommandId(0x03);
/// Client → server: ReportEventConfiguration.
pub const CMD_REPORT_EVENT_CONFIGURATION: CommandId = CommandId(0x04);
/// Client → server: GetCIN (no payload).
pub const CMD_GET_CIN: CommandId = CommandId(0x05);
/// Server → client: PublishChangeOfTenancy.
pub const CMD_PUBLISH_CHANGE_OF_TENANCY: CommandId = CommandId(0x00);
/// Server → client: PublishChangeOfSupplier.
pub const CMD_PUBLISH_CHANGE_OF_SUPPLIER: CommandId = CommandId(0x01);
/// Server → client: RequestNewPasswordResponse.
pub const CMD_REQUEST_NEW_PASSWORD_RESPONSE: CommandId = CommandId(0x02);
/// Server → client: UpdateSiteID.
pub const CMD_UPDATE_SITE_ID: CommandId = CommandId(0x03);
/// Server → client: SetEventConfiguration.
pub const CMD_SET_EVENT_CONFIGURATION: CommandId = CommandId(0x04);
/// Server → client: GetEventConfiguration.
pub const CMD_GET_EVENT_CONFIGURATION: CommandId = CommandId(0x05);
/// Server → client: UpdateCIN.
pub const CMD_UPDATE_CIN: CommandId = CommandId(0x06);

/// Server cluster definition.
pub const SERVER_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[
        CMD_GET_CHANGE_OF_TENANCY,
        CMD_GET_CHANGE_OF_SUPPLIER,
        CMD_REQUEST_NEW_PASSWORD,
        CMD_GET_SITE_ID,
        CMD_REPORT_EVENT_CONFIGURATION,
        CMD_GET_CIN,
    ],
    generated: &[
        CMD_PUBLISH_CHANGE_OF_TENANCY,
        CMD_PUBLISH_CHANGE_OF_SUPPLIER,
        CMD_REQUEST_NEW_PASSWORD_RESPONSE,
        CMD_UPDATE_SITE_ID,
        CMD_SET_EVENT_CONFIGURATION,
        CMD_GET_EVENT_CONFIGURATION,
        CMD_UPDATE_CIN,
    ],
};

/// Client cluster definition.
pub const CLIENT_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: SERVER_DEF.generated,
    generated: SERVER_DEF.received,
};

/// Implementation time meaning "now".
pub const IMMEDIATELY: u32 = 0;
/// Implementation time cancelling a pending command.
pub const CANCEL: u32 = 0xffff_ffff;
/// Event ID selecting every event.
pub const ALL_EVENTS: u16 = 0xffff;
/// Longest provider name.
pub const MAX_NAME: usize = 16;
/// Longest contact details.
pub const MAX_CONTACT: usize = 19;
/// Longest Site ID.
pub const MAX_SITE_ID: usize = 32;
/// Longest Customer ID Number.
pub const MAX_CIN: usize = 24;
/// Longest password.
pub const MAX_PASSWORD: usize = 10;
/// Event IDs in one Apply-by-List command.
pub const MAX_LIST: usize = 16;
/// Configuration entries per ReportEventConfiguration command.
pub const REPORT_ENTRIES: usize = 16;

fn read_octstr<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], CodecError> {
    let n = r.u8()?;
    r.bytes(usize::from(n))
}

fn write_octstr(w: &mut Writer<'_>, s: &[u8]) -> Result<(), CodecError> {
    w.u8(
        u8::try_from(s.len()).map_err(|_| CodecError::Unrepresentable {
            field: "octet string",
        })?,
    )?;
    w.bytes(s)
}

/// PublishChangeOfTenancy (D.10.2.4.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PublishChangeOfTenancy {
    /// Provider identifier.
    pub provider_id: u32,
    /// Issuer event identifier.
    pub issuer_event_id: u32,
    /// Tariff type (low nibble, Table D-108).
    pub tariff_type: u8,
    /// Implementation time (`CANCEL` cancels the pending one).
    pub implementation_time: u32,
    /// Change control (Table D-164).
    pub change_control: u32,
}

impl PublishChangeOfTenancy {
    /// Encoded length.
    pub const LEN: usize = 17;

    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(PublishChangeOfTenancy {
            provider_id: r.u32_le()?,
            issuer_event_id: r.u32_le()?,
            tariff_type: r.u8()?,
            implementation_time: r.u32_le()?,
            change_control: r.u32_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u8(self.tariff_type)?;
        w.u32_le(self.implementation_time)?;
        w.u32_le(self.change_control)
    }
}

/// PublishChangeOfSupplier (D.10.2.4.2).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PublishChangeOfSupplier {
    /// Current provider identifier.
    pub current_provider_id: u32,
    /// Issuer event identifier.
    pub issuer_event_id: u32,
    /// Tariff type.
    pub tariff_type: u8,
    /// Proposed provider identifier.
    pub proposed_provider_id: u32,
    /// Implementation time (`CANCEL` cancels the pending one).
    pub implementation_time: u32,
    /// Change control.
    pub change_control: u32,
    /// Proposed provider name.
    pub name: Vec<u8, MAX_NAME>,
    /// Proposed provider contact details.
    pub contact: Vec<u8, MAX_CONTACT>,
}

impl PublishChangeOfSupplier {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(PublishChangeOfSupplier {
            current_provider_id: r.u32_le()?,
            issuer_event_id: r.u32_le()?,
            tariff_type: r.u8()?,
            proposed_provider_id: r.u32_le()?,
            implementation_time: r.u32_le()?,
            change_control: r.u32_le()?,
            name: Vec::from_slice(read_octstr(&mut r)?).map_err(|_| {
                CodecError::Unrepresentable {
                    field: "provider name",
                }
            })?,
            contact: Vec::from_slice(read_octstr(&mut r)?).map_err(|_| {
                CodecError::Unrepresentable {
                    field: "contact details",
                }
            })?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.current_provider_id)?;
        w.u32_le(self.issuer_event_id)?;
        w.u8(self.tariff_type)?;
        w.u32_le(self.proposed_provider_id)?;
        w.u32_le(self.implementation_time)?;
        w.u32_le(self.change_control)?;
        write_octstr(w, &self.name)?;
        write_octstr(w, &self.contact)
    }
}

/// RequestNewPassword (D.10.2.3.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RequestNewPassword {
    /// Password type (Table D-172).
    pub password_type: u8,
}

impl RequestNewPassword {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(RequestNewPassword {
            password_type: r.u8()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.password_type)
    }
}

/// A password; its `Debug` output is redacted.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Password(pub Vec<u8, MAX_PASSWORD>);

impl core::fmt::Debug for Password {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Password {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "Password(<redacted>)");
    }
}

impl Password {
    /// Constant-time comparison with a candidate.
    pub fn matches(&self, candidate: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        self.0.len() == candidate.len() && bool::from(self.0.ct_eq(candidate))
    }
}

/// RequestNewPasswordResponse (D.10.2.4.3).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RequestNewPasswordResponse {
    /// Issuer event identifier.
    pub issuer_event_id: u32,
    /// Implementation time.
    pub implementation_time: u32,
    /// Validity in minutes (0: until changed).
    pub duration_minutes: u16,
    /// Password type.
    pub password_type: u8,
    /// The password.
    pub password: Password,
}

impl RequestNewPasswordResponse {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(RequestNewPasswordResponse {
            issuer_event_id: r.u32_le()?,
            implementation_time: r.u32_le()?,
            duration_minutes: r.u16_le()?,
            password_type: r.u8()?,
            password: Password(
                Vec::from_slice(read_octstr(&mut r)?)
                    .map_err(|_| CodecError::Unrepresentable { field: "password" })?,
            ),
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.implementation_time)?;
        w.u16_le(self.duration_minutes)?;
        w.u8(self.password_type)?;
        write_octstr(w, &self.password.0)
    }
}

/// UpdateSiteID (D.10.2.4.4).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct UpdateSiteId {
    /// Issuer event identifier.
    pub issuer_event_id: u32,
    /// When to apply (`IMMEDIATELY`, or `CANCEL`).
    pub site_id_time: u32,
    /// Provider identifier.
    pub provider_id: u32,
    /// The Site ID.
    pub site_id: Vec<u8, MAX_SITE_ID>,
}

impl UpdateSiteId {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(UpdateSiteId {
            issuer_event_id: r.u32_le()?,
            site_id_time: r.u32_le()?,
            provider_id: r.u32_le()?,
            site_id: Vec::from_slice(read_octstr(&mut r)?)
                .map_err(|_| CodecError::Unrepresentable { field: "site id" })?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.site_id_time)?;
        w.u32_le(self.provider_id)?;
        write_octstr(w, &self.site_id)
    }
}

/// UpdateCIN (D.10.2.4.7).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct UpdateCin {
    /// Issuer event identifier.
    pub issuer_event_id: u32,
    /// When to apply (`IMMEDIATELY`, or `CANCEL`).
    pub implementation_time: u32,
    /// Provider identifier (must match the current one).
    pub provider_id: u32,
    /// The Customer ID Number.
    pub cin: Vec<u8, MAX_CIN>,
}

impl UpdateCin {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(UpdateCin {
            issuer_event_id: r.u32_le()?,
            implementation_time: r.u32_le()?,
            provider_id: r.u32_le()?,
            cin: Vec::from_slice(read_octstr(&mut r)?)
                .map_err(|_| CodecError::Unrepresentable { field: "cin" })?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.implementation_time)?;
        w.u32_le(self.provider_id)?;
        write_octstr(w, &self.cin)
    }
}

/// The events a SetEventConfiguration applies to (Table D-173).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Selector {
    /// Listed event ids.
    List(Vec<u16, MAX_LIST>),
    /// Every event of an attribute set (`0xnnFF`).
    Group(u16),
    /// Every event currently logged to a log (bits 0–2 value).
    Log(u8),
    /// Every event whose configuration equals the value.
    Matching(u8),
}

/// SetEventConfiguration (D.10.2.4.5).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SetEventConfiguration {
    /// Issuer event identifier.
    pub issuer_event_id: u32,
    /// When the configuration applies.
    pub start_time: u32,
    /// The new configuration (Table D-177).
    pub configuration: u8,
    /// Which events.
    pub selector: Selector,
}

impl SetEventConfiguration {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let issuer_event_id = r.u32_le()?;
        let start_time = r.u32_le()?;
        let configuration = r.u8()?;
        let selector = match r.u8()? {
            0x00 => {
                let n = r.u8()?;
                let mut ids = Vec::new();
                for _ in 0..n {
                    ids.push(r.u16_le()?)
                        .map_err(|_| CodecError::Unrepresentable {
                            field: "event list",
                        })?;
                }
                Selector::List(ids)
            }
            0x01 => Selector::Group(r.u16_le()?),
            0x02 => Selector::Log(r.u8()?),
            0x03 => Selector::Matching(r.u8()?),
            _ => {
                return Err(CodecError::Unrepresentable {
                    field: "configuration control",
                });
            }
        };
        Ok(SetEventConfiguration {
            issuer_event_id,
            start_time,
            configuration,
            selector,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u32_le(self.issuer_event_id)?;
        w.u32_le(self.start_time)?;
        w.u8(self.configuration)?;
        match &self.selector {
            Selector::List(ids) => {
                w.u8(0x00)?;
                w.u8(
                    u8::try_from(ids.len()).map_err(|_| CodecError::Unrepresentable {
                        field: "event list",
                    })?,
                )?;
                for id in ids {
                    w.u16_le(*id)?;
                }
                Ok(())
            }
            Selector::Group(g) => {
                w.u8(0x01)?;
                w.u16_le(*g)
            }
            Selector::Log(l) => {
                w.u8(0x02)?;
                w.u8(*l)
            }
            Selector::Matching(m) => {
                w.u8(0x03)?;
                w.u8(*m)
            }
        }
    }
}

/// GetEventConfiguration (D.10.2.4.6): one event, a group (`0xnnFF`) or
/// `ALL_EVENTS`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetEventConfiguration {
    /// Event identifier.
    pub event_id: u16,
}

impl GetEventConfiguration {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        Ok(GetEventConfiguration {
            event_id: r.u16_le()?,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u16_le(self.event_id)
    }
}

/// ReportEventConfiguration (D.10.2.3.5).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReportEventConfiguration {
    /// Command index.
    pub command_index: u8,
    /// Total commands.
    pub total_commands: u8,
    /// (event id, configuration) pairs.
    pub entries: Vec<(u16, u8), REPORT_ENTRIES>,
}

impl ReportEventConfiguration {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        let command_index = r.u8()?;
        let total_commands = r.u8()?;
        let mut entries = Vec::new();
        while !r.is_empty() {
            let e = (r.u16_le()?, r.u8()?);
            entries
                .push(e)
                .map_err(|_| CodecError::Unrepresentable { field: "entries" })?;
        }
        Ok(ReportEventConfiguration {
            command_index,
            total_commands,
            entries,
        })
    }

    /// Encodes the payload.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), CodecError> {
        w.u8(self.command_index)?;
        w.u8(self.total_commands)?;
        for (id, cfg) in &self.entries {
            w.u16_le(*id)?;
            w.u8(*cfg)?;
        }
        Ok(())
    }
}

/// Client-side event configuration table: the supported event ids and
/// their bitmaps (the `0x01xx`–`0x08xx` attributes).
#[derive(Clone, Debug, Default)]
pub struct EventConfig<const N: usize> {
    entries: Vec<(u16, u8), N>,
    /// Issuer event id of the last accepted SetEventConfiguration.
    pub issuer_event_id: u32,
}

impl<const N: usize> EventConfig<N> {
    /// An empty table.
    pub const fn new() -> Self {
        EventConfig {
            entries: Vec::new(),
            issuer_event_id: 0,
        }
    }

    /// Declares a supported event with its default configuration;
    /// `false` when the table is full.
    pub fn support(&mut self, event_id: u16, configuration: u8) -> bool {
        if let Some(e) = self.entries.iter_mut().find(|e| e.0 == event_id) {
            e.1 = configuration;
            return true;
        }
        self.entries.push((event_id, configuration)).is_ok()
    }

    /// The configuration of an event, when supported.
    pub fn get(&self, event_id: u16) -> Option<u8> {
        self.entries.iter().find(|e| e.0 == event_id).map(|e| e.1)
    }

    /// The configured attribute values, as `AttributeId`s.
    pub fn entries(&self) -> impl Iterator<Item = (AttributeId, u8)> + '_ {
        self.entries.iter().map(|e| (AttributeId(e.0), e.1))
    }

    /// Applies a SetEventConfiguration; the number of events changed
    /// (0 when nothing matched, which the caller may report as
    /// NOT_FOUND).
    pub fn set(&mut self, cmd: &SetEventConfiguration) -> usize {
        let mut n = 0;
        for e in self.entries.iter_mut() {
            let hit = match &cmd.selector {
                Selector::List(ids) => ids.contains(&e.0),
                Selector::Group(g) => (e.0 | 0x00ff) == *g,
                Selector::Log(l) => e.1 & event_config::LOG_MASK == (*l & event_config::LOG_MASK),
                Selector::Matching(m) => e.1 == *m,
            };
            if hit {
                e.1 = cmd.configuration;
                n += 1;
            }
        }
        if n > 0 {
            self.issuer_event_id = cmd.issuer_event_id;
        }
        n
    }

    /// Answers a GetEventConfiguration with the report fragments;
    /// `None` when none of the requested events is supported.
    pub fn report(&self, req: &GetEventConfiguration) -> Option<Vec<ReportEventConfiguration, 8>> {
        let selected = self.entries.iter().filter(|e| {
            req.event_id == ALL_EVENTS || req.event_id == e.0 || (e.0 | 0x00ff) == req.event_id
        });
        let total = selected.clone().count();
        if total == 0 {
            return None;
        }
        let total_commands = u8::try_from(total.div_ceil(REPORT_ENTRIES)).unwrap_or(u8::MAX);
        let mut out = Vec::new();
        let mut current = ReportEventConfiguration {
            command_index: 0,
            total_commands,
            entries: Vec::new(),
        };
        for e in selected {
            if current.entries.is_full() {
                let index = current.command_index + 1;
                if out.push(current).is_err() {
                    return Some(out);
                }
                current = ReportEventConfiguration {
                    command_index: index,
                    total_commands,
                    entries: Vec::new(),
                };
            }
            let _ = current.entries.push(*e);
        }
        let _ = out.push(current);
        Some(out)
    }
}

/// A change that fell due (from [`Pending::poll`]).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Due {
    /// The change of tenancy with its control bits.
    Tenancy {
        /// Provider.
        provider_id: u32,
        /// Change control.
        change_control: u32,
    },
    /// The change of supplier.
    Supplier {
        /// The new provider.
        provider_id: u32,
        /// Change control.
        change_control: u32,
        /// Provider name.
        name: Vec<u8, MAX_NAME>,
        /// Contact details.
        contact: Vec<u8, MAX_CONTACT>,
    },
    /// The new Site ID.
    SiteId(Vec<u8, MAX_SITE_ID>),
    /// The new Customer ID Number.
    Cin(Vec<u8, MAX_CIN>),
}

/// Why a command was refused, as the Default Response status.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Refusal {
    /// Provider id does not match the current one (NOT_AUTHORIZED).
    NotAuthorized,
    /// A cancellation named an unknown pending command (NOT_FOUND).
    NotFound,
    /// Older than the pending information (SUCCESS, ignored).
    Stale,
}

/// Client-side store of pending timed changes (D.10.2.4.1.4,
/// D.10.2.4.2.4, D.10.2.4.4.2, D.10.2.4.7.2).
#[derive(Clone, Debug)]
pub struct Pending {
    /// The current `ProviderID`.
    pub provider_id: u32,
    tenancy: Option<PublishChangeOfTenancy>,
    supplier: Option<PublishChangeOfSupplier>,
    site_id: Option<UpdateSiteId>,
    cin: Option<UpdateCin>,
}

impl Pending {
    /// No pending changes for `provider_id`.
    pub const fn new(provider_id: u32) -> Self {
        Pending {
            provider_id,
            tenancy: None,
            supplier: None,
            site_id: None,
            cin: None,
        }
    }

    /// `ChangeofTenancyUpdateDate/Time` (0xFFFFFFFF when none).
    pub fn tenancy_update_time(&self) -> u32 {
        self.tenancy.map_or(CANCEL, |t| t.implementation_time)
    }

    /// `ProposedTenancyChangeControl` (0 when none).
    pub fn tenancy_change_control(&self) -> u32 {
        self.tenancy.map_or(0, |t| t.change_control)
    }

    /// The pending change of supplier, for `ProposedProvider*`.
    pub fn supplier(&self) -> Option<&PublishChangeOfSupplier> {
        self.supplier.as_ref()
    }

    /// The pending tenancy change.
    pub fn tenancy(&self) -> Option<&PublishChangeOfTenancy> {
        self.tenancy.as_ref()
    }

    /// Applies a PublishChangeOfTenancy.
    pub fn on_tenancy(&mut self, p: &PublishChangeOfTenancy) -> Result<(), Refusal> {
        if p.implementation_time == CANCEL {
            return match self.tenancy {
                Some(t)
                    if t.provider_id == p.provider_id && t.issuer_event_id == p.issuer_event_id =>
                {
                    self.tenancy = None;
                    Ok(())
                }
                _ => Err(Refusal::NotFound),
            };
        }
        if self
            .tenancy
            .is_some_and(|t| t.issuer_event_id > p.issuer_event_id)
        {
            return Err(Refusal::Stale);
        }
        self.tenancy = Some(*p);
        Ok(())
    }

    /// Applies a PublishChangeOfSupplier.
    pub fn on_supplier(&mut self, p: &PublishChangeOfSupplier) -> Result<(), Refusal> {
        if p.implementation_time == CANCEL {
            return match &self.supplier {
                Some(s)
                    if s.current_provider_id == p.current_provider_id
                        && s.issuer_event_id == p.issuer_event_id =>
                {
                    self.supplier = None;
                    Ok(())
                }
                _ => Err(Refusal::NotFound),
            };
        }
        if self
            .supplier
            .as_ref()
            .is_some_and(|s| s.issuer_event_id > p.issuer_event_id)
        {
            return Err(Refusal::Stale);
        }
        self.supplier = Some(p.clone());
        Ok(())
    }

    /// Applies an UpdateSiteID; `Some` with the value when it applies
    /// immediately.
    pub fn on_site_id(&mut self, u: &UpdateSiteId) -> Result<Option<Due>, Refusal> {
        if u.site_id_time == CANCEL {
            return match &self.site_id {
                Some(s)
                    if s.provider_id == u.provider_id && s.issuer_event_id == u.issuer_event_id =>
                {
                    self.site_id = None;
                    Ok(None)
                }
                _ => Err(Refusal::NotFound),
            };
        }
        if u.site_id_time == IMMEDIATELY {
            return Ok(Some(Due::SiteId(u.site_id.clone())));
        }
        if self
            .site_id
            .as_ref()
            .is_some_and(|s| s.issuer_event_id > u.issuer_event_id)
        {
            return Err(Refusal::Stale);
        }
        self.site_id = Some(u.clone());
        Ok(None)
    }

    /// Applies an UpdateCIN (the provider must be the current one).
    pub fn on_cin(&mut self, u: &UpdateCin) -> Result<Option<Due>, Refusal> {
        if u.provider_id != self.provider_id {
            return Err(Refusal::NotAuthorized);
        }
        if u.implementation_time == CANCEL {
            return match &self.cin {
                Some(c) if c.issuer_event_id == u.issuer_event_id => {
                    self.cin = None;
                    Ok(None)
                }
                _ => Err(Refusal::NotFound),
            };
        }
        if u.implementation_time == IMMEDIATELY {
            return Ok(Some(Due::Cin(u.cin.clone())));
        }
        if self
            .cin
            .as_ref()
            .is_some_and(|c| c.issuer_event_id > u.issuer_event_id)
        {
            return Err(Refusal::Stale);
        }
        self.cin = Some(u.clone());
        Ok(None)
    }

    /// Collects the changes whose time has come. A supplier change
    /// also moves `provider_id`.
    pub fn poll(&mut self, now: u32, out: &mut Vec<Due, 4>) {
        if let Some(t) = self.tenancy
            && t.implementation_time <= now
        {
            let _ = out.push(Due::Tenancy {
                provider_id: t.provider_id,
                change_control: t.change_control,
            });
            self.tenancy = None;
        }
        if self
            .supplier
            .as_ref()
            .is_some_and(|s| s.implementation_time <= now)
            && let Some(s) = self.supplier.take()
        {
            self.provider_id = s.proposed_provider_id;
            let _ = out.push(Due::Supplier {
                provider_id: s.proposed_provider_id,
                change_control: s.change_control,
                name: s.name,
                contact: s.contact,
            });
        }
        if self.site_id.as_ref().is_some_and(|s| s.site_id_time <= now)
            && let Some(s) = self.site_id.take()
        {
            let _ = out.push(Due::SiteId(s.site_id));
        }
        if self
            .cin
            .as_ref()
            .is_some_and(|c| c.implementation_time <= now)
            && let Some(c) = self.cin.take()
        {
            let _ = out.push(Due::Cin(c.cin));
        }
    }

    /// The next time [`Pending::poll`] produces something.
    pub fn next_deadline(&self) -> Option<u32> {
        [
            self.tenancy.map(|t| t.implementation_time),
            self.supplier.as_ref().map(|s| s.implementation_time),
            self.site_id.as_ref().map(|s| s.site_id_time),
            self.cin.as_ref().map(|c| c.implementation_time),
        ]
        .into_iter()
        .flatten()
        .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v<const N: usize>(s: &[u8]) -> Vec<u8, N> {
        Vec::from_slice(s).unwrap()
    }

    #[test]
    fn codecs_round_trip() {
        let mut buf = [0u8; 128];
        let t = PublishChangeOfTenancy {
            provider_id: 1,
            issuer_event_id: 2,
            tariff_type: 0,
            implementation_time: 1000,
            change_control: change_control::PRE_SNAPSHOT | (0b01 << 11),
        };
        let mut w = Writer::new(&mut buf);
        t.encode(&mut w).unwrap();
        assert_eq!(w.position(), PublishChangeOfTenancy::LEN);
        assert_eq!(PublishChangeOfTenancy::parse(&buf[..17]).unwrap(), t);
        assert_eq!(
            change_control::contactor_state(t.change_control),
            change_control::ContactorState::OffArmed
        );

        let s = PublishChangeOfSupplier {
            current_provider_id: 1,
            issuer_event_id: 3,
            tariff_type: 0,
            proposed_provider_id: 9,
            implementation_time: 2000,
            change_control: 0,
            name: v(b"NewCo"),
            contact: v(b"0800 000"),
        };
        let mut w = Writer::new(&mut buf);
        s.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(n, 21 + 6 + 9);
        assert_eq!(PublishChangeOfSupplier::parse(&buf[..n]).unwrap(), s);

        let p = RequestNewPasswordResponse {
            issuer_event_id: 4,
            implementation_time: 0,
            duration_minutes: 60,
            password_type: password_type::CONSUMER,
            password: Password(v(b"1234")),
        };
        let mut w = Writer::new(&mut buf);
        p.encode(&mut w).unwrap();
        let n = w.position();
        let back = RequestNewPasswordResponse::parse(&buf[..n]).unwrap();
        assert_eq!(back, p);
        assert!(back.password.matches(b"1234") && !back.password.matches(b"12345"));
        {
            struct Sink(usize, bool);
            impl core::fmt::Write for Sink {
                fn write_str(&mut self, s: &str) -> core::fmt::Result {
                    self.0 += s.len();
                    self.1 |= s.contains("1234");
                    Ok(())
                }
            }
            use core::fmt::Write as _;
            let mut sink = Sink(0, false);
            core::write!(sink, "{:?}", back.password).unwrap();
            assert!(sink.0 > 0 && !sink.1, "password must be redacted");
        }

        let u = UpdateSiteId {
            issuer_event_id: 5,
            site_id_time: 0,
            provider_id: 1,
            site_id: v(b"SITE-1"),
        };
        let mut w = Writer::new(&mut buf);
        u.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(UpdateSiteId::parse(&buf[..n]).unwrap(), u);
        let c = UpdateCin {
            issuer_event_id: 6,
            implementation_time: 0,
            provider_id: 1,
            cin: v(b"C-42"),
        };
        let mut w = Writer::new(&mut buf);
        c.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(UpdateCin::parse(&buf[..n]).unwrap(), c);

        for sel in [
            Selector::List(Vec::from_slice(&[0x0100, 0x0203]).unwrap()),
            Selector::Group(client_attr::group_id(client_attr::set::METERING)),
            Selector::Log(event_config::LOG_TAMPER),
            Selector::Matching(0x13),
        ] {
            let cmd = SetEventConfiguration {
                issuer_event_id: 7,
                start_time: 0,
                configuration: event_config::LOG_SECURITY | event_config::PUSH_TO_HAN,
                selector: sel,
            };
            let mut w = Writer::new(&mut buf);
            cmd.encode(&mut w).unwrap();
            let n = w.position();
            assert_eq!(SetEventConfiguration::parse(&buf[..n]).unwrap(), cmd);
        }
        assert!(SetEventConfiguration::parse(&[0; 11]).is_ok());
        assert!(SetEventConfiguration::parse(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0]).is_err());
        let g = GetEventConfiguration {
            event_id: ALL_EVENTS,
        };
        let mut w = Writer::new(&mut buf);
        g.encode(&mut w).unwrap();
        assert_eq!(GetEventConfiguration::parse(&buf[..2]).unwrap(), g);
        let r = ReportEventConfiguration {
            command_index: 0,
            total_commands: 1,
            entries: Vec::from_slice(&[(0x0100, 0x03), (0x0201, 0x11)]).unwrap(),
        };
        let mut w = Writer::new(&mut buf);
        r.encode(&mut w).unwrap();
        let n = w.position();
        assert_eq!(ReportEventConfiguration::parse(&buf[..n]).unwrap(), r);
        let mut w = Writer::new(&mut buf);
        RequestNewPassword { password_type: 1 }
            .encode(&mut w)
            .unwrap();
        assert_eq!(
            RequestNewPassword::parse(&buf[..1]).unwrap().password_type,
            1
        );
    }

    #[test]
    fn event_configuration_selectors_and_reports() {
        let mut cfg: EventConfig<40> = EventConfig::new();
        for i in 0..20u16 {
            assert!(cfg.support(0x0200 + i, event_config::LOG_GENERAL));
        }
        assert!(cfg.support(0x0100, event_config::LOG_TAMPER));
        assert!(cfg.support(0x0101, event_config::NO_LOG));
        let set = |sel: Selector, conf: u8| SetEventConfiguration {
            issuer_event_id: 1,
            start_time: 0,
            configuration: conf,
            selector: sel,
        };
        // By list.
        assert_eq!(
            cfg.set(&set(
                Selector::List(Vec::from_slice(&[0x0100, 0x0999]).unwrap()),
                0x08 | event_config::LOG_SECURITY
            )),
            1
        );
        assert_eq!(cfg.get(0x0100), Some(0x0c));
        // By log: everything logged as general → tamper + HAN.
        assert_eq!(
            cfg.set(&set(Selector::Log(event_config::LOG_GENERAL), 0x11)),
            20
        );
        // By matching value.
        assert_eq!(cfg.set(&set(Selector::Matching(0x11), 0x12)), 20);
        // By group: the price set.
        assert_eq!(
            cfg.set(&set(
                Selector::Group(client_attr::group_id(client_attr::set::PRICE)),
                0x01
            )),
            2
        );
        assert_eq!(cfg.get(0x0101), Some(0x01));
        // Nothing matched.
        assert_eq!(cfg.set(&set(Selector::Group(0x07ff), 0x01)), 0);
        // Reports: all events split into two commands.
        let all = cfg
            .report(&GetEventConfiguration {
                event_id: ALL_EVENTS,
            })
            .unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!((all[0].entries.len(), all[1].entries.len()), (16, 6));
        assert_eq!((all[1].command_index, all[1].total_commands), (1, 2));
        let group = cfg
            .report(&GetEventConfiguration {
                event_id: client_attr::group_id(client_attr::set::METERING),
            })
            .unwrap();
        assert_eq!(group.len(), 2);
        assert_eq!(group[0].entries.len() + group[1].entries.len(), 20);
        let one = cfg
            .report(&GetEventConfiguration { event_id: 0x0100 })
            .unwrap();
        assert_eq!(one[0].entries[..], [(0x0100, 0x01)]);
        assert!(
            cfg.report(&GetEventConfiguration { event_id: 0x0300 })
                .is_none()
        );
        assert_eq!(cfg.entries().count(), 22);
    }

    #[test]
    fn pending_changes_apply_and_cancel() {
        let mut p = Pending::new(1);
        assert_eq!(p.tenancy_update_time(), CANCEL);
        let t = PublishChangeOfTenancy {
            provider_id: 1,
            issuer_event_id: 10,
            tariff_type: 0,
            implementation_time: 5000,
            change_control: change_control::CLEAR_IHD_CONSUMER_DATA,
        };
        p.on_tenancy(&t).unwrap();
        assert_eq!(p.tenancy_update_time(), 5000);
        assert_eq!(
            p.on_tenancy(&PublishChangeOfTenancy {
                issuer_event_id: 9,
                ..t
            }),
            Err(Refusal::Stale)
        );
        // Cancel with the wrong issuer: not found; with the right one: gone.
        assert_eq!(
            p.on_tenancy(&PublishChangeOfTenancy {
                issuer_event_id: 11,
                implementation_time: CANCEL,
                ..t
            }),
            Err(Refusal::NotFound)
        );
        p.on_tenancy(&PublishChangeOfTenancy {
            implementation_time: CANCEL,
            ..t
        })
        .unwrap();
        assert!(p.tenancy().is_none());
        p.on_tenancy(&t).unwrap();

        let s = PublishChangeOfSupplier {
            current_provider_id: 1,
            issuer_event_id: 20,
            tariff_type: 0,
            proposed_provider_id: 2,
            implementation_time: 6000,
            change_control: change_control::CLEAR_TARIFF_PLAN,
            name: v(b"NewCo"),
            contact: v(b""),
        };
        p.on_supplier(&s).unwrap();
        // CIN from another provider is not authorised; immediate CIN
        // applies at once; a timed one waits.
        let cin = UpdateCin {
            issuer_event_id: 30,
            implementation_time: 0,
            provider_id: 3,
            cin: v(b"X"),
        };
        assert_eq!(p.on_cin(&cin), Err(Refusal::NotAuthorized));
        assert_eq!(
            p.on_cin(&UpdateCin {
                provider_id: 1,
                ..cin.clone()
            }),
            Ok(Some(Due::Cin(v(b"X"))))
        );
        assert_eq!(
            p.on_cin(&UpdateCin {
                provider_id: 1,
                implementation_time: 7000,
                ..cin.clone()
            }),
            Ok(None)
        );
        let site = UpdateSiteId {
            issuer_event_id: 40,
            site_id_time: 5500,
            provider_id: 1,
            site_id: v(b"S"),
        };
        assert_eq!(p.on_site_id(&site), Ok(None));
        assert_eq!(p.next_deadline(), Some(5000));

        let mut due = Vec::new();
        p.poll(4999, &mut due);
        assert!(due.is_empty());
        p.poll(5600, &mut due);
        assert_eq!(due.len(), 2);
        assert!(matches!(due[0], Due::Tenancy { provider_id: 1, .. }));
        assert_eq!(due[1], Due::SiteId(v(b"S")));
        due.clear();
        p.poll(7000, &mut due);
        assert_eq!(due.len(), 2);
        assert!(
            matches!(&due[0], Due::Supplier { provider_id: 2, name, .. } if name == &v::<MAX_NAME>(b"NewCo"))
        );
        assert_eq!(due[1], Due::Cin(v(b"X")));
        assert_eq!(p.provider_id, 2);
        assert_eq!(p.next_deadline(), None);
    }
}
