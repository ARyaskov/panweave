//! The Key Establishment cluster (SE 1.4a Annex C): attribute and command
//! codecs (C.3), the implicit certificate formats of both cryptographic
//! suites (C.4.2.2.4, C.4.2.3.3), the key derivation and key confirmation
//! transforms (C.4.2.4.3–C.4.2.4.4, checked against the C.5 / C.6
//! vectors) and the CBKE initiator / responder machines.
//!
//! The ECMQV primitive itself is supplied through [`Ecmqv`]: the curve
//! arithmetic over sect163k1 / sect283k1 is not part of this workspace
//! (ADR-0012), so a validated implementation is plugged in by the host.

use heapless::Vec;
use panweave_security::cipher::BlockCipher;
use panweave_security::mmo;
use panweave_types::{AttributeId, ClusterId, CommandId, ExtendedAddress, Key128};
use panweave_zcl::attribute::{Access, AttributeDef};
use panweave_zcl::cluster::{ClusterDef, ClusterInstance, Role};
use panweave_zcl::frame::ZclStatus;
use panweave_zcl::types::{DataType, Value};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Cluster identifier.
pub const ID: ClusterId = ClusterId(0x0800);
/// `KeyEstablishmentSuite` attribute (Table C-3 / C-8; a 16-bit
/// enumeration treated as a bitmap).
pub const ATTR_KEY_ESTABLISHMENT_SUITE: AttributeId = AttributeId(0x0000);
/// `KeyEstablishmentSuite` attribute definition.
pub const KEY_ESTABLISHMENT_SUITE: AttributeDef =
    AttributeDef::new(0x0000, DataType::Enum16, Access::RO);

/// Server cluster definition (Table C-5).
pub const SERVER_DEF: ClusterDef = ClusterDef {
    id: ID,
    revision: 1,
    received: &[
        CommandId(command::INITIATE_KEY_ESTABLISHMENT),
        CommandId(command::EPHEMERAL_DATA),
        CommandId(command::CONFIRM_KEY),
        CommandId(command::TERMINATE_KEY_ESTABLISHMENT),
    ],
    generated: &[
        CommandId(command::INITIATE_KEY_ESTABLISHMENT),
        CommandId(command::EPHEMERAL_DATA),
        CommandId(command::CONFIRM_KEY),
        CommandId(command::TERMINATE_KEY_ESTABLISHMENT),
    ],
};

/// Client cluster definition (Table C-10).
pub const CLIENT_DEF: ClusterDef = SERVER_DEF;

/// A server instance advertising `suites` (Table C-4 bitmap).
pub fn server<const A: usize>(suites: u16) -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(SERVER_DEF, Role::Server);
    c.add_attribute(KEY_ESTABLISHMENT_SUITE, &Value::Enum16(suites))?;
    Ok(c)
}

/// A client instance advertising `suites`.
pub fn client<const A: usize>(suites: u16) -> Result<ClusterInstance<A>, ZclStatus> {
    let mut c = ClusterInstance::new(CLIENT_DEF, Role::Client);
    c.add_attribute(KEY_ESTABLISHMENT_SUITE, &Value::Enum16(suites))?;
    Ok(c)
}

/// Command identifiers (Table C-5 / C-10; the same values in both
/// directions).
pub mod command {
    /// Initiate Key Establishment Request / Response.
    pub const INITIATE_KEY_ESTABLISHMENT: u8 = 0x00;
    /// Ephemeral Data Request / Response.
    pub const EPHEMERAL_DATA: u8 = 0x01;
    /// Confirm Key Request / Response.
    pub const CONFIRM_KEY: u8 = 0x02;
    /// Terminate Key Establishment.
    pub const TERMINATE_KEY_ESTABLISHMENT: u8 = 0x03;
}

/// Largest certificate (Suite 2).
pub const MAX_CERTIFICATE_LEN: usize = 74;
/// Largest ephemeral public key (Suite 2 point-compressed).
pub const MAX_POINT_LEN: usize = 37;
/// Largest ECMQV shared secret (Suite 2: 36 octets).
pub const MAX_SECRET_LEN: usize = 36;
/// Length of a message authentication code.
pub const MAC_LEN: usize = 16;

/// Cryptographic suites (Table C-4 bits).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Suite {
    /// Crypto Suite 1: sect163k1, 48-octet certificates, 22-octet points.
    Suite1,
    /// Crypto Suite 2: sect283k1, 74-octet certificates, 37-octet points.
    Suite2,
}

impl Suite {
    /// Bit in the `KeyEstablishmentSuite` bitmap and the request field.
    pub const fn bit(self) -> u16 {
        match self {
            Suite::Suite1 => 0x0001,
            Suite::Suite2 => 0x0002,
        }
    }

    /// The single suite selected by a request field (C.3.1.2.3.1.2: more
    /// than one bit is a BAD_MESSAGE, an unknown bit UNSUPPORTED_SUITE).
    pub const fn from_field(v: u16) -> Result<Suite, Status> {
        match v {
            0x0001 => Ok(Suite::Suite1),
            0x0002 => Ok(Suite::Suite2),
            _ if v.count_ones() > 1 => Err(Status::BadMessage),
            _ => Err(Status::UnsupportedSuite),
        }
    }

    /// Certificate length (Table C-14).
    pub const fn certificate_len(self) -> usize {
        match self {
            Suite::Suite1 => 48,
            Suite::Suite2 => 74,
        }
    }

    /// Point-compressed public key length (Table C-14).
    pub const fn point_len(self) -> usize {
        match self {
            Suite::Suite1 => 22,
            Suite::Suite2 => 37,
        }
    }

    /// Shared secret length (the curve's field size in octets).
    pub const fn secret_len(self) -> usize {
        match self {
            Suite::Suite1 => 21,
            Suite::Suite2 => 36,
        }
    }

    /// Chooses the suite for an exchange from both bitmaps
    /// (C.3.1.1.1: the common suite with the highest bit).
    pub const fn negotiate(local: u16, remote: u16) -> Option<Suite> {
        let common = local & remote;
        if common & 0x0002 != 0 {
            Some(Suite::Suite2)
        } else if common & 0x0001 != 0 {
            Some(Suite::Suite1)
        } else {
            None
        }
    }
}

/// Terminate Key Establishment status (Table C-6).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Status {
    /// The partner's certificate issuer is unknown.
    UnknownIssuer,
    /// Key confirmation failed.
    BadKeyConfirm,
    /// A malformed or out-of-sequence message.
    BadMessage,
    /// No resources for key establishment right now.
    NoResources,
    /// The requested suite is not supported.
    UnsupportedSuite,
    /// The certificate's type, curve, hash or key usage is invalid.
    InvalidCertificate,
    /// Reserved value.
    Reserved(u8),
}

impl Status {
    /// Raw value.
    pub const fn raw(self) -> u8 {
        match self {
            Status::UnknownIssuer => 0x01,
            Status::BadKeyConfirm => 0x02,
            Status::BadMessage => 0x03,
            Status::NoResources => 0x04,
            Status::UnsupportedSuite => 0x05,
            Status::InvalidCertificate => 0x06,
            Status::Reserved(v) => v,
        }
    }

    /// From the raw value.
    pub const fn from_raw(v: u8) -> Self {
        match v {
            0x01 => Status::UnknownIssuer,
            0x02 => Status::BadKeyConfirm,
            0x03 => Status::BadMessage,
            0x04 => Status::NoResources,
            0x05 => Status::UnsupportedSuite,
            0x06 => Status::InvalidCertificate,
            v => Status::Reserved(v),
        }
    }

    /// Whether the partner should not be retried (C.3.1.2.3.4.2).
    pub const fn is_final(self) -> bool {
        matches!(self, Status::UnknownIssuer | Status::BadKeyConfirm)
    }
}

/// A parsed implicit certificate of either suite.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Certificate<'a> {
    /// Suite the certificate belongs to.
    pub suite: Suite,
    /// The device the certificate binds.
    pub subject: ExtendedAddress,
    /// The issuing CA.
    pub issuer: ExtendedAddress,
    /// The public-key reconstruction data (22 or 37 octets).
    pub reconstruction: &'a [u8],
    /// Suite 1: the 10-octet profile attribute data.
    pub attributes: &'a [u8],
    /// Suite 2: certificate serial number.
    pub serial: u64,
    /// Suite 2: the 40-bit ValidFrom Unix time.
    pub valid_from: u64,
    /// Suite 2: validity in seconds from `valid_from` (0xFFFFFFFF forever).
    pub valid_to: u32,
    /// Suite 2: KeyUsage flags.
    pub key_usage: u8,
}

/// Suite 2 certificate type: implicit, no extensions.
pub const CERT_TYPE_IMPLICIT: u8 = 0x00;
/// Suite 2 curve identifier for sect283k1.
pub const CURVE_SECT283K1: u8 = 0x0D;
/// Suite 2 hash identifier for AES-MMO.
pub const HASH_AES_MMO: u8 = 0x08;
/// KeyUsage bit 3: key agreement.
pub const KEY_USAGE_KEY_AGREEMENT: u8 = 0x08;
/// KeyUsage bit 7: digital signature.
pub const KEY_USAGE_DIGITAL_SIGNATURE: u8 = 0x80;

fn be64(b: &[u8]) -> u64 {
    b.iter().fold(0u64, |acc, x| (acc << 8) | u64::from(*x))
}

impl<'a> Certificate<'a> {
    /// Parses a certificate of `suite` (C.4.2.2.4 / Table C-13), applying
    /// the field checks of C.3.1.2.3.1.2.
    pub fn parse(suite: Suite, bytes: &'a [u8]) -> Result<Self, Status> {
        if bytes.len() != suite.certificate_len() {
            return Err(Status::BadMessage);
        }
        match suite {
            Suite::Suite1 => Ok(Certificate {
                suite,
                subject: ExtendedAddress(be64(bytes.get(22..30).unwrap_or(&[]))),
                issuer: ExtendedAddress(be64(bytes.get(30..38).unwrap_or(&[]))),
                reconstruction: bytes.get(..22).unwrap_or(&[]),
                attributes: bytes.get(38..48).unwrap_or(&[]),
                serial: 0,
                valid_from: 0,
                valid_to: 0,
                key_usage: 0,
            }),
            Suite::Suite2 => {
                let ty = bytes.first().copied().unwrap_or(0xff);
                let curve = bytes.get(9).copied().unwrap_or(0);
                let hash = bytes.get(10).copied().unwrap_or(0);
                let key_usage = bytes.get(36).copied().unwrap_or(0);
                if ty != CERT_TYPE_IMPLICIT
                    || curve != CURVE_SECT283K1
                    || hash != HASH_AES_MMO
                    || key_usage & KEY_USAGE_KEY_AGREEMENT == 0
                {
                    return Err(Status::InvalidCertificate);
                }
                let vt = bytes.get(24..28).unwrap_or(&[0; 4]);
                Ok(Certificate {
                    suite,
                    subject: ExtendedAddress(be64(bytes.get(28..36).unwrap_or(&[]))),
                    issuer: ExtendedAddress(be64(bytes.get(11..19).unwrap_or(&[]))),
                    reconstruction: bytes.get(37..74).unwrap_or(&[]),
                    attributes: &[],
                    serial: be64(bytes.get(1..9).unwrap_or(&[])),
                    valid_from: be64(bytes.get(19..24).unwrap_or(&[])),
                    valid_to: u32::from_be_bytes([vt[0], vt[1], vt[2], vt[3]]),
                    key_usage,
                })
            }
        }
    }

    /// Profile identifier of a Suite 1 certificate's attribute data.
    pub fn profile_id(&self) -> Option<u16> {
        match self.attributes {
            [hi, lo, ..] => Some(u16::from_be_bytes([*hi, *lo])),
            _ => None,
        }
    }
}

/// Initiate Key Establishment Request / Response payload (Figure C-4 /
/// C-8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Initiate<'a> {
    /// The requested / confirmed suite (one bit).
    pub suite: Suite,
    /// Seconds the sender takes to generate its ephemeral data.
    pub ephemeral_data_time: u8,
    /// Seconds the sender takes to generate its confirm-key message.
    pub confirm_key_time: u8,
    /// The sender's certificate (CERTU / CERTV).
    pub certificate: &'a [u8],
}

impl<'a> Initiate<'a> {
    /// Parses the payload; the suite must be exactly one supported bit.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Status> {
        let [s0, s1, ed, ck, cert @ ..] = bytes else {
            return Err(Status::BadMessage);
        };
        let suite = Suite::from_field(u16::from_le_bytes([*s0, *s1]))?;
        if cert.len() != suite.certificate_len() {
            return Err(Status::BadMessage);
        }
        Ok(Initiate {
            suite,
            ephemeral_data_time: *ed,
            confirm_key_time: *ck,
            certificate: cert,
        })
    }

    /// Encodes the payload into `out`; returns the length.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let n = 4 + self.certificate.len();
        let o = out.get_mut(..n)?;
        o[..2].copy_from_slice(&self.suite.bit().to_le_bytes());
        o[2] = self.ephemeral_data_time;
        o[3] = self.confirm_key_time;
        o[4..].copy_from_slice(self.certificate);
        Some(n)
    }
}

/// Terminate Key Establishment payload (Figure C-7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Terminate {
    /// Why.
    pub status: Status,
    /// Seconds to wait before another attempt.
    pub wait_time: u8,
    /// The sender's `KeyEstablishmentSuite` bitmap.
    pub suites: u16,
}

impl Terminate {
    /// Parses the payload.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [s, w, k0, k1] => Some(Terminate {
                status: Status::from_raw(*s),
                wait_time: *w,
                suites: u16::from_le_bytes([*k0, *k1]),
            }),
            _ => None,
        }
    }

    /// The four-octet payload.
    pub const fn encode(self) -> [u8; 4] {
        let k = self.suites.to_le_bytes();
        [self.status.raw(), self.wait_time, k[0], k[1]]
    }
}

/// Derived keying material (C.4.2.4.3): `MacKey` for confirmation and
/// `KeyData`, the established link key.
pub struct KeyingMaterial {
    mac_key: [u8; 16],
    key_data: Key128,
}

impl Drop for KeyingMaterial {
    fn drop(&mut self) {
        self.mac_key.zeroize();
    }
}

impl core::fmt::Debug for KeyingMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeyingMaterial(<redacted>)")
    }
}

impl KeyingMaterial {
    /// The KDF of C.5.3.2: `MacKey = H(Z || 00000001)`,
    /// `KeyData = H(Z || 00000002)` with the empty SharedInfo.
    pub fn derive<C: BlockCipher>(z: &[u8]) -> Self {
        let mut buf: Vec<u8, { MAX_SECRET_LEN + 4 }> = Vec::new();
        let _ = buf.extend_from_slice(z);
        let _ = buf.extend_from_slice(&1u32.to_be_bytes());
        let mac_key = mmo::hash::<C>(&buf);
        let n = buf.len();
        if let Some(last) = buf.get_mut(n - 1) {
            *last = 2;
        }
        let key_data = Key128::from_bytes(mmo::hash::<C>(&buf));
        buf.zeroize();
        KeyingMaterial { mac_key, key_data }
    }

    /// `MAC(MacKey){ tag || id_a || id_b || e_a || e_b }` (Table C-14).
    fn mac<C: BlockCipher>(
        &self,
        tag: u8,
        id_a: ExtendedAddress,
        id_b: ExtendedAddress,
        e_a: &[u8],
        e_b: &[u8],
    ) -> [u8; MAC_LEN] {
        let mut m: Vec<u8, { 1 + 16 + 2 * MAX_POINT_LEN }> = Vec::new();
        let _ = m.push(tag);
        let _ = m.extend_from_slice(&id_a.0.to_be_bytes());
        let _ = m.extend_from_slice(&id_b.0.to_be_bytes());
        let _ = m.extend_from_slice(e_a);
        let _ = m.extend_from_slice(e_b);
        mmo::hmac::<C>(&self.mac_key, &m)
    }

    /// MACU: the initiator's confirmation (tag 0x02).
    pub fn mac_u<C: BlockCipher>(
        &self,
        initiator: ExtendedAddress,
        responder: ExtendedAddress,
        qeu: &[u8],
        qev: &[u8],
    ) -> [u8; MAC_LEN] {
        self.mac::<C>(0x02, initiator, responder, qeu, qev)
    }

    /// MACV: the responder's confirmation (tag 0x03).
    pub fn mac_v<C: BlockCipher>(
        &self,
        initiator: ExtendedAddress,
        responder: ExtendedAddress,
        qeu: &[u8],
        qev: &[u8],
    ) -> [u8; MAC_LEN] {
        self.mac::<C>(0x03, responder, initiator, qev, qeu)
    }

    /// The established link key.
    pub fn key_data(&self) -> &Key128 {
        &self.key_data
    }

    /// Consumes the material, returning the link key.
    pub fn into_key(self) -> Key128 {
        self.key_data.clone()
    }
}

/// Errors of the ECMQV primitive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EcmqvError {
    /// The partner's certificate does not verify against the CA key or
    /// its public key cannot be reconstructed.
    InvalidCertificate,
    /// The partner's ephemeral point is not on the curve.
    InvalidPoint,
    /// No resources (e.g. no ephemeral key generated yet).
    NoResources,
}

/// The elliptic-curve MQV primitive of one suite (C.4.2.4.3, SEC1 §6.2
/// with the SEC4 implicit certificate processing). An implementation
/// holds the device's static private key, its certificate and the CA
/// public key.
pub trait Ecmqv {
    /// The suite implemented.
    fn suite(&self) -> Suite;
    /// The device's certificate (CERTU / CERTV).
    fn certificate(&self) -> &[u8];
    /// Generates a fresh ephemeral key pair and returns the
    /// point-compressed public key (QEU / QEV).
    fn generate_ephemeral(&mut self, out: &mut [u8]) -> Result<usize, EcmqvError>;
    /// Computes the shared secret `Z` from the last ephemeral key pair,
    /// the partner's certificate and ephemeral public key. `out` is at
    /// least `suite().secret_len()` octets.
    fn shared_secret(
        &mut self,
        remote_certificate: &[u8],
        remote_ephemeral: &[u8],
        out: &mut [u8],
    ) -> Result<usize, EcmqvError>;
}

/// Local certificate policy: which issuers are trusted for a suite.
pub trait IssuerPolicy {
    /// Whether a certificate from `issuer` under `suite` is accepted
    /// (C.3.1.2.3.1.2: an unknown issuer terminates with UNKNOWN_ISSUER).
    fn known_issuer(&self, suite: Suite, issuer: ExtendedAddress) -> bool;
}

impl IssuerPolicy for ExtendedAddress {
    fn known_issuer(&self, _: Suite, issuer: ExtendedAddress) -> bool {
        *self == issuer
    }
}

impl<const N: usize> IssuerPolicy for [ExtendedAddress; N] {
    fn known_issuer(&self, _: Suite, issuer: ExtendedAddress) -> bool {
        self.contains(&issuer)
    }
}

/// A point-compressed ephemeral public key.
pub type Point = Vec<u8, MAX_POINT_LEN>;

/// A message the machine wants sent to the partner.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Outgoing {
    /// Ephemeral Data Request / Response.
    EphemeralData(Point),
    /// Confirm Key Request / Response.
    ConfirmKey([u8; MAC_LEN]),
    /// Terminate Key Establishment.
    Terminate(Terminate),
}

/// Timing hints (C.3.1.1): how long this device takes to produce its
/// ephemeral data and its confirm-key message, in seconds.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Timing {
    /// Ephemeral Data Generate Time.
    pub ephemeral_data: u8,
    /// Confirm Key Generate Time.
    pub confirm_key: u8,
}

/// Recommended minimum transmission allowance added to the partner's
/// generate times when choosing a timeout (C.3.1.1).
pub const TRANSMISSION_ALLOWANCE_SECS: u8 = 2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Initiated,
    EphemeralSent,
    Confirmed,
    Done,
}

/// The initiator (client) side of one CBKE exchange.
pub struct Initiator<E: Ecmqv> {
    ecmqv: E,
    local: ExtendedAddress,
    remote: ExtendedAddress,
    phase: Phase,
    qeu: Point,
    qev: Point,
    material: Option<KeyingMaterial>,
    /// The partner's timing hints from its response.
    pub partner_timing: Timing,
}

impl<E: Ecmqv> Initiator<E> {
    /// Starts an exchange with `remote`; `initiate` is the Initiate Key
    /// Establishment Request to send.
    pub fn new(ecmqv: E, local: ExtendedAddress, remote: ExtendedAddress) -> Self {
        Initiator {
            ecmqv,
            local,
            remote,
            phase: Phase::Initiated,
            qeu: Vec::new(),
            qev: Vec::new(),
            material: None,
            partner_timing: Timing::default(),
        }
    }

    /// Hands the primitive back once the exchange is over.
    pub fn into_ecmqv(self) -> E {
        self.ecmqv
    }

    /// The suite in use.
    pub fn suite(&self) -> Suite {
        self.ecmqv.suite()
    }

    /// The Initiate Key Establishment Request.
    pub fn initiate(&self, timing: Timing) -> Initiate<'_> {
        Initiate {
            suite: self.ecmqv.suite(),
            ephemeral_data_time: timing.ephemeral_data,
            confirm_key_time: timing.confirm_key,
            certificate: self.ecmqv.certificate(),
        }
    }

    /// Handles the Initiate Key Establishment Response (C.3.1.3.3.1.2):
    /// checks the suite and certificate, generates the ephemeral data.
    pub fn on_initiate_response<C: BlockCipher>(
        &mut self,
        rsp: &Initiate<'_>,
        issuers: &impl IssuerPolicy,
    ) -> Outgoing {
        if self.phase != Phase::Initiated {
            return self.fail(Status::BadMessage);
        }
        if rsp.suite != self.ecmqv.suite() {
            return self.fail(Status::BadMessage);
        }
        let cert = match Certificate::parse(rsp.suite, rsp.certificate) {
            Ok(c) => c,
            Err(s) => return self.fail(s),
        };
        if cert.subject != self.remote {
            return self.fail(Status::InvalidCertificate);
        }
        if !issuers.known_issuer(rsp.suite, cert.issuer) {
            return self.fail(Status::UnknownIssuer);
        }
        self.partner_timing = Timing {
            ephemeral_data: rsp.ephemeral_data_time,
            confirm_key: rsp.confirm_key_time,
        };
        let mut buf = [0u8; MAX_POINT_LEN];
        match self.ecmqv.generate_ephemeral(&mut buf) {
            Ok(n) if n == rsp.suite.point_len() => {
                self.qeu.clear();
                let _ = self.qeu.extend_from_slice(buf.get(..n).unwrap_or(&[]));
                self.phase = Phase::EphemeralSent;
                Outgoing::EphemeralData(self.qeu.clone())
            }
            _ => self.fail(Status::NoResources),
        }
    }

    /// Handles the Ephemeral Data Response with the partner's certificate
    /// (kept by the caller from the Initiate response): derives the
    /// keying material and produces the Confirm Key Request.
    pub fn on_ephemeral_response<C: BlockCipher>(
        &mut self,
        remote_certificate: &[u8],
        qev: &[u8],
    ) -> Outgoing {
        if self.phase != Phase::EphemeralSent {
            return self.fail(Status::BadMessage);
        }
        let suite = self.ecmqv.suite();
        if qev.len() != suite.point_len() {
            return self.fail(Status::BadMessage);
        }
        let mut z = [0u8; MAX_SECRET_LEN];
        let n = match self.ecmqv.shared_secret(remote_certificate, qev, &mut z) {
            Ok(n) => n,
            Err(EcmqvError::NoResources) => return self.fail(Status::NoResources),
            Err(_) => return self.fail(Status::InvalidCertificate),
        };
        let material = KeyingMaterial::derive::<C>(z.get(..n).unwrap_or(&[]));
        z.zeroize();
        self.qev.clear();
        let _ = self.qev.extend_from_slice(qev);
        let mac_u = material.mac_u::<C>(self.local, self.remote, &self.qeu, &self.qev);
        self.material = Some(material);
        self.phase = Phase::Confirmed;
        Outgoing::ConfirmKey(mac_u)
    }

    /// Handles the Confirm Key Response: verifies MACV and returns the
    /// established link key.
    pub fn on_confirm_response<C: BlockCipher>(
        &mut self,
        mac_v: &[u8],
    ) -> Result<Key128, Outgoing> {
        if self.phase != Phase::Confirmed {
            return Err(self.fail(Status::BadMessage));
        }
        let Some(material) = self.material.take() else {
            return Err(self.fail(Status::BadMessage));
        };
        let expected = material.mac_v::<C>(self.local, self.remote, &self.qeu, &self.qev);
        if mac_v.len() != MAC_LEN || !bool::from(expected.ct_eq(mac_v)) {
            return Err(self.fail(Status::BadKeyConfirm));
        }
        self.phase = Phase::Done;
        Ok(material.into_key())
    }

    /// The partner terminated: the exchange is over.
    pub fn on_terminate(&mut self) {
        self.phase = Phase::Done;
        self.material = None;
    }

    /// Whether the exchange has ended (success or failure).
    pub fn is_done(&self) -> bool {
        self.phase == Phase::Done
    }

    fn fail(&mut self, status: Status) -> Outgoing {
        self.phase = Phase::Done;
        self.material = None;
        Outgoing::Terminate(Terminate {
            status,
            wait_time: 0,
            suites: self.ecmqv.suite().bit(),
        })
    }
}

/// The responder (server) side of one CBKE exchange.
pub struct Responder<E: Ecmqv> {
    ecmqv: E,
    local: ExtendedAddress,
    remote: ExtendedAddress,
    phase: Option<Phase>,
    qeu: Point,
    qev: Point,
    remote_certificate: Vec<u8, MAX_CERTIFICATE_LEN>,
    material: Option<KeyingMaterial>,
    /// The partner's timing hints from its request.
    pub partner_timing: Timing,
}

impl<E: Ecmqv> Responder<E> {
    /// A responder serving `remote`.
    pub fn new(ecmqv: E, local: ExtendedAddress, remote: ExtendedAddress) -> Self {
        Responder {
            ecmqv,
            local,
            remote,
            phase: None,
            qeu: Vec::new(),
            qev: Vec::new(),
            remote_certificate: Vec::new(),
            material: None,
            partner_timing: Timing::default(),
        }
    }

    /// Hands the primitive back once the exchange is over.
    pub fn into_ecmqv(self) -> E {
        self.ecmqv
    }

    /// The suite in use.
    pub fn suite(&self) -> Suite {
        self.ecmqv.suite()
    }

    /// Handles the Initiate Key Establishment Request (C.3.1.2.3.1.2);
    /// on success returns the response to send.
    pub fn on_initiate(
        &mut self,
        req: &Initiate<'_>,
        issuers: &impl IssuerPolicy,
        timing: Timing,
    ) -> Result<Initiate<'_>, Terminate> {
        if req.suite != self.ecmqv.suite() {
            return Err(self.fail(Status::UnsupportedSuite));
        }
        let cert = match Certificate::parse(req.suite, req.certificate) {
            Ok(c) => c,
            Err(s) => return Err(self.fail(s)),
        };
        if cert.subject != self.remote {
            return Err(self.fail(Status::InvalidCertificate));
        }
        if !issuers.known_issuer(req.suite, cert.issuer) {
            return Err(self.fail(Status::UnknownIssuer));
        }
        self.remote_certificate.clear();
        let _ = self.remote_certificate.extend_from_slice(req.certificate);
        self.partner_timing = Timing {
            ephemeral_data: req.ephemeral_data_time,
            confirm_key: req.confirm_key_time,
        };
        self.phase = Some(Phase::Initiated);
        Ok(Initiate {
            suite: req.suite,
            ephemeral_data_time: timing.ephemeral_data,
            confirm_key_time: timing.confirm_key,
            certificate: self.ecmqv.certificate(),
        })
    }

    /// Handles the Ephemeral Data Request: generates QEV, derives the
    /// keying material and answers with the Ephemeral Data Response.
    pub fn on_ephemeral<C: BlockCipher>(&mut self, qeu: &[u8]) -> Outgoing {
        if self.phase != Some(Phase::Initiated) {
            return self.fail_out(Status::BadMessage);
        }
        let suite = self.ecmqv.suite();
        if qeu.len() != suite.point_len() {
            return self.fail_out(Status::BadMessage);
        }
        let mut buf = [0u8; MAX_POINT_LEN];
        let n = match self.ecmqv.generate_ephemeral(&mut buf) {
            Ok(n) if n == suite.point_len() => n,
            _ => return self.fail_out(Status::NoResources),
        };
        self.qev.clear();
        let _ = self.qev.extend_from_slice(buf.get(..n).unwrap_or(&[]));
        self.qeu.clear();
        let _ = self.qeu.extend_from_slice(qeu);
        let mut z = [0u8; MAX_SECRET_LEN];
        let n = match self
            .ecmqv
            .shared_secret(&self.remote_certificate, qeu, &mut z)
        {
            Ok(n) => n,
            Err(EcmqvError::NoResources) => return self.fail_out(Status::NoResources),
            Err(_) => return self.fail_out(Status::InvalidCertificate),
        };
        self.material = Some(KeyingMaterial::derive::<C>(z.get(..n).unwrap_or(&[])));
        z.zeroize();
        self.phase = Some(Phase::EphemeralSent);
        Outgoing::EphemeralData(self.qev.clone())
    }

    /// Handles the Confirm Key Request: verifies MACU and answers with
    /// MACV; the established key is returned alongside.
    pub fn on_confirm<C: BlockCipher>(
        &mut self,
        mac_u: &[u8],
    ) -> Result<(Outgoing, Key128), Outgoing> {
        if self.phase != Some(Phase::EphemeralSent) {
            return Err(self.fail_out(Status::BadMessage));
        }
        let Some(material) = self.material.take() else {
            return Err(self.fail_out(Status::BadMessage));
        };
        let expected = material.mac_u::<C>(self.remote, self.local, &self.qeu, &self.qev);
        if mac_u.len() != MAC_LEN || !bool::from(expected.ct_eq(mac_u)) {
            return Err(self.fail_out(Status::BadKeyConfirm));
        }
        let mac_v = material.mac_v::<C>(self.remote, self.local, &self.qeu, &self.qev);
        self.phase = Some(Phase::Done);
        Ok((Outgoing::ConfirmKey(mac_v), material.into_key()))
    }

    /// The partner terminated.
    pub fn on_terminate(&mut self) {
        self.phase = Some(Phase::Done);
        self.material = None;
    }

    /// Whether an exchange is in progress.
    pub fn is_busy(&self) -> bool {
        matches!(
            self.phase,
            Some(Phase::Initiated | Phase::EphemeralSent | Phase::Confirmed)
        )
    }

    fn fail(&mut self, status: Status) -> Terminate {
        self.phase = Some(Phase::Done);
        self.material = None;
        Terminate {
            status,
            wait_time: 0,
            suites: self.ecmqv.suite().bit(),
        }
    }

    fn fail_out(&mut self, status: Status) -> Outgoing {
        Outgoing::Terminate(self.fail(status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_security::cipher::SoftwareAes;

    const CERT_V1: [u8; 48] = [
        0x03, 0x04, 0x5F, 0xDF, 0xC8, 0xD8, 0x5F, 0xFB, 0x8B, 0x39, 0x93, 0xCB, 0x72, 0xDD, 0xCA,
        0xA5, 0x5F, 0x00, 0xB3, 0xE8, 0x7D, 0x6D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x54, 0x45, 0x53, 0x54, 0x53, 0x45, 0x43, 0x41, 0x01, 0x09, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ];
    const CERT_U1: [u8; 48] = [
        0x02, 0x06, 0x15, 0xE0, 0x7D, 0x30, 0xEC, 0xA2, 0xDA, 0xD5, 0x80, 0x02, 0xE6, 0x67, 0xD9,
        0x4B, 0xC1, 0xB4, 0x22, 0x39, 0x83, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x54, 0x45, 0x53, 0x54, 0x53, 0x45, 0x43, 0x41, 0x01, 0x09, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ];
    const QEU1: [u8; 22] = [
        0x03, 0x00, 0xE1, 0x17, 0xC8, 0x6D, 0x0E, 0x7C, 0xD1, 0x28, 0xB2, 0xF3, 0x4E, 0x90, 0x76,
        0xCF, 0xF2, 0x4A, 0xF4, 0x6D, 0x72, 0x88,
    ];
    const QEV1: [u8; 22] = [
        0x03, 0x06, 0xAB, 0x52, 0x06, 0x22, 0x01, 0xD9, 0x95, 0xB8, 0xB8, 0x59, 0x1F, 0x3F, 0x08,
        0x6A, 0x3A, 0x2E, 0x21, 0x4D, 0x84, 0x5E,
    ];
    const Z1: [u8; 21] = [
        0x00, 0xE0, 0xD2, 0xC3, 0xCC, 0xD5, 0xC1, 0x06, 0xA8, 0x9C, 0x4F, 0x6C, 0xC2, 0x6A, 0x5F,
        0x7E, 0xC9, 0xDF, 0x78, 0xA7, 0xBE,
    ];
    const MACU1: [u8; 16] = [
        0xB8, 0x2F, 0x1F, 0x97, 0x74, 0x74, 0x0C, 0x32, 0xF8, 0x0F, 0xCF, 0xC3, 0x92, 0x1B, 0x64,
        0x20,
    ];
    const MACV1: [u8; 16] = [
        0x79, 0xD5, 0xF2, 0xAD, 0x1C, 0x31, 0xD4, 0xD1, 0xEE, 0x7C, 0xB7, 0x19, 0xAC, 0x68, 0x3C,
        0x3C,
    ];
    const ISSUER: ExtendedAddress = ExtendedAddress(0x5445_5354_5345_4341);

    /// A primitive that replays the Annex C vectors instead of doing the
    /// curve arithmetic.
    struct Vectors {
        suite: Suite,
        cert: &'static [u8],
        ephemeral: &'static [u8],
        z: &'static [u8],
    }

    impl Ecmqv for Vectors {
        fn suite(&self) -> Suite {
            self.suite
        }
        fn certificate(&self) -> &[u8] {
            self.cert
        }
        fn generate_ephemeral(&mut self, out: &mut [u8]) -> Result<usize, EcmqvError> {
            out[..self.ephemeral.len()].copy_from_slice(self.ephemeral);
            Ok(self.ephemeral.len())
        }
        fn shared_secret(
            &mut self,
            _: &[u8],
            _: &[u8],
            out: &mut [u8],
        ) -> Result<usize, EcmqvError> {
            out[..self.z.len()].copy_from_slice(self.z);
            Ok(self.z.len())
        }
    }

    #[test]
    fn annex_c5_suite1_transform() {
        let m = KeyingMaterial::derive::<SoftwareAes>(&Z1);
        assert_eq!(
            m.mac_key,
            [
                0x90, 0xF9, 0x67, 0xB2, 0x2C, 0x83, 0x57, 0xC1, 0x0C, 0x1C, 0x04, 0x78, 0x8D, 0xE9,
                0xE8, 0x48
            ]
        );
        assert_eq!(
            m.key_data().as_bytes(),
            &[
                0x86, 0xD5, 0x8A, 0xAA, 0x99, 0x8E, 0x2F, 0xAE, 0xFA, 0xF9, 0xFE, 0xF4, 0x96, 0x06,
                0x54, 0x3A
            ]
        );
        let u = ExtendedAddress(2);
        let v = ExtendedAddress(1);
        assert_eq!(m.mac_u::<SoftwareAes>(u, v, &QEU1, &QEV1), MACU1);
        assert_eq!(m.mac_v::<SoftwareAes>(u, v, &QEU1, &QEV1), MACV1);
        // Certificates parse as documented.
        let c = Certificate::parse(Suite::Suite1, &CERT_V1).unwrap();
        assert_eq!(c.subject, ExtendedAddress(1));
        assert_eq!(c.issuer, ISSUER);
        assert_eq!(c.profile_id(), Some(0x0109));
        assert_eq!(c.reconstruction, &CERT_V1[..22]);
    }

    #[test]
    fn annex_c6_suite2_transform() {
        let z: [u8; 36] = [
            0x04, 0xF7, 0x72, 0x4A, 0x9A, 0x77, 0xB2, 0x1D, 0x27, 0x47, 0xCC, 0xEF, 0x68, 0xA4,
            0x57, 0xE4, 0x52, 0x46, 0xC4, 0xBE, 0x9F, 0x66, 0xFD, 0x94, 0x25, 0x22, 0x7B, 0xCB,
            0x2C, 0xC5, 0x18, 0x0E, 0xA9, 0xCC, 0xCB, 0x9A,
        ];
        let qeu: [u8; 37] = [
            0x03, 0x05, 0xF3, 0x39, 0x4E, 0x15, 0x68, 0x06, 0x60, 0xEE, 0xCA, 0xA3, 0x67, 0x88,
            0xD9, 0xB6, 0xF3, 0x12, 0xB9, 0x71, 0xCE, 0x2C, 0x96, 0x17, 0x57, 0x0B, 0xF7, 0xDF,
            0xCD, 0x21, 0xC9, 0x72, 0x01, 0x77, 0x62, 0xC3, 0x32,
        ];
        let qev: [u8; 37] = [
            0x03, 0x00, 0x9A, 0x51, 0x31, 0xCF, 0x5B, 0x92, 0xA0, 0x16, 0x37, 0x8C, 0x0F, 0x7F,
            0x28, 0x4E, 0xCD, 0x47, 0xF9, 0x40, 0x10, 0xF8, 0x75, 0xD4, 0x3B, 0xF1, 0xE9, 0xA6,
            0x54, 0x74, 0xAD, 0xBF, 0xC6, 0x36, 0x96, 0xA9, 0x30,
        ];
        let m = KeyingMaterial::derive::<SoftwareAes>(&z);
        assert_eq!(
            m.mac_key,
            [
                0xED, 0x38, 0x0A, 0x00, 0x29, 0x66, 0x00, 0xFB, 0x6B, 0x89, 0x30, 0x25, 0xDE, 0x5F,
                0xD1, 0x37
            ]
        );
        assert_eq!(
            m.key_data().as_bytes(),
            &[
                0xAA, 0x46, 0x89, 0xC7, 0x0B, 0xE0, 0xFA, 0xF0, 0xC9, 0xBE, 0x53, 0x4A, 0xBD, 0x9F,
                0x4C, 0xDC
            ]
        );
        let u = ExtendedAddress(0x0A0B_0C0D_0E0F_1012);
        let v = ExtendedAddress(0x0A0B_0C0D_0E0F_1011);
        assert_eq!(
            m.mac_u::<SoftwareAes>(u, v, &qeu, &qev),
            [
                0xBF, 0x7E, 0x1A, 0x26, 0xD4, 0xEF, 0x70, 0x38, 0xB5, 0x68, 0x13, 0xE4, 0x65, 0xA1,
                0x31, 0xC9
            ]
        );
        assert_eq!(
            m.mac_v::<SoftwareAes>(u, v, &qeu, &qev),
            [
                0xC5, 0xB4, 0x32, 0xA9, 0x99, 0x5A, 0x09, 0x2F, 0x44, 0x49, 0xF8, 0x36, 0x13, 0x93,
                0x00, 0x64
            ]
        );
        // The Suite 2 responder certificate of C.6.1.2.
        let cert: [u8; 74] = [
            0x00, 0x26, 0x22, 0xA5, 0x05, 0xE8, 0x93, 0x8F, 0x27, 0x0D, 0x08, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17, 0x18, 0x00, 0x52, 0x92, 0xA3, 0x5B, 0xFF, 0xFF, 0xFF, 0xFF,
            0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x88, 0x03, 0x03, 0xB4, 0xE9, 0xDC,
            0x54, 0x3A, 0x64, 0x33, 0x3C, 0x98, 0x23, 0x08, 0x02, 0x2B, 0x54, 0xE6, 0x7E, 0x2F,
            0x15, 0xF5, 0x32, 0x55, 0x1B, 0x0A, 0x11, 0xE2, 0xE2, 0xC1, 0xC1, 0xD3, 0x09, 0x7A,
            0x43, 0x24, 0xE7, 0xED,
        ];
        let c = Certificate::parse(Suite::Suite2, &cert).unwrap();
        assert_eq!(c.subject, v);
        assert_eq!(c.issuer, ExtendedAddress(0x1112_1314_1516_1718));
        assert_eq!(c.serial, 0x2622_A505_E893_8F27);
        assert_eq!(c.valid_from, 0x5292_A35B);
        assert_eq!(c.valid_to, 0xFFFF_FFFF);
        assert_eq!(c.key_usage, 0x88);
        assert_eq!(c.reconstruction.len(), 37);
        let mut bad = cert;
        bad[36] = 0x80;
        assert_eq!(
            Certificate::parse(Suite::Suite2, &bad),
            Err(Status::InvalidCertificate)
        );
    }

    #[test]
    fn annex_c5_exchange_between_machines() {
        let mut u = Initiator::new(
            Vectors {
                suite: Suite::Suite1,
                cert: &CERT_U1,
                ephemeral: &QEU1,
                z: &Z1,
            },
            ExtendedAddress(2),
            ExtendedAddress(1),
        );
        let mut v = Responder::new(
            Vectors {
                suite: Suite::Suite1,
                cert: &CERT_V1,
                ephemeral: &QEV1,
                z: &Z1,
            },
            ExtendedAddress(1),
            ExtendedAddress(2),
        );
        let timing = Timing {
            ephemeral_data: 3,
            confirm_key: 6,
        };
        // Initiate request: the C.5.2.1 payload.
        let req = u.initiate(timing);
        let mut buf = [0u8; 64];
        let n = req.encode(&mut buf).unwrap();
        assert_eq!(&buf[..4], &[0x01, 0x00, 0x03, 0x06]);
        assert_eq!(&buf[4..n], &CERT_U1);
        let req = Initiate::parse(&buf[..n]).unwrap();
        let rsp = v.on_initiate(&req, &ISSUER, timing).unwrap();
        assert_eq!(rsp.certificate, &CERT_V1);
        let rsp = Initiate {
            suite: rsp.suite,
            ephemeral_data_time: rsp.ephemeral_data_time,
            confirm_key_time: rsp.confirm_key_time,
            certificate: &CERT_V1,
        };
        let Outgoing::EphemeralData(qeu) = u.on_initiate_response::<SoftwareAes>(&rsp, &ISSUER)
        else {
            panic!("ephemeral data expected");
        };
        assert_eq!(qeu.as_slice(), &QEU1);
        let Outgoing::EphemeralData(qev) = v.on_ephemeral::<SoftwareAes>(&qeu) else {
            panic!("ephemeral data expected");
        };
        assert_eq!(qev.as_slice(), &QEV1);
        let Outgoing::ConfirmKey(mac_u) = u.on_ephemeral_response::<SoftwareAes>(&CERT_V1, &qev)
        else {
            panic!("confirm key expected");
        };
        assert_eq!(mac_u, MACU1);
        let (out, key_v) = v.on_confirm::<SoftwareAes>(&mac_u).unwrap();
        let Outgoing::ConfirmKey(mac_v) = out else {
            panic!("confirm key expected");
        };
        assert_eq!(mac_v, MACV1);
        let key_u = u.on_confirm_response::<SoftwareAes>(&mac_v).unwrap();
        assert_eq!(key_u, key_v);
        assert!(u.is_done() && !v.is_busy());
        // A wrong MACU terminates with BAD_KEY_CONFIRM.
        let mut v2 = Responder::new(
            Vectors {
                suite: Suite::Suite1,
                cert: &CERT_V1,
                ephemeral: &QEV1,
                z: &Z1,
            },
            ExtendedAddress(1),
            ExtendedAddress(2),
        );
        v2.on_initiate(&req, &ISSUER, timing).unwrap();
        let _ = v2.on_ephemeral::<SoftwareAes>(&QEU1);
        assert_eq!(
            v2.on_confirm::<SoftwareAes>(&[0; 16]).unwrap_err(),
            Outgoing::Terminate(Terminate {
                status: Status::BadKeyConfirm,
                wait_time: 0,
                suites: 0x0001
            })
        );
        // Unknown issuer / wrong subject / bad suite field.
        let mut v3 = Responder::new(
            Vectors {
                suite: Suite::Suite1,
                cert: &CERT_V1,
                ephemeral: &QEV1,
                z: &Z1,
            },
            ExtendedAddress(1),
            ExtendedAddress(2),
        );
        assert_eq!(
            v3.on_initiate(&req, &ExtendedAddress(9), timing)
                .unwrap_err()
                .status,
            Status::UnknownIssuer
        );
        let mut v4 = Responder::new(
            Vectors {
                suite: Suite::Suite1,
                cert: &CERT_V1,
                ephemeral: &QEV1,
                z: &Z1,
            },
            ExtendedAddress(1),
            ExtendedAddress(7),
        );
        assert_eq!(
            v4.on_initiate(&req, &ISSUER, timing).unwrap_err().status,
            Status::InvalidCertificate
        );
        assert_eq!(Suite::from_field(0x0003), Err(Status::BadMessage));
        assert_eq!(Suite::from_field(0x0004), Err(Status::UnsupportedSuite));
        assert_eq!(Suite::negotiate(0x0003, 0x0001), Some(Suite::Suite1));
        assert_eq!(Suite::negotiate(0x0003, 0x0002), Some(Suite::Suite2));
        assert_eq!(Suite::negotiate(0x0001, 0x0002), None);
        let t = Terminate {
            status: Status::NoResources,
            wait_time: 30,
            suites: 0x0003,
        };
        assert_eq!(Terminate::parse(&t.encode()), Some(t));
    }
}
