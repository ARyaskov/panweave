//! Secure session establishment over the Authenticate characteristics
//! (ZD 1.1 §6.3, §6.5.1): the four Session Establishment messages, the
//! ZVD (initiator) and ZDD (responder) state machines, key derivation for
//! SPEKE/Curve25519/AES-MMO-128 and ECDHE-PSK/P-256/SHA-256, and the
//! MacTag key confirmation. No message of the exchange is encrypted.

use heapless::Vec;
use panweave_codec::Writer;
use panweave_codec::tlv::TlvSet;
use panweave_security::cipher::BlockCipher;
use panweave_types::{CryptoRng, ExtendedAddress, Key128};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::tlv::{self, Method, Psk};

/// Opcode of Session Establishment Message 1.
pub const OPCODE_MESSAGE_1: u8 = 1;
/// Opcode of Session Establishment Message 2.
pub const OPCODE_MESSAGE_2: u8 = 2;
/// Opcode of Session Establishment Message 3.
pub const OPCODE_MESSAGE_3: u8 = 3;
/// Opcode of Session Establishment Message 4.
pub const OPCODE_MESSAGE_4: u8 = 4;
/// SecureSessionTimeout default (§6.5.1.4).
pub const SESSION_TIMEOUT_SECS: u32 = 15;
/// Largest session establishment message.
pub const MAX_MESSAGE: usize = 1 + 4 + 2 + 72 + 3;
/// The anonymous well-known secret (Table 1).
pub const ANONYMOUS_PSK: &[u8; 16] = b"ZigBeeAlliance18";

/// A session establishment message buffer.
pub type Message = Vec<u8, MAX_MESSAGE>;

/// Session establishment failures (§6.5.1.4: the peer is disconnected).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SessionError {
    /// Malformed message or TLVs.
    Malformed,
    /// Unexpected opcode for the current state.
    UnexpectedMessage,
    /// The method does not match the Authenticate characteristic, or is
    /// not supported by this build.
    UnsupportedMethod,
    /// The pre-shared secret is not available / not allowed.
    UnsupportedPsk,
    /// Invalid public point.
    InvalidPoint,
    /// The MacTag did not verify.
    KeyConfirmationFailed,
    /// Output buffer too small.
    Overflow,
}

/// The pre-shared secret selected for the exchange.
#[derive(Clone)]
pub enum Secret<'a> {
    /// Anonymous well-known secret.
    Anonymous,
    /// A 128-bit key (install-code link key, authorization key, token).
    Key(&'a Key128),
    /// A variable-length passcode (SPEKE only).
    Passcode(&'a [u8]),
}

impl Secret<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Secret::Anonymous => ANONYMOUS_PSK,
            Secret::Key(k) => k.as_bytes(),
            Secret::Passcode(p) => p,
        }
    }
}

/// Ephemeral key material of one method.
#[derive(Zeroize, ZeroizeOnDrop)]
enum Ephemeral {
    #[cfg(feature = "curve25519")]
    Curve25519 {
        #[zeroize(skip)]
        inner: panweave_security::dlk::Ephemeral,
    },
    #[cfg(feature = "p256")]
    P256 {
        secret: [u8; 32],
        #[zeroize(skip)]
        public: [u8; 64],
    },
    /// No key agreement method compiled in.
    #[cfg(not(any(feature = "curve25519", feature = "p256")))]
    #[allow(dead_code)]
    Unsupported,
}

impl Ephemeral {
    fn generate<C: BlockCipher, R: CryptoRng>(
        rng: &mut R,
        method: Method,
        psk: &[u8],
    ) -> Result<Self, SessionError> {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        Self::from_secret::<C>(secret, method, psk)
    }

    #[cfg_attr(
        not(feature = "curve25519"),
        allow(clippy::extra_unused_type_parameters)
    )]
    fn from_secret<C: BlockCipher>(
        secret: [u8; 32],
        method: Method,
        psk: &[u8],
    ) -> Result<Self, SessionError> {
        match method {
            #[cfg(feature = "curve25519")]
            Method::Curve25519AesMmo => Ok(Ephemeral::Curve25519 {
                inner: panweave_security::dlk::Ephemeral::from_secret::<C>(secret, psk),
            }),
            #[cfg(feature = "p256")]
            Method::P256Sha256 => {
                let _ = psk;
                use p256::elliptic_curve::sec1::ToSec1Point;
                let sk =
                    p256::SecretKey::from_slice(&secret).map_err(|_| SessionError::InvalidPoint)?;
                let point = sk.public_key().to_sec1_point(false);
                let mut public = [0u8; 64];
                public.copy_from_slice(
                    point
                        .as_bytes()
                        .get(1..65)
                        .ok_or(SessionError::InvalidPoint)?,
                );
                Ok(Ephemeral::P256 { secret, public })
            }
            #[allow(unreachable_patterns)]
            _ => {
                let _ = (secret, psk);
                Err(SessionError::UnsupportedMethod)
            }
        }
    }

    fn public(&self) -> &[u8] {
        match self {
            #[cfg(feature = "curve25519")]
            Ephemeral::Curve25519 { inner } => inner.public(),
            #[cfg(feature = "p256")]
            Ephemeral::P256 { public, .. } => public,
            #[cfg(not(any(feature = "curve25519", feature = "p256")))]
            Ephemeral::Unsupported => &[],
        }
    }

    /// Derives the session key: `KDF(H(xk || I || PSK-or-G), {0x01})`
    /// with the session identifier ordering the (address, point) pairs by
    /// EUI-64 value.
    #[cfg_attr(
        not(feature = "curve25519"),
        allow(clippy::extra_unused_type_parameters)
    )]
    fn derive<C: BlockCipher>(
        &self,
        local: ExtendedAddress,
        remote: ExtendedAddress,
        remote_public: &[u8],
        psk: &[u8],
    ) -> Result<Key128, SessionError> {
        match self {
            #[cfg(feature = "curve25519")]
            Ephemeral::Curve25519 { inner } => {
                let _ = psk;
                inner
                    .derive::<C>(local, remote, remote_public)
                    .map_err(|_| SessionError::InvalidPoint)
            }
            #[cfg(feature = "p256")]
            Ephemeral::P256 { secret, public } => {
                use hmac::{KeyInit, Mac};
                use sha2::Digest;
                let remote_public: [u8; 64] = remote_public
                    .try_into()
                    .map_err(|_| SessionError::InvalidPoint)?;
                let mut sec1 = [0u8; 65];
                sec1[0] = 0x04;
                sec1[1..].copy_from_slice(&remote_public);
                let peer = p256::PublicKey::from_sec1_bytes(&sec1)
                    .map_err(|_| SessionError::InvalidPoint)?;
                let sk =
                    p256::SecretKey::from_slice(secret).map_err(|_| SessionError::InvalidPoint)?;
                let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
                let (first_a, first_q, second_a, second_q): (
                    ExtendedAddress,
                    &[u8],
                    ExtendedAddress,
                    &[u8],
                ) = if local.0 < remote.0 {
                    (local, public, remote, &remote_public)
                } else {
                    (remote, &remote_public, local, public)
                };
                let mut h = sha2::Sha256::new();
                h.update(shared.raw_secret_bytes());
                h.update(first_a.0.to_le_bytes());
                h.update(first_q);
                h.update(second_a.0.to_le_bytes());
                h.update(second_q);
                h.update(psk);
                let s = h.finalize();
                let mut mac = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&s)
                    .map_err(|_| SessionError::InvalidPoint)?;
                mac.update(&[0x01]);
                let out = mac.finalize().into_bytes();
                let mut key = [0u8; 16];
                key.copy_from_slice(out.get(..16).ok_or(SessionError::InvalidPoint)?);
                Ok(Key128::from_bytes(key))
            }
            #[cfg(not(any(feature = "curve25519", feature = "p256")))]
            Ephemeral::Unsupported => {
                let _ = (local, remote, remote_public, psk);
                Err(SessionError::UnsupportedMethod)
            }
        }
    }
}

/// `MacTag = MAC(sk, label || Ar || Qr || Ai || Qi)` (§6.5.1.2.4): the
/// responder (ZDD) pair always comes first.
#[allow(clippy::too_many_arguments)]
fn mac_tag<C: BlockCipher>(
    method: Method,
    key: &Key128,
    label: [u8; 6],
    responder: ExtendedAddress,
    responder_public: &[u8],
    initiator: ExtendedAddress,
    initiator_public: &[u8],
    out: &mut [u8; 32],
) -> usize {
    match method {
        Method::Curve25519AesMmo => {
            let mut data = [0u8; 6 + 8 + 32 + 8 + 32];
            data[..6].copy_from_slice(&label);
            data[6..14].copy_from_slice(&responder.0.to_le_bytes());
            data[14..46].copy_from_slice(responder_public.get(..32).unwrap_or(&[0; 32]));
            data[46..54].copy_from_slice(&initiator.0.to_le_bytes());
            data[54..86].copy_from_slice(initiator_public.get(..32).unwrap_or(&[0; 32]));
            let t = panweave_security::mmo::hmac::<C>(key.as_bytes(), &data);
            out[..16].copy_from_slice(&t);
            16
        }
        #[cfg(feature = "p256")]
        Method::P256Sha256 | Method::Curve25519Sha256 => {
            use hmac::{KeyInit, Mac};
            let Ok(mut mac) = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key.as_bytes())
            else {
                return 0;
            };
            mac.update(&label);
            mac.update(&responder.0.to_le_bytes());
            mac.update(responder_public);
            mac.update(&initiator.0.to_le_bytes());
            mac.update(initiator_public);
            out.copy_from_slice(&mac.finalize().into_bytes());
            32
        }
        #[cfg(not(feature = "p256"))]
        _ => 0,
    }
}

const LABEL_INITIATOR: [u8; 6] = *b"KC_2_U";
const LABEL_RESPONDER: [u8; 6] = *b"KC_2_V";

/// The outcome of a completed exchange.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Established {
    /// The 128-bit session key.
    pub key: Key128,
    /// The peer's EUI-64.
    pub peer: ExtendedAddress,
    /// The pre-shared secret used (the authorization level follows from
    /// it, §6.3).
    pub psk: Psk,
    /// Network key sequence number announced by the ZDD (Message 2), if
    /// any.
    pub key_sequence: Option<u8>,
    /// Network key sequence number the ZVD put in Message 1: the key its
    /// Basic authorization key was derived from (§9.1). On the ZDD a
    /// value other than the active one marks a Limited Authorization
    /// session.
    pub peer_key_sequence: Option<u8>,
}

fn parse(message: &[u8], expected: u8) -> Result<TlvSet<'_>, SessionError> {
    let (&op, rest) = message.split_first().ok_or(SessionError::Malformed)?;
    if op != expected {
        return Err(SessionError::UnexpectedMessage);
    }
    TlvSet::validate(rest, |_| false).map_err(|_| SessionError::Malformed)
}

/// Responder (ZDD) side of the exchange for one Authenticate
/// characteristic (`method`).
pub struct Responder<'a> {
    method: Method,
    local: ExtendedAddress,
    key_sequence: Option<u8>,
    state: ResponderState,
    secrets: &'a dyn Fn(Psk, Option<u8>) -> Option<Secret<'a>>,
}

enum ResponderState {
    AwaitingMessage1,
    AwaitingMessage3 {
        key: Key128,
        peer: ExtendedAddress,
        psk: Psk,
        peer_key_sequence: Option<u8>,
        ephemeral: Ephemeral,
        peer_public: Vec<u8, 64>,
    },
    Done,
}

impl<'a> Responder<'a> {
    /// A responder that identifies itself as `local`, announces
    /// `key_sequence` (the active network key sequence number of a
    /// provisioned ZDD) and resolves pre-shared secrets through
    /// `secrets` (returning `None` refuses the PSK, e.g. anonymous
    /// sessions while the Anonymous Join Countdown Timer is 0). The
    /// resolver also receives the network key sequence number the peer
    /// put in Message 1, so a Basic authorization key derived from a
    /// past network key can be found (§9.1 Limited Authorization).
    pub fn new(
        method: Method,
        local: ExtendedAddress,
        key_sequence: Option<u8>,
        secrets: &'a dyn Fn(Psk, Option<u8>) -> Option<Secret<'a>>,
    ) -> Self {
        Responder {
            method,
            local,
            key_sequence,
            state: ResponderState::AwaitingMessage1,
            secrets,
        }
    }

    /// Processes Message 1 and produces Message 2.
    pub fn on_message1<C: BlockCipher, R: CryptoRng>(
        &mut self,
        rng: &mut R,
        message: &[u8],
    ) -> Result<Message, SessionError> {
        if !matches!(self.state, ResponderState::AwaitingMessage1) {
            return Err(SessionError::UnexpectedMessage);
        }
        let set = parse(message, OPCODE_MESSAGE_1)?;
        let (method, psk) = tlv::method(&set).ok_or(SessionError::Malformed)?;
        if method != self.method {
            return Err(SessionError::UnsupportedMethod);
        }
        let (peer, peer_public) = tlv::point(&set, method).ok_or(SessionError::Malformed)?;
        let peer_key_sequence = tlv::key_sequence(&set);
        let secret = (self.secrets)(psk, peer_key_sequence).ok_or(SessionError::UnsupportedPsk)?;
        let ephemeral = Ephemeral::generate::<C, R>(rng, method, secret.bytes())?;
        let key = ephemeral.derive::<C>(self.local, peer, peer_public, secret.bytes())?;
        let mut out = Message::new();
        let mut buf = [0u8; MAX_MESSAGE];
        let mut w = Writer::new(&mut buf);
        w.u8(OPCODE_MESSAGE_2).map_err(|_| SessionError::Overflow)?;
        if let Some(seq) = self.key_sequence.filter(|s| *s != 0) {
            tlv::write_key_sequence(&mut w, seq).map_err(|_| SessionError::Overflow)?;
        }
        tlv::write_point(&mut w, method.point_tag(), self.local, ephemeral.public())
            .map_err(|_| SessionError::Overflow)?;
        let n = w.position();
        out.extend_from_slice(buf.get(..n).unwrap_or(&[]))
            .map_err(|_| SessionError::Overflow)?;
        let mut pp = Vec::new();
        pp.extend_from_slice(peer_public)
            .map_err(|_| SessionError::Malformed)?;
        self.state = ResponderState::AwaitingMessage3 {
            key,
            peer,
            psk,
            peer_key_sequence,
            ephemeral,
            peer_public: pp,
        };
        Ok(out)
    }

    /// Verifies Message 3 and produces Message 4; the session is
    /// established once Message 4 is sent.
    pub fn on_message3<C: BlockCipher>(
        &mut self,
        message: &[u8],
    ) -> Result<(Message, Established), SessionError> {
        let state = core::mem::replace(&mut self.state, ResponderState::Done);
        let ResponderState::AwaitingMessage3 {
            key,
            peer,
            psk,
            peer_key_sequence,
            ephemeral,
            peer_public,
        } = state
        else {
            return Err(SessionError::UnexpectedMessage);
        };
        let set = parse(message, OPCODE_MESSAGE_3)?;
        let tag = tlv::mac_tag(&set).ok_or(SessionError::Malformed)?;
        let mut expected = [0u8; 32];
        let n = mac_tag::<C>(
            self.method,
            &key,
            LABEL_INITIATOR,
            self.local,
            ephemeral.public(),
            peer,
            &peer_public,
            &mut expected,
        );
        let ok: bool = expected.get(..n).unwrap_or(&[]).ct_eq(tag).into();
        if n == 0 || tag.len() != n || !ok {
            return Err(SessionError::KeyConfirmationFailed);
        }
        let mut mine = [0u8; 32];
        let n = mac_tag::<C>(
            self.method,
            &key,
            LABEL_RESPONDER,
            self.local,
            ephemeral.public(),
            peer,
            &peer_public,
            &mut mine,
        );
        let mut out = Message::new();
        let mut buf = [0u8; MAX_MESSAGE];
        let mut w = Writer::new(&mut buf);
        w.u8(OPCODE_MESSAGE_4).map_err(|_| SessionError::Overflow)?;
        tlv::write_mac_tag(&mut w, mine.get(..n).unwrap_or(&[]))
            .map_err(|_| SessionError::Overflow)?;
        let len = w.position();
        out.extend_from_slice(buf.get(..len).unwrap_or(&[]))
            .map_err(|_| SessionError::Overflow)?;
        Ok((
            out,
            Established {
                key,
                peer,
                psk,
                key_sequence: self.key_sequence,
                peer_key_sequence,
            },
        ))
    }
}

/// Initiator (ZVD) side of the exchange.
pub struct Initiator {
    method: Method,
    local: ExtendedAddress,
    psk: Psk,
    state: InitiatorState,
}

enum InitiatorState {
    Fresh,
    AwaitingMessage2 {
        ephemeral: Ephemeral,
        secret: Vec<u8, 32>,
    },
    AwaitingMessage4 {
        key: Key128,
        peer: ExtendedAddress,
        ephemeral: Ephemeral,
        peer_public: Vec<u8, 64>,
        key_sequence: Option<u8>,
    },
    Done,
}

impl Initiator {
    /// An initiator identified by `local`, using `method` and `psk`.
    pub fn new(method: Method, local: ExtendedAddress, psk: Psk) -> Self {
        Initiator {
            method,
            local,
            psk,
            state: InitiatorState::Fresh,
        }
    }

    /// Produces Message 1 (`key_sequence` is the sequence number a Basic
    /// authorization key was derived from, when non-zero).
    pub fn message1<C: BlockCipher, R: CryptoRng>(
        &mut self,
        rng: &mut R,
        secret: &Secret<'_>,
        key_sequence: Option<u8>,
    ) -> Result<Message, SessionError> {
        self.start(
            Ephemeral::generate::<C, R>(rng, self.method, secret.bytes())?,
            secret,
            key_sequence,
        )
    }

    /// [`Self::message1`] with a fixed ephemeral scalar (test vectors).
    pub fn message1_with_secret<C: BlockCipher>(
        &mut self,
        ephemeral_secret: [u8; 32],
        secret: &Secret<'_>,
        key_sequence: Option<u8>,
    ) -> Result<Message, SessionError> {
        self.start(
            Ephemeral::from_secret::<C>(ephemeral_secret, self.method, secret.bytes())?,
            secret,
            key_sequence,
        )
    }

    fn start(
        &mut self,
        ephemeral: Ephemeral,
        secret: &Secret<'_>,
        key_sequence: Option<u8>,
    ) -> Result<Message, SessionError> {
        if !matches!(self.state, InitiatorState::Fresh) {
            return Err(SessionError::UnexpectedMessage);
        }
        let mut out = Message::new();
        let mut buf = [0u8; MAX_MESSAGE];
        let mut w = Writer::new(&mut buf);
        w.u8(OPCODE_MESSAGE_1).map_err(|_| SessionError::Overflow)?;
        tlv::write_method(&mut w, self.method, self.psk).map_err(|_| SessionError::Overflow)?;
        tlv::write_point(
            &mut w,
            self.method.point_tag(),
            self.local,
            ephemeral.public(),
        )
        .map_err(|_| SessionError::Overflow)?;
        if let Some(seq) = key_sequence.filter(|s| *s != 0) {
            tlv::write_key_sequence(&mut w, seq).map_err(|_| SessionError::Overflow)?;
        }
        let n = w.position();
        out.extend_from_slice(buf.get(..n).unwrap_or(&[]))
            .map_err(|_| SessionError::Overflow)?;
        let mut s = Vec::new();
        s.extend_from_slice(secret.bytes())
            .map_err(|_| SessionError::UnsupportedPsk)?;
        self.state = InitiatorState::AwaitingMessage2 {
            ephemeral,
            secret: s,
        };
        Ok(out)
    }

    /// Processes Message 2 and produces Message 3.
    pub fn on_message2<C: BlockCipher>(&mut self, message: &[u8]) -> Result<Message, SessionError> {
        let state = core::mem::replace(&mut self.state, InitiatorState::Done);
        let InitiatorState::AwaitingMessage2 { ephemeral, secret } = state else {
            return Err(SessionError::UnexpectedMessage);
        };
        let set = parse(message, OPCODE_MESSAGE_2)?;
        let (peer, peer_public) = tlv::point(&set, self.method).ok_or(SessionError::Malformed)?;
        let key_sequence = tlv::key_sequence(&set);
        let key = ephemeral.derive::<C>(self.local, peer, peer_public, &secret)?;
        let mut tag = [0u8; 32];
        let n = mac_tag::<C>(
            self.method,
            &key,
            LABEL_INITIATOR,
            peer,
            peer_public,
            self.local,
            ephemeral.public(),
            &mut tag,
        );
        let mut out = Message::new();
        let mut buf = [0u8; MAX_MESSAGE];
        let mut w = Writer::new(&mut buf);
        w.u8(OPCODE_MESSAGE_3).map_err(|_| SessionError::Overflow)?;
        tlv::write_mac_tag(&mut w, tag.get(..n).unwrap_or(&[]))
            .map_err(|_| SessionError::Overflow)?;
        let len = w.position();
        out.extend_from_slice(buf.get(..len).unwrap_or(&[]))
            .map_err(|_| SessionError::Overflow)?;
        let mut pp = Vec::new();
        pp.extend_from_slice(peer_public)
            .map_err(|_| SessionError::Malformed)?;
        self.state = InitiatorState::AwaitingMessage4 {
            key,
            peer,
            ephemeral,
            peer_public: pp,
            key_sequence,
        };
        Ok(out)
    }

    /// Verifies Message 4; the session is established on success.
    pub fn on_message4<C: BlockCipher>(
        &mut self,
        message: &[u8],
    ) -> Result<Established, SessionError> {
        let state = core::mem::replace(&mut self.state, InitiatorState::Done);
        let InitiatorState::AwaitingMessage4 {
            key,
            peer,
            ephemeral,
            peer_public,
            key_sequence,
        } = state
        else {
            return Err(SessionError::UnexpectedMessage);
        };
        let set = parse(message, OPCODE_MESSAGE_4)?;
        let tag = tlv::mac_tag(&set).ok_or(SessionError::Malformed)?;
        let mut expected = [0u8; 32];
        let n = mac_tag::<C>(
            self.method,
            &key,
            LABEL_RESPONDER,
            peer,
            &peer_public,
            self.local,
            ephemeral.public(),
            &mut expected,
        );
        let ok: bool = expected.get(..n).unwrap_or(&[]).ct_eq(tag).into();
        if n == 0 || tag.len() != n || !ok {
            return Err(SessionError::KeyConfirmationFailed);
        }
        Ok(Established {
            key,
            peer,
            psk: self.psk,
            key_sequence,
            peer_key_sequence: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_security::cipher::SoftwareAes;

    const ZVD: ExtendedAddress = ExtendedAddress(0x001F_EE00_0000_0001);
    const ZDD: ExtendedAddress = ExtendedAddress(0x001F_EE00_0000_0002);

    /// A deterministic generator for tests only (never cryptographic).
    struct TestRng(panweave_types::rng::DeterministicRng);
    impl panweave_types::rng::Rng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.fill_bytes(dest);
        }
    }
    impl CryptoRng for TestRng {}

    fn hex(s: &str) -> Vec<u8, 160> {
        s.split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect()
    }

    fn scalar(s: &str) -> [u8; 32] {
        let v = hex(s);
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }

    /// A responder whose ephemeral scalar is fixed (Annex B).
    fn responder_with_secret<C: BlockCipher>(
        method: Method,
        local: ExtendedAddress,
        secret: [u8; 32],
        psk: &[u8],
        message1: &[u8],
    ) -> (
        Responder<'static>,
        Message,
        Key128,
        Vec<u8, 64>,
        ExtendedAddress,
    ) {
        // Reproduce Responder::on_message1 with a fixed scalar.
        let set = parse(message1, OPCODE_MESSAGE_1).unwrap();
        let (m, _) = tlv::method(&set).unwrap();
        assert_eq!(m, method);
        let (peer, peer_public) = tlv::point(&set, method).unwrap();
        let ephemeral = Ephemeral::from_secret::<C>(secret, method, psk).unwrap();
        let key = ephemeral
            .derive::<C>(local, peer, peer_public, psk)
            .unwrap();
        let mut buf = [0u8; MAX_MESSAGE];
        let mut w = Writer::new(&mut buf);
        w.u8(OPCODE_MESSAGE_2).unwrap();
        tlv::write_point(&mut w, method.point_tag(), local, ephemeral.public()).unwrap();
        let n = w.position();
        let mut m2 = Message::new();
        m2.extend_from_slice(&buf[..n]).unwrap();
        let mut pp = Vec::new();
        pp.extend_from_slice(peer_public).unwrap();
        static SECRETS: fn(Psk, Option<u8>) -> Option<Secret<'static>> =
            |_, _| Some(Secret::Anonymous);
        let mut r = Responder::new(method, local, None, &SECRETS);
        r.state = ResponderState::AwaitingMessage3 {
            key: key.clone(),
            peer,
            psk: Psk::Anonymous,
            peer_key_sequence: None,
            ephemeral,
            peer_public: pp.clone(),
        };
        (r, m2, key, pp, peer)
    }

    #[test]
    fn annex_b2_speke_curve25519_vectors() {
        let di = scalar(
            "a0 f1 d9 2a 82 c8 d8 fe 43 4d 98 55 8c e2 b3 47 17 11 98 54 2f 11 2d 05 58 f5 6b d6 88 07 99 52",
        );
        let dr = scalar(
            "48 33 62 41 f3 0d 23 e5 5f 30 d1 c8 ed 61 0c 4b 02 35 39 81 84 b8 14 a2 9c b4 5a 67 2a ca e5 48",
        );
        let mut zvd = Initiator::new(Method::Curve25519AesMmo, ZVD, Psk::Anonymous);
        let m1 = zvd
            .message1_with_secret::<SoftwareAes>(di, &Secret::Anonymous, None)
            .unwrap();
        assert_eq!(
            m1.as_slice(),
            hex("01 00 01 01 ff 02 27 01 00 00 00 00 ee 1f 00 5d 28 29 8c 91 3d 58 8a 35 e0 1f 79 c9 11 66 10 b7 9b 38 e9 c6 cf 15 5c 55 b0 52 9b bc cc 85 56").as_slice()
        );
        let (mut zdd, m2, key, _, _) = responder_with_secret::<SoftwareAes>(
            Method::Curve25519AesMmo,
            ZDD,
            dr,
            ANONYMOUS_PSK,
            &m1,
        );
        assert_eq!(
            m2.as_slice(),
            hex("02 02 27 02 00 00 00 00 ee 1f 00 82 77 2f 75 3d e9 4e b4 92 0f b4 17 d4 67 17 80 81 74 0c 1a 87 58 fd 3f 2f 63 02 b5 0b 98 35 6f").as_slice()
        );
        assert_eq!(
            key.as_bytes(),
            hex("af f1 93 4b e6 9b 40 11 17 9d 81 d9 f9 a5 ff eb").as_slice()
        );
        let m3 = zvd.on_message2::<SoftwareAes>(&m2).unwrap();
        assert_eq!(
            m3.as_slice(),
            hex("03 04 0f da 21 b1 04 d0 73 96 6f 5a 38 80 27 2f 8a f2 f0").as_slice()
        );
        let (m4, established) = zdd.on_message3::<SoftwareAes>(&m3).unwrap();
        assert_eq!(
            m4.as_slice(),
            hex("04 04 0f c2 3b 54 c1 3d 8a 8a 14 18 a4 ff a6 9d 2b bb 0d").as_slice()
        );
        assert_eq!(established.key, key);
        assert_eq!(established.peer, ZVD);
        let done = zvd.on_message4::<SoftwareAes>(&m4).unwrap();
        assert_eq!(done.key, key);
        assert_eq!(done.peer, ZDD);
        assert_eq!(done.psk, Psk::Anonymous);
        // A tampered MacTag is rejected.
        let mut bad = m4.clone();
        bad[3] ^= 1;
        let mut again = Initiator::new(Method::Curve25519AesMmo, ZVD, Psk::Anonymous);
        let _ = again
            .message1_with_secret::<SoftwareAes>(di, &Secret::Anonymous, None)
            .unwrap();
        let _ = again.on_message2::<SoftwareAes>(&m2).unwrap();
        assert_eq!(
            again.on_message4::<SoftwareAes>(&bad),
            Err(SessionError::KeyConfirmationFailed)
        );
    }

    #[cfg(feature = "p256")]
    #[test]
    fn annex_b1_ecdhe_p256_vectors() {
        let di = scalar(
            "85 5b 95 f0 d4 1f e3 5d 57 64 3e 5c 59 7f 17 5a ac 33 2d 75 95 71 49 ce 89 26 5a 71 90 c3 67 7c",
        );
        let dr = scalar(
            "fc fc 52 02 c7 20 52 8b ab f4 bf 0d 1f f5 17 bb af e6 a2 4a c5 ad 21 f0 39 d5 88 bd 15 b8 10 a6",
        );
        let mut zvd = Initiator::new(Method::P256Sha256, ZVD, Psk::Anonymous);
        let m1 = zvd
            .message1_with_secret::<SoftwareAes>(di, &Secret::Anonymous, None)
            .unwrap();
        let expected1 = hex(
            "01 00 01 03 ff 01 47 01 00 00 00 00 ee 1f 00 37 7f 24 60 3f 7f 49 34 e3 bc 11 3f 58 ad 45 81 50 78 b3 39 a7 87 49 12 dd d9 bf 3d 94 35 8a 1d 2e 03 06 08 42 81 ed bb 98 44 69 a2 83 64 ed 0c ba 6f 47 83 4d 18 cb 40 80 35 28 d9 75 4b 1c 42",
        );
        assert_eq!(m1.as_slice(), expected1.as_slice());
        let (mut zdd, m2, key, _, _) =
            responder_with_secret::<SoftwareAes>(Method::P256Sha256, ZDD, dr, ANONYMOUS_PSK, &m1);
        let expected2 = hex(
            "02 01 47 02 00 00 00 00 ee 1f 00 b1 87 5c 74 87 c1 e2 ca ae e4 14 23 71 b2 cd 42 fd e9 d9 42 3b f3 a1 aa 08 40 7d 2c 01 8a 9e b8 84 0c db 17 08 4d fd f9 b8 02 5a 9b ba 38 bd 3c f1 48 0f 3b 91 f7 16 89 2c ad a2 b6 77 a8 68 9b",
        );
        assert_eq!(m2.as_slice(), expected2.as_slice());
        assert_eq!(
            key.as_bytes(),
            hex("87 96 cc 62 87 30 37 d2 52 cf 28 ed df 45 c0 82").as_slice()
        );
        let m3 = zvd.on_message2::<SoftwareAes>(&m2).unwrap();
        assert_eq!(
            m3.as_slice(),
            hex("03 04 1f cf 34 23 df 94 ca 5f 79 1d ca 21 b6 14 9b 71 84 5b 51 78 be 12 23 2f 21 2e 17 24 7c 25 e2 88 08").as_slice()
        );
        let (m4, established) = zdd.on_message3::<SoftwareAes>(&m3).unwrap();
        assert_eq!(
            m4.as_slice(),
            hex("04 04 1f f1 94 28 82 f2 46 dc 62 eb da 61 85 79 23 04 54 6f 08 f1 ec 98 9b 0c 35 f2 16 99 76 8c cc 97 4a").as_slice()
        );
        assert_eq!(established.key, key);
        assert_eq!(zvd.on_message4::<SoftwareAes>(&m4).unwrap().key, key);
    }

    #[test]
    fn responder_refuses_wrong_method_and_psk() {
        static NO_ANON: fn(Psk, Option<u8>) -> Option<Secret<'static>> = |p, _| match p {
            Psk::Anonymous => None,
            _ => Some(Secret::Anonymous),
        };
        let mut zdd = Responder::new(Method::Curve25519AesMmo, ZDD, Some(3), &NO_ANON);
        let mut rng = TestRng(panweave_types::rng::DeterministicRng::seed(7));
        let mut zvd = Initiator::new(Method::Curve25519AesMmo, ZVD, Psk::Anonymous);
        let m1 = zvd
            .message1::<SoftwareAes, _>(&mut rng, &Secret::Anonymous, None)
            .unwrap();
        assert_eq!(
            zdd.on_message1::<SoftwareAes, _>(&mut rng, &m1),
            Err(SessionError::UnsupportedPsk)
        );
        // Wrong characteristic for the method.
        let mut zdd = Responder::new(Method::P256Sha256, ZDD, None, &NO_ANON);
        assert_eq!(
            zdd.on_message1::<SoftwareAes, _>(&mut rng, &m1),
            Err(SessionError::UnsupportedMethod)
        );
    }
}
