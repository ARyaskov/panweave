//! The Zigbee Direct Tunnel Service (ZD 1.1 §7.7.3): NPDU Message TLVs
//! carried by the ZDTS NPDU characteristic, and the trusted-link
//! pre-/post-processing of §7.7.4.1 / §7.7.4.2 that turns NWK frames
//! into characteristic payloads and back.

use panweave_codec::Writer;
use panweave_codec::tlv::{TlvIter, write_tlv};

/// Type ID of the NPDU Message TLV (Table 52).
pub const NPDU_MESSAGE: u8 = 0x00;
/// Largest TLV value (Table 53: length field 0x00..=0xF1).
pub const MAX_VALUE_LEN: usize = 0xF2;
/// Largest NPDU that fits one NPDU Message TLV.
pub const MAX_NPDU_LEN: usize = MAX_VALUE_LEN - 2;
/// Flags bit 0: SecurityEnable (Table 55).
pub const FLAG_SECURITY_ENABLE: u8 = 0x01;

/// The kind of secure session the tunnel runs over (§7.7.3.6.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SessionKind {
    /// A provisioning session opened with the ZVD's pre-shared secret:
    /// only unsecured NPDUs (the Network Commissioning exchange) pass.
    ZvdProvisioning,
    /// A provisioning session opened with the ZDD's pre-shared secret.
    ZddProvisioning,
    /// A session opened with a basic or admin authorization key.
    Authorized,
}

/// A decoded NPDU Message TLV (Table 54 / Table 55).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NpduMessage<'a> {
    /// The NPDU is to be treated as NWK-secured (`assumeSecurity`).
    pub assume_security: bool,
    /// The NWK frame without auxiliary header, security bit clear.
    pub npdu: &'a [u8],
}

/// Tunnel errors.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TunnelError {
    /// The TLV or its value field is malformed.
    Malformed,
    /// The NPDU exceeds one TLV or the output buffer.
    TooLong,
    /// A secured NPDU arrived over a ZVD provisioning session.
    Dropped,
}

impl<'a> NpduMessage<'a> {
    /// Parses the value field of an NPDU Message TLV. Octets after the
    /// NPDU are ignored so that later additions stay compatible.
    pub fn parse(value: &'a [u8]) -> Result<Self, TunnelError> {
        let (&flags, rest) = value.split_first().ok_or(TunnelError::Malformed)?;
        let (&len, rest) = rest.split_first().ok_or(TunnelError::Malformed)?;
        if flags & !FLAG_SECURITY_ENABLE != 0 {
            return Err(TunnelError::Malformed);
        }
        let npdu = rest.get(..usize::from(len)).ok_or(TunnelError::Malformed)?;
        Ok(NpduMessage {
            assume_security: flags & FLAG_SECURITY_ENABLE != 0,
            npdu,
        })
    }

    /// Post-processing (§7.7.4.1): writes the NPDU Message TLV for this
    /// NPDU into `out`; returns the length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, TunnelError> {
        let len = u8::try_from(self.npdu.len())
            .ok()
            .filter(|&l| usize::from(l) <= MAX_NPDU_LEN)
            .ok_or(TunnelError::TooLong)?;
        let mut value = [0u8; MAX_VALUE_LEN];
        value[0] = u8::from(self.assume_security);
        value[1] = len;
        value
            .get_mut(2..2 + self.npdu.len())
            .ok_or(TunnelError::TooLong)?
            .copy_from_slice(self.npdu);
        let mut w = Writer::new(out);
        write_tlv(
            &mut w,
            NPDU_MESSAGE,
            value
                .get(..2 + self.npdu.len())
                .ok_or(TunnelError::TooLong)?,
        )
        .map_err(|_| TunnelError::TooLong)?;
        Ok(w.position())
    }
}

/// Pre-processing (§7.7.4.2) of a decrypted ZDTS NPDU characteristic
/// payload: yields each NPDU Message TLV in order (Table 51 allows
/// several), applying the session rule of §7.7.3.6.2. Unknown TLVs are
/// skipped; a malformed payload ends the iteration with an error.
pub fn preprocess(
    payload: &[u8],
    session: SessionKind,
) -> impl Iterator<Item = Result<NpduMessage<'_>, TunnelError>> {
    TlvIter::new(payload).filter_map(move |item| match item {
        Err(_) => Some(Err(TunnelError::Malformed)),
        Ok(tlv) if tlv.tag != NPDU_MESSAGE => None,
        Ok(tlv) => Some(NpduMessage::parse(tlv.value).and_then(|m| {
            if m.assume_security && session == SessionKind::ZvdProvisioning {
                Err(TunnelError::Dropped)
            } else {
                Ok(m)
            }
        })),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type Got<'a> = heapless::Vec<Result<NpduMessage<'a>, TunnelError>, 4>;

    #[test]
    fn npdu_message_round_trip_and_session_rule() {
        let npdu = [0x08, 0x02, 0x01, 0x00, 0x02, 0x00, 0x1e, 0x2a, 0xaa];
        let m = NpduMessage {
            assume_security: true,
            npdu: &npdu,
        };
        let mut out = [0u8; 32];
        let n = m.encode(&mut out).unwrap();
        assert_eq!(n, 2 + 2 + npdu.len());
        assert_eq!(&out[..4], &[0x00, 10, 0x01, 9]);
        let got: Got<'_> = preprocess(&out[..n], SessionKind::Authorized).collect();
        assert_eq!(got.as_slice(), &[Ok(m)]);
        // Secured NPDUs are dropped on a ZVD provisioning session, but
        // unsecured ones pass and later TLVs are still handled.
        let mut two = [0u8; 64];
        two[..n].copy_from_slice(&out[..n]);
        let m2 = NpduMessage {
            assume_security: false,
            npdu: &npdu[..3],
        };
        let n2 = m2.encode(&mut two[n..]).unwrap();
        let got: Got<'_> = preprocess(&two[..n + n2], SessionKind::ZvdProvisioning).collect();
        assert_eq!(got.as_slice(), &[Err(TunnelError::Dropped), Ok(m2)]);
        // Trailing octets after the NPDU are tolerated; a short NPDU is not.
        assert_eq!(
            NpduMessage::parse(&[0x00, 0x01, 0xaa, 0xbb]).unwrap().npdu,
            &[0xaa]
        );
        assert_eq!(
            NpduMessage::parse(&[0x00, 0x02, 0xaa]),
            Err(TunnelError::Malformed)
        );
        assert_eq!(
            NpduMessage::parse(&[0x02, 0x00]),
            Err(TunnelError::Malformed)
        );
        let big = [0u8; MAX_NPDU_LEN + 1];
        assert_eq!(
            NpduMessage {
                assume_security: false,
                npdu: &big
            }
            .encode(&mut [0u8; 300]),
            Err(TunnelError::TooLong)
        );
        // A truncated payload ends with an error.
        let got: Got<'_> = preprocess(&[0x00, 0x05, 0x00], SessionKind::Authorized).collect();
        assert_eq!(got.as_slice(), &[Err(TunnelError::Malformed)]);
    }
}
