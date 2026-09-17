//! Secured characteristic payloads (ZD 1.1 §6.3.3, §6.4): AES-CCM-128
//! with a 32-bit MIC, the nonce built from the sender's EUI-64 and its
//! outgoing counter, the characteristic's unique address as associated
//! data, and the per-connection counter rules of §6.4.6 / §6.4.7.

use panweave_security::ccm;
use panweave_security::cipher::BlockCipher;
use panweave_types::{ExtendedAddress, Key128};

/// Length of the security header (the 32-bit counter).
pub const HEADER_LEN: usize = 4;
/// Length of the MIC.
pub const MIC_LEN: usize = 4;
/// Length of a characteristic's unique address (Table 4).
pub const UNIQUE_ADDRESS_LEN: usize = 34;
/// Security control octet of the nonce: level 5, reserved bits 0.
pub const SECURITY_CONTROL: u8 = 0x05;

/// A 128-bit UUID in RFC 4122 byte order.
pub type Uuid = [u8; 16];

/// The Bluetooth Base UUID for 16-bit UUIDs.
pub const BASE_UUID: Uuid = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
];

/// Expands a 16-bit UUID to the 128-bit form (Table 4 note).
pub const fn expand_uuid16(uuid: u16) -> Uuid {
    let mut u = BASE_UUID;
    u[2] = (uuid >> 8) as u8;
    u[3] = (uuid & 0xff) as u8;
    u
}

/// The unique address of a characteristic (§6.4.5): service UUID,
/// service instance (0), characteristic UUID, characteristic instance
/// (0).
pub fn unique_address(service: &Uuid, characteristic: &Uuid) -> [u8; UNIQUE_ADDRESS_LEN] {
    let mut a = [0u8; UNIQUE_ADDRESS_LEN];
    a[..16].copy_from_slice(service);
    a[16] = 0;
    a[17..33].copy_from_slice(characteristic);
    a[33] = 0;
    a
}

/// The CCM nonce (§6.4.3).
pub fn nonce(source: ExtendedAddress, counter: u32) -> [u8; 13] {
    let mut n = [0u8; 13];
    n[..8].copy_from_slice(&source.0.to_le_bytes());
    n[8..12].copy_from_slice(&counter.to_le_bytes());
    n[12] = SECURITY_CONTROL;
    n
}

/// Failures of the secure channel.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SecureError {
    /// The counter is not greater than the last accepted one (§6.4.7.1).
    Stale,
    /// The MIC did not verify.
    AuthFailed,
    /// The frame is shorter than header + MIC, or the buffer is too small.
    Malformed,
    /// The outgoing counter reached 0xffffffff: disconnect (§6.4.7.2).
    CounterExhausted,
}

/// One side of a BLE secure session (§6.4.6): the session key and the
/// two counters.
#[derive(Clone, Debug)]
pub struct SecureChannel {
    key: Key128,
    local: ExtendedAddress,
    remote: ExtendedAddress,
    outgoing: u32,
    incoming: u32,
}

impl SecureChannel {
    /// A fresh channel after session establishment: both counters 0.
    pub const fn new(key: Key128, local: ExtendedAddress, remote: ExtendedAddress) -> Self {
        SecureChannel {
            key,
            local,
            remote,
            outgoing: 0,
            incoming: 0,
        }
    }

    /// Last accepted incoming counter.
    pub const fn incoming(&self) -> u32 {
        self.incoming
    }

    /// Last used outgoing counter.
    pub const fn outgoing(&self) -> u32 {
        self.outgoing
    }

    /// Protects `plaintext` for the characteristic with `unique_address`
    /// into `out` as `counter || ciphertext || MIC`; returns the length.
    pub fn protect<C: BlockCipher>(
        &mut self,
        unique_address: &[u8; UNIQUE_ADDRESS_LEN],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, SecureError> {
        if self.outgoing == u32::MAX {
            return Err(SecureError::CounterExhausted);
        }
        let total = HEADER_LEN + plaintext.len() + MIC_LEN;
        if out.len() < total {
            return Err(SecureError::Malformed);
        }
        let counter = self.outgoing + 1;
        let n = nonce(self.local, counter);
        let cipher = C::new(&self.key);
        let (head, rest) = out.split_at_mut(HEADER_LEN);
        head.copy_from_slice(&counter.to_le_bytes());
        let (body, tail) = rest.split_at_mut(plaintext.len());
        body.copy_from_slice(plaintext);
        let mic = tail.get_mut(..MIC_LEN).ok_or(SecureError::Malformed)?;
        ccm::encrypt_in_place(&cipher, &n, unique_address, body, mic)
            .map_err(|_| SecureError::Malformed)?;
        self.outgoing = counter;
        Ok(total)
    }

    /// Validates and decrypts a received `counter || ciphertext || MIC`
    /// value in place; returns the plaintext. A failure leaves the
    /// incoming counter untouched (§6.4.7.1).
    pub fn unprotect<'a, C: BlockCipher>(
        &mut self,
        unique_address: &[u8; UNIQUE_ADDRESS_LEN],
        frame: &'a mut [u8],
    ) -> Result<&'a [u8], SecureError> {
        if frame.len() < HEADER_LEN + MIC_LEN {
            return Err(SecureError::Malformed);
        }
        let mut c = [0u8; 4];
        c.copy_from_slice(frame.get(..HEADER_LEN).ok_or(SecureError::Malformed)?);
        let counter = u32::from_le_bytes(c);
        if counter <= self.incoming {
            return Err(SecureError::Stale);
        }
        let n = nonce(self.remote, counter);
        let cipher = C::new(&self.key);
        let body_len = frame.len() - HEADER_LEN - MIC_LEN;
        let (_, rest) = frame.split_at_mut(HEADER_LEN);
        let (body, mic) = rest.split_at_mut(body_len);
        let mut tag = [0u8; MIC_LEN];
        tag.copy_from_slice(mic.get(..MIC_LEN).ok_or(SecureError::Malformed)?);
        ccm::decrypt_in_place(&cipher, &n, unique_address, body, &tag)
            .map_err(|_| SecureError::AuthFailed)?;
        self.incoming = counter;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gatt;
    use panweave_security::cipher::SoftwareAes;

    #[test]
    fn annex_b4_join_network_write() {
        let zvd = ExtendedAddress(0x001F_EE00_0000_0001);
        let zdd = ExtendedAddress(0x001F_EE00_0000_0002);
        let key = Key128::from_bytes([
            0xa2, 0xe2, 0xb6, 0x1b, 0xf1, 0xa8, 0x05, 0x81, 0xd0, 0x7f, 0x1f, 0x06, 0x72, 0xd1,
            0xd6, 0x24,
        ]);
        let plaintext: [u8; 42] = [
            0x07, 0x00, 0x03, 0x00, 0x07, 0xd9, 0x1f, 0x00, 0x00, 0x00, 0xae, 0x1f, 0x00, 0x01,
            0x01, 0x26, 0x90, 0x02, 0x03, 0x00, 0x00, 0x01, 0x00, 0x03, 0x0f, 0x5c, 0xd2, 0xf8,
            0xbe, 0xd4, 0xea, 0x50, 0x56, 0xac, 0x02, 0xa8, 0xee, 0x84, 0x1a, 0xa0, 0x86, 0x06,
        ];
        let plaintext_full: [u8; 45] = {
            let mut p = [0u8; 45];
            p[..42].copy_from_slice(&plaintext);
            p[42..].copy_from_slice(&[0x01, 0xcd, 0xab]);
            p
        };
        let aad = unique_address(
            &gatt::COMMISSIONING_SERVICE,
            &gatt::commissioning::JOIN_NETWORK,
        );
        assert_eq!(
            &aad[..17],
            &[
                0x00, 0x00, 0xff, 0xf7, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b,
                0x34, 0xfb, 0x00
            ]
        );
        assert_eq!(
            &aad[17..],
            &[
                0x70, 0x72, 0x37, 0x7d, 0x00, 0x02, 0x42, 0x1c, 0xb1, 0x63, 0x49, 0x1c, 0x27, 0x33,
                0x3a, 0x61, 0x00
            ]
        );
        assert_eq!(
            nonce(zvd, 2),
            [
                0x01, 0x00, 0x00, 0x00, 0x00, 0xee, 0x1f, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05
            ]
        );
        // The ZVD's second message: outgoing counter 1 already used.
        let mut tx = SecureChannel::new(key.clone(), zvd, zdd);
        tx.outgoing = 1;
        let mut out = [0u8; 64];
        let n = tx
            .protect::<SoftwareAes>(&aad, &plaintext_full, &mut out)
            .unwrap();
        assert_eq!(n, 4 + 45 + 4);
        assert_eq!(&out[..4], &[0x02, 0x00, 0x00, 0x00]);
        assert_eq!(
            &out[4..49],
            &[
                0x23, 0xb7, 0x11, 0xa6, 0x91, 0x6a, 0xba, 0x32, 0x82, 0xb3, 0x7a, 0x7c, 0xb4, 0x4f,
                0x30, 0x18, 0x7c, 0x43, 0xc2, 0x45, 0xd3, 0xbd, 0x6f, 0xf1, 0xaf, 0xe5, 0x9d, 0x0b,
                0x3a, 0x9b, 0x0f, 0xda, 0xc5, 0x26, 0xd3, 0x63, 0x3d, 0xae, 0xdf, 0x73, 0x5d, 0x78,
                0x35, 0xfe, 0x9f
            ]
        );
        assert_eq!(&out[49..53], &[0x3f, 0x12, 0xbd, 0xf8]);
        // The ZDD accepts it once, then rejects the replay.
        let mut rx = SecureChannel::new(key, zdd, zvd);
        let mut frame = out;
        let plain = rx.unprotect::<SoftwareAes>(&aad, &mut frame[..n]).unwrap();
        assert_eq!(plain, &plaintext_full);
        assert_eq!(rx.incoming(), 2);
        let mut frame = out;
        assert_eq!(
            rx.unprotect::<SoftwareAes>(&aad, &mut frame[..n]),
            Err(SecureError::Stale)
        );
        // A tampered MIC fails without advancing the counter.
        let mut rx = SecureChannel::new(
            Key128::from_bytes([
                0xa2, 0xe2, 0xb6, 0x1b, 0xf1, 0xa8, 0x05, 0x81, 0xd0, 0x7f, 0x1f, 0x06, 0x72, 0xd1,
                0xd6, 0x24,
            ]),
            zdd,
            zvd,
        );
        let mut frame = out;
        frame[50] ^= 1;
        assert_eq!(
            rx.unprotect::<SoftwareAes>(&aad, &mut frame[..n]),
            Err(SecureError::AuthFailed)
        );
        assert_eq!(rx.incoming(), 0);
    }
}
