//! Random number generation abstraction.
//!
//! The protocol core never calls a global RNG. Every component that needs
//! randomness (address assignment, sequence-number seeding, jitter, key
//! generation, key negotiation) receives an `&mut impl Rng`.
//!
//! [`CryptoRng`] is a marker trait that an implementation asserts only when
//! its output is suitable for key material. Deterministic test generators
//! implement [`Rng`] but never [`CryptoRng`], and the security crate only
//! accepts `CryptoRng` for key generation, so a mistake fails to compile.

/// A source of random bytes.
pub trait Rng {
    /// Fills `dest` with random bytes.
    fn fill_bytes(&mut self, dest: &mut [u8]);

    /// Returns a random `u32`.
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    /// Returns a random `u16`.
    fn next_u16(&mut self) -> u16 {
        let mut b = [0u8; 2];
        self.fill_bytes(&mut b);
        u16::from_le_bytes(b)
    }

    /// Returns a random `u8`.
    fn next_u8(&mut self) -> u8 {
        let mut b = [0u8; 1];
        self.fill_bytes(&mut b);
        b[0]
    }

    /// Returns a random `u64`.
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    /// Returns a uniformly distributed value in `0..bound` (returns 0 when
    /// `bound` is 0). Uses rejection sampling to avoid modulo bias.
    fn below(&mut self, bound: u32) -> u32 {
        if bound == 0 {
            return 0;
        }
        // Largest multiple of `bound` that fits in u32.
        let zone = u32::MAX - (u32::MAX % bound);
        loop {
            let v = self.next_u32();
            if v < zone {
                return v % bound;
            }
        }
    }
}

/// Marker trait for cryptographically secure generators.
///
/// Only implement this for hardware TRNGs or properly seeded CSPRNGs.
pub trait CryptoRng: Rng {}

impl<T: Rng + ?Sized> Rng for &mut T {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        (**self).fill_bytes(dest);
    }
    fn next_u32(&mut self) -> u32 {
        (**self).next_u32()
    }
}

impl<T: CryptoRng + ?Sized> CryptoRng for &mut T {}

/// Adapter exposing a [`rand_core::Rng`] as a Panweave [`Rng`].
///
/// Cryptographic suitability is inherited: the adapter implements
/// [`CryptoRng`] only when the wrapped generator implements
/// [`rand_core::CryptoRng`].
pub struct RandCoreAdapter<R>(pub R);

impl<R: rand_core::Rng> Rng for RandCoreAdapter<R> {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
}

impl<R: rand_core::CryptoRng> CryptoRng for RandCoreAdapter<R> {}

/// A small deterministic generator for tests and simulation (xoshiro128**).
///
/// It deliberately does **not** implement [`CryptoRng`].
#[derive(Clone, Debug)]
pub struct DeterministicRng {
    s: [u32; 4],
}

impl DeterministicRng {
    /// Creates a generator from a 64-bit seed (expanded with splitmix64).
    pub fn seed(seed: u64) -> Self {
        let mut x = seed;
        let mut next = || {
            x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        let a = next();
        let b = next();
        // Splitting a u64 into two u32 halves is intentional.
        #[allow(clippy::cast_possible_truncation)]
        let s = [a as u32, (a >> 32) as u32, b as u32, (b >> 32) as u32];
        let mut rng = DeterministicRng { s };
        if rng.s == [0; 4] {
            rng.s = [1, 2, 3, 4];
        }
        rng
    }

    fn step(&mut self) -> u32 {
        let result = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 9;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(11);
        result
    }
}

impl Rng for DeterministicRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(4) {
            let v = self.step().to_le_bytes();
            let n = chunk.len();
            if let Some(src) = v.get(..n) {
                chunk.copy_from_slice(src);
            }
        }
    }

    fn next_u32(&mut self) -> u32 {
        self.step()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_rng_is_reproducible() {
        let mut a = DeterministicRng::seed(42);
        let mut b = DeterministicRng::seed(42);
        for _ in 0..100 {
            assert_eq!(a.next_u32(), b.next_u32());
        }
        let mut c = DeterministicRng::seed(43);
        assert_ne!(a.next_u32(), c.next_u32());
    }

    #[test]
    fn below_is_in_range() {
        let mut r = DeterministicRng::seed(7);
        for _ in 0..1000 {
            assert!(r.below(10) < 10);
        }
        assert_eq!(r.below(0), 0);
        assert_eq!(r.below(1), 0);
    }
}
