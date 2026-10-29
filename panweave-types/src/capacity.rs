//! Compile-time table capacities carried by types.
//!
//! A layer that is generic over a *profile* type names each of its
//! bounded tables by a [`Capacity`] (`Cap<4>`, `Cap<0>`) instead of a
//! `const` parameter, so that one profile parameter replaces a dozen
//! capacities and a profile can choose them all at once:
//!
//! ```
//! use panweave_types::capacity::{Cap, Capacity, DequeOf, VecOf};
//!
//! trait Dims {
//!     type Queue: Capacity;
//!     type Table: Capacity;
//! }
//! struct Small;
//! impl Dims for Small {
//!     type Queue = Cap<2>;
//!     type Table = Cap<0>;
//! }
//! struct Layer<D: Dims> {
//!     queue: DequeOf<u32, D::Queue>,
//!     table: VecOf<u16, D::Table>,
//! }
//! let mut l = Layer::<Small> { queue: <Small as Dims>::Queue::deque(), table: <Small as Dims>::Table::vec() };
//! assert!(l.queue.push_back(1).is_ok());
//! assert!(l.table.push(1).is_err());
//! ```
//!
//! [`VecOf`] and [`DequeOf`] are `heapless` vectors and deques over the
//! capacity's storage: every method `heapless` implements for any
//! storage is available on them in generic code. Construction, cloning
//! and the length of a deque go through [`Capacity`] and [`DequeLen`],
//! whose `heapless` counterparts exist only for a known `N`.
//!
//! Profiles are types, not Cargo features: two stacks of different
//! profiles can coexist in one binary.

use heapless::deque::DequeInner;
use heapless::vec::{OwnedVecStorage, VecInner, VecStorage};

/// A table capacity known at compile time.
pub trait Capacity: 'static {
    /// The number of entries.
    const N: usize;
    /// The `heapless` storage of `N` entries of `T`.
    type Storage<T>: VecStorage<T>;
    /// An empty vector of this capacity.
    fn vec<T>() -> VecOf<T, Self>;
    /// An empty deque of this capacity (a deque needs at least one
    /// entry: `Cap<0>` deques fail to compile).
    fn deque<T>() -> DequeOf<T, Self>;
    /// A copy of `v`.
    fn clone_vec<T: Clone>(v: &VecOf<T, Self>) -> VecOf<T, Self>;
    /// A copy of `d`.
    fn clone_deque<T: Clone>(d: &DequeOf<T, Self>) -> DequeOf<T, Self>;
}

/// The capacity of `N` entries.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Cap<const N: usize>;

impl<const K: usize> Capacity for Cap<K> {
    const N: usize = K;
    type Storage<T> = OwnedVecStorage<T, K>;

    fn vec<T>() -> heapless::Vec<T, K> {
        heapless::Vec::new()
    }

    fn deque<T>() -> heapless::Deque<T, K> {
        heapless::Deque::new()
    }

    fn clone_vec<T: Clone>(v: &heapless::Vec<T, K>) -> heapless::Vec<T, K> {
        v.clone()
    }

    fn clone_deque<T: Clone>(d: &heapless::Deque<T, K>) -> heapless::Deque<T, K> {
        d.clone()
    }
}

/// A vector of capacity `K`.
pub type VecOf<T, K> = VecInner<T, usize, <K as Capacity>::Storage<T>>;

/// A deque of capacity `K`.
pub type DequeOf<T, K> = DequeInner<T, <K as Capacity>::Storage<T>>;

/// Length and capacity of a deque in generic code (`heapless` implements
/// `len` and `capacity` for a known `N` only).
pub trait DequeLen {
    /// Number of queued entries.
    fn len(&self) -> usize;
    /// Whether no entry is queued.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Maximum number of entries.
    fn capacity(&self) -> usize;
}

impl<T, S: VecStorage<T> + ?Sized> DequeLen for DequeInner<T, S> {
    fn len(&self) -> usize {
        self.storage_len()
    }

    fn capacity(&self) -> usize {
        self.storage_capacity()
    }
}

/// `serde(with = "panweave_types::capacity::serde_vec")` for a
/// [`VecOf`] field: a sequence, refused on deserialization when longer
/// than the capacity.
#[cfg(feature = "serde")]
pub mod serde_vec {
    use core::marker::PhantomData;

    use serde::de::{Error, SeqAccess, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{Capacity, VecOf};

    /// Serializes the entries as a sequence.
    pub fn serialize<T: Serialize, K: Capacity, S: Serializer>(
        v: &VecOf<T, K>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter())
    }

    /// Deserializes a sequence of at most `K::N` entries.
    pub fn deserialize<'de, T: Deserialize<'de>, K: Capacity, D: Deserializer<'de>>(
        d: D,
    ) -> Result<VecOf<T, K>, D::Error> {
        struct Seq<T, K>(PhantomData<(T, K)>);
        impl<'de, T: Deserialize<'de>, K: Capacity> Visitor<'de> for Seq<T, K> {
            type Value = VecOf<T, K>;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "a sequence of at most {} entries", K::N)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut v = K::vec();
                while let Some(x) = seq.next_element()? {
                    v.push(x)
                        .map_err(|_| A::Error::invalid_length(K::N + 1, &self))?;
                }
                Ok(v)
            }
        }
        d.deserialize_seq(Seq::<T, K>(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Big(#[allow(dead_code)] [u8; 64]);

    #[test]
    fn storage_follows_the_capacity() {
        assert_eq!(<Cap<3> as Capacity>::N, 3);
        let mut v = <Cap<2>>::vec::<u8>();
        assert!(v.push(1).is_ok() && v.push(2).is_ok());
        assert_eq!(v.push(3), Err(3));
        assert_eq!(<Cap<2>>::clone_vec(&v).as_slice(), &[1, 2]);
        let mut d = <Cap<1>>::deque::<Big>();
        assert!(d.push_back(Big([0; 64])).is_ok());
        assert!(d.push_back(Big([1; 64])).is_err());
        assert_eq!((DequeLen::len(&d), DequeLen::capacity(&d)), (1, 1));
        let none = <Cap<0>>::vec::<Big>();
        assert!(size_of_val(&none) < size_of::<Big>());
    }
}
