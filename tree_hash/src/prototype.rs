/*
type Hash256 = [u8; 32];

enum Error {
    Oops
}

trait TreeHash {
    fn get_field(&self, index: usize) -> Result<&dyn TreeHash, Error>;

    fn merkle_proof(&self, generalized_index: usize) -> Result<Vec<Hash256>, Error>;
}
*/
use crate::{TreeHash, TreeHashType, BYTES_PER_CHUNK};
use std::marker::PhantomData;

// A path is a sequence of field accesses like `self.foo.bar`.
//
// We can resolve these at compile time, because we're sickos.
pub struct Path<First, Rest>(PhantomData<(First, Rest)>);

// The field trait is implemented for all struct fields.
//
// It provides conversion from a named field type to a numeric field index.
pub trait Field {
    const NUM_FIELDS: usize;
    const INDEX: usize;
}

// If T implements Resolve<Field> it means T has a field named Field of type Output.
pub trait Resolve<Field> {
    type Output;

    fn gindex(parent_index: usize) -> usize;
}

// This impl defines how paths are resolved and converted to gindices.
impl<T, First, Rest> Resolve<Path<First, Rest>> for T
where
    Self: Resolve<First>,
    First: Field,
    <Self as Resolve<First>>::Output: Resolve<Rest>,
{
    type Output = <<Self as Resolve<First>>::Output as Resolve<Rest>>::Output;

    fn gindex(parent_index: usize) -> usize {
        // From `get_generalized_index`:
        // https://github.com/ethereum/consensus-specs/blob/dev/ssz/merkle-proofs.md#ssz-object-to-index
        let new_parent_index = <Self as Resolve<First>>::gindex(parent_index);
        <Self as Resolve<First>>::Output::gindex(new_parent_index)
    }
}

pub struct VecIndex<const I: usize, const N: usize>;

impl<const I: usize, const N: usize> Field for VecIndex<I, N> {
    const NUM_FIELDS: usize = N;
    const INDEX: usize = I;
}

pub fn item_length<T: TreeHash>() -> usize {
    if T::tree_hash_type() == TreeHashType::Basic {
        BYTES_PER_CHUNK / T::tree_hash_packing_factor()
    } else {
        BYTES_PER_CHUNK
    }
}

pub fn vector_chunk_count<T: TreeHash>(length: usize) -> usize {
    (length * item_length::<T>()).div_ceil(BYTES_PER_CHUNK)
}

pub fn get_vector_item_position<T: TreeHash>(index: usize) -> usize {
    let start = index * item_length::<T>();
    start / BYTES_PER_CHUNK
}

/*
impl TreeHash for u64 {
    fn get_field(&self, _: usize) -> Result<&dyn TreeHash, Error> {
        Err(Error::Oops)
    }

    fn merkle_proof(&self)
}
*/
