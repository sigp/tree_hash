//! Differential property tests between the three merkleization implementations.
//!
//! The equivalence is checked as a chain:
//!
//!  - `merkleize_padded` against `merkleize_standard` (the naive reference), and
//!  - `MerkleHasher` and `merkle_root` against `merkleize_padded`.
//!
//! `ProgressiveMerkleHasher` and `ProgressiveBitList` hashing are checked against a recursive
//! reference implementation of EIP-7916 `merkleize_progressive`, built on `merkle_root` (itself
//! verified by the chain above).

use ethereum_hashing::hash32_concat;
use proptest::prelude::*;
use ssz::ProgressiveBitList;
use tree_hash::{
    merkle_root, merkleize_padded, merkleize_standard, mix_in_length, Error, Hash256, MerkleHasher,
    ProgressiveMerkleHasher, TreeHash, BYTES_PER_CHUNK,
};

const MAX_BYTES: usize = 2048;
const MAX_MIN_CHUNKS: usize = 70;
/// Large enough (128 chunks) to cross the progressive level boundaries at 1, 5, 21 and 85 chunks.
const MAX_PROGRESSIVE_BYTES: usize = 4096;
const MAX_BITLIST_BITS: usize = 2048;

/// Computes the root of `bytes` with the naive algorithm, padding the input out to `min_chunks`
/// (rounded to the next power of two) since `merkleize_standard` does not take a chunk count.
fn reference_root(bytes: &[u8], min_chunks: usize) -> Hash256 {
    let mut padded = bytes.to_vec();
    padded.resize(
        std::cmp::max(
            bytes.len(),
            min_chunks.next_power_of_two() * BYTES_PER_CHUNK,
        ),
        0,
    );
    merkleize_standard(&padded)
}

proptest! {
    #[test]
    fn merkleize_padded_matches_standard(
        bytes in proptest::collection::vec(any::<u8>(), 0..=MAX_BYTES),
        min_chunks in 0..=MAX_MIN_CHUNKS,
    ) {
        prop_assert_eq!(
            merkleize_padded(&bytes, min_chunks),
            reference_root(&bytes, min_chunks)
        );
    }

    #[test]
    fn merkle_hasher_matches_merkleize_padded(
        bytes in proptest::collection::vec(any::<u8>(), 0..=MAX_BYTES),
        extra_leaves in 0_usize..=8,
        write_size in 1_usize..=64,
    ) {
        let num_leaves = bytes.len().div_ceil(BYTES_PER_CHUNK) + extra_leaves;

        let mut hasher = MerkleHasher::with_leaves(num_leaves);
        for chunk in bytes.chunks(write_size) {
            hasher.write(chunk).expect("num_leaves is sufficient for bytes");
        }
        let root = hasher.finish().expect("num_leaves is sufficient for bytes");

        prop_assert_eq!(root, merkleize_padded(&bytes, num_leaves));
    }

    #[test]
    fn merkle_hasher_rejects_too_many_bytes(
        num_leaves in 0_usize..=MAX_MIN_CHUNKS,
        extra_bytes in 1_usize..=3 * BYTES_PER_CHUNK,
        write_size in 1_usize..=64,
    ) {
        // `with_leaves` rounds the leaf count up to the next power of two, so that is the true
        // capacity of the tree.
        let capacity = num_leaves.next_power_of_two();
        let bytes = vec![0xff_u8; capacity * BYTES_PER_CHUNK + extra_bytes];

        // Any bytes beyond the tree's capacity must produce an error, never a root that silently
        // ignores them. Depending on `extra_bytes` and `write_size` the error surfaces either in
        // `write` (a whole excess leaf) or in `finish` (excess bytes still in the buffer).
        let mut hasher = MerkleHasher::with_leaves(num_leaves);
        let result = bytes
            .chunks(write_size)
            .try_for_each(|chunk| hasher.write(chunk))
            .and_then(|()| hasher.finish().map(|_| ()));

        prop_assert_eq!(
            result,
            Err(Error::MaximumLeavesExceeded { max_leaves: capacity })
        );
    }

    #[test]
    fn merkle_root_matches_merkleize_padded(
        bytes in proptest::collection::vec(any::<u8>(), 0..=MAX_BYTES),
        min_leaves in 0..=MAX_MIN_CHUNKS,
    ) {
        // This exercises the 0, 1 and 2-leaf fast-paths in `merkle_root` as well as the
        // `MerkleHasher` path.
        prop_assert_eq!(
            merkle_root(&bytes, min_leaves),
            merkleize_padded(&bytes, min_leaves)
        );
    }
}

/// Recursive reference implementation of EIP-7916 `merkleize_progressive` over zero-padded chunks:
///
/// ```text
/// merkleize_progressive([], num_leaves) = Bytes32()
/// merkleize_progressive(chunks, num_leaves) = hash(
///     merkleize(chunks[:num_leaves], num_leaves),
///     merkleize_progressive(chunks[num_leaves:], num_leaves * 4),
/// )
/// ```
fn reference_progressive_root(bytes: &[u8], num_leaves: usize) -> Hash256 {
    if bytes.is_empty() {
        return Hash256::ZERO;
    }
    let take = (num_leaves * BYTES_PER_CHUNK).min(bytes.len());
    let left = merkle_root(&bytes[..take], num_leaves);
    let right = reference_progressive_root(&bytes[take..], num_leaves * 4);
    Hash256::from(hash32_concat(left.as_slice(), right.as_slice()))
}

proptest! {
    #[test]
    fn progressive_hasher_matches_reference(
        bytes in proptest::collection::vec(any::<u8>(), 0..=MAX_PROGRESSIVE_BYTES),
        write_size in 1_usize..=64,
    ) {
        // Random `write_size` exercises the partial-chunk carry buffer across write boundaries.
        let mut hasher = ProgressiveMerkleHasher::new();
        for chunk in bytes.chunks(write_size) {
            hasher.write(chunk).expect("progressive hasher has no leaf limit");
        }
        let root = hasher.finish().expect("progressive hasher has no leaf limit");

        prop_assert_eq!(root, reference_progressive_root(&bytes, 1));
    }

    #[test]
    fn progressive_bitlist_matches_reference(
        bits in proptest::collection::vec(any::<bool>(), 0..=MAX_BITLIST_BITS),
    ) {
        let mut bitlist = ProgressiveBitList::with_capacity(bits.len());
        for (i, bit) in bits.iter().enumerate() {
            bitlist.set(i, *bit).expect("index is within the bitlist length");
        }

        // Pack the bits independently of the `Bitfield` internals. In particular an empty bitlist
        // packs to zero bytes here, whereas `Bitfield` stores a single zero byte internally, so
        // this catches any regression of the empty-list workaround in `tree_hash_root`.
        let mut packed = vec![0u8; bits.len().div_ceil(8)];
        for (i, bit) in bits.iter().enumerate() {
            if *bit {
                packed[i / 8] |= 1 << (i % 8);
            }
        }
        let expected = mix_in_length(&reference_progressive_root(&packed, 1), bits.len());

        prop_assert_eq!(bitlist.tree_hash_root(), expected);
    }
}
