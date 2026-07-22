//! Differential property tests between the three merkleization implementations.
//!
//! The equivalence is checked as a chain:
//!
//!  - `merkleize_padded` against `merkleize_standard` (the naive reference), and
//!  - `MerkleHasher` and `merkle_root` against `merkleize_padded`.

use proptest::prelude::*;
use tree_hash::{
    merkle_root, merkleize_padded, merkleize_standard, Hash256, MerkleHasher, BYTES_PER_CHUNK,
};

const MAX_BYTES: usize = 2048;
const MAX_MIN_CHUNKS: usize = 70;

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
