use crate::{get_zero_hash, merkle_root, Hash256, BYTES_PER_CHUNK};
use ethereum_hashing::hash32_concat;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// The maximum number of leaves has been exceeded.
    MaximumLeavesExceeded { max_leaves: usize },
}

/// A progressive Merkle hasher that implements the semantics of `merkleize_progressive` as
/// defined in EIP-7916.
///
/// The progressive merkle tree has a unique structure where:
/// - At each level, the right child is a binary merkle tree with a specific number of leaves
/// - The left child recursively contains more progressive structure
/// - The number of leaves in each right subtree grows by 4x at each level (1, 4, 16, 64, ...)
///
/// # Example Tree Structure
///
/// ```text
///         root
///          /\
///         /  \
///        /\   1: chunks[0 ..< 1]
///       /  \
///      /\   4: chunks[1 ..< 5]
///     /  \
///    /\  16: chunks[5 ..< 21]
///   /  \
///  0   64: chunks[21 ..< 85]
/// ```
///
/// This structure allows efficient appending and proof generation for growing lists.
pub struct ProgressiveMerkleHasher {
    /// All chunks that have been written to the hasher.
    chunks: Vec<[u8; BYTES_PER_CHUNK]>,
    /// Maximum number of leaves this hasher can accept.
    max_leaves: usize,
}

impl ProgressiveMerkleHasher {
    /// Create a new progressive merkle hasher that can accept up to `max_leaves` leaves.
    ///
    /// # Panics
    ///
    /// Panics if `max_leaves == 0`.
    pub fn with_leaves(max_leaves: usize) -> Self {
        assert!(max_leaves > 0, "must have at least one leaf");
        Self {
            chunks: Vec::new(),
            max_leaves,
        }
    }

    /// Write bytes to the hasher.
    ///
    /// The bytes will be split into 32-byte chunks. If the final chunk is incomplete,
    /// it will be padded with zeros.
    ///
    /// # Errors
    ///
    /// Returns an error if writing these bytes would exceed the maximum number of leaves.
    pub fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let num_new_leaves = bytes.len().div_ceil(BYTES_PER_CHUNK);
        
        if self.chunks.len() + num_new_leaves > self.max_leaves {
            return Err(Error::MaximumLeavesExceeded {
                max_leaves: self.max_leaves,
            });
        }

        // Split bytes into 32-byte chunks
        for chunk_bytes in bytes.chunks(BYTES_PER_CHUNK) {
            let mut chunk = [0u8; BYTES_PER_CHUNK];
            chunk[..chunk_bytes.len()].copy_from_slice(chunk_bytes);
            self.chunks.push(chunk);
        }

        Ok(())
    }

    /// Finish the hasher and return the progressive merkle root.
    ///
    /// This implements the recursive merkleize_progressive algorithm:
    /// - If no chunks: return zero hash
    /// - Otherwise: hash(merkleize_progressive(left), merkleize(right))
    ///   where right contains the first num_leaves chunks as a binary tree,
    ///   and left recursively contains the rest with num_leaves * 4.
    pub fn finish(self) -> Result<Hash256, Error> {
        Ok(merkleize_progressive(&self.chunks, 1))
    }
}

/// Recursively compute the progressive merkle root for the given chunks.
///
/// # Arguments
///
/// * `chunks` - The chunks to merkleize
/// * `num_leaves` - The number of leaves for the right (binary tree) subtree at this level
///
/// # Algorithm
///
/// Following the spec:
/// ```text
/// merkleize_progressive(chunks, num_leaves=1): Given ordered BYTES_PER_CHUNK-byte chunks:
///     The merkleization depends on the number of input chunks and is defined recursively:
///         If len(chunks) == 0: the root is a zero value, Bytes32().
///         Otherwise: compute the root using hash(a, b)
///             a: Recursively merkleize chunks beyond num_leaves using 
///                merkleize_progressive(chunks[num_leaves:], num_leaves * 4).
///             b: Merkleize the first up to num_leaves chunks as a binary tree using 
///                merkleize(chunks[:num_leaves], num_leaves).
/// ```
fn merkleize_progressive(chunks: &[[u8; BYTES_PER_CHUNK]], num_leaves: usize) -> Hash256 {
    if chunks.is_empty() {
        // Base case: no chunks, return zero hash
        return Hash256::ZERO;
    }

    // Split chunks into right (first num_leaves) and left (rest)
    let right_chunks = &chunks[..chunks.len().min(num_leaves)];
    let left_chunks = &chunks[chunks.len().min(num_leaves)..];

    // Compute right subtree: binary merkle tree with num_leaves leaves
    let right_root = if right_chunks.is_empty() {
        // If no chunks for right, use zero hash
        Hash256::from_slice(get_zero_hash(compute_height(num_leaves)))
    } else {
        // Use merkle_root to compute binary tree root
        let bytes: Vec<u8> = right_chunks.iter().flat_map(|c| c.iter().copied()).collect();
        merkle_root(&bytes, num_leaves)
    };

    // Compute left subtree: recursive progressive merkle tree with num_leaves * 4
    let left_root = merkleize_progressive(left_chunks, num_leaves * 4);

    // Combine left and right roots
    Hash256::from_slice(&hash32_concat(left_root.as_slice(), right_root.as_slice()))
}

/// Compute the height of a binary tree with the given number of leaves.
fn compute_height(num_leaves: usize) -> usize {
    if num_leaves == 0 {
        0
    } else {
        // Height is log2(next_power_of_two(num_leaves))
        let power_of_two = num_leaves.next_power_of_two();
        power_of_two.trailing_zeros() as usize
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let hasher = ProgressiveMerkleHasher::with_leaves(1);
        let root = hasher.finish().unwrap();
        assert_eq!(root, Hash256::ZERO);
    }

    #[test]
    fn test_single_chunk() {
        let mut hasher = ProgressiveMerkleHasher::with_leaves(1);
        let chunk = [1u8; BYTES_PER_CHUNK];
        hasher.write(&chunk).unwrap();
        let root = hasher.finish().unwrap();
        
        // For a single chunk, the progressive tree should be:
        // hash(merkleize_progressive([], 4), merkleize([chunk], 1))
        // = hash(zero_hash, chunk)
        let zero_left = Hash256::ZERO;
        let right = Hash256::from_slice(&chunk);
        let expected = Hash256::from_slice(&hash32_concat(
            zero_left.as_slice(),
            right.as_slice()
        ));
        
        assert_eq!(root, expected);
    }

    #[test]
    fn test_two_chunks() {
        let mut hasher = ProgressiveMerkleHasher::with_leaves(5);
        let chunk1 = [1u8; BYTES_PER_CHUNK];
        let chunk2 = [2u8; BYTES_PER_CHUNK];
        hasher.write(&chunk1).unwrap();
        hasher.write(&chunk2).unwrap();
        let root = hasher.finish().unwrap();
        
        // First chunk goes to right (num_leaves=1)
        // Second chunk goes to left recursive call (num_leaves=4)
        
        // Right: binary tree with 1 leaf = chunk1
        let right = Hash256::from_slice(&chunk1);
        
        // Left: progressive tree with chunk2 at num_leaves=4
        // At this level: hash(merkleize_progressive([], 16), merkleize([chunk2], 4))
        // = hash(zero_hash, merkle([chunk2], 4))
        let chunk2_padded = merkle_root(&chunk2, 4);
        let zero_left_inner = Hash256::ZERO;
        let left = Hash256::from_slice(&hash32_concat(
            zero_left_inner.as_slice(),
            chunk2_padded.as_slice()
        ));
        
        let expected = Hash256::from_slice(&hash32_concat(left.as_slice(), right.as_slice()));
        assert_eq!(root, expected);
    }

    #[test]
    fn test_max_leaves_exceeded() {
        let mut hasher = ProgressiveMerkleHasher::with_leaves(2);
        let chunk = [1u8; BYTES_PER_CHUNK];
        hasher.write(&chunk).unwrap();
        hasher.write(&chunk).unwrap();
        
        // Third write should fail
        let result = hasher.write(&chunk);
        assert!(matches!(result, Err(Error::MaximumLeavesExceeded { .. })));
    }

    #[test]
    fn test_partial_chunk() {
        let mut hasher = ProgressiveMerkleHasher::with_leaves(1);
        let partial = vec![1u8, 2u8, 3u8];
        hasher.write(&partial).unwrap();
        let root = hasher.finish().unwrap();
        
        // Partial chunk should be padded with zeros
        let mut chunk = [0u8; BYTES_PER_CHUNK];
        chunk[0] = 1;
        chunk[1] = 2;
        chunk[2] = 3;
        
        let zero_left = Hash256::ZERO;
        let right = Hash256::from_slice(&chunk);
        let expected = Hash256::from_slice(&hash32_concat(
            zero_left.as_slice(),
            right.as_slice()
        ));
        
        assert_eq!(root, expected);
    }

    #[test]
    fn test_multiple_writes() {
        let mut hasher = ProgressiveMerkleHasher::with_leaves(10);
        hasher.write(&[1u8; 16]).unwrap();
        hasher.write(&[2u8; 16]).unwrap();
        hasher.write(&[3u8; 32]).unwrap();
        let root = hasher.finish().unwrap();
        
        // Should handle multiple writes correctly
        assert_ne!(root, Hash256::ZERO);
    }

    #[test]
    #[should_panic(expected = "must have at least one leaf")]
    fn test_zero_leaves_panics() {
        ProgressiveMerkleHasher::with_leaves(0);
    }
}
