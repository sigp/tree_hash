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
    /// Buffer for bytes that haven't been completed into a chunk yet.
    buffer: Vec<u8>,
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
            buffer: Vec::new(),
        }
    }

    /// Write bytes to the hasher.
    ///
    /// The bytes will be split into 32-byte chunks. Bytes are buffered across multiple
    /// write calls to ensure proper chunk boundaries.
    ///
    /// # Errors
    ///
    /// Returns an error if writing these bytes would exceed the maximum number of leaves.
    pub fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        // Add bytes to buffer
        self.buffer.extend_from_slice(bytes);
        
        // Process complete chunks from buffer
        while self.buffer.len() >= BYTES_PER_CHUNK {
            if self.chunks.len() >= self.max_leaves {
                return Err(Error::MaximumLeavesExceeded {
                    max_leaves: self.max_leaves,
                });
            }
            
            let mut chunk = [0u8; BYTES_PER_CHUNK];
            chunk.copy_from_slice(&self.buffer[..BYTES_PER_CHUNK]);
            self.chunks.push(chunk);
            self.buffer.drain(..BYTES_PER_CHUNK);
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
    ///
    /// Any remaining bytes in the buffer will be padded to form a final chunk.
    pub fn finish(mut self) -> Result<Hash256, Error> {
        // Process any remaining bytes in the buffer as a final chunk
        if !self.buffer.is_empty() {
            if self.chunks.len() >= self.max_leaves {
                return Err(Error::MaximumLeavesExceeded {
                    max_leaves: self.max_leaves,
                });
            }
            
            let mut chunk = [0u8; BYTES_PER_CHUNK];
            chunk[..self.buffer.len()].copy_from_slice(&self.buffer);
            self.chunks.push(chunk);
        }
        
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

    // Combine left and right roots according to spec: hash(a, b) where
    // a = left subtree (recursive progressive), b = right subtree (binary tree)
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

    #[test]
    fn test_five_chunks() {
        // Test with 5 chunks as per the problem statement structure:
        // chunks[0] goes to right at level 1 (1 leaf)
        // chunks[1..5] go to left recursive call (4 leaves at level 2)
        let mut hasher = ProgressiveMerkleHasher::with_leaves(5);
        for i in 0..5 {
            let mut chunk = [0u8; BYTES_PER_CHUNK];
            chunk[0] = i as u8;
            hasher.write(&chunk).unwrap();
        }
        let root = hasher.finish().unwrap();
        
        // Manually compute expected root:
        // Right: chunks[0]
        let mut chunk0 = [0u8; BYTES_PER_CHUNK];
        chunk0[0] = 0;
        let right = Hash256::from_slice(&chunk0);
        
        // Left: merkleize_progressive(chunks[1..5], 4)
        // Which is: hash(merkleize_progressive([], 16), merkleize(chunks[1..5], 4))
        let chunks_1_to_4: Vec<u8> = (1..5)
            .flat_map(|i| {
                let mut chunk = [0u8; BYTES_PER_CHUNK];
                chunk[0] = i;
                chunk
            })
            .collect();
        let right_inner = merkle_root(&chunks_1_to_4, 4);
        let left_inner = Hash256::ZERO;
        let left = Hash256::from_slice(&hash32_concat(
            left_inner.as_slice(),
            right_inner.as_slice()
        ));
        
        let expected = Hash256::from_slice(&hash32_concat(left.as_slice(), right.as_slice()));
        assert_eq!(root, expected);
    }

    #[test]
    fn test_21_chunks() {
        // Test with 21 chunks as per problem statement:
        // chunks[0] goes to right at level 1 (1 leaf)
        // chunks[1..5] go to right at level 2 (4 leaves)
        // chunks[5..21] go to right at level 3 (16 leaves)
        let mut hasher = ProgressiveMerkleHasher::with_leaves(21);
        for i in 0..21 {
            let mut chunk = [0u8; BYTES_PER_CHUNK];
            chunk[0] = i as u8;
            hasher.write(&chunk).unwrap();
        }
        let root = hasher.finish().unwrap();
        
        // Root should not be zero
        assert_ne!(root, Hash256::ZERO);
    }

    #[test]
    fn test_85_chunks() {
        // Test with 85 chunks as per problem statement structure:
        // chunks[0] at level 1 (1 leaf)
        // chunks[1..5] at level 2 (4 leaves)
        // chunks[5..21] at level 3 (16 leaves)
        // chunks[21..85] at level 4 (64 leaves)
        let mut hasher = ProgressiveMerkleHasher::with_leaves(85);
        for i in 0..85 {
            let mut chunk = [0u8; BYTES_PER_CHUNK];
            chunk[0] = (i % 256) as u8;
            hasher.write(&chunk).unwrap();
        }
        let root = hasher.finish().unwrap();
        
        // Root should not be zero
        assert_ne!(root, Hash256::ZERO);
    }

    #[test]
    fn test_consistency_with_manual_calculation() {
        // Test that using ProgressiveMerkleHasher gives the same result as
        // manually calling merkleize_progressive
        let chunks: Vec<[u8; BYTES_PER_CHUNK]> = (0..10)
            .map(|i| {
                let mut chunk = [0u8; BYTES_PER_CHUNK];
                chunk[0] = i;
                chunk
            })
            .collect();
        
        // Use ProgressiveMerkleHasher
        let mut hasher = ProgressiveMerkleHasher::with_leaves(10);
        for chunk in &chunks {
            hasher.write(chunk).unwrap();
        }
        let hasher_root = hasher.finish().unwrap();
        
        // Manually call merkleize_progressive
        let manual_root = merkleize_progressive(&chunks, 1);
        
        assert_eq!(hasher_root, manual_root);
    }

    #[test]
    fn test_byte_streaming() {
        // Test that we can write bytes in various chunk sizes
        let data = vec![42u8; BYTES_PER_CHUNK * 3 + 10];
        
        // Write all at once
        let mut hasher1 = ProgressiveMerkleHasher::with_leaves(10);
        hasher1.write(&data).unwrap();
        let root1 = hasher1.finish().unwrap();
        
        // Write in smaller chunks
        let mut hasher2 = ProgressiveMerkleHasher::with_leaves(10);
        hasher2.write(&data[0..50]).unwrap();
        hasher2.write(&data[50..]).unwrap();
        let root2 = hasher2.finish().unwrap();
        
        assert_eq!(root1, root2);
    }
}
