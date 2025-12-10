use crate::{Hash256, MerkleHasher, BYTES_PER_CHUNK};
use ethereum_hashing::hash32_concat;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    MerkleHasher(crate::merkle_hasher::Error),
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
///
/// # Efficiency
///
/// This implementation hashes chunks as they are streamed in, storing only the minimum
/// necessary state (completed subtree roots). When a level is filled, its binary merkle
/// root is computed and stored, avoiding the need to keep all chunks in memory.
pub struct ProgressiveMerkleHasher {
    /// Completed subtree roots at each level, stored in order of completion.
    /// Index 0 = first completed level (1 leaf), index 1 = second level (4 leaves), etc.
    /// Level i contains 4^i leaves.
    completed_roots: Vec<Hash256>,
    /// MerkleHasher for computing the current level's binary tree root.
    current_hasher: MerkleHasher,
    /// The number of leaves expected at the current level (1, 4, 16, 64, ...).
    current_level_size: usize,
    /// Number of chunks written to the current hasher.
    current_level_chunks: usize,
    /// Buffer for bytes that haven't been completed into a chunk yet.
    buffer: Vec<u8>,
    /// Total number of chunks written so far.
    total_chunks: usize,
}

impl ProgressiveMerkleHasher {
    /// Create a new progressive merkle hasher that can accept any number of chunks.
    pub fn new() -> Self {
        Self {
            completed_roots: Vec::new(),
            current_hasher: MerkleHasher::with_leaves(1),
            current_level_size: 1,
            current_level_chunks: 0,
            buffer: Vec::new(),
            total_chunks: 0,
        }
    }

    /// Write bytes to the hasher.
    ///
    /// The bytes will be split into 32-byte chunks. Bytes are buffered across multiple
    /// write calls to ensure proper chunk boundaries. Complete subtrees are hashed
    /// immediately as chunks are written.
    ///
    /// # Errors
    ///
    /// Returns an error if writing these bytes would exceed the maximum number of leaves.
    pub fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        // Add bytes to buffer
        self.buffer.extend_from_slice(bytes);

        // Process complete chunks from buffer
        while self.buffer.len() >= BYTES_PER_CHUNK {
            let mut chunk = [0u8; BYTES_PER_CHUNK];
            chunk.copy_from_slice(&self.buffer[..BYTES_PER_CHUNK]);
            self.buffer.drain(..BYTES_PER_CHUNK);

            self.process_chunk(chunk)?;
        }

        Ok(())
    }

    /// Process a single chunk by adding it to the current level and completing the level if full.
    fn process_chunk(&mut self, chunk: [u8; BYTES_PER_CHUNK]) -> Result<(), Error> {
        // Write the chunk to the current MerkleHasher
        self.current_hasher
            .write(&chunk)
            .map_err(Error::MerkleHasher)?;

        self.current_level_chunks += 1;
        self.total_chunks += 1;

        // Check if current level is complete
        if self.current_level_chunks == self.current_level_size {
            // Move to next level (4x larger)
            let next_level_size = self.current_level_size * 4;

            // Replace the current hasher with a new one for the next level
            let completed_hasher = std::mem::replace(
                &mut self.current_hasher,
                MerkleHasher::with_leaves(next_level_size),
            );

            // Finish the completed hasher to get the root
            let root = completed_hasher.finish().map_err(Error::MerkleHasher)?;

            // Store this completed root
            self.completed_roots.push(root);

            self.current_level_size = next_level_size;
            self.current_level_chunks = 0;
        }

        Ok(())
    }

    /// Finish the hasher and return the progressive merkle root.
    ///
    /// This completes any partial level and combines all completed subtree roots
    /// according to the progressive merkleization algorithm.
    ///
    /// Any remaining bytes in the buffer will be padded to form a final chunk.
    pub fn finish(mut self) -> Result<Hash256, Error> {
        // Process any remaining bytes in the buffer as a final chunk
        if !self.buffer.is_empty() {
            let mut chunk = [0u8; BYTES_PER_CHUNK];
            chunk[..self.buffer.len()].copy_from_slice(&self.buffer);
            self.process_chunk(chunk)?;
        }

        // If we have no chunks at all, return zero hash
        if self.total_chunks == 0 {
            return Ok(Hash256::ZERO);
        }

        // If there are chunks in current level (partial level), compute their root
        let current_root = if self.current_level_chunks > 0 {
            // Create a temporary hasher to replace the current one (since finish() takes ownership)
            // FIXME(sproul): get rid of this by making build_progressive_root a static method.
            let temp_hasher = std::mem::replace(
                &mut self.current_hasher,
                MerkleHasher::with_leaves(1), // dummy value, won't be used
            );
            Some(temp_hasher.finish().map_err(Error::MerkleHasher)?)
        } else {
            None
        };

        // Build the progressive tree from completed roots and current root
        // completed_roots are in order: [smallest level, ..., largest level]
        // We need to build from right to left in the tree
        Ok(self.build_progressive_root(current_root))
    }

    /// Build the final progressive merkle root by combining completed subtree roots.
    ///
    /// The progressive tree structure: at each node, hash(left=deeper_levels, right=this_level).
    /// This builds the tree from the largest (leftmost) level backwards to the smallest (rightmost).
    fn build_progressive_root(&self, current_root: Option<Hash256>) -> Hash256 {
        // Start from the leftmost (largest/deepest) level
        // Per EIP-7916 spec, even partial levels follow the progressive structure:
        // merkleize_progressive(chunks, n) = hash(merkleize_progressive(chunks[n:], n*4), merkleize(chunks[:n], n))
        // So a partial level with k chunks becomes: hash(ZERO (no further chunks), merkleize(chunks, n))
        let mut result = if let Some(curr) = current_root {
            Hash256::from_slice(&hash32_concat(Hash256::ZERO.as_slice(), curr.as_slice()))
        } else {
            Hash256::ZERO
        };

        // Process completed roots from largest to smallest (reverse order)
        // At each step: result = hash(result, completed_root)
        // - result accumulates the left subtree (deeper/larger levels)
        // - completed_root is the right subtree at this level
        for &completed_root in self.completed_roots.iter().rev() {
            result =
                Hash256::from_slice(&hash32_concat(result.as_slice(), completed_root.as_slice()));
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_root;

    #[test]
    fn test_empty_tree() {
        let hasher = ProgressiveMerkleHasher::new();
        let root = hasher.finish().unwrap();
        assert_eq!(root, Hash256::ZERO);
    }

    #[test]
    fn test_single_chunk() {
        let mut hasher = ProgressiveMerkleHasher::new();
        let chunk = [1u8; BYTES_PER_CHUNK];
        hasher.write(&chunk).unwrap();
        let root = hasher.finish().unwrap();

        // For a single chunk, the progressive tree should be:
        // hash(merkleize_progressive([], 4), merkleize([chunk], 1))
        // = hash(zero_hash, chunk)
        let zero_left = Hash256::ZERO;
        let right = Hash256::from_slice(&chunk);
        let expected = Hash256::from_slice(&hash32_concat(zero_left.as_slice(), right.as_slice()));

        assert_eq!(root, expected);
    }

    #[test]
    fn test_two_chunks() {
        let mut hasher = ProgressiveMerkleHasher::new();
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
            chunk2_padded.as_slice(),
        ));

        let expected = Hash256::from_slice(&hash32_concat(left.as_slice(), right.as_slice()));
        assert_eq!(root, expected);
    }

    #[test]
    fn test_partial_chunk() {
        let mut hasher = ProgressiveMerkleHasher::new();
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
        let expected = Hash256::from_slice(&hash32_concat(zero_left.as_slice(), right.as_slice()));

        assert_eq!(root, expected);
    }

    #[test]
    fn test_multiple_writes() {
        let mut hasher = ProgressiveMerkleHasher::new();
        hasher.write(&[1u8; 16]).unwrap();
        hasher.write(&[2u8; 16]).unwrap();
        hasher.write(&[3u8; 32]).unwrap();
        let root = hasher.finish().unwrap();

        // Should handle multiple writes correctly
        assert_ne!(root, Hash256::ZERO);
    }

    #[test]
    fn test_five_chunks() {
        // Test with 5 chunks as per the problem statement structure:
        // chunks[0] goes to right at level 1 (1 leaf)
        // chunks[1..5] go to left recursive call (4 leaves at level 2)
        let mut hasher = ProgressiveMerkleHasher::new();
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
            right_inner.as_slice(),
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
        let mut hasher = ProgressiveMerkleHasher::new();
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
        let mut hasher = ProgressiveMerkleHasher::new();
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
    fn test_consistency_across_write_patterns() {
        // Test that different write patterns produce the same result
        let chunks: Vec<[u8; BYTES_PER_CHUNK]> = (0..10)
            .map(|i| {
                let mut chunk = [0u8; BYTES_PER_CHUNK];
                chunk[0] = i;
                chunk
            })
            .collect();

        // Write all chunks individually
        let mut hasher1 = ProgressiveMerkleHasher::new();
        for chunk in &chunks {
            hasher1.write(chunk).unwrap();
        }
        let root1 = hasher1.finish().unwrap();

        // Write all chunks at once
        let mut hasher2 = ProgressiveMerkleHasher::new();
        let all_bytes: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        hasher2.write(&all_bytes).unwrap();
        let root2 = hasher2.finish().unwrap();

        // Write in groups
        let mut hasher3 = ProgressiveMerkleHasher::new();
        hasher3.write(&all_bytes[..3 * BYTES_PER_CHUNK]).unwrap();
        hasher3
            .write(&all_bytes[3 * BYTES_PER_CHUNK..7 * BYTES_PER_CHUNK])
            .unwrap();
        hasher3.write(&all_bytes[7 * BYTES_PER_CHUNK..]).unwrap();
        let root3 = hasher3.finish().unwrap();

        assert_eq!(root1, root2);
        assert_eq!(root1, root3);
    }

    #[test]
    fn test_byte_streaming() {
        // Test that we can write bytes in various chunk sizes
        let data = vec![42u8; BYTES_PER_CHUNK * 3 + 10];

        // Write all at once
        let mut hasher1 = ProgressiveMerkleHasher::new();
        hasher1.write(&data).unwrap();
        let root1 = hasher1.finish().unwrap();

        // Write in smaller chunks
        let mut hasher2 = ProgressiveMerkleHasher::new();
        hasher2.write(&data[0..50]).unwrap();
        hasher2.write(&data[50..]).unwrap();
        let root2 = hasher2.finish().unwrap();

        assert_eq!(root1, root2);
    }
}
