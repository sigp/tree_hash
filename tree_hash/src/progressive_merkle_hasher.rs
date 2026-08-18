use crate::{Hash256, MerkleHasher, BYTES_PER_CHUNK};
use ethereum_hashing::hash32_concat;
use smallvec::SmallVec;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    MerkleHasher(crate::merkle_hasher::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::MerkleHasher(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::MerkleHasher(e) => Some(e),
        }
    }
}

/// A progressive Merkle hasher that implements the semantics of `merkleize_progressive` as
/// defined in EIP-7916.
///
/// The progressive merkle tree has a unique structure where:
/// - At each level, the left child is a binary merkle tree with a specific number of leaves
/// - The right child recursively contains more progressive structure
/// - The number of leaves in each left subtree grows by 4x at each level (1, 4, 16, 64, ...)
///
/// # Example Tree Structure
///
/// ```text
///                    root
///                     /\
///                    /  \
///  1: chunks[0 ..< 1]   /\
///                      /  \
///    4: chunks[1 ..< 5]   /\
///                        /  \
///    16: chunks[5 ..< 21]   /\
///                          /  \
///     64: chunks[21 ..< 85]    0
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
    /// `MerkleHasher` for computing the current level's binary tree root, created lazily on the
    /// first chunk of each level so that a level completed by its final chunk does not allocate a
    /// hasher that is never used.
    current_hasher: Option<MerkleHasher>,
    /// The number of leaves expected at the current level (1, 4, 16, 64, ...).
    current_level_size: usize,
    /// Number of chunks written to the current hasher.
    current_level_chunks: usize,
    /// Carry for bytes that haven't been completed into a chunk yet. Always < 32 bytes, so this
    /// never spills to the heap.
    buffer: SmallVec<[u8; BYTES_PER_CHUNK]>,
}

impl ProgressiveMerkleHasher {
    /// Create a new progressive merkle hasher that can accept any number of chunks.
    pub fn new() -> Self {
        Self {
            completed_roots: Vec::new(),
            current_hasher: None,
            current_level_size: 1,
            current_level_chunks: 0,
            buffer: SmallVec::new(),
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
    /// This hasher imposes no leaf limit, so under normal use `write` does not fail; the `Result`
    /// only forwards an error from the internal per-level [`MerkleHasher`], which is not expected
    /// to occur.
    pub fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let mut bytes = bytes;

        // If a partial carry exists, top it up from the front of `bytes` to complete a chunk.
        if !self.buffer.is_empty() {
            let take = (BYTES_PER_CHUNK - self.buffer.len()).min(bytes.len());
            self.buffer.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];

            // Still short of a full chunk; nothing more to do.
            if self.buffer.len() < BYTES_PER_CHUNK {
                return Ok(());
            }

            let chunk = std::mem::take(&mut self.buffer);
            self.process_chunk(&chunk)?;
        }

        // Forward each complete 32-byte chunk directly, then carry the remainder.
        let mut chunks = bytes.chunks_exact(BYTES_PER_CHUNK);
        for chunk in &mut chunks {
            self.process_chunk(chunk)?;
        }
        self.buffer.extend_from_slice(chunks.remainder());

        Ok(())
    }

    /// Process a single 32-byte chunk by adding it to the current level and completing the level if
    /// full.
    fn process_chunk(&mut self, chunk: &[u8]) -> Result<(), Error> {
        // Lazily create the current level's hasher, so a level completed by its final chunk does
        // not allocate a hasher that is immediately discarded.
        let level_size = self.current_level_size;
        let hasher = self
            .current_hasher
            .get_or_insert_with(|| MerkleHasher::with_leaves(level_size));
        hasher.write(chunk).map_err(Error::MerkleHasher)?;

        self.current_level_chunks += 1;

        // Once the current level is full, finalize its binary root and advance to the next level
        // (4x larger). `current_level_size` grows as 4^i, which cannot overflow `usize` in
        // practice: completing level i requires streaming 4^i chunks, far beyond any realizable
        // input.
        if self.current_level_chunks == self.current_level_size {
            let completed_hasher = self
                .current_hasher
                .take()
                .expect("current hasher exists after a chunk has been written");
            let root = completed_hasher.finish().map_err(Error::MerkleHasher)?;
            self.completed_roots.push(root);

            self.current_level_size *= 4;
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
            self.process_chunk(&chunk)?;
        }

        // With no chunks at all, the root is zero. Because the first level holds a single chunk,
        // any processed chunk immediately populates `completed_roots`, so this is exactly the
        // empty case.
        if self.completed_roots.is_empty() && self.current_level_chunks == 0 {
            return Ok(Hash256::ZERO);
        }

        // If the final level is partially filled, compute its (zero-padded) binary root.
        let current_root = if self.current_level_chunks > 0 {
            let hasher = self
                .current_hasher
                .take()
                .expect("current hasher exists while the level is partially filled");
            Some(hasher.finish().map_err(Error::MerkleHasher)?)
        } else {
            None
        };

        // completed_roots are in order [smallest level, ..., largest level]; build the progressive
        // tree by folding them from the largest level inward.
        Ok(build_progressive_root(current_root, &self.completed_roots))
    }
}

/// Build the final progressive merkle root by combining completed subtree roots.
///
/// The progressive tree structure: at each node, `hash(left = this level, right = deeper levels)`.
/// This builds the tree from the largest (rightmost) level backwards to the smallest (leftmost).
fn build_progressive_root(current_root: Option<Hash256>, completed_roots: &[Hash256]) -> Hash256 {
    // Per EIP-7916, a partial final level still follows the progressive structure:
    //   merkleize_progressive(chunks, n)
    //     = hash(merkleize(chunks[:n], n), merkleize_progressive(chunks[n:], n*4))
    // so a partial level with k chunks becomes hash(merkleize(chunks, n), ZERO).
    let mut result = if let Some(curr) = current_root {
        Hash256::from(hash32_concat(curr.as_slice(), Hash256::ZERO.as_slice()))
    } else {
        Hash256::ZERO
    };

    // Fold completed roots from largest to smallest: result = hash(completed_root, result), where
    // completed_root is the left (binary) subtree and result accumulates the deeper levels.
    for &completed_root in completed_roots.iter().rev() {
        result = Hash256::from(hash32_concat(completed_root.as_slice(), result.as_slice()));
    }

    result
}

impl Default for ProgressiveMerkleHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_root;

    /// Independent, non-streaming reference implementation of `merkleize_progressive` (EIP-7916),
    /// used to cross-check the streaming hasher.
    fn reference_progressive(chunks: &[[u8; BYTES_PER_CHUNK]], num_leaves: usize) -> Hash256 {
        if chunks.is_empty() {
            return Hash256::ZERO;
        }
        let take = num_leaves.min(chunks.len());
        let left_bytes: Vec<u8> = chunks[..take].iter().flatten().copied().collect();
        let left = merkle_root(&left_bytes, num_leaves);
        let right = reference_progressive(&chunks[take..], num_leaves * 4);
        Hash256::from(hash32_concat(left.as_slice(), right.as_slice()))
    }

    fn streaming_root(chunks: &[[u8; BYTES_PER_CHUNK]]) -> Hash256 {
        let mut hasher = ProgressiveMerkleHasher::new();
        for chunk in chunks {
            hasher.write(chunk).unwrap();
        }
        hasher.finish().unwrap()
    }

    fn indexed_chunk(i: usize) -> [u8; BYTES_PER_CHUNK] {
        let mut c = [0u8; BYTES_PER_CHUNK];
        c[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        c
    }

    /// Cross-check the streaming hasher against the recursive reference across a range of chunk
    /// counts, including exact level fills (1, 5, 21, 85, 341), partial trailing levels, and a
    /// deep level (>256) that crosses the inner `MerkleHasher`'s inline-stack capacity.
    #[test]
    fn matches_reference_oracle() {
        for count in [
            0usize, 1, 2, 3, 4, 5, 6, 16, 20, 21, 22, 64, 84, 85, 86, 200, 341, 342,
        ] {
            let chunks: Vec<[u8; BYTES_PER_CHUNK]> = (0..count).map(indexed_chunk).collect();
            assert_eq!(
                streaming_root(&chunks),
                reference_progressive(&chunks, 1),
                "mismatch for {count} chunks"
            );
        }
    }

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
        // hash(merkleize([chunk], 1), merkleize_progressive([], 4))
        // = hash(chunk, zero_hash)
        let left = Hash256::from_slice(&chunk);
        let zero_right = Hash256::ZERO;
        let expected = Hash256::from_slice(&hash32_concat(left.as_slice(), zero_right.as_slice()));

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

        // First chunk goes to left (num_leaves=1)
        // Second chunk goes to right recursive call (num_leaves=4)

        // Left: binary tree with 1 leaf = chunk1
        let left = Hash256::from_slice(&chunk1);

        // Right: progressive tree with chunk2 at num_leaves=4
        // At this level: hash(merkleize([chunk2], 4), merkleize_progressive([], 16))
        // = hash(merkle([chunk2], 4), zero_hash)
        let chunk2_padded = merkle_root(&chunk2, 4);
        let zero_right_inner = Hash256::ZERO;
        let right = Hash256::from_slice(&hash32_concat(
            chunk2_padded.as_slice(),
            zero_right_inner.as_slice(),
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

        let left = Hash256::from_slice(&chunk);
        let zero_right = Hash256::ZERO;
        let expected = Hash256::from_slice(&hash32_concat(left.as_slice(), zero_right.as_slice()));

        assert_eq!(root, expected);
    }

    #[test]
    fn test_multiple_writes() {
        let mut hasher = ProgressiveMerkleHasher::new();
        hasher.write(&[1u8; 16]).unwrap();
        hasher.write(&[2u8; 16]).unwrap();
        hasher.write(&[3u8; 32]).unwrap();
        let root = hasher.finish().unwrap();

        // The three writes form exactly two chunks: [1; 16] ++ [2; 16], then [3; 32].
        let mut chunk0 = [0u8; BYTES_PER_CHUNK];
        chunk0[..16].fill(1);
        chunk0[16..].fill(2);
        let chunk1 = [3u8; BYTES_PER_CHUNK];
        assert_eq!(root, reference_progressive(&[chunk0, chunk1], 1));
    }

    #[test]
    fn test_five_chunks() {
        // Test with 5 chunks as per the problem statement structure:
        // chunks[0] goes to left at level 1 (1 leaf)
        // chunks[1..5] go to right recursive call (4 leaves at level 2)
        let mut hasher = ProgressiveMerkleHasher::new();
        for i in 0..5 {
            let mut chunk = [0u8; BYTES_PER_CHUNK];
            chunk[0] = i as u8;
            hasher.write(&chunk).unwrap();
        }
        let root = hasher.finish().unwrap();

        // Manually compute expected root:
        // Left: chunks[0]
        let mut chunk0 = [0u8; BYTES_PER_CHUNK];
        chunk0[0] = 0;
        let left = Hash256::from_slice(&chunk0);

        // Right: merkleize_progressive(chunks[1..5], 4)
        // Which is: hash(merkleize(chunks[1..5], 4), merkleize_progressive([], 16))
        let chunks_1_to_4: Vec<u8> = (1..5)
            .flat_map(|i| {
                let mut chunk = [0u8; BYTES_PER_CHUNK];
                chunk[0] = i;
                chunk
            })
            .collect();
        let left_inner = merkle_root(&chunks_1_to_4, 4);
        let right_inner = Hash256::ZERO;
        let right = Hash256::from_slice(&hash32_concat(
            left_inner.as_slice(),
            right_inner.as_slice(),
        ));

        let expected = Hash256::from_slice(&hash32_concat(left.as_slice(), right.as_slice()));
        assert_eq!(root, expected);
    }

    #[test]
    fn test_21_chunks() {
        // 21 chunks exactly fills levels 1 + 4 + 16.
        let chunks: Vec<[u8; BYTES_PER_CHUNK]> = (0..21).map(indexed_chunk).collect();
        assert_eq!(streaming_root(&chunks), reference_progressive(&chunks, 1));
    }

    #[test]
    fn test_85_chunks() {
        // 85 chunks exactly fills levels 1 + 4 + 16 + 64.
        let chunks: Vec<[u8; BYTES_PER_CHUNK]> = (0..85).map(indexed_chunk).collect();
        assert_eq!(streaming_root(&chunks), reference_progressive(&chunks, 1));
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
