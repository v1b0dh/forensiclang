//! Cryptographic Utilities for Evidential Integrity
//!
//! Provides pure-Rust, zero-dependency SHA-256 and HMAC-SHA256 implementations
//! for digital evidence hashing and tamper-resistant audit certificates.

/// Compute standard SHA-256 hash of a byte slice, returning a lowercase 64-char hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256_digest(data);
    let mut hex = String::with_capacity(64);
    for b in digest {
        hex.push_str(&format!("{:02x}", b));
    }
    hex
}

/// Compute standard SHA-256 digest returning 32 bytes.
pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    // Padding
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h_val = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_val
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_val = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_val);
    }

    let mut result = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        result[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }
    result
}

/// Compute HMAC-SHA256 for tamper-proof certificate signing.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> String {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let digest = sha256_digest(key);
        key_block[..32].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut o_key_pad = [0x5cu8; 64];
    let mut i_key_pad = [0x36u8; 64];
    for i in 0..64 {
        o_key_pad[i] ^= key_block[i];
        i_key_pad[i] ^= key_block[i];
    }

    let mut inner_input = i_key_pad.to_vec();
    inner_input.extend_from_slice(message);
    let inner_hash = sha256_digest(&inner_input);

    let mut outer_input = o_key_pad.to_vec();
    outer_input.extend_from_slice(&inner_hash);
    sha256_hex(&outer_input)
}

use serde::{Deserialize, Serialize};

/// Direction of sibling in a binary Merkle tree
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MerkleDirection {
    Left,
    Right,
}

/// Single step in a Merkle inclusion proof
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleProofStep {
    pub sibling_hash: String,
    pub direction: MerkleDirection,
}

/// Merkle inclusion proof for a leaf
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleProof {
    pub leaf_hash: String,
    pub steps: Vec<MerkleProofStep>,
    pub root_hash: String,
}

impl MerkleProof {
    /// Verify that this proof resolves to the stated root hash
    pub fn verify(&self) -> bool {
        let mut current = self.leaf_hash.clone();
        for step in &self.steps {
            let combined = match step.direction {
                MerkleDirection::Left => format!("{}{}", step.sibling_hash, current),
                MerkleDirection::Right => format!("{}{}", current, step.sibling_hash),
            };
            current = sha256_hex(combined.as_bytes());
        }
        current.eq_ignore_ascii_case(&self.root_hash)
    }
}

/// Binary Merkle Tree for bundling multiple evidence items and certificates
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleTree {
    pub leaves: Vec<String>,
    pub root: String,
}

impl MerkleTree {
    /// Construct a new Merkle Tree from a list of leaf hashes (hex strings)
    pub fn new(leaves: Vec<String>) -> Self {
        if leaves.is_empty() {
            return Self {
                leaves,
                root: sha256_hex(b""),
            };
        }
        if leaves.len() == 1 {
            return Self {
                root: leaves[0].clone(),
                leaves,
            };
        }

        let mut current_level = leaves.clone();
        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    let combined = format!("{}{}", chunk[0], chunk[1]);
                    next_level.push(sha256_hex(combined.as_bytes()));
                } else {
                    let combined = format!("{}{}", chunk[0], chunk[0]);
                    next_level.push(sha256_hex(combined.as_bytes()));
                }
            }
            current_level = next_level;
        }

        Self {
            root: current_level.into_iter().next().unwrap(),
            leaves,
        }
    }

    /// Generate an inclusion proof for a leaf by index
    pub fn proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let mut steps = Vec::new();
        let mut idx = leaf_index;
        let mut current_level = self.leaves.clone();

        while current_level.len() > 1 {
            let sibling_idx = if idx % 2 == 0 {
                if idx + 1 < current_level.len() {
                    idx + 1
                } else {
                    idx
                }
            } else {
                idx - 1
            };

            let direction = if idx % 2 == 0 {
                MerkleDirection::Right
            } else {
                MerkleDirection::Left
            };

            steps.push(MerkleProofStep {
                sibling_hash: current_level[sibling_idx].clone(),
                direction,
            });

            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    let combined = format!("{}{}", chunk[0], chunk[1]);
                    next_level.push(sha256_hex(combined.as_bytes()));
                } else {
                    let combined = format!("{}{}", chunk[0], chunk[0]);
                    next_level.push(sha256_hex(combined.as_bytes()));
                }
            }
            current_level = next_level;
            idx /= 2;
        }

        Some(MerkleProof {
            leaf_hash: self.leaves[leaf_index].clone(),
            steps,
            root_hash: self.root.clone(),
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_vector() {
        // "abc" -> ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret-audit-key";
        let msg = b"certified sanitization pass completed";
        let hmac = hmac_sha256(key, msg);
        assert_eq!(hmac.len(), 64);
    }

    #[test]
    fn test_merkle_tree_and_proof_verification() {
        let leaf1 = sha256_hex(b"evidence_mft_dump.raw");
        let leaf2 = sha256_hex(b"destruction_certificate_101.pdf");
        let leaf3 = sha256_hex(b"carved_sqlite_database.db");
        let leaf4 = sha256_hex(b"network_traffic_dump.pcap");
        let leaves = vec![leaf1, leaf2, leaf3, leaf4];

        let tree = MerkleTree::new(leaves.clone());
        assert_eq!(tree.root.len(), 64);

        // Verify proofs for all leaves
        for i in 0..leaves.len() {
            let proof = tree.proof(i).expect("Proof must be generated");
            assert!(proof.verify(), "Proof for leaf {} must verify against root", i);
        }

        // Tamper test: if leaf hash is altered, verification fails
        let mut tampered_proof = tree.proof(0).unwrap();
        tampered_proof.leaf_hash = sha256_hex(b"tampered_attacker_payload");
        assert!(!tampered_proof.verify(), "Tampered proof must fail verification");
    }

    #[test]
    fn test_merkle_tree_odd_leaves() {
        let leaves = vec![
            sha256_hex(b"item_1"),
            sha256_hex(b"item_2"),
            sha256_hex(b"item_3"),
        ];
        let tree = MerkleTree::new(leaves.clone());
        assert_eq!(tree.root.len(), 64);
        for i in 0..leaves.len() {
            let proof = tree.proof(i).unwrap();
            assert!(proof.verify());
        }
    }
}

