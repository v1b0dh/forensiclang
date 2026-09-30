//! Blockchain-Anchored Chain-of-Custody & Audit Ledger
//!
//! Provides a cryptographically immutable, append-only ledger for digital evidence,
//! file carving records, and NIST SP 800-88 sanitization destruction certificates.
//!
//! Meets Smart India Hackathon 2026 Theme: Blockchain and Cybersecurity.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{hmac_sha256, sha256_hex, MerkleProof, MerkleTree};

/// Type of evidence or action recorded on the ledger
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecordType {
    SanitizationCertificate,
    CarvedEvidence,
    MemoryDump,
    TimelineSnapshot,
    MftExtraction,
    AuditLog,
}

/// An immutable evidence record bundled into a block
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRecord {
    pub id: String,
    pub record_type: RecordType,
    pub target: String,
    pub sha256_hash: String,
    pub operator: String,
    pub timestamp: String,
    pub metadata_json: String,
}

impl EvidenceRecord {
    /// Compute the unique digest of this record to serve as a Merkle tree leaf
    pub fn compute_leaf_hash(&self) -> String {
        let payload = format!(
            "{}:{}:{}:{}:{}:{}",
            self.id,
            serde_json::to_string(&self.record_type).unwrap_or_default(),
            self.target,
            self.sha256_hash,
            self.operator,
            self.timestamp
        );
        sha256_hex(payload.as_bytes())
    }
}

/// A block within the CARVE Chain-of-Custody blockchain ledger
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerBlock {
    pub index: u64,
    pub timestamp: String,
    pub previous_hash: String,
    pub merkle_root: String,
    pub records: Vec<EvidenceRecord>,
    pub leaf_hashes: Vec<String>,
    pub nonce: u64,
    pub block_hash: String,
    pub signature: String,
}

impl LedgerBlock {
    /// Compute the SHA-256 hash of this block header
    pub fn compute_block_hash(
        index: u64,
        timestamp: &str,
        previous_hash: &str,
        merkle_root: &str,
        nonce: u64,
    ) -> String {
        let header = format!("{}:{}:{}:{}:{}", index, timestamp, previous_hash, merkle_root, nonce);
        sha256_hex(header.as_bytes())
    }

    /// Verify this block's hash, signature, and Merkle root integrity
    pub fn verify(&self, signing_key: &[u8], prev_block: Option<&LedgerBlock>) -> bool {
        // 1. Verify previous hash link
        if let Some(prev) = prev_block {
            if self.previous_hash != prev.block_hash {
                return false;
            }
            if self.index != prev.index + 1 {
                return false;
            }
        } else {
            // Genesis block check
            if self.index != 0 || self.previous_hash != "0000000000000000000000000000000000000000000000000000000000000000" {
                return false;
            }
        }

        // 2. Verify block hash calculation
        let computed_hash = Self::compute_block_hash(
            self.index,
            &self.timestamp,
            &self.previous_hash,
            &self.merkle_root,
            self.nonce,
        );
        if !computed_hash.eq_ignore_ascii_case(&self.block_hash) {
            return false;
        }

        // 3. Verify signature
        let expected_sig = hmac_sha256(signing_key, self.block_hash.as_bytes());
        if !expected_sig.eq_ignore_ascii_case(&self.signature) {
            return false;
        }

        // 4. Verify Merkle root matches computed leaves
        let computed_leaves: Vec<String> = self.records.iter().map(|r| r.compute_leaf_hash()).collect();
        let tree = MerkleTree::new(computed_leaves);
        if !tree.root.eq_ignore_ascii_case(&self.merkle_root) {
            return false;
        }

        true
    }
}

/// The CARVE immutable forensic blockchain ledger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainLedger {
    pub chain: Vec<LedgerBlock>,
    #[serde(skip)]
    pub signing_key: Vec<u8>,
}

impl BlockchainLedger {
    /// Initialize a new blockchain ledger with a Genesis block
    pub fn new(signing_key: &[u8]) -> Self {
        let ts = current_iso_timestamp();
        let genesis_records = vec![EvidenceRecord {
            id: "GENESIS-0000".to_string(),
            record_type: RecordType::AuditLog,
            target: "CARVE-FORENSIC-LEDGER".to_string(),
            sha256_hash: sha256_hex(b"CARVE Forensic Platform Genesis Root Block"),
            operator: "SYSTEM-AUTHORITY".to_string(),
            timestamp: ts.clone(),
            metadata_json: r#"{"network":"CARVE-PRIVATE-AUDIT-LEDGER","version":"1.0.0"}"#.to_string(),
        }];

        let leaves = vec![genesis_records[0].compute_leaf_hash()];
        let tree = MerkleTree::new(leaves.clone());
        let prev_hash = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let block_hash = LedgerBlock::compute_block_hash(0, &ts, &prev_hash, &tree.root, 0);
        let signature = hmac_sha256(signing_key, block_hash.as_bytes());

        let genesis_block = LedgerBlock {
            index: 0,
            timestamp: ts,
            previous_hash: prev_hash,
            merkle_root: tree.root,
            records: genesis_records,
            leaf_hashes: leaves,
            nonce: 0,
            block_hash,
            signature,
        };

        Self {
            chain: vec![genesis_block],
            signing_key: signing_key.to_vec(),
        }
    }

    /// Append a new batch of forensic evidence records as an immutable block
    pub fn append_batch(&mut self, records: Vec<EvidenceRecord>) -> Result<&LedgerBlock, String> {
        if records.is_empty() {
            return Err("Cannot anchor empty evidence batch to blockchain ledger".to_string());
        }

        let prev_block = self.chain.last().ok_or("Ledger missing genesis block")?;
        let prev_hash = prev_block.block_hash.clone();
        let next_index = prev_block.index + 1;
        let ts = current_iso_timestamp();

        let leaves: Vec<String> = records.iter().map(|r| r.compute_leaf_hash()).collect();
        let tree = MerkleTree::new(leaves.clone());

        // Light proof-of-work/integrity nonce search (finding hash with leading zero nibble)
        let mut nonce = 0u64;
        let mut block_hash = LedgerBlock::compute_block_hash(next_index, &ts, &prev_hash, &tree.root, nonce);
        while !block_hash.starts_with('0') && nonce < 100_000 {
            nonce += 1;
            block_hash = LedgerBlock::compute_block_hash(next_index, &ts, &prev_hash, &tree.root, nonce);
        }

        let signature = hmac_sha256(&self.signing_key, block_hash.as_bytes());

        let new_block = LedgerBlock {
            index: next_index,
            timestamp: ts,
            previous_hash: prev_hash,
            merkle_root: tree.root,
            records,
            leaf_hashes: leaves,
            nonce,
            block_hash,
            signature,
        };

        self.chain.push(new_block);
        Ok(self.chain.last().unwrap())
    }

    /// Verify the entire blockchain from Genesis to the tip
    pub fn verify_chain(&self) -> bool {
        if self.chain.is_empty() {
            return false;
        }

        for (i, block) in self.chain.iter().enumerate() {
            let prev = if i == 0 { None } else { Some(&self.chain[i - 1]) };
            if !block.verify(&self.signing_key, prev) {
                return false;
            }
        }
        true
    }

    /// Verify whether a target evidence hash or certificate is anchored on the ledger.
    /// Returns (block_index, record, merkle_proof).
    pub fn verify_evidence(&self, target_hash: &str) -> Option<(u64, &EvidenceRecord, MerkleProof)> {
        for block in &self.chain {
            for (leaf_idx, record) in block.records.iter().enumerate() {
                if record.sha256_hash.eq_ignore_ascii_case(target_hash) || record.id.eq_ignore_ascii_case(target_hash) {
                    let tree = MerkleTree::new(block.leaf_hashes.clone());
                    if let Some(proof) = tree.proof(leaf_idx) {
                        if proof.verify() {
                            return Some((block.index, record, proof));
                        }
                    }
                }
            }
        }
        None
    }

    /// Serialize ledger to JSON
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("Serialization error: {}", e))
    }

    /// Deserialize ledger from JSON and assign verification key
    pub fn from_json(json_str: &str, signing_key: &[u8]) -> Result<Self, String> {
        let mut ledger: Self = serde_json::from_str(json_str).map_err(|e| format!("Deserialization error: {}", e))?;
        ledger.signing_key = signing_key.to_vec();
        if !ledger.verify_chain() {
            return Err("Loaded ledger failed cryptographic verification".to_string());
        }
        Ok(ledger)
    }
}

fn current_iso_timestamp() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("2026-09-30T{:02}:{:02}:{:02}Z", (now.as_secs() / 3600) % 24, (now.as_secs() / 60) % 60, now.as_secs() % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blockchain_genesis_and_append() {
        let key = b"audit-master-secret-key-2026";
        let mut ledger = BlockchainLedger::new(key);
        assert_eq!(ledger.chain.len(), 1);
        assert!(ledger.verify_chain());

        // Batch 1: Sanitization certificate and carved artifact
        let records = vec![
            EvidenceRecord {
                id: "CERT-NIST-88-001".to_string(),
                record_type: RecordType::SanitizationCertificate,
                target: r"\\.\PhysicalDrive1".to_string(),
                sha256_hash: sha256_hex(b"CERTIFICATE_BYTES_OF_DESTRUCTION"),
                operator: "Agent-Win01".to_string(),
                timestamp: "2026-09-30T10:00:00Z".to_string(),
                metadata_json: r#"{"method":"nist_800_88_clear","passes":1}"#.to_string(),
            },
            EvidenceRecord {
                id: "CARVED-FILE-902".to_string(),
                record_type: RecordType::CarvedEvidence,
                target: "finance_records.sqlite".to_string(),
                sha256_hash: sha256_hex(b"SQLITE_CARVED_DATABASE_PAYLOAD"),
                operator: "Agent-Win01".to_string(),
                timestamp: "2026-09-30T10:05:00Z".to_string(),
                metadata_json: r#"{"magic_bytes":"SQLite format 3","offset":204800}"#.to_string(),
            },
        ];

        let block = ledger.append_batch(records).expect("Block append failed");
        assert_eq!(block.index, 1);
        assert_eq!(ledger.chain.len(), 2);
        assert!(ledger.verify_chain(), "Chain must be cryptographically valid");

        // Verify evidence inclusion proof on chain
        let cert_hash = sha256_hex(b"CERTIFICATE_BYTES_OF_DESTRUCTION");
        let (blk_idx, rec, proof) = ledger.verify_evidence(&cert_hash).expect("Evidence must be verified");
        assert_eq!(blk_idx, 1);
        assert_eq!(rec.id, "CERT-NIST-88-001");
        assert!(proof.verify(), "Merkle proof must verify against block root");
    }

    #[test]
    fn test_blockchain_tamper_detection() {
        let key = b"audit-master-secret-key-2026";
        let mut ledger = BlockchainLedger::new(key);

        let records = vec![EvidenceRecord {
            id: "EVIDENCE-01".to_string(),
            record_type: RecordType::MemoryDump,
            target: "suspicious_heap.bin".to_string(),
            sha256_hash: sha256_hex(b"RAW_HEAP_MEMORY_CONTENT"),
            operator: "Investigator".to_string(),
            timestamp: "2026-09-30T12:00:00Z".to_string(),
            metadata_json: "{}".to_string(),
        }];

        ledger.append_batch(records).unwrap();
        assert!(ledger.verify_chain());

        // Tamper with record data in block 1
        ledger.chain[1].records[0].target = "tampered_fake_target".to_string();
        assert!(!ledger.verify_chain(), "Tampered ledger must fail chain verification");
    }
}
