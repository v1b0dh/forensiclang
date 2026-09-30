//! Advanced File Carving & Recovery Engine
//!
//! Provides signature-based and structure-based file carving from unallocated
//! space, damaged file systems, or disk streams without metadata dependencies.

pub mod scanner;
pub mod signatures;
pub mod validators;

use crate::artifact::Artifact;
use crate::crypto::sha256_hex;
use log::info;
use serde::{Deserialize, Serialize};
use signatures::{FileType, FileSignature, SIGNATURES};
use std::collections::HashMap;

/// An individual carved file recovered from raw media.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedFile {
    pub id: String,
    pub file_type: FileType,
    pub offset: u64,
    pub length: usize,
    pub confidence: f32,
    pub sha256: String,
    pub threat_level: String,
    pub threat_tags: Vec<String>,
    pub metadata: HashMap<String, String>,
    #[serde(skip_serializing)]
    pub data: Vec<u8>,
}

/// Configuration parameters controlling the carving sweep.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarveConfig {
    /// File types to search for (empty = search for all supported types).
    pub target_types: Vec<FileType>,
    /// Minimum confidence threshold (0.0 to 1.0). Files below this are discarded.
    pub min_confidence: f32,
    /// Whether to align signature searches to sector boundaries (typically 512 bytes).
    pub sector_aligned: bool,
    /// Sector size in bytes (default 512).
    pub sector_size: usize,
    /// Maximum number of files to recover (0 = unlimited).
    pub max_files: usize,
}

impl Default for CarveConfig {
    fn default() -> Self {
        Self {
            target_types: Vec::new(),
            min_confidence: 0.40,
            sector_aligned: false,
            sector_size: 512,
            max_files: 0,
        }
    }
}

/// Carve files from a raw byte buffer (e.g. disk image slice or memory buffer).
pub fn carve_bytes(data: &[u8], config: &CarveConfig) -> Vec<CarvedFile> {
    info!(
        "Beginning carving sweep across {} bytes (min confidence: {:.2})",
        data.len(),
        config.min_confidence
    );

    let mut results = Vec::new();
    let step = if config.sector_aligned && config.sector_size > 0 {
        config.sector_size
    } else {
        1
    };

    let active_signatures: Vec<&FileSignature> = if config.target_types.is_empty() {
        SIGNATURES.iter().collect()
    } else {
        SIGNATURES
            .iter()
            .filter(|sig| config.target_types.contains(&sig.file_type))
            .collect()
    };

    let mut i = 0;
    while i < data.len() {
        if config.max_files > 0 && results.len() >= config.max_files {
            break;
        }

        let slice = &data[i..];

        // Check if any active signature matches at current offset
        let mut matched_sig = None;
        for sig in &active_signatures {
            if slice.starts_with(sig.header) {
                matched_sig = Some(*sig);
                break;
            }
        }

        if let Some(sig) = matched_sig {
            let max_len = sig.max_size.min(slice.len());
            let candidate_bytes = &slice[..max_len];

            // Perform deep structural validation and confidence calculation
            let validation = validators::validate(sig.file_type, candidate_bytes);

            if validation.is_valid && validation.confidence >= config.min_confidence {
                let actual_len = validation.estimated_length.min(max_len);
                if actual_len > 0 {
                    let file_data = candidate_bytes[..actual_len].to_vec();
                    let file_hash = sha256_hex(&file_data);
                    let file_id = format!(
                        "carved_{:08x}_{}.{}",
                        i,
                        &file_hash[..8],
                        sig.file_type.extension()
                    );

                    let threat = scanner::scan_carved_buffer(&file_data);
                    let mut meta = validation.metadata;
                    if !threat.matched_rules.is_empty() {
                        meta.insert("threat_score".to_string(), format!("{:.2}", threat.risk_score));
                        meta.insert("threat_rules".to_string(), threat.matched_rules.iter().map(|r| r.rule_name.as_str()).collect::<Vec<_>>().join(","));
                    }
                    let threat_level_str = format!("{:?}", threat.threat_level);
                    let threat_tags = threat.matched_rules.into_iter().map(|r| r.rule_name).collect();

                    let carved = CarvedFile {
                        id: file_id,
                        file_type: sig.file_type,
                        offset: i as u64,
                        length: actual_len,
                        confidence: validation.confidence,
                        sha256: file_hash,
                        threat_level: threat_level_str,
                        threat_tags,
                        metadata: meta,
                        data: file_data,
                    };

                    info!(
                        "Carved {} at offset {:#x} (len: {} bytes, confidence: {:.2})",
                        carved.id, carved.offset, carved.length, carved.confidence
                    );

                    results.push(carved);

                    // Advance cursor past this file's length (or aligned to sector boundary)
                    let advance = actual_len.max(step);
                    i += advance;
                    continue;
                }
            }
        }

        i += step;
    }

    info!("Carving completed. Total recovered: {} files", results.len());
    results
}

/// Package carved files into a forensic JOCKY Artifact (.jkya) container.
pub fn export_carved_artifact(carved_files: &[CarvedFile], artifact_name: &str) -> Artifact {
    let mut artifact = Artifact::new(artifact_name);
    artifact.metadata.insert("module".into(), "advanced_carver".into());
    artifact.metadata.insert("count".into(), carved_files.len().to_string());

    for (idx, f) in carved_files.iter().enumerate() {
        let meta_prefix = format!("file_{idx}_");
        artifact
            .metadata
            .insert(format!("{meta_prefix}id"), f.id.clone());
        artifact
            .metadata
            .insert(format!("{meta_prefix}type"), f.file_type.extension().into());
        artifact
            .metadata
            .insert(format!("{meta_prefix}offset"), f.offset.to_string());
        artifact
            .metadata
            .insert(format!("{meta_prefix}confidence"), format!("{:.2}", f.confidence));
        artifact
            .metadata
            .insert(format!("{meta_prefix}sha256"), f.sha256.clone());

        // Store file data as a distinct memory/evidence region
        artifact.append_region(f.offset, f.data.clone(), 0x02 /* PAGE_READONLY */);
    }

    artifact
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_carve_sqlite_from_dummy_disk() {
        // Construct a synthetic 16KB disk image with noise and an embedded SQLite database
        let mut disk = vec![0xE5; 16384]; // 0xE5 is traditional FAT deleted marker

        let db_offset = 2048;
        let mut db = vec![0u8; 4096];
        db[..16].copy_from_slice(b"SQLite format 3\0");
        db[16] = 0x10; // 4096 page size
        db[17] = 0x00;
        db[31] = 1;    // 1 page
        disk[db_offset..db_offset + 4096].copy_from_slice(&db);

        let config = CarveConfig {
            target_types: vec![FileType::Sqlite],
            min_confidence: 0.70,
            ..Default::default()
        };

        let carved = carve_bytes(&disk, &config);
        assert_eq!(carved.len(), 1);
        assert_eq!(carved[0].offset, 2048);
        assert_eq!(carved[0].file_type, FileType::Sqlite);
        assert_eq!(carved[0].length, 4096);
        assert!(carved[0].confidence >= 0.95);
        assert_eq!(carved[0].metadata.get("page_size").unwrap(), "4096");
    }

    #[test]
    fn test_carve_multiple_types() {
        let mut disk = vec![0x00; 8192];

        // 1. Embed PNG at offset 512
        let png = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
            0x00, 0x00, 0x00, 0x0D,
            0x49, 0x48, 0x44, 0x52,
            0x00, 0x00, 0x00, 0x20,
            0x00, 0x00, 0x00, 0x20,
            0x08, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x49, 0x45, 0x4E, 0x44,
            0xAE, 0x42, 0x60, 0x82,
        ];
        disk[512..512 + png.len()].copy_from_slice(&png);

        // 2. Embed PDF at offset 4096
        let pdf = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\nxref\n0 1\ntrailer\n<<>>\nstartxref\n9\n%%EOF\n";
        disk[4096..4096 + pdf.len()].copy_from_slice(pdf);

        let config = CarveConfig::default();
        let carved = carve_bytes(&disk, &config);

        assert_eq!(carved.len(), 2);
        assert_eq!(carved[0].file_type, FileType::Png);
        assert_eq!(carved[0].offset, 512);

        assert_eq!(carved[1].file_type, FileType::Pdf);
        assert_eq!(carved[1].offset, 4096);
    }
}
