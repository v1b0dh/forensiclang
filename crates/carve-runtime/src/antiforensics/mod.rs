//! Anti-Forensic Evasion Detection Suite
//!
//! Provides automated scanning for anti-forensic techniques:
//! - Timestomping ($STANDARD_INFORMATION vs $FILE_NAME delta analysis)
//! - NTFS Alternate Data Streams (hidden payload enumeration)

pub mod streams;
pub mod timestomp;

use serde::{Deserialize, Serialize};
use std::path::Path;

pub use streams::{AlternateDataStream, classify_stream, enumerate_streams, scan_directory_streams};
pub use timestomp::{
    AnomalyType, TimestampQuad, TimestompAnomaly, TimestompSeverity,
    analyze_ntfs_timestamps, audit_file_metadata, filetime_to_iso, parse_mft_record_and_audit,
    unix_secs_to_filetime,
};

/// Combined audit report for anti-forensic artifacts across a target directory or volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiForensicAuditReport {
    pub target_path: String,
    pub scanned_at: String,
    pub total_files_scanned: usize,
    pub timestomp_anomalies: Vec<TimestompAnomaly>,
    pub hidden_streams: Vec<AlternateDataStream>,
    pub evasion_detected: bool,
}

/// Run an anti-forensics evasion audit on a path.
pub fn scan_path_antiforensics(target: &Path) -> AntiForensicAuditReport {
    let mut timestomps = Vec::new();
    let mut streams = Vec::new();
    let mut scanned_count = 0;

    if target.is_file() {
        scanned_count = 1;
        let ts = audit_file_metadata(target);
        timestomps.extend(ts);
        if let Ok(s) = enumerate_streams(target) {
            streams.extend(s);
        }
    } else if target.is_dir() {
        if let Ok(entries) = std::fs::read_dir(target) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    scanned_count += 1;
                    let ts = audit_file_metadata(&p);
                    timestomps.extend(ts);
                    if let Ok(s) = enumerate_streams(&p) {
                        streams.extend(s);
                    }
                }
            }
        }
    }

    let evasion_detected = !timestomps.is_empty() || streams.iter().any(|s| s.is_suspicious);

    AntiForensicAuditReport {
        target_path: target.to_string_lossy().to_string(),
        scanned_at: crate::utc_timestamp_now(),
        total_files_scanned: scanned_count,
        timestomp_anomalies: timestomps,
        hidden_streams: streams,
        evasion_detected,
    }
}
