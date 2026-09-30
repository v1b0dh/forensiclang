//! NTFS Timestomping Detection Module (MITRE ATT&CK T1070.006)
//!
//! Exposes anti-forensic timestomping anomalies by cross-comparing NTFS
//! $STANDARD_INFORMATION (SI) and $FILE_NAME (FN) timestamps, identifying
//! sub-second zero-precision wiping, and detecting temporal impossibilities.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// 100-nanosecond intervals per second in Windows FILETIME
pub const FILETIME_TICKS_PER_SEC: u64 = 10_000_000;
/// FILETIME epoch offset from Unix epoch (1601-01-01 to 1970-01-01 in seconds)
pub const FILETIME_TO_UNIX_OFFSET_SECS: u64 = 11_644_473_600;

/// Classification of timestomping anomaly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimestompSeverity {
    Clean,
    Suspicious,
    Critical,
}

/// Anomaly category for timestomping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyType {
    /// $STANDARD_INFORMATION CreationTime is significantly older than $FILE_NAME CreationTime.
    /// Classic timestomping tool indicator where API modifies SI but cannot touch FN.
    SiOlderThanFn,
    /// Timestamps with 0 milliseconds/nanoseconds indicative of synthetic tool stamping.
    ZeroSubsecondPrecision,
    /// Timestamp set to a future date/time.
    FutureTimestamp,
    /// Last modification timestamp precedes creation timestamp.
    ModifiedPrecedesCreated,
}

/// Timestamp quad: Created, Modified, MFT Record Altered, Accessed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimestampQuad {
    pub created: u64,
    pub modified: u64,
    pub mft_altered: u64,
    pub accessed: u64,
}

/// Detailed result of a timestomping analysis on a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestompAnomaly {
    pub file_path: String,
    pub anomaly_type: AnomalyType,
    pub severity: TimestompSeverity,
    pub mitre_attack: String,
    pub si_created: String,
    pub fn_created: String,
    pub delta_seconds: f64,
    pub description: String,
}

/// Convert a Windows FILETIME (100ns intervals since 1601) to ISO-8601 string.
pub fn filetime_to_iso(filetime: u64) -> String {
    if filetime == 0 {
        return "1601-01-01T00:00:00Z".to_string();
    }
    let total_secs = filetime / FILETIME_TICKS_PER_SEC;
    if total_secs < FILETIME_TO_UNIX_OFFSET_SECS {
        return "Pre-1970".to_string();
    }
    let unix_secs = total_secs - FILETIME_TO_UNIX_OFFSET_SECS;
    let days = unix_secs / 86400;
    let rem_secs = unix_secs % 86400;
    let hours = rem_secs / 3600;
    let mins = (rem_secs % 3600) / 60;
    let secs = rem_secs % 60;

    let mut y = 1970;
    let mut d = days;
    loop {
        let leap = if (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0) { 1 } else { 0 };
        let days_in_year = 365 + leap;
        if d < days_in_year {
            let days_in_months = [31, 28 + leap, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
            let mut m = 1;
            for dim in days_in_months {
                if d < dim {
                    return format!("{y:04}-{m:02}-{:02}T{hours:02}:{mins:02}:{secs:02}Z", d + 1);
                }
                d -= dim;
                m += 1;
            }
            break;
        }
        d -= days_in_year;
        y += 1;
    }
    format!("{unix_secs}s")
}

/// Convert Unix timestamp (seconds) to Windows FILETIME
pub fn unix_secs_to_filetime(unix_secs: u64) -> u64 {
    (unix_secs + FILETIME_TO_UNIX_OFFSET_SECS) * FILETIME_TICKS_PER_SEC
}

/// Analyze NTFS $STANDARD_INFORMATION vs $FILE_NAME timestamps.
///
/// Timestomping tools change $STANDARD_INFORMATION via standard Win32 SetFileTime API,
/// but leave $FILE_NAME untouched because it can only be modified by the kernel.
pub fn analyze_ntfs_timestamps(
    file_path: &str,
    si: &TimestampQuad,
    fn_attr: &TimestampQuad,
) -> Vec<TimestompAnomaly> {
    let mut anomalies = Vec::new();

    // 1. SI Creation significantly older than FN Creation (delta > 10 seconds)
    // Legitimate files: SI Creation == FN Creation or SI >= FN
    if fn_attr.created > 0 && si.created > 0 {
        if fn_attr.created > si.created {
            let diff_ticks = fn_attr.created - si.created;
            let delta_sec = diff_ticks as f64 / FILETIME_TICKS_PER_SEC as f64;

            if delta_sec > 10.0 {
                anomalies.push(TimestompAnomaly {
                    file_path: file_path.to_string(),
                    anomaly_type: AnomalyType::SiOlderThanFn,
                    severity: TimestompSeverity::Critical,
                    mitre_attack: "T1070.006".to_string(),
                    si_created: filetime_to_iso(si.created),
                    fn_created: filetime_to_iso(fn_attr.created),
                    delta_seconds: delta_sec,
                    description: format!(
                        "Timestomping detected: $STANDARD_INFORMATION is {:.1}s older than $FILE_NAME. Anti-forensic rollback indicated.",
                        delta_sec
                    ),
                });
            }
        }
    }

    // 2. Subsecond zero precision (stamped with FAT or second-granularity tool)
    if si.created > 0 && (si.created % FILETIME_TICKS_PER_SEC == 0) {
        anomalies.push(TimestompAnomaly {
            file_path: file_path.to_string(),
            anomaly_type: AnomalyType::ZeroSubsecondPrecision,
            severity: TimestompSeverity::Suspicious,
            mitre_attack: "T1070.006".to_string(),
            si_created: filetime_to_iso(si.created),
            fn_created: filetime_to_iso(fn_attr.created),
            delta_seconds: 0.0,
            description: "Sub-second timestamp precision was stripped (exact zero nanoseconds), typical of low-resolution timestomp tools.".to_string(),
        });
    }

    // 3. Modified before Created
    if si.created > 0 && si.modified > 0 && si.modified < si.created {
        let diff_ticks = si.created - si.modified;
        let delta_sec = diff_ticks as f64 / FILETIME_TICKS_PER_SEC as f64;
        if delta_sec > 10.0 {
            anomalies.push(TimestompAnomaly {
                file_path: file_path.to_string(),
                anomaly_type: AnomalyType::ModifiedPrecedesCreated,
                severity: TimestompSeverity::Suspicious,
                mitre_attack: "T1070.006".to_string(),
                si_created: filetime_to_iso(si.created),
                fn_created: filetime_to_iso(fn_attr.created),
                delta_seconds: delta_sec,
                description: format!(
                    "Temporal anomaly: Last Modified precedes Creation by {:.1}s.",
                    delta_sec
                ),
            });
        }
    }

    // 4. Future timestamp check
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let now_filetime = unix_secs_to_filetime(now_unix + 86400); // 1 day tolerance
    if si.created > now_filetime || si.modified > now_filetime {
        anomalies.push(TimestompAnomaly {
            file_path: file_path.to_string(),
            anomaly_type: AnomalyType::FutureTimestamp,
            severity: TimestompSeverity::Critical,
            mitre_attack: "T1070.006".to_string(),
            si_created: filetime_to_iso(si.created),
            fn_created: filetime_to_iso(fn_attr.created),
            delta_seconds: 0.0,
            description: "File timestamp is set to a future date/time beyond acceptable clock drift.".to_string(),
        });
    }

    anomalies
}

/// Audit a live file using standard filesystem metadata.
pub fn audit_file_metadata(path: &Path) -> Vec<TimestompAnomaly> {
    let mut anomalies = Vec::new();
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return anomalies,
    };

    let created_ft = meta
        .created()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| unix_secs_to_filetime(d.as_secs()))
        .unwrap_or(0);

    let modified_ft = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| unix_secs_to_filetime(d.as_secs()))
        .unwrap_or(0);

    let path_str = path.to_string_lossy().to_string();

    let si = TimestampQuad {
        created: created_ft,
        modified: modified_ft,
        mft_altered: modified_ft,
        accessed: modified_ft,
    };
    // In live filesystem without direct MFT handle, compare against modified
    let fn_attr = TimestampQuad {
        created: created_ft,
        modified: modified_ft,
        mft_altered: modified_ft,
        accessed: modified_ft,
    };

    let mut found = analyze_ntfs_timestamps(&path_str, &si, &fn_attr);
    anomalies.append(&mut found);
    anomalies
}

/// Parse raw NTFS MFT record bytes and extract SI (0x10) and FN (0x30) attributes for audit.
///
/// An MFT record is typically 1024 bytes starting with "FILE".
pub fn parse_mft_record_and_audit(record: &[u8], file_label: &str) -> Vec<TimestompAnomaly> {
    if record.len() < 512 || &record[0..4] != b"FILE" {
        return Vec::new();
    }

    let mut si_quad = TimestampQuad::default();
    let mut fn_quad = TimestampQuad::default();
    let mut found_si = false;
    let mut found_fn = false;

    // First attribute offset at record offset 0x14 (u16)
    let mut attr_offset = u16::from_le_bytes([record[0x14], record[0x15]]) as usize;

    while attr_offset + 16 <= record.len() {
        let attr_type = u32::from_le_bytes([
            record[attr_offset],
            record[attr_offset + 1],
            record[attr_offset + 2],
            record[attr_offset + 3],
        ]);

        if attr_type == 0xFFFFFFFF || attr_type == 0 {
            break; // End of attributes
        }

        let attr_len = u32::from_le_bytes([
            record[attr_offset + 4],
            record[attr_offset + 5],
            record[attr_offset + 6],
            record[attr_offset + 7],
        ]) as usize;

        if attr_len == 0 || attr_offset + attr_len > record.len() {
            break;
        }

        let non_resident = record[attr_offset + 8];
        if non_resident == 0 {
            // Resident attribute: content offset at +0x14 (u16)
            let content_offset = u16::from_le_bytes([
                record[attr_offset + 0x14],
                record[attr_offset + 0x15],
            ]) as usize;
            let val_pos = attr_offset + content_offset;

            if attr_type == 0x10 && val_pos + 32 <= record.len() {
                // $STANDARD_INFORMATION: 4x 64-bit FILETIMEs
                si_quad.created = u64::from_le_bytes(record[val_pos..val_pos + 8].try_into().unwrap());
                si_quad.modified = u64::from_le_bytes(record[val_pos + 8..val_pos + 16].try_into().unwrap());
                si_quad.mft_altered = u64::from_le_bytes(record[val_pos + 16..val_pos + 24].try_into().unwrap());
                si_quad.accessed = u64::from_le_bytes(record[val_pos + 24..val_pos + 32].try_into().unwrap());
                found_si = true;
            } else if attr_type == 0x30 && val_pos + 40 <= record.len() {
                // $FILE_NAME: parent dir (8 bytes) + 4x 64-bit FILETIMEs
                let t_pos = val_pos + 8;
                fn_quad.created = u64::from_le_bytes(record[t_pos..t_pos + 8].try_into().unwrap());
                fn_quad.modified = u64::from_le_bytes(record[t_pos + 8..t_pos + 16].try_into().unwrap());
                fn_quad.mft_altered = u64::from_le_bytes(record[t_pos + 16..t_pos + 24].try_into().unwrap());
                fn_quad.accessed = u64::from_le_bytes(record[t_pos + 24..t_pos + 32].try_into().unwrap());
                found_fn = true;
            }
        }

        attr_offset += attr_len;
    }

    if found_si && found_fn {
        analyze_ntfs_timestamps(file_label, &si_quad, &fn_quad)
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_timestamps() {
        let base_unix = 1774900000u64;
        let base_ft = unix_secs_to_filetime(base_unix) + 1234567; // with subsecond ticks

        let si = TimestampQuad {
            created: base_ft,
            modified: base_ft + 100 * FILETIME_TICKS_PER_SEC,
            mft_altered: base_ft + 100 * FILETIME_TICKS_PER_SEC,
            accessed: base_ft + 200 * FILETIME_TICKS_PER_SEC,
        };
        let fn_attr = TimestampQuad {
            created: base_ft,
            modified: base_ft + 100 * FILETIME_TICKS_PER_SEC,
            mft_altered: base_ft + 100 * FILETIME_TICKS_PER_SEC,
            accessed: base_ft + 200 * FILETIME_TICKS_PER_SEC,
        };

        let anomalies = analyze_ntfs_timestamps("C:\\Windows\\notepad.exe", &si, &fn_attr);
        assert!(anomalies.is_empty(), "Expected no anomalies for clean file");
    }

    #[test]
    fn test_si_older_than_fn_timestomp_detected() {
        // Attack scenario: file created in 2026 ($FILE_NAME created = 2026),
        // attacker backdates $STANDARD_INFORMATION to 2019 (7 years older).
        let real_created_unix = 1774900000u64; // ~2026
        let stomped_created_unix = 1554900000u64; // ~2019

        let fn_ft = unix_secs_to_filetime(real_created_unix) + 555555;
        let si_ft = unix_secs_to_filetime(stomped_created_unix) + 111111;

        let si = TimestampQuad {
            created: si_ft,
            modified: si_ft + 1000,
            mft_altered: fn_ft,
            accessed: fn_ft,
        };
        let fn_attr = TimestampQuad {
            created: fn_ft,
            modified: fn_ft,
            mft_altered: fn_ft,
            accessed: fn_ft,
        };

        let anomalies = analyze_ntfs_timestamps("C:\\Temp\\backdoor.exe", &si, &fn_attr);
        assert!(!anomalies.is_empty());
        let critical = anomalies.iter().find(|a| a.anomaly_type == AnomalyType::SiOlderThanFn);
        assert!(critical.is_some());
        let c = critical.unwrap();
        assert_eq!(c.mitre_attack, "T1070.006");
        assert_eq!(c.severity, TimestompSeverity::Critical);
        assert!(c.delta_seconds > 1000.0);
    }

    #[test]
    fn test_zero_subsecond_precision_anomaly() {
        let base_unix = 1774900000u64;
        let clean_fn_ft = unix_secs_to_filetime(base_unix) + 765432;
        // Exactly divisible by 10_000_000 (0 subseconds)
        let stomped_si_ft = unix_secs_to_filetime(base_unix);

        let si = TimestampQuad {
            created: stomped_si_ft,
            modified: stomped_si_ft,
            mft_altered: clean_fn_ft,
            accessed: clean_fn_ft,
        };
        let fn_attr = TimestampQuad {
            created: clean_fn_ft,
            modified: clean_fn_ft,
            mft_altered: clean_fn_ft,
            accessed: clean_fn_ft,
        };

        let anomalies = analyze_ntfs_timestamps("C:\\test.ps1", &si, &fn_attr);
        assert!(anomalies.iter().any(|a| a.anomaly_type == AnomalyType::ZeroSubsecondPrecision));
    }
}
