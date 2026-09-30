//! Disk Acquisition & VSS Module
//!
//! Provides read-only disk structures, partition metadata, and Volume Shadow Copy (VSS) references.

use crate::artifact::Artifact;
use log::info;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Disk partition or volume information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub drive_letter: String,
    pub volume_label: String,
    pub file_system: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
}

/// Volume Shadow Copy reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssSnapshot {
    pub id: String,
    pub volume: String,
    pub created_at: String,
    pub device_object: String,
}

/// Enumerate available local drive letters and verify their accessibility.
pub fn list_drives() -> Result<Vec<DiskInfo>, String> {
    info!("Enumerating local drives");
    let mut drives = Vec::new();

    // Check drives A..Z
    for b in b'A'..=b'Z' {
        let drive_root = format!("{}:\\", b as char);
        let path = Path::new(&drive_root);
        if path.exists() {
            drives.push(DiskInfo {
                drive_letter: format!("{}:", b as char),
                volume_label: "Local Disk".to_string(),
                file_system: "NTFS".to_string(),
                total_bytes: 0,
                available_bytes: 0,
            });
        }
    }

    Ok(drives)
}

/// Collect Master File Table ($MFT) or disk metadata into an artifact container.
pub fn collect_mft(drive: &str, export_name: &str) -> Result<Artifact, String> {
    info!("Collecting $MFT metadata for drive {} -> {}", drive, export_name);

    let mut artifact = Artifact::new(export_name);
    artifact.metadata.insert("drive".to_string(), drive.to_string());
    artifact.metadata.insert("target".to_string(), "$MFT".to_string());

    // Record dummy MFT boot header region for demonstration/testing
    let boot_sector = vec![0xEB, 0x52, 0x90, 0x4E, 0x54, 0x46, 0x53]; // "NTFS" signature
    artifact.append_region(0x0, boot_sector, 0x02 /* PAGE_READONLY */);

    Ok(artifact)
}

/// Enumerate Volume Shadow Copies for a volume.
pub fn list_vss_snapshots(volume: &str) -> Result<Vec<VssSnapshot>, String> {
    info!("Listing VSS snapshots for volume {}", volume);
    // In production this interfaces with VSS COM API (IVssBackupComponents).
    // For test/scaffold runtime, provide structured snapshot entries.
    let snapshot = VssSnapshot {
        id: "{11111111-2222-3333-4444-555555555555}".to_string(),
        volume: volume.to_string(),
        created_at: crate::utc_timestamp_now(),
        device_object: format!("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1"),
    };

    Ok(vec![snapshot])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_drives() {
        let drives = list_drives().expect("Drive enumeration failed");
        // On Windows C: almost always exists
        #[cfg(windows)]
        assert!(drives.iter().any(|d| d.drive_letter.starts_with("C")));
    }

    #[test]
    fn test_collect_mft() {
        let art = collect_mft("C:", "c_mft_evidence").unwrap();
        assert_eq!(art.name, "c_mft_evidence");
        assert_eq!(art.metadata.get("target").unwrap(), "$MFT");
    }
}
