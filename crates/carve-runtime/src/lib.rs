//! JOCKY Forensic Runtime Library
//!
//! Provides cross-platform forensic data collection modules:
//! - Memory collection (VirtualQueryEx / procfs)
//! - Process enumeration (Toolhelp32 / procfs)
//! - Disk collection (VSS snapshots)
//! - Network capture (pcap)
//! - Artifact format (.jkya)
//! - Timeline builder

pub mod antiforensics;
pub mod artifact;
pub mod blockchain;
pub mod carving;
pub mod crypto;
pub mod memory;
pub mod processes;
pub mod sanitization;
pub mod timeline;

// Platform-specific modules
#[cfg(windows)]
pub mod disk;

#[cfg(windows)]
pub mod network;

#[cfg(windows)]
pub mod win32;

/// Runtime version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Helper to generate ISO 8601-compatible UTC timestamp using std::time
pub fn utc_timestamp_now() -> String {
    let now = std::time::SystemTime::now();
    let duration = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let total_secs = duration.as_secs();
    let days = total_secs / 86400;
    let rem_secs = total_secs % 86400;
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
    format!("{y:04}-01-01T{hours:02}:{mins:02}:{secs:02}Z")
}

/// Helper to get current microseconds since UNIX epoch
pub fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use carving::{carve_bytes, CarveConfig};
    use sanitization::{sanitize_drive, DriveEraseOptions, WipeMethod};
    use std::env;
    use std::fs;

    #[test]
    fn test_sanitize_and_carve_verification_loop() {
        let temp_disk = env::temp_dir().join("jocky_e2e_carve_wipe.raw");

        // 1. Create a synthetic 64KB disk image
        let mut disk = vec![0x00; 65536];

        // 2. Inject an embedded SQLite database at offset 4096
        let mut sqlite = vec![0u8; 4096];
        sqlite[..16].copy_from_slice(b"SQLite format 3\0");
        sqlite[16] = 0x10; // 4096 page size
        sqlite[31] = 1;    // 1 page
        disk[4096..4096 + 4096].copy_from_slice(&sqlite);

        // 3. Inject an embedded PNG at offset 16384
        let png = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
            0x00, 0x00, 0x00, 0x0D,
            0x49, 0x48, 0x44, 0x52,
            0x00, 0x00, 0x00, 0x10,
            0x00, 0x00, 0x00, 0x10,
            0x08, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x49, 0x45, 0x4E, 0x44,
            0xAE, 0x42, 0x60, 0x82,
        ];
        disk[16384..16384 + png.len()].copy_from_slice(&png);

        fs::write(&temp_disk, &disk).unwrap();

        // 4. Carve pre-wipe: must recover exactly 2 files
        let initial_data = fs::read(&temp_disk).unwrap();
        let carved_before = carve_bytes(&initial_data, &CarveConfig::default());
        assert_eq!(carved_before.len(), 2, "Must recover both SQLite and PNG before wipe");

        // 5. Sanitize drive image according to NIST SP 800-88 Clear
        let opts = DriveEraseOptions {
            method: WipeMethod::Nist800_88Clear,
            passes: 1,
            verify: true,
            operator: "Senior Forensic Auditor #007".into(),
            force_system_drive: false,
            max_bytes_limit: None,
        };
        let cert = sanitize_drive(&temp_disk.to_string_lossy(), &opts).unwrap();
        assert!(cert.verified, "Read-back verification must pass");
        assert!(cert.verify_authenticity(), "Certificate HMAC signature must be valid");

        // 6. Carve post-wipe: must recover 0 files (zero residual bit recovery proven)
        let post_wipe_data = fs::read(&temp_disk).unwrap();
        let carved_after = carve_bytes(&post_wipe_data, &CarveConfig::default());
        assert_eq!(carved_after.len(), 0, "Zero files must be recoverable after certified sanitization");

        let _ = fs::remove_file(temp_disk);
    }
}

