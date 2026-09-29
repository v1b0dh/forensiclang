//! Secure Drive Erasure Engine
//!
//! Provides certified whole-drive sanitization for HDDs, SSDs, USB drives,
//! and raw disk images with safety interlocks and verified sector coverage.

use super::algorithms::{generate_pass_pattern, verify_slice_pattern, WipeMethod};
use super::cert::ErasureCertificate;
use log::{info, warn};
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

const DRIVE_BUFFER_SIZE: usize = 1024 * 1024; // 1MB aligned streaming buffer

/// Options controlling drive erasure operations.
#[derive(Debug, Clone)]
pub struct DriveEraseOptions {
    pub method: WipeMethod,
    pub passes: usize,
    pub verify: bool,
    pub operator: String,
    pub force_system_drive: bool,
    pub max_bytes_limit: Option<u64>, // For partial or test image wipes
}

impl Default for DriveEraseOptions {
    fn default() -> Self {
        Self {
            method: WipeMethod::Nist800_88Clear,
            passes: 1,
            verify: true,
            operator: "Jocky Forensics Agent".into(),
            force_system_drive: false,
            max_bytes_limit: None,
        }
    }
}

/// Verify whether a target string represents the active operating system drive.
pub fn is_system_drive(target: &str) -> bool {
    let t = target.trim().to_ascii_uppercase();
    #[cfg(windows)]
    {
        t == "C:"
            || t == "C:\\"
            || t == "\\\\.\\C:"
            || t == "\\\\.\\C:\\"
            || t == "\\\\?\\C:"
            || t == "\\\\?\\C:\\"
            || t == "\\\\.\\PHYSICALDRIVE0"
    }
    #[cfg(unix)]
    {
        t == "/dev/sda" || t == "/dev/nvme0n1" || t == "/"
    }
    #[cfg(not(any(windows, unix)))]
    {
        false
    }
}

/// Perform certified drive erasure on a block device or raw disk image.
pub fn sanitize_drive(
    target: &str,
    options: &DriveEraseOptions,
) -> Result<ErasureCertificate, String> {
    if is_system_drive(target) && !options.force_system_drive {
        return Err(format!(
            "SAFETY INTERLOCK: Target '{}' is identified as the operating system boot drive. \
             Erasure aborted to prevent system destruction. Set force_system_drive = true to override.",
            target
        ));
    }

    info!(
        "Initiating certified drive sanitization on '{}' using {:?}",
        target, options.method
    );

    let path = Path::new(target);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("Cannot open drive/device target '{}': {e}", target))?;

    let total_len = if let Some(limit) = options.max_bytes_limit {
        limit
    } else {
        file.seek(SeekFrom::End(0))
            .map_err(|e| format!("Cannot determine drive capacity: {e}"))?
    };

    let passes = if options.passes > 0 {
        options.passes
    } else {
        options.method.default_passes()
    };

    let seed = 0x517cc1b727220a95u64;
    let mut buffer = vec![0u8; DRIVE_BUFFER_SIZE];

    for pass_idx in 0..passes {
        info!("Drive '{}': executing pass {} of {}", target, pass_idx + 1, passes);
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("Seek failed: {e}"))?;

        let mut bytes_left = total_len;
        while bytes_left > 0 {
            let write_len = (bytes_left as usize).min(DRIVE_BUFFER_SIZE);
            generate_pass_pattern(options.method, pass_idx, &mut buffer[..write_len], seed);

            file.write_all(&buffer[..write_len])
                .map_err(|e| format!("Write failed at offset {}: {e}", total_len - bytes_left))?;

            bytes_left -= write_len as u64;
        }

        file.sync_all().map_err(|e| format!("Device flush failed: {e}"))?;
    }

    // Readback verification
    let mut verified = false;
    if options.verify {
        info!("Drive '{}': performing read-back verification", target);
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("Seek for verification failed: {e}"))?;

        let last_pass = passes.saturating_sub(1);
        let mut bytes_left = total_len;
        let mut pass_ok = true;

        while bytes_left > 0 {
            let read_len = (bytes_left as usize).min(DRIVE_BUFFER_SIZE);
            file.read_exact(&mut buffer[..read_len])
                .map_err(|e| format!("Verification read failed: {e}"))?;

            if !verify_slice_pattern(options.method, last_pass, &buffer[..read_len], seed) {
                pass_ok = false;
                warn!("Verification mismatch detected at offset {}", total_len - bytes_left);
                break;
            }
            bytes_left -= read_len as u64;
        }
        verified = pass_ok;
    }

    let sectors_erased = (total_len + 511) / 512;
    let cert = ErasureCertificate::new(
        target,
        "StorageDrive",
        Some("RAW-MEDIA-DEVICE"),
        options.method,
        passes,
        total_len,
        sectors_erased,
        verified,
        &options.operator,
    );

    info!(
        "Drive sanitization finished for '{}' -> Certificate: {}",
        target, cert.cert_id
    );

    Ok(cert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;

    #[test]
    fn test_system_drive_safety_interlock() {
        let opts = DriveEraseOptions {
            force_system_drive: false,
            ..Default::default()
        };
        let res = sanitize_drive("C:\\", &opts);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("SAFETY INTERLOCK"));
    }

    #[test]
    fn test_sanitize_virtual_disk_image() {
        let temp_file = env::temp_dir().join("test_virtual_disk.raw");
        // Create 2MB dummy disk image filled with noise 0xAA
        fs::write(&temp_file, vec![0xAA; 2 * 1024 * 1024]).unwrap();

        let opts = DriveEraseOptions {
            method: WipeMethod::Nist800_88Clear,
            passes: 1,
            verify: true,
            operator: "Test Analyst".into(),
            force_system_drive: false,
            max_bytes_limit: None,
        };

        let cert = sanitize_drive(&temp_file.to_string_lossy(), &opts).unwrap();
        assert_eq!(cert.bytes_erased, 2 * 1024 * 1024);
        assert!(cert.verified);

        // Verify file is indeed now all 0x00
        let contents = fs::read(&temp_file).unwrap();
        assert!(contents.iter().all(|&b| b == 0x00));

        let _ = fs::remove_file(temp_file);
    }
}
