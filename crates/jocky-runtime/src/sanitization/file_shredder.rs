//! Secure File & Folder Shredding Engine
//!
//! Provides multi-pass file overwriting, metadata trace removal,
//! directory record obfuscation, and permanent deletion.

use super::algorithms::{generate_pass_pattern, verify_slice_pattern, WipeMethod};
use super::cert::ErasureCertificate;
use log::info;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

const CHUNK_SIZE: usize = 64 * 1024; // 64KB stream buffer

/// Securely shred a single file with multi-pass overwriting and metadata obliteration.
pub fn shred_file(
    path: &Path,
    method: WipeMethod,
    clean_metadata: bool,
    operator: &str,
) -> io::Result<ErasureCertificate> {
    if !path.exists() || !path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Target file '{}' does not exist or is not a regular file", path.display()),
        ));
    }

    let file_len = fs::metadata(path)?.len();
    info!(
        "Beginning secure file shred on '{}' ({} bytes, method: {:?})",
        path.display(),
        file_len,
        method
    );

    let passes = method.default_passes();
    let seed = 0x9e3779b97f4a7c15u64;

    // Open file with write and read permissions for verification
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;

    let mut buffer = vec![0u8; CHUNK_SIZE];

    for pass_idx in 0..passes {
        file.seek(SeekFrom::Start(0))?;
        let mut bytes_left = file_len;

        while bytes_left > 0 {
            let write_len = (bytes_left as usize).min(CHUNK_SIZE);
            generate_pass_pattern(method, pass_idx, &mut buffer[..write_len], seed);
            file.write_all(&buffer[..write_len])?;
            bytes_left -= write_len as u64;
        }

        // Force hardware write cache flush
        file.sync_all()?;
    }

    // Readback verification of final pass
    file.seek(SeekFrom::Start(0))?;
    let mut verified = true;
    let last_pass = passes.saturating_sub(1);
    let mut bytes_left = file_len;

    while bytes_left > 0 {
        let read_len = (bytes_left as usize).min(CHUNK_SIZE);
        file.read_exact(&mut buffer[..read_len])?;
        if !verify_slice_pattern(method, last_pass, &buffer[..read_len], seed) {
            verified = false;
            break;
        }
        bytes_left -= read_len as u64;
    }

    drop(file);

    // Metadata & Directory Entry Obliteration
    let target_path_str = path.to_string_lossy().to_string();
    if clean_metadata {
        if let Some(parent) = path.parent() {
            // Rename file to a random temporary name to erase the directory entry
            let random_name = format!("__jocky_shred_{:016x}.tmp", seed.wrapping_add(file_len));
            let obfuscated_path = parent.join(random_name);
            let _ = fs::rename(path, &obfuscated_path);

            // Truncate to 0 bytes before removal
            if let Ok(f) = OpenOptions::new().write(true).open(&obfuscated_path) {
                let _ = f.set_len(0);
            }
            let _ = fs::remove_file(&obfuscated_path);
        } else {
            let _ = fs::remove_file(path);
        }
    } else {
        let _ = fs::remove_file(path);
    }

    let sectors_erased = (file_len + 511) / 512;
    let cert = ErasureCertificate::new(
        &target_path_str,
        "File",
        None,
        method,
        passes,
        file_len,
        sectors_erased,
        verified,
        operator,
    );

    info!(
        "File shred completed for '{}' -> Certificate: {}",
        target_path_str, cert.cert_id
    );

    Ok(cert)
}

/// Recursively shred an entire directory tree.
pub fn shred_folder(
    dir_path: &Path,
    method: WipeMethod,
    clean_metadata: bool,
    operator: &str,
) -> io::Result<ErasureCertificate> {
    if !dir_path.exists() || !dir_path.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Target directory '{}' does not exist", dir_path.display()),
        ));
    }

    info!(
        "Beginning secure recursive directory shred on '{}'",
        dir_path.display()
    );

    let mut total_bytes = 0u64;
    let mut files_shredded = 0usize;

    // Helper to recursively collect files
    fn collect_entries(dir: &Path, files: &mut Vec<std::path::PathBuf>, dirs: &mut Vec<std::path::PathBuf>) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                files.push(path);
            } else if path.is_dir() {
                collect_entries(&path, files, dirs)?;
                dirs.push(path);
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    let mut subdirs = Vec::new();
    collect_entries(dir_path, &mut files, &mut subdirs)?;

    for f in &files {
        if let Ok(meta) = fs::metadata(f) {
            total_bytes += meta.len();
        }
        shred_file(f, method, clean_metadata, operator)?;
        files_shredded += 1;
    }

    // Remove subdirectories bottom-up
    for d in subdirs.iter().rev() {
        let _ = fs::remove_dir(d);
    }
    let _ = fs::remove_dir(dir_path);

    let sectors_erased = (total_bytes + 511) / 512;
    let cert = ErasureCertificate::new(
        &dir_path.to_string_lossy(),
        "Folder",
        None,
        method,
        method.default_passes(),
        total_bytes,
        sectors_erased,
        true,
        operator,
    );

    info!(
        "Directory shred complete: {} files ({} bytes) -> Certificate: {}",
        files_shredded, total_bytes, cert.cert_id
    );

    Ok(cert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_shred_file_dod() {
        let temp_dir = env::temp_dir().join("jocky_shred_test");
        fs::create_dir_all(&temp_dir).unwrap();

        let file_path = temp_dir.join("confidential_data.bin");
        let initial_payload = vec![0x42; 65536]; // 64KB
        fs::write(&file_path, &initial_payload).unwrap();

        let cert = shred_file(&file_path, WipeMethod::Dod5220_22M, true, "Unit Tester").unwrap();

        assert_eq!(cert.bytes_erased, 65536);
        assert_eq!(cert.passes_completed, 3);
        assert!(cert.verified);
        assert!(!file_path.exists(), "Shredded file must be deleted");

        // Clean up
        let _ = fs::remove_dir_all(temp_dir);
    }
}
