//! File Slack Space Sanitization
//!
//! Zeros out residual cluster tips and unallocated slack space between
//! the logical End-Of-File (EOF) and the physical cluster boundary.

use std::fs::OpenOptions;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;

/// Default filesystem cluster size in bytes (4KB).
pub const DEFAULT_CLUSTER_SIZE: usize = 4096;

/// Sanitizes the residual slack space of a file on disk.
///
/// Returns the number of slack bytes overwritten with zeros.
pub fn wipe_file_slack(path: &Path, cluster_size: usize) -> io::Result<usize> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    let file_len = file.seek(SeekFrom::End(0))?;

    let remainder = (file_len as usize) % cluster_size;
    if remainder == 0 {
        // File perfectly aligns with cluster boundary; zero slack space
        return Ok(0);
    }

    let slack_len = cluster_size - remainder;
    let zeros = vec![0u8; slack_len];

    // Overwrite the slack space up to the end of the cluster
    file.seek(SeekFrom::Start(file_len))?;
    file.write_all(&zeros)?;
    file.sync_all()?;

    // Truncate back to the original logical file size
    file.set_len(file_len)?;
    file.sync_all()?;

    Ok(slack_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;

    #[test]
    fn test_wipe_file_slack() {
        let temp_file = env::temp_dir().join("slack_test.bin");
        // Create 5000-byte file (in 4096 cluster size, slack is 8192 - 5000 = 3192 bytes)
        fs::write(&temp_file, vec![0xEE; 5000]).unwrap();

        let slack_wiped = wipe_file_slack(&temp_file, 4096).unwrap();
        assert_eq!(slack_wiped, 3192);

        // Ensure logical length was preserved
        assert_eq!(fs::metadata(&temp_file).unwrap().len(), 5000);

        let _ = fs::remove_file(temp_file);
    }
}
