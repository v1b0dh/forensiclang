//! JOCKY Artifact Format (.jkya)
//!
//! Binary artifact container that stores forensic evidence:
//! - Memory regions with metadata (base address, protection flags)
//! - Network packets with timestamps
//! - Disk sectors and MFT records

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// A single memory region captured from a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base_address: u64,
    pub size: usize,
    pub protection: u32,
    pub data: Vec<u8>,
}

/// A captured network packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub timestamp_us: u64,
    pub length: u32,
    pub data: Vec<u8>,
}

/// Top-level artifact container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub name: String,
    pub created_at: String,
    pub regions: Vec<MemoryRegion>,
    pub packets: Vec<Packet>,
    pub metadata: std::collections::HashMap<String, String>,
}

impl Artifact {
    /// Create a new empty artifact.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            created_at: crate::utc_timestamp_now(),
            regions: Vec::new(),
            packets: Vec::new(),
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Append a memory region to the artifact.
    pub fn append_region(&mut self, base: u64, data: Vec<u8>, protection: u32) {
        let size = data.len();
        self.regions.push(MemoryRegion {
            base_address: base,
            size,
            protection,
            data,
        });
    }

    /// Append a network packet.
    pub fn append_packet(&mut self, timestamp_us: u64, data: Vec<u8>) {
        let length = data.len() as u32;
        self.packets.push(Packet {
            timestamp_us,
            length,
            data,
        });
    }

    /// Save artifact to disk as JSON (for portability; binary format is future work).
    pub fn save(&self, dir: &Path) -> io::Result<PathBuf> {
        fs::create_dir_all(dir)?;
        let path = dir.join(format!("{}.jkya", self.name));
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let mut file = fs::File::create(&path)?;
        file.write_all(json.as_bytes())?;
        Ok(path)
    }

    /// Load artifact from disk.
    pub fn load(path: &Path) -> io::Result<Self> {
        let data = fs::read_to_string(path)?;
        serde_json::from_str(&data).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_artifact_create_and_save() {
        let mut art = Artifact::new("test_artifact");
        art.append_region(0x1000, vec![0xDE, 0xAD, 0xBE, 0xEF], 0x04);
        assert_eq!(art.regions.len(), 1);
        assert_eq!(art.regions[0].base_address, 0x1000);

        let dir = env::temp_dir().join("jocky_test_artifacts");
        let path = art.save(&dir).unwrap();
        assert!(path.exists());

        let loaded = Artifact::load(&path).unwrap();
        assert_eq!(loaded.name, "test_artifact");
        assert_eq!(loaded.regions.len(), 1);

        // Cleanup
        let _ = std::fs::remove_file(path);
    }
}
