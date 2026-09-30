//! NTFS Alternate Data Stream (ADS) Enumeration & Analysis (MITRE ATT&CK T1564.004)
//!
//! Scans NTFS volumes for hidden streams attached to legitimate host files.
//! Detects hidden executable payloads, scripts, and audits Zone.Identifier metadata.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[cfg(windows)]
use crate::win32::*;

/// Classification and attributes of an Alternate Data Stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlternateDataStream {
    pub parent_file: String,
    pub stream_name: String,
    pub full_stream_path: String,
    pub size_bytes: u64,
    pub is_suspicious: bool,
    pub threat_tags: Vec<String>,
    pub mitre_attack: String,
    pub description: String,
}

/// Known high-risk executable or script extensions hidden inside NTFS data streams.
const SUSPICIOUS_STREAM_EXTENSIONS: &[&str] = &[
    ".exe", ".dll", ".sys", ".scr", ".cpl", ".ps1", ".vbs", ".vbe", ".js", ".jse",
    ".bat", ".cmd", ".hta", ".bin", ".elf",
];

/// Known suspicious stream names used by malware stagers.
const SUSPICIOUS_STREAM_KEYWORDS: &[&str] = &[
    "payload", "beacon", "dropper", "hidden", "shell", "stealth", "meterpreter", "injector",
];

/// Heuristic evaluation of an Alternate Data Stream name.
pub fn classify_stream(stream_name: &str) -> (bool, Vec<String>, String) {
    let lower = stream_name.to_lowercase();
    let mut tags = Vec::new();
    let mut is_suspicious = false;
    let mut desc = Vec::new();

    // Default stream is harmless
    if lower == "::$data" || lower == ":$data" {
        return (false, tags, "Default primary data stream.".to_string());
    }

    // Zone.Identifier is standard Windows Mark-of-the-Web (MOTW)
    if lower.starts_with(":zone.identifier") {
        tags.push("MOTW".to_string());
        return (
            false,
            tags,
            "Mark-of-the-Web metadata stream indicating origin internet security zone.".to_string(),
        );
    }

    // Check for executable / script extensions
    for ext in SUSPICIOUS_STREAM_EXTENSIONS {
        if lower.contains(ext) {
            is_suspicious = true;
            tags.push(format!("ADS-EXEC-{}", ext.trim_start_matches('.')));
            desc.push(format!("Hidden executable/script format detected: '{ext}'"));
        }
    }

    // Check for suspicious payload keywords
    for kw in SUSPICIOUS_STREAM_KEYWORDS {
        if lower.contains(kw) {
            is_suspicious = true;
            tags.push(format!("ADS-MALWARE-{}", kw.to_uppercase()));
            desc.push(format!("Suspicious threat keyword in stream name: '{kw}'"));
        }
    }

    if is_suspicious {
        (
            true,
            tags,
            format!("High-risk hidden data stream (T1564.004): {}", desc.join("; ")),
        )
    } else {
        (
            false,
            tags,
            "Non-standard data stream attached to file.".to_string(),
        )
    }
}

/// Enumerate Alternate Data Streams on a single file using Win32 API.
#[cfg(windows)]
pub fn enumerate_streams(file_path: &Path) -> Result<Vec<AlternateDataStream>, String> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;

    let path_str = file_path.to_string_lossy().to_string();
    let mut wide_path: Vec<u16> = file_path.as_os_str().encode_wide().collect();
    wide_path.push(0); // Null terminator

    let mut stream_data = WIN32_FIND_STREAM_DATA::default();
    let handle = unsafe {
        FindFirstStreamW(
            wide_path.as_ptr(),
            0, // FindStreamInfoStandard
            &mut stream_data as *mut _ as *mut c_void,
            0,
        )
    };

    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Ok(Vec::new());
    }

    let mut streams = Vec::new();

    loop {
        // Convert stream name from wide char array
        let mut len = 0;
        while len < stream_data.cStreamName.len() && stream_data.cStreamName[len] != 0 {
            len += 1;
        }
        let stream_name = String::from_utf16_lossy(&stream_data.cStreamName[..len]);

        // Exclude default primary unnamed data stream "::$DATA"
        if stream_name != "::$DATA" && !stream_name.is_empty() {
            let (is_suspicious, tags, description) = classify_stream(&stream_name);
            let full_stream_path = format!("{}{}", path_str, stream_name);

            streams.push(AlternateDataStream {
                parent_file: path_str.clone(),
                stream_name: stream_name.clone(),
                full_stream_path,
                size_bytes: stream_data.StreamSize as u64,
                is_suspicious,
                threat_tags: tags,
                mitre_attack: "T1564.004".to_string(),
                description,
            });
        }

        let next = unsafe {
            FindNextStreamW(
                handle,
                &mut stream_data as *mut _ as *mut c_void,
            )
        };

        if next == 0 {
            break;
        }
    }

    unsafe {
        FindClose(handle);
    }

    Ok(streams)
}

/// Fallback for non-Windows platforms.
#[cfg(not(windows))]
pub fn enumerate_streams(_file_path: &Path) -> Result<Vec<AlternateDataStream>, String> {
    Ok(Vec::new())
}

/// Recursively scan a directory for Alternate Data Streams.
pub fn scan_directory_streams(dir: &Path, recursive: bool) -> Vec<AlternateDataStream> {
    let mut results = Vec::new();
    if !dir.exists() {
        return results;
    }

    if dir.is_file() {
        if let Ok(streams) = enumerate_streams(dir) {
            results.extend(streams);
        }
        return results;
    }

    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return results,
    };

    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Ok(streams) = enumerate_streams(&path) {
                results.extend(streams);
            }
        } else if recursive && path.is_dir() {
            let mut sub = scan_directory_streams(&path, recursive);
            results.append(&mut sub);
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_motw_stream() {
        let (is_susp, tags, desc) = classify_stream(":Zone.Identifier:$DATA");
        assert!(!is_susp);
        assert!(tags.contains(&"MOTW".to_string()));
        assert!(desc.contains("Mark-of-the-Web"));
    }

    #[test]
    fn test_classify_suspicious_payload_streams() {
        let (is_susp, tags, desc) = classify_stream(":payload.exe:$DATA");
        assert!(is_susp);
        assert!(tags.iter().any(|t| t.contains("EXEC-exe")));
        assert!(tags.iter().any(|t| t.contains("MALWARE-PAYLOAD")));
        assert!(desc.contains("T1564.004"));

        let (is_susp2, tags2, _) = classify_stream(":beacon.ps1:$DATA");
        assert!(is_susp2);
        assert!(tags2.iter().any(|t| t.contains("ps1")));
    }

    #[cfg(windows)]
    #[test]
    fn test_live_ads_creation_and_enumeration() {
        use std::fs::File;
        use std::io::Write;

        let temp_dir = std::env::temp_dir();
        let host_file = temp_dir.join("carve_ads_test_host.txt");
        {
            let mut f = File::create(&host_file).unwrap();
            f.write_all(b"harmless document content").unwrap();
        }

        // On Windows NTFS, writing to file:stream writes an ADS!
        let stream_path = format!("{}:dropper.vbs", host_file.display());
        let _ = std::fs::write(&stream_path, b"WScript.Echo \"Injected\"");

        let streams = enumerate_streams(&host_file).expect("Failed to enumerate streams");
        let _ = std::fs::remove_file(&host_file);

        let dropper = streams.iter().find(|s| s.stream_name.contains("dropper.vbs"));
        assert!(dropper.is_some(), "Expected to detect dropper.vbs ADS");
        let d = dropper.unwrap();
        assert!(d.is_suspicious);
        assert_eq!(d.mitre_attack, "T1564.004");
    }
}
