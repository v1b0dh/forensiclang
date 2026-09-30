//! Real-Time "Carve & YARA" Threat Classification Engine
//!
//! Scans reconstructed file clusters and unallocated carving streams in real-time
//! to identify APT payloads, Cobalt Strike stagers, webshells, ransomware markers,
//! and weaponized macro scripts without requiring external dependencies.
//!
//! Note: Signatures are stored with a single-byte XOR mask (0xAA) to prevent
//! endpoint security solutions from misidentifying the scanner source code itself.

use serde::{Deserialize, Serialize};

/// Threat severity classification for carved artifacts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatLevel {
    Clean,
    Suspicious,
    Critical,
}

/// A matched threat detection signature rule
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreatMatch {
    pub rule_name: String,
    pub category: String,
    pub severity: ThreatLevel,
    pub description: String,
    pub offset: usize,
}

/// Threat assessment report for a carved file
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThreatAssessment {
    pub threat_level: ThreatLevel,
    pub risk_score: f32, // 0.0 (Clean) to 1.0 (Critical APT)
    pub matched_rules: Vec<ThreatMatch>,
}

/// Obfuscated signature definition (XOR 0xAA) to prevent false-positive AV triggers
struct SignatureDef {
    name: &'static str,
    category: &'static str,
    severity: ThreatLevel,
    enc_pattern: &'static [u8],
    description: &'static str,
    weight: f32,
}

const SIGNATURE_DB: &[SignatureDef] = &[
    SignatureDef {
        name: "WEBSHELL_EVAL_BASE64",
        category: "Webshell",
        severity: ThreatLevel::Critical,
        enc_pattern: &[0xcf, 0xdc, 0xcb, 0xc6, 0x82, 0xc8, 0xcb, 0xd9, 0xcf, 0x9c, 0x9e, 0xf5, 0xce, 0xcf, 0xc9, 0xc5, 0xce, 0xcf, 0x82],
        description: "Obfuscated PHP base64 evaluation payload",
        weight: 0.85,
    },
    SignatureDef {
        name: "WEBSHELL_GZINFLATE",
        category: "Webshell",
        severity: ThreatLevel::Critical,
        enc_pattern: &[0xcf, 0xdc, 0xcb, 0xc6, 0x82, 0xcd, 0xd0, 0xc3, 0xc4, 0xcc, 0xc6, 0xcb, 0xde, 0xcf, 0x82],
        description: "Compressed and obfuscated PHP dropper payload",
        weight: 0.90,
    },
    SignatureDef {
        name: "WEBSHELL_PASSTHRU",
        category: "Webshell",
        severity: ThreatLevel::Suspicious,
        enc_pattern: &[0xda, 0xcb, 0xd9, 0xd9, 0xde, 0xc2, 0xd8, 0xdf, 0x82, 0x8e, 0xf5, 0xfa, 0xe5, 0xf9, 0xfe, 0xf1],
        description: "Direct POST parameter command execution backdoor",
        weight: 0.75,
    },
    SignatureDef {
        name: "STAGER_COBALT_STRIKE",
        category: "C2_Beacon",
        severity: ThreatLevel::Critical,
        enc_pattern: &[0x8f, 0xd9, 0x8a, 0xcb, 0xd9, 0x8a, 0x8f, 0xd9, 0xf6, 0x8f, 0xd9, 0x90, 0x8a, 0x8f, 0xce],
        description: "Cobalt Strike beacon credential and pipe artifact",
        weight: 0.95,
    },
    SignatureDef {
        name: "REFLECTIVE_LOADER_STUB",
        category: "Loader",
        severity: ThreatLevel::Critical,
        enc_pattern: &[0xe7, 0xf0, 0x42, 0xaa, 0xaa, 0xaa, 0xaa, 0xf2],
        description: "PE reflective DLL injection call-pop stub",
        weight: 0.90,
    },
    SignatureDef {
        name: "RANSOMWARE_VSS_PURGE",
        category: "Ransomware",
        severity: ThreatLevel::Critical,
        enc_pattern: &[0xdc, 0xd9, 0xd9, 0xcb, 0xce, 0xc7, 0xc3, 0xc4, 0x8a, 0xce, 0xcf, 0xc6, 0xcf, 0xde, 0xcf, 0x8a, 0xd9, 0xc2, 0xcb, 0xce, 0xc5, 0xdd, 0xd9],
        description: "Volume Shadow Copy deletion indicator",
        weight: 0.95,
    },
    SignatureDef {
        name: "RANSOMWARE_WMIC_SHADOW",
        category: "Ransomware",
        severity: ThreatLevel::Critical,
        enc_pattern: &[0xdd, 0xc7, 0xc3, 0xc9, 0x8a, 0xd9, 0xc2, 0xcb, 0xce, 0xc5, 0xdd, 0xc9, 0xc5, 0xda, 0xd3, 0x8a, 0xce, 0xcf, 0xc6, 0xcf, 0xde, 0xcf],
        description: "WMI invocation destroying recovery snapshots",
        weight: 0.90,
    },
    SignatureDef {
        name: "VBA_AUTO_OPEN_EXEC",
        category: "WeaponizedDoc",
        severity: ThreatLevel::Suspicious,
        enc_pattern: &[0xf9, 0xdf, 0xc8, 0x8a, 0xeb, 0xdf, 0xde, 0xc5, 0xe5, 0xda, 0xcf, 0xc4, 0x82, 0x83],
        description: "Automatic macro execution entrypoint on document open",
        weight: 0.50,
    },
    SignatureDef {
        name: "VBA_WSCRIPT_SHELL",
        category: "WeaponizedDoc",
        severity: ThreatLevel::Critical,
        enc_pattern: &[0xfd, 0xf9, 0xc9, 0xd8, 0xc3, 0xda, 0xde, 0x84, 0xf9, 0xc2, 0xcf, 0xc6, 0xc6],
        description: "VBA instantiation of Windows Script Host shell execution",
        weight: 0.85,
    },
];

fn decode_pattern(enc: &[u8]) -> Vec<u8> {
    enc.iter().map(|b| b ^ 0xAA).collect()
}

/// Scan a buffer of carved bytes against the threat signature database
pub fn scan_carved_buffer(data: &[u8]) -> ThreatAssessment {
    let mut matches = Vec::new();
    let mut max_risk: f32 = 0.0;
    let mut has_critical = false;
    let mut has_suspicious = false;

    for sig in SIGNATURE_DB {
        let pattern = decode_pattern(sig.enc_pattern);
        if let Some(pos) = find_subsequence(data, &pattern) {
            matches.push(ThreatMatch {
                rule_name: sig.name.to_string(),
                category: sig.category.to_string(),
                severity: sig.severity.clone(),
                description: sig.description.to_string(),
                offset: pos,
            });

            if sig.weight > max_risk {
                max_risk = sig.weight;
            }

            match sig.severity {
                ThreatLevel::Critical => has_critical = true,
                ThreatLevel::Suspicious => has_suspicious = true,
                ThreatLevel::Clean => {}
            }
        }
    }

    let threat_level = if has_critical {
        ThreatLevel::Critical
    } else if has_suspicious {
        ThreatLevel::Suspicious
    } else {
        ThreatLevel::Clean
    };

    ThreatAssessment {
        threat_level,
        risk_score: max_risk,
        matched_rules: matches,
    }
}

/// Fast sliding-window byte search
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_buffer_scan() {
        let clean_pdf = b"%PDF-1.7 Normal financial report without malicious signatures %%EOF";
        let res = scan_carved_buffer(clean_pdf);
        assert_eq!(res.threat_level, ThreatLevel::Clean);
        assert_eq!(res.risk_score, 0.0);
        assert!(res.matched_rules.is_empty());
    }

    #[test]
    fn test_webshell_detection() {
        let mut carved_webshell = Vec::new();
        carved_webshell.extend_from_slice(b"<?php @");
        carved_webshell.extend(decode_pattern(&[0xcf, 0xdc, 0xcb, 0xc6, 0x82, 0xc8, 0xcb, 0xd9, 0xcf, 0x9c, 0x9e, 0xf5, 0xce, 0xcf, 0xc9, 0xc5, 0xce, 0xcf, 0x82]));
        carved_webshell.extend_from_slice(b"$_POST['cmd'])); ?>");

        let res = scan_carved_buffer(&carved_webshell);
        assert_eq!(res.threat_level, ThreatLevel::Critical);
        assert!(res.risk_score >= 0.85);
        assert_eq!(res.matched_rules[0].rule_name, "WEBSHELL_EVAL_BASE64");
    }

    #[test]
    fn test_ransomware_shadow_copy_detection() {
        let mut dropper_script = Vec::new();
        dropper_script.extend_from_slice(b"powershell.exe -Command \"");
        dropper_script.extend(decode_pattern(&[0xdc, 0xd9, 0xd9, 0xcb, 0xce, 0xc7, 0xc3, 0xc4, 0x8a, 0xce, 0xcf, 0xc6, 0xcf, 0xde, 0xcf, 0x8a, 0xd9, 0xc2, 0xcb, 0xce, 0xc5, 0xdd, 0xd9]));
        dropper_script.extend_from_slice(b" /all /quiet\"");

        let res = scan_carved_buffer(&dropper_script);
        assert_eq!(res.threat_level, ThreatLevel::Critical);
        assert_eq!(res.matched_rules[0].category, "Ransomware");
    }
}
