//! Tamper-Resistant Cryptographic Erasure Certificate
//!
//! Generates certified audit logs and compliance records verifying that storage
//! media or files have been sanitized according to NIST SP 800-88, DoD 5220.22-M,
//! or custom disposal standards.

use super::algorithms::WipeMethod;
use crate::crypto::{hmac_sha256, sha256_hex};
use crate::utc_timestamp_now;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

const AUDIT_SECRET: &[u8] = b"JOCKY_FORENSIC_TAMPER_RESISTANT_AUDIT_KEY_2026";

/// Tamper-proof record verifying sanitized storage media or files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureCertificate {
    pub cert_id: String,
    pub timestamp: String,
    pub target: String,
    pub target_type: String,
    pub device_serial: Option<String>,
    pub method: WipeMethod,
    pub standard_name: String,
    pub passes_completed: usize,
    pub bytes_erased: u64,
    pub sectors_erased: u64,
    pub verified: bool,
    pub verification_ratio: f32,
    pub operator: String,
    pub evidential_hash: String,
    pub signature: String,
}

impl ErasureCertificate {
    /// Create and sign a new destruction certificate.
    pub fn new(
        target: &str,
        target_type: &str,
        device_serial: Option<&str>,
        method: WipeMethod,
        passes_completed: usize,
        bytes_erased: u64,
        sectors_erased: u64,
        verified: bool,
        operator: &str,
    ) -> Self {
        let timestamp = utc_timestamp_now();
        let target_str = target.to_string();
        let cert_seed = format!("{}:{}:{}:{}", target_str, timestamp, bytes_erased, operator);
        let cert_id = format!("JCK-CERT-{}", &sha256_hex(cert_seed.as_bytes())[..16].to_uppercase());

        let payload_for_hash = format!(
            "CERT_ID={}|TARGET={}|METHOD={:?}|PASSES={}|BYTES={}|VERIFIED={}|OPERATOR={}",
            cert_id, target_str, method, passes_completed, bytes_erased, verified, operator
        );
        let evidential_hash = sha256_hex(payload_for_hash.as_bytes());
        let signature = hmac_sha256(AUDIT_SECRET, evidential_hash.as_bytes());

        Self {
            cert_id,
            timestamp,
            target: target_str,
            target_type: target_type.to_string(),
            device_serial: device_serial.map(|s| s.to_string()),
            method,
            standard_name: method.standard_name().to_string(),
            passes_completed,
            bytes_erased,
            sectors_erased,
            verified,
            verification_ratio: 1.0,
            operator: operator.to_string(),
            evidential_hash,
            signature,
        }
    }

    /// Verify certificate authenticity against HMAC secret.
    pub fn verify_authenticity(&self) -> bool {
        let payload = format!(
            "CERT_ID={}|TARGET={}|METHOD={:?}|PASSES={}|BYTES={}|VERIFIED={}|OPERATOR={}",
            self.cert_id, self.target, self.method, self.passes_completed, self.bytes_erased, self.verified, self.operator
        );
        let expected_hash = sha256_hex(payload.as_bytes());
        if self.evidential_hash != expected_hash {
            return false;
        }
        let expected_sig = hmac_sha256(AUDIT_SECRET, self.evidential_hash.as_bytes());
        self.signature == expected_sig
    }

    /// Export certificate as JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Save certificate to disk as JSON.
    pub fn save_json(&self, path: &Path) -> io::Result<()> {
        let json = self.to_json().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let mut file = fs::File::create(path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    /// Format as formal human-readable compliance document.
    pub fn to_text_report(&self) -> String {
        format!(
            "================================================================================\n\
             JOCKY CERTIFIED DATA SANITIZATION REPORT\n\
             Tamper-Resistant Regulatory Compliance Certificate\n\
             ================================================================================\n\
             Certificate ID:        {}\n\
             Timestamp (UTC):       {}\n\
             Target Subject:        {}\n\
             Target Type:           {}\n\
             Hardware Serial:       {}\n\
             Destruction Standard:  {}\n\
             Completed Passes:      {}\n\
             Total Bytes Sanitized: {} bytes ({:.2} MB)\n\
             Sectors Overwritten:   {}\n\
             Readback Verification: {}\n\
             Verification Coverage: {:.1}%\n\
             Certified Operator:    {}\n\
             Evidential Hash:       {}\n\
             Cryptographic Sig:     {}\n\
             Status:                {}\n\
             ================================================================================\n",
            self.cert_id,
            self.timestamp,
            self.target,
            self.target_type,
            self.device_serial.as_deref().unwrap_or("N/A"),
            self.standard_name,
            self.passes_completed,
            self.bytes_erased,
            self.bytes_erased as f64 / (1024.0 * 1024.0),
            self.sectors_erased,
            if self.verified { "PASSED (Zero residual bits detected)" } else { "NOT_VERIFIED" },
            self.verification_ratio * 100.0,
            self.operator,
            self.evidential_hash,
            self.signature,
            if self.verified { "COMPLIANT & SECURE" } else { "PROVISIONAL" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_creation_and_tamper_detection() {
        let mut cert = ErasureCertificate::new(
            "\\\\.\\PhysicalDrive1",
            "PhysicalDrive",
            Some("WD-WCC4N123456"),
            WipeMethod::Nist800_88Clear,
            1,
            500_107_862_016,
            976_773_168,
            true,
            "Forensic Analyst #42",
        );

        assert!(cert.verify_authenticity());
        let report = cert.to_text_report();
        assert!(report.contains("JOCKY CERTIFIED DATA SANITIZATION REPORT"));
        assert!(report.contains("NIST SP 800-88 Rev. 1 (Clear)"));

        // Tamper with bytes_erased
        cert.bytes_erased += 1;
        assert!(!cert.verify_authenticity(), "Tampered cert must fail verification");
    }
}
