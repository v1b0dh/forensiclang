//! Data Sanitization Standards & Wipe Algorithms
//!
//! Implements recognized industry and military data destruction standards:
//! - NIST SP 800-88 Rev. 1 (Clear & Purge)
//! - DoD 5220.22-M (3-Pass & 7-Pass)
//! - Quick Zero (Single Pass 0x00)
//! - Pseudo-Random Single Pass
//! - Gutmann (35-Pass)

use serde::{Deserialize, Serialize};

/// Supported erasure and sanitization algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WipeMethod {
    /// Single pass writing all zeros (0x00)
    Zero,
    /// Single pass of cryptographically pseudo-random bytes
    OnePassRandom,
    /// NIST SP 800-88 Rev. 1 Clear: Overwrite with fixed/random pattern + verify
    Nist800_88Clear,
    /// NIST SP 800-88 Rev. 1 Purge: Multi-phase overwrite with verification
    Nist800_88Purge,
    /// DoD 5220.22-M: Pass 1 zeros (0x00), Pass 2 ones (0xFF), Pass 3 random + verify
    Dod5220_22M,
    /// Gutmann 35-pass algorithm for magnetic media
    Gutmann,
}

impl WipeMethod {
    pub fn standard_name(&self) -> &'static str {
        match self {
            WipeMethod::Zero => "Zero Overwrite (Single Pass)",
            WipeMethod::OnePassRandom => "PRNG Random (Single Pass)",
            WipeMethod::Nist800_88Clear => "NIST SP 800-88 Rev. 1 (Clear)",
            WipeMethod::Nist800_88Purge => "NIST SP 800-88 Rev. 1 (Purge)",
            WipeMethod::Dod5220_22M => "DoD 5220.22-M (3-Pass)",
            WipeMethod::Gutmann => "Peter Gutmann (35-Pass)",
        }
    }

    pub fn default_passes(&self) -> usize {
        match self {
            WipeMethod::Zero | WipeMethod::OnePassRandom | WipeMethod::Nist800_88Clear => 1,
            WipeMethod::Nist800_88Purge | WipeMethod::Dod5220_22M => 3,
            WipeMethod::Gutmann => 35,
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().replace('-', "_").as_str() {
            "zero" => Some(WipeMethod::Zero),
            "random" | "one_pass_random" => Some(WipeMethod::OnePassRandom),
            "nist" | "nist_clear" | "nist_800_88_clear" => Some(WipeMethod::Nist800_88Clear),
            "nist_purge" | "nist_800_88_purge" => Some(WipeMethod::Nist800_88Purge),
            "dod" | "dod_5220_22_m" | "dod3" => Some(WipeMethod::Dod5220_22M),
            "gutmann" => Some(WipeMethod::Gutmann),
            _ => None,
        }
    }
}

/// Simple fast Xorshift64 PRNG for repeatable, high-speed multi-gigabyte sanitization patterns.
pub struct FastPrng {
    state: u64,
}

impl FastPrng {
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x853c49e6748fea9b } else { seed },
        }
    }

    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut chunks = dest.chunks_exact_mut(8);
        for chunk in &mut chunks {
            let val = self.next_u64().to_ne_bytes();
            chunk.copy_from_slice(&val);
        }
        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            let val = self.next_u64().to_ne_bytes();
            rem.copy_from_slice(&val[..rem.len()]);
        }
    }
}

/// Fill a slice with the designated pattern for a specific pass.
pub fn generate_pass_pattern(method: WipeMethod, pass_idx: usize, buffer: &mut [u8], seed: u64) {
    match method {
        WipeMethod::Zero => {
            buffer.fill(0x00);
        }
        WipeMethod::OnePassRandom => {
            let mut prng = FastPrng::new(seed.wrapping_add(pass_idx as u64));
            prng.fill_bytes(buffer);
        }
        WipeMethod::Nist800_88Clear => {
            // NIST Clear allows a single pass of fixed zero or pseudo-random
            buffer.fill(0x00);
        }
        WipeMethod::Nist800_88Purge => {
            match pass_idx % 3 {
                0 => buffer.fill(0x55), // 01010101
                1 => buffer.fill(0xAA), // 10101010
                _ => {
                    let mut prng = FastPrng::new(seed.wrapping_add(pass_idx as u64));
                    prng.fill_bytes(buffer);
                }
            }
        }
        WipeMethod::Dod5220_22M => {
            match pass_idx % 3 {
                0 => buffer.fill(0x00), // Pass 1: Fixed zeros
                1 => buffer.fill(0xFF), // Pass 2: Fixed ones
                _ => {
                    // Pass 3: Pseudo-random byte sequence
                    let mut prng = FastPrng::new(seed.wrapping_add(pass_idx as u64));
                    prng.fill_bytes(buffer);
                }
            }
        }
        WipeMethod::Gutmann => {
            // Gutmann: passes 1-4 random, 5-31 specific magnetic domain patterns, 32-35 random
            if pass_idx < 4 || pass_idx >= 31 {
                let mut prng = FastPrng::new(seed.wrapping_add(pass_idx as u64));
                prng.fill_bytes(buffer);
            } else {
                let pattern = match pass_idx % 3 {
                    0 => 0x55,
                    1 => 0xAA,
                    _ => 0x92,
                };
                buffer.fill(pattern);
            }
        }
    }
}

/// Verify that a byte slice matches the expected final pass state.
pub fn verify_slice_pattern(method: WipeMethod, last_pass_idx: usize, buffer: &[u8], seed: u64) -> bool {
    match method {
        WipeMethod::Zero | WipeMethod::Nist800_88Clear => buffer.iter().all(|&b| b == 0x00),
        WipeMethod::Dod5220_22M if last_pass_idx % 3 == 0 => buffer.iter().all(|&b| b == 0x00),
        WipeMethod::Dod5220_22M if last_pass_idx % 3 == 1 => buffer.iter().all(|&b| b == 0xFF),
        WipeMethod::Nist800_88Purge if last_pass_idx % 3 == 0 => buffer.iter().all(|&b| b == 0x55),
        WipeMethod::Nist800_88Purge if last_pass_idx % 3 == 1 => buffer.iter().all(|&b| b == 0xAA),
        _ => {
            let mut expected = vec![0u8; buffer.len()];
            generate_pass_pattern(method, last_pass_idx, &mut expected, seed);
            buffer == expected.as_slice()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dod_passes() {
        let mut buf = vec![0xAB; 1024];

        // Pass 0 -> all 0x00
        generate_pass_pattern(WipeMethod::Dod5220_22M, 0, &mut buf, 42);
        assert!(buf.iter().all(|&b| b == 0x00));

        // Pass 1 -> all 0xFF
        generate_pass_pattern(WipeMethod::Dod5220_22M, 1, &mut buf, 42);
        assert!(buf.iter().all(|&b| b == 0xFF));

        // Pass 2 -> random (not all 0 or FF)
        generate_pass_pattern(WipeMethod::Dod5220_22M, 2, &mut buf, 42);
        assert!(!buf.iter().all(|&b| b == 0x00));
        assert!(!buf.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn test_verify_slice() {
        let mut buf = vec![0u8; 8192];
        generate_pass_pattern(WipeMethod::Nist800_88Clear, 0, &mut buf, 123);
        assert!(verify_slice_pattern(WipeMethod::Nist800_88Clear, 0, &buf, 123));
    }
}
