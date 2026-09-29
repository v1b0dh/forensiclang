//! Data Sanitization & Destruction Engine
//!
//! Provides certified data wiping for whole drives, files, folders, and slack space
//! conforming to NIST SP 800-88 Rev. 1, DoD 5220.22-M, and cryptographic audit logging.

pub mod algorithms;
pub mod cert;
pub mod drive;
pub mod file_shredder;
pub mod slack;

pub use algorithms::WipeMethod;
pub use cert::ErasureCertificate;
pub use drive::{is_system_drive, sanitize_drive, DriveEraseOptions};
pub use file_shredder::{shred_file, shred_folder};
pub use slack::wipe_file_slack;
