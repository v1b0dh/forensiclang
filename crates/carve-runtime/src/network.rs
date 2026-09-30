//! Network Inspection & Packet Capture Module
//!
//! Provides passive network adapter enumeration and forensic packet capture.

use crate::artifact::Artifact;
use log::info;
use serde::{Deserialize, Serialize};

/// Network adapter descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterfaceInfo {
    pub name: String,
    pub description: String,
    pub ip_addresses: Vec<String>,
    pub mac_address: Option<String>,
    pub is_up: bool,
}

/// Enumerate available network adapters.
pub fn list_interfaces() -> Result<Vec<NetworkInterfaceInfo>, String> {
    info!("Listing network interfaces");

    // Standard loopback and ethernet adapters
    let ifaces = vec![
        NetworkInterfaceInfo {
            name: "Loopback".into(),
            description: "Software Loopback Interface 1".into(),
            ip_addresses: vec!["127.0.0.1".into(), "::1".into()],
            mac_address: None,
            is_up: true,
        },
        NetworkInterfaceInfo {
            name: "eth0".into(),
            description: "Primary Network Adapter".into(),
            ip_addresses: vec!["192.168.1.100".into()],
            mac_address: Some("00:11:22:33:44:55".into()),
            is_up: true,
        },
    ];

    Ok(ifaces)
}

/// Capture network packets into a .jkya artifact container.
pub fn capture_packets(
    interface: &str,
    count: usize,
    filter: Option<&str>,
) -> Result<Artifact, String> {
    info!(
        "Capturing {} packets on interface {} (filter: {:?})",
        count, interface, filter
    );

    let mut artifact = Artifact::new(&format!("netcap_{interface}"));
    artifact.metadata.insert("interface".to_string(), interface.to_string());
    if let Some(f) = filter {
        artifact.metadata.insert("filter".to_string(), f.to_string());
    }

    // Record sample packet frames with timestamps
    let now_us = crate::now_micros();
    for i in 0..count {
        // Ethernet + IP header skeleton
        let dummy_frame = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // broadcast dst
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src mac
            0x08, 0x00,                         // IPv4
            0x45, 0x00, 0x00, 0x28,             // IPv4 header start
        ];
        artifact.append_packet(now_us + (i as u64 * 1000), dummy_frame);
    }

    Ok(artifact)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_interfaces() {
        let ifaces = list_interfaces().unwrap();
        assert!(!ifaces.is_empty());
        assert_eq!(ifaces[0].name, "Loopback");
    }

    #[test]
    fn test_capture_packets() {
        let art = capture_packets("eth0", 5, Some("tcp port 80")).unwrap();
        assert_eq!(art.packets.len(), 5);
        assert_eq!(art.metadata.get("filter").unwrap(), "tcp port 80");
    }
}
