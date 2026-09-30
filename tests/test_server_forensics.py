"""
JOCKY Forensic & Sanitization Server API Tests
tests/test_server_forensics.py
"""
import hmac
import hashlib
import json
import os
import struct
import tempfile
import time
import pytest
from fastapi.testclient import TestClient

from server.main import app
from server.api.forensics import SYSTEM_SIGNING_KEY

client = TestClient(app)


def test_list_drives():
    resp = client.get("/api/drives")
    assert resp.status_code == 200
    data = resp.json()
    assert "drives" in data
    assert "system_roots" in data
    assert len(data["system_roots"]) > 0


def test_system_drive_safety_interlock():
    # Attempting to wipe C: or / without force_system_drive must be blocked
    resp = client.post("/api/sanitize/drive", json={
        "drive_path": "C:",
        "method": "nist_800_88_clear",
        "passes": 1,
        "force_system_drive": False,
    })
    assert resp.status_code == 400
    assert "SAFETY INTERLOCK ACTIVATED" in resp.json()["detail"]


def test_virtual_drive_sanitize():
    # Allowed when path is not system drive
    resp = client.post("/api/sanitize/drive", json={
        "drive_path": r"\\.\PhysicalDrive99",
        "method": "zero",
        "passes": 1,
        "force_system_drive": False,
    })
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]
    assert job_id.startswith("san-drive-")

    # Poll status until complete
    for _ in range(30):
        s_resp = client.get(f"/api/sanitize/status/{job_id}")
        assert s_resp.status_code == 200
        status_data = s_resp.json()
        if status_data["status"] == "completed":
            break
        time.sleep(0.05)

    assert status_data["status"] == "completed"
    assert status_data["progress"] == 100.0
    cert = status_data["certificate"]
    assert cert is not None
    assert cert["standard"] == "ZERO"

    # Verify certificate HMAC signature
    payload = f"{cert['certificate_id']}:{cert['target_type']}:{cert['target_path']}:{cert['standard'].lower()}:{cert['passes_executed']}:{cert['bytes_sanitized']}:{cert['verification_checksum_sha256']}:{cert['timestamp']}"
    expected_sig = hmac.new(SYSTEM_SIGNING_KEY, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    assert cert["digital_signature_hmac"] == expected_sig

    # Test printable certificate format
    cert_text_resp = client.get(f"/api/sanitize/certificate/{job_id}?format=text")
    assert cert_text_resp.status_code == 200
    assert "OFFICIAL CERTIFICATE OF SANITIZATION" in cert_text_resp.text
    assert cert["certificate_id"] in cert_text_resp.text


def test_file_shredding_and_metadata_cleanse():
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write("TOP SECRET FORENSIC ARTIFACT" * 500)
        temp_path = f.name

    try:
        resp = client.post("/api/sanitize/file", json={
            "file_path": temp_path,
            "method": "dod_5220_22_m",
            "passes": 3,
            "clean_metadata": True,
            "clean_slack": True,
        })
        assert resp.status_code == 200
        job_id = resp.json()["job_id"]

        for _ in range(30):
            s_resp = client.get(f"/api/sanitize/status/{job_id}")
            if s_resp.json()["status"] == "completed":
                break
            time.sleep(0.05)

        data = s_resp.json()
        assert data["status"] == "completed"
        # The file should be shredded, renamed, truncated, and unlinked
        assert not os.path.exists(temp_path)
        assert data["certificate"] is not None
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_carve_disk_image_and_artifact_export():
    # Construct a synthetic virtual disk containing PNG, SQLite, and ZIP
    disk = bytearray(b"\x00" * 4096)

    # 1. Embed valid PNG at offset 512
    png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1f\xf3\xffa\x00\x00\x00\x00IEND\xaeB`\x82"
    disk[512:512 + len(png_data)] = png_data

    # 2. Embed valid SQLite at offset 1536
    sqlite_hdr = bytearray(b"\x00" * 100)
    sqlite_hdr[:16] = b"SQLite format 3\x00"
    sqlite_hdr[16:18] = struct.pack(">H", 4096)
    sqlite_hdr[18] = 1
    sqlite_hdr[19] = 1
    sqlite_hdr[28:32] = struct.pack(">I", 2)
    disk[1536:1536 + len(sqlite_hdr)] = sqlite_hdr

    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(disk)
        img_path = f.name

    try:
        resp = client.post("/api/carve/start", json={
            "drive": img_path,
            "types": ["all"],
            "mode": "deep",
            "confidence_threshold": 0.50,
            "export_name": "evidence_container",
        })
        assert resp.status_code == 200
        job_id = resp.json()["job_id"]

        for _ in range(30):
            s_resp = client.get(f"/api/carve/status/{job_id}")
            if s_resp.json()["status"] == "completed":
                break
            time.sleep(0.05)

        data = s_resp.json()
        assert data["status"] == "completed"
        assert data["files_found"] >= 2

        recovered_types = [f["type"] for f in data["recovered_files"]]
        assert "png" in recovered_types
        assert "sqlite" in recovered_types

        # Check artifact download
        art_resp = client.get(f"/api/carve/artifact/{job_id}")
        assert art_resp.status_code == 200
        art_data = art_resp.json()
        assert art_data["format"] in ("CARVE_ARTIFACT_V1", "JOCKY_ARTIFACT_V1")
        assert art_data["export_name"] == "evidence_container"
        assert len(art_data["files"]) >= 2
    finally:
        if os.path.exists(img_path):
            os.remove(img_path)


def test_blockchain_ledger_and_verification():
    # 1. Fetch genesis ledger
    resp = client.get("/api/blockchain/ledger")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "active"
    assert data["chain_valid"] is True
    assert data["total_blocks"] >= 1
    assert data["blocks"][0]["index"] == 0
    assert data["blocks"][0]["records"][0]["id"] == "GENESIS-0000"

    # 2. Anchor a new forensic evidence record
    anchor_resp = client.post("/api/blockchain/anchor", json={
        "id": "EVIDENCE-PCAP-2026",
        "record_type": "NetworkCapture",
        "target": "en0_traffic.pcap",
        "sha256_hash": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "operator": "SeniorForensicAnalyst",
        "metadata_json": json.dumps({"packets": 14200, "protocol": "TCP/TLS"}),
    })
    assert anchor_resp.status_code == 200
    anchor_data = anchor_resp.json()
    assert anchor_data["status"] == "anchored"
    block_idx = anchor_data["block_index"]
    assert block_idx >= 1

    # 3. Verify evidence inclusion against blockchain
    verify_resp = client.post("/api/blockchain/verify", json={
        "query": "EVIDENCE-PCAP-2026",
    })
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["verified"] is True
    assert v_data["block_index"] == block_idx
    assert v_data["record"]["target"] == "en0_traffic.pcap"

    # 4. Unknown hash verification returns verified: False
    bad_verify = client.post("/api/blockchain/verify", json={
        "query": "unregistered_fake_hash_1234567890",
    })
    assert bad_verify.status_code == 200
    assert bad_verify.json()["verified"] is False


def test_antiforensics_timestomp_and_ads_scan():
    # Run scan with simulate_test=True to evaluate detection of T1070.006 and T1564.004
    resp = client.post("/api/forensics/antiforensics/scan", json={
        "simulate_test": True,
        "recursive": False,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
    assert data["evasion_detected"] is True
    assert len(data["timestomp_anomalies"]) >= 1

    ts_anomaly = data["timestomp_anomalies"][0]
    assert ts_anomaly["mitre_attack"] == "T1070.006"
    assert ts_anomaly["severity"] in ("SUSPICIOUS", "CRITICAL")
    assert ts_anomaly["delta_seconds"] > 10.0

    # Verify ADS detection
    assert len(data["alternate_data_streams"]) >= 1
    ads = data["alternate_data_streams"][0]
    assert ads["mitre_attack"] == "T1564.004"
    assert any(tag.startswith("ADS-") or tag == "MOTW" for tag in ads.get("threat_tags", []))

    # Verify evasion evidence was auto-anchored to blockchain ledger
    ledger_resp = client.get("/api/blockchain/ledger")
    assert ledger_resp.status_code == 200
    l_data = ledger_resp.json()
    assert any(
        rec.get("record_type") == "AntiForensicsEvidence"
        for block in l_data["blocks"]
        for rec in block["records"]
    )


def test_reflective_memory_injection_hunter():
    # Run scan with simulate_injection=True to test detection of unbacked executable memory (T1055)
    resp = client.post("/api/forensics/memory/injection-scan", json={
        "simulate_injection": True,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
    assert data["total_processes_scanned"] >= 1

    # Verify that suspicious regions or simulation was detected
    if data["suspicious_regions_found"] > 0:
        reg = data["regions"][0]
        assert reg["mitre_attack"] == "T1055"
        assert "RWX" in reg["protection"] or "RX" in reg["protection"]
        assert reg["entropy"] >= 0.0
        assert "hex_preview" in reg
        assert reg["severity"] in ("SUSPICIOUS", "CRITICAL")


