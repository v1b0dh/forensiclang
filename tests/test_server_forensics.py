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
        assert art_data["format"] == "JOCKY_ARTIFACT_V1"
        assert art_data["export_name"] == "evidence_container"
        assert len(art_data["files"]) >= 2
    finally:
        if os.path.exists(img_path):
            os.remove(img_path)
