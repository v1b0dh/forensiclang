# CARVE — Carving, Auditing, Recovery, and Verification Engine

A high-performance domain-specific language (DSL) and forensic platform integrating certified storage sanitization, deep file carving, evidence acquisition, and incident response automation.

```
   ██████╗ █████╗ ██████╗ ██╗   ██╗███████╗
  ██╔════╝██╔══██╗██╔══██╗██║   ██║██╔════╝
  ██║     ███████║██████╔╝██║   ██║█████╗  
  ██║     ██╔══██║██╔══██╗╚██╗ ██╔╝██╔══╝  
  ╚██████╗██║  ██║██║  ██║ ╚████╔╝ ███████╗
   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝
  Carving, Auditing, Recovery, and Verification Engine
```

---

## Architecture Overview

```
carve/
├── crates/
│   ├── carve-compiler/    ← Native Rust AST parser (Pest grammar) & CLI (carvec)
│   └── carve-runtime/     ← Systems engine: DoD/NIST sanitization, cluster slack scrub,
│                            magic byte carving & validation, MFT parser, Win32 I/O
├── compiler/              ← ANTLR4 grammar + Python LLVM IR compiler
│   ├── carvec.py          ← Primary compiler driver (emits LLVM IR & native binaries)
│   ├── Jocky.g4           ← ANTLR4 language grammar
│   ├── ast/               ← AST node definitions & typed parse tree builder
│   └── ir/                ← Multi-target LLVM IR code generator (llvmlite)
├── runtime/               ← C forensic modules (read-only OS telemetry & live capture)
│   ├── modules/           ← Memory, raw disk, pcap network, and artifact serializers
│   └── agent/             ← Authenticated TLS agent (Fernet encryption + cert pinning)
├── server/                ← FastAPI management server (WebSocket dispatch & DB storage)
├── dashboard/             ← React + Vite forensic analyst dashboard
├── stdlib/carve/          ← Standard forensic & sanitization playbooks (.crv)
├── tests/                 ← Comprehensive pytest and cargo test suites
└── ci/build.yml           ← Multi-platform CI pipeline
```

---

## Core Capabilities

1. **Certified Storage Sanitization**
   - **NIST SP 800-88 Rev. 1** (*Clear* / *Purge*) & **DoD 5220.22-M** (3-pass overwrite).
   - **Hardware Safety Interlock**: Automatically identifies OS boot volumes (`\\.\C:`, `PhysicalDrive0`) and refuses destruction without explicit administrative bypass.
   - **Residual Data Scrubbing**: Overwrites `$MFT` record names/metadata and zeroes unallocated cluster slack space.
   - **Cryptographic Destruction Certificates**: Generates SHA-256 / HMAC-signed verification records.

2. **Advanced Forensic File Carving**
   - **Multi-Format Extraction**: Carves PDF, PNG, JPEG, SQLite, ZIP, Office (DOCX/XLSX), PCAP, and PE binaries.
   - **Structure Validation**: Validates database headers, page integrity, deflate blocks, and PNG chunk CRC32 checksums.
   - **Confidence Scoring & Sector Mapping**: Live visual density heatmaps isolate corrupted fragments from intact files.

3. **Domain-Specific Language (CARVE DSL)**
   - Declarative, human-readable forensic playbooks (`.crv` files).
   - Compiles down to native machine code via LLVM IR.

---

## Quick Start

### 1. Compile & Inspect a Playbook

#### Using Native Rust Compiler (`carvec`):
```powershell
# Syntax validation only:
cargo run -p carve-compiler -- stdlib/carve/sanitization_and_recovery.crv --check

# Dump full Abstract Syntax Tree as JSON:
cargo run -p carve-compiler -- stdlib/carve/sanitization_and_recovery.crv --ast
```

#### Using Python / LLVM Compiler (`carvec.py`):
```powershell
# Generate optimized LLVM IR:
python compiler/carvec.py stdlib/carve/sanitization_and_recovery.crv --ir-only
```

---

### 2. Start the Management Server
```powershell
uvicorn server.main:app --reload --port 8000
```
- API & WebSocket Server: `http://127.0.0.1:8000`
- Interactive API Docs: `http://127.0.0.1:8000/docs`

---

### 3. Launch the Analyst Dashboard
```powershell
cd dashboard
npm run dev
```
- Web UI: `http://127.0.0.1:5173/`

---

## Example CARVE Script (`.crv`)

```carve
// Certified Drive Sanitization & Verification Playbook

function certified_drive_wipe(drive_path, audit_log, cert_file) {
  erase drive drive_path
    method nist_800_88_clear
    passes 1
    clean_metadata true
    clean_slack true
    audit audit_log
    certificate cert_file
}

function verify_zero_residual_carve(drive_path, artifact_out) {
  carve disk from drive drive_path
    types [all]
    mode deep
    confidence_threshold 0.50
    export to artifact artifact_out
}

function full_media_disposal_cycle(drive_path) {
  certified_drive_wipe(drive_path, "disposal_audit.json", "destruction_cert.pdf")
  verify_zero_residual_carve(drive_path, "post_wipe_evidence")
  report "disposal_audit" as "compliance_report.html" format html
}
```

---

## Testing

```powershell
# Run all Python compiler & server tests:
python -m pytest tests/ -v

# Run all Rust compiler & runtime tests:
cargo test --workspace
```
