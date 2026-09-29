# JOCKY Language Guide & Reference Manual

Welcome to **JOCKY** — a compiled, domain-specific programming language (DSL) engineered specifically for **Digital Forensics and Incident Response (DFIR)**.

JOCKY replaces hundreds of lines of fragile forensic scripts and OS API boilerplate with expressive, first-class statements designed to collect, correlate, timeline, and report forensic evidence across Windows and Linux systems.

---

## Table of Contents
1. [Language Basics](#1-language-basics)
2. [Forensic Statements](#2-forensic-statements)
   - [`collect`](#collect)
   - [`scan`](#scan)
   - [`carve`](#carve)
   - [`erase`](#erase)
   - [`timeline`](#timeline)
   - [`correlate`](#correlate)
   - [`analyze`](#analyze)
   - [`report`](#report)
3. [Control Flow & Functions](#3-control-flow--functions)
4. [Standard Library & Example Scripts](#4-standard-library--example-scripts)
5. [Compiling & Running JOCKY Scripts](#5-compiling--running-jocky-scripts)
   - [Using the Rust Compiler (`jockc`)](#using-the-rust-compiler-jockc)
   - [Using the Python / LLVM Compiler (`jockc.py`)](#using-the-python--llvm-compiler-jockcpy)
6. [Forensic Artifact Format (`.jkya`)](#6-forensic-artifact-format-jkya)
7. [Server REST API & Dashboard](#7-server-rest-api--dashboard)

---

## 1. Language Basics

JOCKY source files use the `.jky` extension. The language uses C-style curly braces for blocks, supports standard arithmetic and boolean logic, and treats forensic operations as native language statements.

### Comments
```jocky
// This is a single-line comment

/*
   This is a multi-line
   forensic investigation note
*/
```

### Variables & Types
JOCKY supports strings, numbers (integers and floats), booleans, and identifier references:
```jocky
target_host = "WORKSTATION-09";
target_pid = 4128;
anomaly_threshold = 0.85;
is_active = true;
```

---

## 2. Forensic Statements

### `collect`
Acquires volatile and non-volatile evidence safely using read-only OS operations.

#### Syntax:
```jocky
collect <target> [from <source>] [using <plugin>] [where <filters>] [export <artifact_name>];
```

- **Supported Targets**: `memory`, `disk`, `registry`, `artifacts`
- **Supported Sources**: `pid <number>`, `host <string>`, or variable identifiers

#### Examples:
```jocky
// Snapshot memory regions of a target process
collect memory from pid 1337 using win32 where protection != "PAGE_NOACCESS" export "proc_1337.mem";

// Collect disk metadata via Volume Shadow Copy (VSS)
collect disk from host "SERVER-01" export "c_drive.vss";

// Acquire registry hives
collect registry from host "WORKSTATION-01" export "system_hives";
```

---

### `scan`
Enumerates active system state, including running processes, open network interfaces, listening sockets, and loaded drivers.

#### Syntax:
```jocky
scan <target> [on interface <interface_name>] [where <filter_condition>];
```

- **Supported Targets**: `processes`, `network_interfaces`, `open_ports`, `loaded_modules`

#### Examples:
```jocky
// Scan all running processes
scan processes;

// Passive network packet capture on a specific adapter
scan network_interfaces on interface "eth0" where port == 443;
```

---

### `carve`
Performs deep forensic-grade file carving directly from raw physical disks, unallocated clusters, or forensic disk images (`.raw`, `.dd`, `.img`).

Unlike simple header-matching tools, JOCKY's carving engine performs **deep structural validation** (e.g. PNG chunk streams, SQLite page allocators, JPEG markers, ZIP central directories) and computes a calibrated **confidence score** ($0.00 - 1.00$) to eliminate corrupt false positives.

#### Syntax:
```jocky
carve disk from drive <target_path>
    [types [<type1>, <type2>, ...]]
    [mode <quick | deep | fragmented>]
    [confidence_threshold <score>]
    [export [to artifact] <artifact_name>]
```

- **Supported Formats**:
  - Documents: `pdf`, `docx`, `xlsx`, `pptx`, `office`
  - Images: `png`, `jpg`, `jpeg`, `gif`
  - Databases: `sqlite`
  - Network Captures: `pcap`
  - Executables: `pe` (`exe`, `dll`), `elf`
  - All Formats: `all`
- **Carving Modes**:
  - `quick`: Aligned sector jumps (512-byte boundaries) for high-speed triage.
  - `deep`: Exhaustive byte-by-byte sweep with full structural cross-validation.
  - `fragmented`: Entropy-guided bifragment cluster stitcher for discontiguous files.
- **Evidential Export**: Carved files are packaged into a tamper-evident `.jkya` container with individual SHA-256 hashes and offset maps.

#### Examples:
```jocky
// Deep file recovery from secondary drive
carve disk from drive "\\\\.\\PhysicalDrive1"
    types [pdf, docx, sqlite]
    mode deep
    confidence_threshold 0.75
    export to artifact "recovered_evidence";

// Quick triage on raw virtual disk image
carve disk from drive "evidence.dd"
    types [sqlite, pcap]
    mode quick
    confidence_threshold 0.50
    export "triage_artifacts";
```

---

### `erase`
Executes certified, multi-pass cryptographic data sanitization on raw physical drives, folders, or specific files to legally destroy sensitive information and prevent forensic recovery.

Complies with global data destruction mandates including **NIST SP 800-88 Revision 1** and **DoD 5220.22-M**.

#### Safety Interlocks:
JOCKY includes active safety interlocks. Attempting to sanitize an active operating system boot drive (`C:`, `/`, `/dev/sda`) is blocked immediately unless an explicit `--force-system-drive` override is granted.

#### Syntax:
```jocky
erase <drive | file | folder> <target_path>
    method <sanitization_method>
    [passes <number>]
    [clean_metadata <true | false>]
    [clean_slack <true | false>]
    [audit <audit_log_path>]
    [certificate <certificate_path>]
```

- **Target Types**: `drive` (raw block device or partition), `file` (single file shredder), `folder` (recursive tree wipe).
- **Sanitization Standards**:
  - `nist_800_88_clear`: NIST SP 800-88 Clear (Pseudo-random overwrite + read verify).
  - `nist_800_88_purge`: NIST SP 800-88 Purge (Cryptographic multi-pass overwrite).
  - `dod_5220_22_m`: DoD 5220.22-M (Pass 1: $0\times00$, Pass 2: $0\times\text{FF}$, Pass 3: PRNG + verify).
  - `zero`: Single-pass zeroing ($0\times00$).
  - `random`: High-entropy CSPRNG random stream.
  - `gutmann`: 35-pass magnetic media overwrite algorithm.
- **Deep Clean Options**:
  - `clean_metadata`: Obfuscates file names to randomized alphanumeric strings, truncates file sizes to 0 bytes, and scrubs directory index records ($MFT / Inodes).
  - `clean_slack`: Zeros residual cluster tip slack space to prevent cluster tail leakage.
- **Cryptographic Audit Certificate**:
  - Automatically generates an `ErasureCertificate` containing hardware MAC ID, algorithm, execution timestamp, SHA-256 verification hash, and an **HMAC-SHA256 digital signature**.

#### Examples:
```jocky
// Certified media disposal complying with DoD 5220.22-M
erase drive "\\\\.\\PhysicalDrive2"
    method dod_5220_22_m
    passes 3
    clean_metadata true
    clean_slack true
    audit "disposal_audit.json"
    certificate "destruction_cert.pdf";

// Fast file shredder with metadata obfuscation
erase file "secret_keys.pem"
    method nist_800_88_clear
    passes 1
    clean_metadata true
    clean_slack true
    certificate "cert.json";
```

---

### `timeline`
Aggregates heterogeneous event sources into a unified, chronologically sorted event timeline.

#### Syntax:
```jocky
timeline host <hostname> from <iso_timestamp> to <iso_timestamp> sources [<source_list>] [output <file>];
```

- **Supported Sources**: `registry`, `eventlog`, `prefetch`, `browser`, `shellbags`, `mft`

#### Example:
```jocky
timeline host "FINANCE-PC" 
    from "2026-09-01T00:00:00Z" 
    to "2026-09-02T23:59:59Z" 
    sources [eventlog, prefetch, registry, mft] 
    output "breach_timeline.csv";
```

---

### `correlate`
Cross-references collected evidence against threat intelligence feeds, IOC tables, or known malware signatures.

#### Syntax:
```jocky
correlate <evidence_artifact> with <ioc_file> [flag anomalies];
```

#### Example:
```jocky
correlate "proc_1337.mem" with "threat_intel_iocs.json" flag anomalies;
```

---

### `analyze`
Executes heuristic and behavioral analysis plugins against an artifact container.

#### Syntax:
```jocky
analyze <artifact_name> using <plugin_name> [threshold <score>];
```

#### Example:
```jocky
analyze "proc_1337.mem" using entropy_scan threshold 0.85;
```

---

### `report`
Compiles findings and evidence into structured formats for incident reporting and chain-of-custody documentation.

#### Syntax:
```jocky
report <target_artifact> as <filename> format <html | json | csv>;
```

#### Examples:
```jocky
report "proc_1337.mem" as "incident_summary.html" format html;
report "breach_timeline" as "events.json" format json;
```

---

## 3. Control Flow & Functions

JOCKY provides standard control flow and modular functions:

### Conditional Execution (`if / else`)
```jocky
if suspicious_count > 0 {
    collect memory from pid target_pid export "malicious.dmp";
    report "malicious.dmp" as "alert.html" format html;
} else {
    report "clean" as "status.json" format json;
}
```

### Iteration (`for each`)
```jocky
for proc each suspicious_pids {
    collect memory from pid proc export "dump";
}
```

### Function Declarations
```jocky
function triage_workstation(hostname, target_pid) {
    collect memory from pid target_pid export "mem.jkya";
    correlate "mem.jkya" with "yara_rules.yar" flag anomalies;
    timeline host hostname from "2026-09-20T00:00:00Z" to "2026-09-27T00:00:00Z" sources [eventlog, prefetch];
    report "mem.jkya" as "triage_report.html" format html;
}
```

---

## 4. Standard Library & Example Scripts

A complete incident response triage routine is available in `stdlib/jocky/forensics.jky`:

```jocky
function quick_memory_scan(pid) {
    collect memory from pid pid using win32 export "quick_scan.dmp";
    correlate "quick_scan.dmp" with "known_bad_hashes.txt" flag anomalies;
    report "quick_scan.dmp" as "quick_scan_report.html" format html;
}

function persistence_check(hostname) {
    collect disk from host hostname export "disk_snap.vss";
    collect registry from host hostname export "reg.hives";
    timeline host hostname from "2026-01-01" to "2026-09-01" sources [registry, eventlog];
}

function full_forensic_triage(hostname, analyst_pid) {
    quick_memory_scan(analyst_pid);
    persistence_check(hostname);
    scan network_interfaces on interface "eth0" where port == 80;
    report "triage_all" as "final_triage.json" format json;
}
```

### Media Disposal & Zero-Residual Carve Audit (`stdlib/jocky/sanitization_and_recovery.jky`)
Orchestrates certified storage wiping and immediately performs deep forensic carving to formally verify that zero residual files can be recovered:

```jocky
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

### Certified Storage Sanitization (`stdlib/jocky/sanitization.jky`)
```jocky
function sanitize_physical_volume(target_device, audit_out, cert_out) {
  erase drive target_device
    method dod_5220_22_m
    passes 3
    clean_metadata true
    clean_slack true
    audit audit_out
    certificate cert_out
}
```

### Deep Evidence Carving Routine (`stdlib/jocky/recovery.jky`)
```jocky
function carve_evidence_disk(drive_path, output_artifact) {
  carve disk from drive drive_path
    types [pdf, png, jpg, sqlite, zip, pcap]
    mode deep
    confidence_threshold 0.70
    export to artifact output_artifact
}
```

---

## 5. Compiling & Running JOCKY Scripts

JOCKY provides two toolchain options:

### Using the Rust Compiler (`jockc`)
High-performance parser and syntax validator built on PEG (Pest):

```powershell
cd crates
```

1. **Syntax Validation Only (`--check`)**:
   ```powershell
   cargo run -p jocky-compiler -- ..\stdlib\jocky\forensics.jky --check
   ```
   *Output: `[jockc] OK: 4 statement(s) parsed from '..\stdlib\jocky\forensics.jky'`*

2. **Summarize Parsed Statements**:
   ```powershell
   cargo run -p jocky-compiler -- ..\stdlib\jocky\forensics.jky
   ```

3. **Dump Abstract Syntax Tree as JSON (`--ast`)**:
   ```powershell
   cargo run -p jocky-compiler -- ..\stdlib\jocky\forensics.jky --ast
   ```

4. **Run Compiler & Runtime Unit Tests**:
   ```powershell
   cargo test --workspace
   ```

---

### Using the Python / LLVM Compiler (`jockc.py`)
Generates native LLVM IR (`.ll`) and links to target machine executables:

```powershell
# From the project root
python compiler/jockc.py stdlib/jocky/forensics.jky --ir-only
```
This produces `stdlib/jocky/forensics.ll` containing LLVM IR instructions ready for `clang` / `opt` optimization and machine compilation.

To run the Python compiler test suite:
```powershell
python -m pytest tests/test_compiler.py -v
```

---

## 6. Forensic Artifact Format (`.jkya`)

When JOCKY scripts collect evidence, data is written into `.jkya` (JOCKY Artifact) containers. Each container includes:

- **Metadata Header**: Originating host, timestamp, process ID, collection flags.
- **Memory Regions**: Base addresses, region sizes, page protection attributes, and raw bytes.
- **Packet Frames**: Microsecond epoch timestamps, packet length, raw frame data.
- **Integrity Verification**: Crytographic verification hashes to maintain chain of custody.

Artifacts can be parsed programmatically using the `jocky-runtime` library or inspected through the JOCKY API and Dashboard.

---

## 7. Server REST API & Dashboard

JOCKY includes an enterprise management backend and interactive React/Vite web dashboard for orchestrating investigations and viewing real-time evidence.

### Running the Services

1. **Launch the FastAPI Management Server**:
   ```powershell
   uvicorn server.main:app --reload --port 8000
   ```

2. **Launch the Web Dashboard**:
   ```powershell
   cd dashboard
   npm run dev
   ```
   Open `http://localhost:5173` in your browser.

### Key API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/drives` | Enumerate host physical volumes and detect OS system boot partitions |
| `POST` | `/api/sanitize/drive` | Start background certified drive wipe with safety interlock protection |
| `POST` | `/api/sanitize/file` | Multi-pass file shredder with metadata obfuscation & slack wiping |
| `GET` | `/api/sanitize/status/{id}` | Real-time wiping progress, pass counter, and verification status |
| `GET` | `/api/sanitize/certificate/{id}` | Download HMAC-SHA256 signed destruction certificate (`json` or `text`) |
| `POST` | `/api/carve/start` | Launch forensic file carving job on a disk image or block device |
| `GET` | `/api/carve/status/{id}` | Real-time progress, sector streamer, and discovered file metadata list |
| `GET` | `/api/carve/artifact/{id}` | Download carved evidential items as a `.jkya` container |
| `WS` | `/api/ws/progress/{id}` | WebSocket stream for live sector-by-sector visualization |

### Interactive Dashboard Features

- **Forensic Carving Workbench**:
  - Live 64-block Physical Sector Map showing cluster scanning and header discovery in real time.
  - Formats selector, carving modes (`Quick`, `Deep`, `Fragmented`), and confidence threshold slider.
  - Interactive **Hex Inspector Modal** for raw byte examination and SHA-256 verification.
  - Direct `.jkya` evidential export.
- **Certified Sanitization Center**:
  - Storage volume selector with automatic **Critical Safety Interlock Alerts** when an OS volume is detected.
  - Standard selector: NIST SP 800-88 Clear/Purge, DoD 5220.22-M, Single-Pass Zero, and Gutmann 35-pass.
  - Live multi-pass progress bar and **Official Certificate of Sanitization Card** displaying the cryptographic seal.

