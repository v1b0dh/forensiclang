# JOCKY Unified Platform Extension: Forensic Carving, Recovery & Certified Sanitization

## Executive Overview
This implementation plan integrates three core capabilities into the JOCKY ecosystem:
1. **Secure Drive Eraser** (NIST SP 800-88 Rev 1, DoD 5220.22-M, ATA/NVMe sanitize primitives, tamper-proof audit trails).
2. **Secure File & Folder Eraser** (Multi-pass shredding, NTFS `$MFT` record cleansing, `$I30` directory index scrubbing, slack space wipe).
3. **Advanced Forensic File Carving & Recovery Engine** (Signature-based, structure-based, bi-fragment gap stitching, confidence scoring, evidential integrity preservation).

All three capabilities are exposed through:
- **First-class language statements** in the JOCKY DSL (`carve`, `erase`, `verify`).
- **High-performance native Rust engine** in `crates/jocky-runtime`.
- **FastAPI backend services & endpoints** in `server/`.
- **Interactive UI Dashboard components** in `dashboard/`.

---

## 1. What Makes This Solution Truly Unique?

Traditional forensic software and data destruction software exist in opposing silos:
- **Silo A (Sanitizers):** Tools like Blancco or DBAN wipe sectors, but provide no forensic mechanism to verify the wipe from an investigator's viewpoint.
- **Silo B (Carvers):** Tools like Scalpel, PhotoRec, or Autopsy recover files, but offer no native capability to sanitize residual evidence.

### The JOCKY Advantages:
1. **The "Prove It's Gone" Loop (Sanitize + Carve Verification):**
   JOCKY allows an auditor or security engineer to script a complete cycle in a single `.jky` program:
   ```jocky
   erase drive "E:" method nist_800_88_clear verify passes 1;
   carve disk from drive "E:" types [all] export "verify_carve.jkya";
   assert count("verify_carve.jkya") == 0;
   report "verify_carve.jkya" as "zero_residue_cert.pdf" format certificate;
   ```
   No other tool in the industry offers a domain-specific language that natively couples evidence destruction with forensic recovery verification.

2. **DSL Programmability for Forensic Playbooks:**
   Instead of clicking through complex wizard GUIs for every disk or writing flaky Python/Bash wrappers, investigators can version-control their triage and sanitization playbooks in Git using clean `.jky` code.

3. **Intelligent Multi-Tier Carving with Confidence Scoring:**
   Rather than merely dumping false positives upon encountering header magic bytes, JOCKY performs **structure validation** (e.g. validating JPEG SOF/EOI markers, ZIP central directory records, PDF cross-reference tables) and outputs a **Confidence Score (0.00 – 1.00)**.

4. **Tamper-Resistant Cryptographic Destruction Certificates:**
   Every drive or file wipe generates an Ed25519-signed or HMAC-SHA256 audit log containing drive serials, sector counts, pattern verification hashes, and operator metadata, suitable for legal and regulatory compliance (GDPR, HIPAA, DoD, NIST).

---

## 2. DSL Syntax Extensions

We extend JOCKY's grammar (`grammar.pest` & `jocky.g4`) with two primary statements:

### A. The `carve` Statement
```jocky
carve disk from drive <string> 
    [types [<ident_list>]] 
    [mode <quick | deep | fragmented>] 
    [confidence_threshold <float>] 
    [export <string>];
```
*Example:*
```jocky
carve disk from drive "E:" 
    types [pdf, docx, sqlite, png, pcap] 
    mode deep 
    confidence_threshold 0.75 
    export "case_104_carved.jkya";
```

### B. The `erase` Statement
```jocky
erase <drive | file | folder> <target_path> 
    method <zero | nist_800_88_clear | nist_800_88_purge | dod_5220_22_m | gutmann> 
    [passes <number>] 
    [clean_metadata <bool>] 
    [clean_slack <bool>] 
    [audit <string>] 
    [certificate <string>];
```
*Example:*
```jocky
erase drive "\\\\.\\PhysicalDrive2" 
    method nist_800_88_clear 
    passes 1 
    audit "audit_drive2.json" 
    certificate "cert_drive2.pdf";

erase file "D:\\Confidential\\evidence.db" 
    method dod_5220_22_m 
    clean_metadata true 
    clean_slack true;
```

---

## 3. Core Engine Architecture

```
 crates/jocky-runtime/src/
 ├── carving/
 │   ├── mod.rs             ← Carving pipeline orchestrator
 │   ├── signatures.rs      ← File signature definitions (Magic headers & footers)
 │   ├── validators/        ← Format-specific structural validators
 │   │   ├── pdf.rs         ← PDF trailer / xref validator
 │   │   ├── zip_office.rs  ← ZIP / DOCX / XLSX central directory validator
 │   │   ├── image.rs       ← JPEG / PNG / GIF dimension and chunk validator
 │   │   ├── sqlite.rs      ← SQLite header and b-tree page structure validator
 │   │   └── pcap.rs        ← PCAP / PCAPNG packet block validator
 │   ├── fragment.rs        ← Entropy-driven bifragment cluster stitcher
 │   └── classifier.rs      ← File classification & confidence scoring
 │
 ├── sanitization/
 │   ├── mod.rs             ← Erasure pipeline orchestrator
 │   ├── algorithms.rs      ← NIST SP 800-88, DoD 5220.22-M, 0x00/0xFF/PRNG patterns
 │   ├── drive.rs           ← Direct raw block device sanitization & sector verification
 │   ├── file_shredder.rs   ← Multi-pass file overwriter
 │   ├── metadata_clean.rs  ← NTFS ($MFT, $I30 index allocations) & ext4 inode scrub
 │   ├── slack.rs           ← Cluster tip and slack space zeroing
 │   └── cert.rs            ← Tamper-resistant signed JSON/PDF audit certificate generator
```

---

## 4. Detailed Step-by-Step Implementation Plan

### Phase 1: Engine Foundation in Rust (`crates/jocky-runtime`)
- [x] **Step 1.1 — Signature Database & Carving Base Types:**
  - Define `FileSignature` (magic start, optional footer, max size, mime type).
  - Implement signatures for PDF, PNG, JPG, GIF, ZIP (DOCX/XLSX/PPTX), SQLite, PCAP, ELF, PE (EXE/DLL).
- [x] **Step 1.2 — Sector Streamer & Direct Block Access:**
  - Implement read-only buffered chunk streamer for disks (`\\.\PhysicalDriveX` / `\\.\X:` on Windows, `/dev/sdX` on Linux) and raw image files (`.dd`, `.raw`, `.e01` stub).
- [x] **Step 1.3 — Structural Format Validators:**
  - Implement validators that parse internal structure to filter out corrupt false positives.
  - Compute `confidence_score` (0.0 to 1.0) based on header match + internal segment valid + clean footer.
- [x] **Step 1.4 — Bifragment Gap Carver:**
  - For fragmented files (e.g. JPEG, PDF), use Shannon entropy calculations to identify cluster boundary discontinuities and reconnect fragmented segments.
- [x] **Step 1.5 — Sanitization Engine & Algorithms:**
  - Implement data destruction patterns: Single pass zeros, NIST 800-88 Clear (pseudo-random overwrite + zero verify), DoD 5220.22-M (Pass 1: 0x00, Pass 2: 0xFF, Pass 3: Random + verify).
  - Implement direct disk sector overwriting with flush/sync barriers (`FILE_FLAG_NO_BUFFERING` / `O_DIRECT`).
- [x] **Step 1.6 — Metadata & Slack Space Cleanser:**
  - File shredder: overwrite file data, rename to random string, truncate to 0 bytes, then delete.
  - NTFS slack space wiper: calculate `file_size % cluster_size` and zero the residual cluster tip.
  - Windows `$I30` / directory record cleansing hooks.
- [x] **Step 1.7 — Cryptographic Audit Certificate Generator:**
  - Create `ErasureCertificate`: hardware device ID, serial number, wiping standard, verification checksum, operator timestamp, cryptographic hash of the entire wipe log.

### Phase 2: Compiler & Language Integration (`crates/jocky-compiler`)
- [x] **Step 2.1 — Grammar Updates (`grammar.pest`):**
  - Add rules for `carve_stmt` and `erase_stmt`.
  - Add tokens: `carve`, `erase`, `drive`, `folder`, `method`, `nist_800_88_clear`, `dod_5220_22_m`, `clean_metadata`, `confidence_threshold`, `certificate`.
- [x] **Step 2.2 — AST Node Definitions (`ast.rs`):**
  - Define `CarveStatement` and `EraseStatement` structs with full enum support for methods and targets.
- [x] **Step 2.3 — Parser Dispatch (`parser.rs`):**
  - Implement parse tree converters for `carve` and `erase`.
- [x] **Step 2.4 — Python Compiler Sync:**
  - Update `compiler/jocky.g4`, `compiler/ast/nodes.py`, and `compiler/codegen/llvm.py` with runtime dispatch stubs for `jocky_carve_disk` and `jocky_erase_target`.

### Phase 3: Server API & Queue Integration (`server/`)
- [x] **Step 3.1 — Fast-API Background Jobs:**
  - Add endpoints: `POST /api/carve/start`, `GET /api/carve/status/{job_id}`, `POST /api/sanitize/drive`, `POST /api/sanitize/file`.
- [x] **Step 3.2 — Progress Streaming:**
  - Provide SSE (Server-Sent Events) or WebSockets reporting sectors processed, carving matches found in real time, and pass progress.
- [x] **Step 3.3 — Certificate & Artifact Download Endpoints:**
  - Download `.jkya` carved packages and signed PDF/JSON erasure certificates.

### Phase 4: UI Dashboard (`dashboard/`)
- [x] **Step 4.1 — Forensic Carving Workbench:**
  - Visual disk map, hex preview of carved segments, filterable table of recovered files categorized by file type with confidence badges.
- [x] **Step 4.2 — Certified Sanitization Center:**
  - Drive selector with safety locks (prevent accidental OS drive wipe), standard selector (NIST, DoD), real-time progress gauge, and downloadable destruction certificate viewer.

### Phase 5: Verification & Standard Library
- [x] **Step 5.1 — Standard Library Routines (`stdlib/jocky/`):**
  - Write standard scripts: `stdlib/jocky/sanitization.jky` and `stdlib/jocky/recovery.jky`.
- [x] **Step 5.2 — Automated End-to-End Test Suite:**
  - Write tests creating dummy formatted disk images, injecting known files, deleting them, running `carve`, asserting recovery, running `erase`, and asserting zero recoverability.

---

## 5. Architectural Recommendations & Best Practices

1. **Safety Interlocks for Erasure:**
   Always inspect the target physical drive against the operating system's root volume. If a user attempts to run `erase drive "C:"` or `/dev/sda` without explicit `--force-system-drive` override flags, the engine must abort immediately with a safety diagnostic.

2. **Read-Only Guarantees During Carving:**
   The carving subsystem must open disk handles exclusively in read-only mode (`GENERIC_READ`, `FILE_SHARE_READ | FILE_SHARE_WRITE`) to prevent accidental modification of evidence during investigation.

3. **Performance (SIMD & Direct I/O):**
   - Use 1MB or 2MB aligned sector buffers with `O_DIRECT` / unbuffered I/O for 10x faster disk sweeps.
   - Use vectorized SIMD pattern generation (AVX2/NEON) when generating multi-gigabyte DoD/NIST random and zero wipe patterns.
