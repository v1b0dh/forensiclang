# JOCKY Language Guide & Reference Manual

Welcome to **JOCKY** — a compiled, domain-specific programming language (DSL) engineered specifically for **Digital Forensics and Incident Response (DFIR)**.

JOCKY replaces hundreds of lines of fragile forensic scripts and OS API boilerplate with expressive, first-class statements designed to collect, correlate, timeline, and report forensic evidence across Windows and Linux systems.

---

## Table of Contents
1. [Language Basics](#1-language-basics)
2. [Forensic Statements](#2-forensic-statements)
   - [`collect`](#collect)
   - [`scan`](#scan)
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
