# JOCKY — Forensic Scripting Language Platform

A domain-specific language and platform for digital forensics investigations.

## Architecture

```
jocky/
├── compiler/          ← ANTLR4 grammar + Python LLVM IR compiler
│   ├── Jocky.g4       ← Language grammar
│   ├── jockc.py       ← Compiler driver (jockc)
│   ├── ast/           ← AST node definitions + builder
│   ├── ir/            ← LLVM IR code generator (llvmlite)
│   └── generated/     ← ANTLR4-generated parser (gitignored)
├── runtime/           ← C forensic modules (read-only OS APIs)
│   ├── modules/
│   │   ├── memory/    ← VirtualQueryEx / /proc/pid/mem
│   │   ├── disk/      ← VSS snapshot (Windows) / block read (Linux)
│   │   ├── network/   ← libpcap passive capture
│   │   └── artifacts/ ← .jkya artifact format
│   ├── agent/         ← Python WebSocket agent
│   └── CMakeLists.txt
├── server/            ← FastAPI management server
├── dashboard/         ← React + Vite dashboard
├── stdlib/jocky/      ← Standard forensic library in JOCKY itself
├── tests/             ← pytest test suite
└── ci/build.yml       ← GitHub Actions pipeline
```

## Quick Start

### 1. Install dependencies
```bash
pip install antlr4-tools antlr4-python3-runtime llvmlite fastapi uvicorn sqlalchemy websockets cryptography
npm install         # in dashboard/
```

### 2. Generate the parser
```bash
cd compiler
antlr4 -Dlanguage=Python3 -visitor -o generated/ Jocky.g4
```

### 3. Build the C runtime
```bash
cd runtime
cmake -B build -G Ninja
cmake --build build
```

### 4. Compile a JOCKY script
```bash
python compiler/jockc.py script.jky output_binary
```

### 5. Start the management server
```bash
uvicorn server.main:app --reload --port 8000
```

### 6. Start the dashboard
```bash
cd dashboard
npm run dev
```

## Example JOCKY Script
```jocky
// Detect persistence mechanism on a host

scan processes
  filter by parent_pid == 1

collect memory from pid 4512
  filter by region [heap]
  export to artifact "suspicious_heap"

timeline host "DEMO-HOST"
  from "2026-09-20" to "2026-09-25"
  include [registry, eventlog, prefetch, shellbags]
  output report "persistence_analysis.html"

correlate "suspicious_heap" with "known_malware.ioc"
  flag anomalies

report "persistence_analysis" as "final_report"
  format html
```

## Design Principles
- **Read-only**: Every runtime function uses read-only OS APIs (no write to foreign process memory)
- **Passive capture**: Network module is non-promiscuous by default
- **Encrypted transport**: Agent-server communication uses Fernet + TLS with cert pinning
- **Cross-platform**: Same JOCKY script compiles for Windows and Linux

## Language Reference

| Statement | Description |
|-----------|-------------|
| `collect memory from pid N` | Dump process memory regions |
| `collect disk from host H` | VSS snapshot + MFT read |
| `collect registry from host H` | Registry hive read |
| `scan processes` | Enumerate running processes |
| `scan network interfaces` | Passive NIC scan |
| `timeline host H from T1 to T2` | Build event timeline |
| `correlate ARTIFACT with IOC_FILE` | Match against IOC list |
| `report ARTIFACT as FILE format html\|json\|csv` | Generate report |
| `analyze ARTIFACT using PLUGIN` | Run analysis plugin (YARA/etc) |

## Running Tests
```bash
python -m pytest tests/ -v
```
