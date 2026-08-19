# Static syscall analyzer

This repository implements a static syscall analysis module for modern Linux ELF binaries, following the same broad design idea as Confine:

- discover relevant ELF files in an extracted filesystem
- extract imported functions
- map imported functions through a libc call graph to syscall numbers
- inspect executable instructions for direct `syscall` instructions
- union the results while preserving the source of each syscall

Important: this is a static-only analyzer. It does not run the binary, does not monitor a container at runtime, and does not depend on dynamic tracing. That makes it suitable for offline research of an extracted rootfs or application directory.

## Relationship to Confine

This implementation is conceptually aligned with Confine:

- identify ELF binaries
- collect imported libc functions
- map those functions through a glibc/musl call graph
- identify direct machine-code syscalls
- combine both sets for a final static syscall set

However, it is not a blind copy of the legacy Confine code. It is redesigned for modern Linux/x86-64, uses ELF parsing via pyelftools, disassembly via Capstone, and keeps the data model source-aware (direct vs indirect).

## Requirements

Python 3.11+ is recommended.

Install dependencies:

```bash
python3 -m pip install --break-system-packages -r requirements.txt
```

## Usage

Analyze a directory containing extracted ELF files:

```bash
python3 static_analyzer.py --input ./extracted_rootfs
```

Analyze the nginx binary at the project root:

```bash
python3 static_analyzer.py --input . --json-out nginx_report.json --text-out nginx_report.txt
```

Optional custom graph files and syscall mapping overrides:

```bash
python3 static_analyzer.py \
  --input ./extracted_rootfs \
  --glibc-callgraph ./confine/libc-callgraphs/glibc.callgraph \
  --musl-callgraph ./confine/libc-callgraphs/musllibc.callgraph \
  --syscall-table ./syscalls.json \
  --json-out report.json \
  --text-out report.txt
```

## Output

The tool writes:

- a JSON report containing per-binary and per-syscall evidence
- a human-readable text report with direct, indirect, and final unique syscall sets

Example output sections:

- `DIRECT SYSCALLS`
- `INDIRECT SYSCALLS`
- `FINAL STATIC SYSCALL SET`
- summary counts

## Notes on correctness

The implementation is intentionally conservative:

- direct syscall numbers are resolved only when the value can be derived statically from a narrow instruction window
- unresolved direct syscall instructions are preserved as evidence instead of guessed
- callgraph traversal follows reachable nodes while guarding against cycles and loops
- the final static syscall set is deduplicated, but the evidence for each syscall remains available

## Example: nginx validation

The project root includes a sample `nginx` ELF binary, which can be analyzed with:

```bash
python3 static_analyzer.py --input . --json-out /tmp/nginx_report.json --text-out /tmp/nginx_report.txt
```

On a typical x86_64 host, the binary is dynamically linked and may show no direct `syscall` instructions in the stripped binary, while the indirect libc-derived syscall set is discovered from the glibc call graph.

## Repository layout

- `static_analyzer/` — package implementation
- `tests/` — unit tests
- `confine/libc-callgraphs/` — Confine-compatible callgraph files used as reference inputs
- `nginx` — sample ELF binary for validation
