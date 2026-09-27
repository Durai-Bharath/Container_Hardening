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

## Dynamic and running-phase profiling

The `dynamic_phase/` package consumes newline-delimited JSON syscall events. This
keeps the profiling and segmentation algorithms independent of the event collector;
an eBPF/BCC or libbpf agent can emit the same schema later.

Each event requires `timestamp` (or `time`) and `syscall` (or `name`). Optional
fields are `number`, `arguments` (or `args`), `pid`, and `process` (or `comm`).
Events are sorted by timestamp before processing.

Run dynamic profiling only from an existing Tracee JSONL trace:

```bash
python3 -m dynamic_phase.main \
  --trace syscall_events.jsonl \
  --static-report static_syscall_report.json \
  --output dynamic_phase_report.json
```

Run running-phase segmentation separately from the same trace:

```bash
python3 -m dynamic_phase.main \
  --running-trace syscall_events.jsonl \
  --output running_phase_report.json \
  --window-seconds 0.001 \
  --similarity-threshold 0.8 \
  --stabilization-seconds 5
```

Running-phase segmentation follows the paper's similarity-based method. It
 uses only syscall frequency vectors, compares adjacent windows, and selects
 the end of the first sustained stabilization interval whose cosine similarity
 remains at or above `0.8`. The stabilization interval defaults to five
 seconds; there is no adaptive change-point or warm-up parameter. The command
 writes the JSON report and an OCI seccomp profile to
 `running-seccomp/<report-name>_seccomp.json` (or to `--seccomp-output` when
 provided).

Run the real Docker/Tracee dynamic analysis directly against an image:

```bash
python3 -m dynamic_phase.main \
  --image nginx:latest \
  --command "nginx -g 'daemon off;'" \
  --static-report static_syscall_report.json \
  --output dynamic_phase_report.json \
  --max-iterations 10 \
  --timeout 60
```

`--timeout` is the per-run profiling window, not a crash. Workloads such as
`nginx -g 'daemon off;'` never exit, so the window always ends with the
container still running. A new iteration is started only when Tracee observed a
syscall that is not already in the candidate allowlist. If that set is already
complete, the report correctly contains a single iteration.

For hosts where Docker requires `sudo`, pass the complete command prefix:

```bash
python3 -m dynamic_phase.main \
  --image nginx:latest \
  --command "nginx -g 'daemon off;'" \
  --static-report static_syscall_report.json \
  --docker-command "sudo docker"
```

The controller starts Tracee first (`--scope container=new`, with the Docker
socket mounted so container IDs can be resolved), then creates the target with
the candidate OCI profile. That order captures initialization syscalls; attaching
Tracee after the target is already running misses them and makes the loop stop
at iteration 1. After the profiling window, the container is removed and rebuilt
only when the trace contains a syscall outside the current allowlist. A failed
run with no missing observed syscall is reported as unresolved instead of
blindly widening the profile.

Run the opt-in real integration test with:

```bash
RUN_TRACE_INTEGRATION=1 pytest -q tests/test_tracee_integration.py
```

The dynamic report contains only the observed runtime syscall set (D-SF) and
the static/runtime initialization union (I-SF). The running-phase report
 The running-phase report contains time windows, frequency features,
 dissimilarity scores, the sustained cosine-similarity segmentation point, and
 the steady-state syscall set (R-SF). This separation also allows the
 running-phase algorithm to be tested against captured traces without rerunning
 Docker or Tracee.

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
