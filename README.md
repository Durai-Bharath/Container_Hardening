# Phase-Based Container Syscall Security

This repository implements a three-phase syscall policy workflow inspired by
the paper *Enhancing Container Security Through Phase-Based System Call
Filtering*:

- **Static analysis** produces S-SF, the static syscall set.
- **Dynamic analysis** produces D-SF, the runtime-observed syscall set, and
  I-SF = S-SF union D-SF.
- **Running-phase analysis** identifies a steady-state boundary and produces
  R-SF, the syscall set observed after that boundary.

Static analysis is offline. Dynamic analysis uses Tracee/eBPF and Docker. The
repository generates OCI seccomp profiles, but does not yet perform live policy
switching inside a running container.

## Relationship To The Paper And Confine

The static phase is a modern Confine-style implementation:

- discover ELF binaries
- extract imported functions
- map libc functions through glibc/musl call graphs
- detect resolvable direct `syscall` instructions
- combine direct and indirect results into S-SF

This is not an exact reproduction of the paper. The paper describes
crash-driven dynamic supplementation under restrictive policies, collection of
syscall context, and live phase-aware policy switching. This implementation
uses Tracee observations under `SCMP_ACT_LOG`, performs running-phase analysis
offline, and writes profiles for later use. It follows the paper's
S-SF/D-SF/I-SF/R-SF model and objective, but its runtime enforcement is not yet
implemented.

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

## Three-Phase Workflow

The commands below use Nginx as an example. Replace the image and paths for
Redis or HTTPD. Static analysis must be run against an extracted rootfs or
application directory; it does not inspect a Docker image automatically.

### 1. Static Phase: S-SF

```bash
python3 static_analyzer.py \
  --input ./extracted_rootfs \
  --json-out nginx_static_report.json \
  --text-out nginx_static_report.txt \
  --seccomp-out static-seccomp/nginx_seccomp.json
```

This writes the static evidence, S-SF, and an enforcing static OCI profile.

### 2. Dynamic Phase: D-SF And I-SF

The crash loop starts Tracee before each target container, runs the registered
workload, filters events by target container ID, and repeats until two clean
passes add no new syscalls.

```bash
python3 dynamic_phase_crash_loop/crash_loop.py \
  --image nginx:latest \
  --static-seccomp static-seccomp/nginx_seccomp.json \
  --config dynamic_phase_crash_loop/workload-runner/workloads.yaml \
  --output nginx_dynamic_report.json \
  --clean-passes 2 \
  --max-iterations 10
```

The report contains S-SF in `static_syscalls`, complete runtime D-SF in
`dynamic_syscalls` including overlap with S-SF, per-pass additions in
`added_syscalls`, and I-SF in `initialize_syscalls`. It also records the
generated profile paths in `dynamic_seccomp_profile` and
`initialize_seccomp_profile`.

The command writes two enforcing profiles:

- `dynamic-seccomp/nginx_seccomp.json`: D-SF only
- `initialize-seccomp/nginx_seccomp.json`: I-SF = S-SF union D-SF

The registry maps Nginx/HTTPD to `wrk` and Redis to `redis-benchmark`.

### 3. Running Phase: R-SF

Running analysis consumes an existing newline-delimited Tracee JSONL trace. It
uses fixed windows, syscall-frequency vectors, adjacent-window cosine
similarity, and a sustained similarity threshold to find the running boundary.

```bash
python3 -m running_phase.main \
  --running-trace nginx_trace.jsonl \
  --output nginx_running_phase_report.json \
  --window-seconds 0.001 \
  --similarity-threshold 0.8 \
  --stabilization-seconds 5 \
  --seccomp-output running-seccomp/nginx_seccomp.json
```

This writes the segmentation result and R-SF profile. The crash-loop report
does not currently export its raw Tracee JSONL, so provide a separately
captured trace for this phase.

## Running-Phase Ablation Study

The existing `running_phase/` implementation is unchanged. Ablation experiments
use the separate `running_phase_ablation/` package, which supports:

- `frequency`: syscall-frequency features only
- `bigram`: syscall-transition features only
- `combined`: concatenated frequency and bigram features

Segmentation can use the paper-style sustained threshold, the first matching
similarity threshold. Windows can be wall-clock based or fixed-size syscall
count windows. Count windows avoid nearly empty windows during idle periods and
provide enough events for meaningful bigram distributions. For example:

```bash
python3 -m running_phase_ablation.main \
  --running-trace nginx_trace.jsonl \
  --feature-mode combined \
  --segmentation-mode sustained \
  --output ablation-reports/nginx_combined_report.json \
  --window-seconds 0.001 \
  --similarity-threshold 0.8 \
  --stabilization-seconds 5
```

Run the other feature variants by changing `--feature-mode` to `frequency` or
`bigram`. Use count-based windows with:

```bash
python3 -m running_phase_ablation.main \
  --running-trace traces/nginx_test_discovery_trace.jsonl \
  --feature-mode combined \
  --segmentation-mode sustained \
  --window-mode count \
  --events-per-window 100 \
  --stabilization-windows 5 \
  --output ablation-reports/nginx_combined_count100_report.json
```

Profiles are isolated from the standard running-phase outputs under:

```text
running-seccomp-ablation/<window-mode>/<window-size>/<feature-mode>/<segmentation-mode>/
```

For count-mode profiles using 100 events per window:

```text
running-seccomp-ablation/count/100/<feature-mode>/<segmentation-mode>/
```

Use `--seccomp-output` to override that location for a particular experiment.
Each ablation report records the feature mode, segmentation mode, window mode,
events per window, feature vocabularies, per-window frequency and bigram
vectors, similarities, the segmentation point, R-SF, and the generated profile
path. Reports are compact by default and record `window_count` instead of every
window vector. Add `--include-windows` when full per-window vectors are needed;
this can consume substantial memory for large traces. In count mode,
`--stabilization-windows` controls how many consecutive similar windows are
required by sustained segmentation.

Adaptive change-point modes are also available:

```bash
python3 -m running_phase_ablation.main \
  --running-trace traces/nginx_test_discovery_trace.jsonl \
  --feature-mode combined \
  --segmentation-mode pht \
  --window-mode count \
  --events-per-window 100 \
  --change-point-min-samples 10 \
  --output ablation-reports/nginx_combined_pht_report.json
```

Use `--segmentation-mode bocpd` for the Bayesian predictive change-score
variant. PHT and BOCPD report `adaptive_threshold` and `change_point_score`.
PHT is most sensitive to a downward shift in dissimilarity, while BOCPD can
respond to either direction. The BOCPD implementation uses a bounded online
predictive approximation to avoid retaining an unbounded run-length history.

For hosts where Tracee's Docker command requires a prefix, add:

```bash
--tracee-docker-command "sudo docker"
```

The workload runner itself invokes `docker` directly, so Docker access must be
configured for the invoking user.

## Legacy Trace-Based Profiling

The reusable `dynamic_phase/` and `running_phase/` packages consume
newline-delimited JSON syscall events. Each event requires `timestamp` (or
`time`) and `syscall` (or `name`). Optional fields are `number`, `arguments`
(`args`), `pid`, and `process` (`comm`). Events are sorted by timestamp.

Run the opt-in real integration test with:

```bash
RUN_TRACE_INTEGRATION=1 pytest -q tests/test_tracee_integration.py
```

The three-phase workflow above is the supported end-to-end path. These lower
level packages remain useful for tests and for externally captured traces.

## Notes on correctness

The implementation is intentionally conservative:

- direct syscall numbers are resolved only when the value can be derived statically from a narrow instruction window
- unresolved direct syscall instructions are preserved as evidence instead of guessed
- callgraph traversal follows reachable nodes while guarding against cycles and loops
- the final static syscall set is deduplicated, but the evidence for each syscall remains available
- static analysis is ELF/rootfs analysis and does not automatically inspect a Docker image
- failed or unreadable ELF files must be investigated; runtime discovery cannot prove that an unexercised path is safe
- D-SF and R-SF depend on the workload commands and duration used during collection
- the current dynamic phase uses Tracee observation under `SCMP_ACT_LOG`, not the paper's crash-driven restrictive retry loop
- the current running phase writes an R-SF profile but does not switch seccomp policy live at the detected boundary

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
