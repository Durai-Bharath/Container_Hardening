# Running-Phase Ablation Study

This package is isolated from `running_phase/` so ablation results and generated
profiles do not overwrite the baseline implementation.

The study varies three independent dimensions:

1. Feature representation: `frequency`, `bigram`, or `combined`.
2. Segmentation method: `sustained`, `first`, `pht`, or `bocpd`.
3. Windowing: wall-clock `time` windows or fixed syscall-count `count` windows.

That gives 12 feature/segmentation combinations for each window configuration.
For count windows, repeat the study with different values such as 50 and 100
syscalls per window.

## Input Trace

The input must be newline-delimited JSON. Each event requires:

```json
{"timestamp": 123.456, "syscall": "read"}
```

Optional fields are `number`, `arguments` or `args`, `pid`, and `process` or
`comm`. Events are sorted by timestamp before analysis.

Example input:

```text
traces/nginx_test_discovery_trace.jsonl
```

## Feature Modes

| Mode | Vector | Captures |
|---|---|---|
| `frequency` | Per-syscall normalized counts | Which syscalls occur and how often |
| `bigram` | Per-transition normalized counts | Ordering such as `read>write` |
| `combined` | Frequency vector + bigram vector | Frequency and ordering together |

## Segmentation Modes

| Mode | Behavior | Parameters |
|---|---|---|
| `sustained` | First interval whose similarity remains above the threshold for the required duration/window count | `--similarity-threshold`, `--stabilization-seconds` or `--stabilization-windows` |
| `first` | First adjacent-window similarity at or above the threshold | `--similarity-threshold` |
| `pht` | Page-Hinkley detection of a change in dissimilarity | `--pht-delta`, `--pht-threshold`, `--change-point-min-samples` |
| `bocpd` | Bounded Bayesian predictive change score | `--bocpd-hazard`, `--change-point-min-samples` |

PHT and BOCPD report `adaptive_threshold` and `change_point_score` in the
result. The BOCPD implementation is a bounded predictive approximation rather
than an unbounded run-length posterior.

## Window Modes

### Time windows

```text
--window-mode time
--window-seconds 0.001
```

The trace is divided by wall-clock duration. Idle periods can create sparse
windows.

### Syscall-count windows

```text
--window-mode count
--events-per-window 100
```

Every window contains up to the specified number of events. This adapts to
load and gives bigram features enough events to be meaningful. In count mode,
`sustained` uses a number of windows instead of seconds:

```text
--stabilization-windows 5
```

## Common Parameters

| Parameter | Default | Meaning |
|---|---:|---|
| `--running-trace` | required | JSONL syscall trace |
| `--output` | `running_phase_ablation_report.json` | Report path |
| `--feature-mode` | `combined` | `frequency`, `bigram`, or `combined` |
| `--segmentation-mode` | `sustained` | `sustained`, `first`, `pht`, or `bocpd` |
| `--window-mode` | `time` | `time` or `count` |
| `--window-seconds` | `0.001` | Size of time windows |
| `--events-per-window` | `100` | Size of count windows |
| `--similarity-threshold` | `0.8` | Fixed threshold for `sustained` and `first` |
| `--stabilization-seconds` | `5` | Required stable duration in time mode |
| `--stabilization-windows` | `5` | Required stable window count in count mode |
| `--pht-delta` | `0.0` | Page-Hinkley tolerance |
| `--pht-threshold` | adaptive | Optional fixed Page-Hinkley threshold |
| `--change-point-min-samples` | `10` | Warm-up observations for PHT/BOCPD |
| `--bocpd-hazard` | `0.01` | BOCPD prior change probability |
| `--include-windows` | disabled | Include all per-window vectors; can use substantial memory |
| `--seccomp-output` | automatic | Override generated profile path |

`--stabilization-seconds` is ignored by count-mode sustained segmentation.
`--stabilization-windows` is ignored by time-mode sustained segmentation.
`first`, `pht`, and `bocpd` do not require a stabilization duration.

## All 12 Combinations

The following feature/segmentation matrix is run for each chosen window
configuration:

| Feature mode | Segmentation modes |
|---|---|
| `frequency` | `sustained`, `first`, `pht`, `bocpd` |
| `bigram` | `sustained`, `first`, `pht`, `bocpd` |
| `combined` | `sustained`, `first`, `pht`, `bocpd` |

### One command per combination

Replace `FEATURE` and `SEGMENTATION` as shown below:

```bash
python3 -m running_phase_ablation.main \
  --running-trace traces/nginx_test_discovery_trace.jsonl \
  --feature-mode FEATURE \
  --segmentation-mode SEGMENTATION \
  --window-mode count \
  --events-per-window 100 \
  --stabilization-windows 5 \
  --change-point-min-samples 10 \
  --bocpd-hazard 0.01 \
  --output ablation-reports/nginx_FEATURE_SEGMENTATION_count100.json
```

The 12 substitutions are:

```text
frequency sustained
frequency first
frequency pht
frequency bocpd
bigram sustained
bigram first
bigram pht
bigram bocpd
combined sustained
combined first
combined pht
combined bocpd
```

For time windows, replace the window arguments with:

```bash
--window-mode time \
--window-seconds 0.001 \
--stabilization-seconds 5
```

### Run all 12 with count windows

```bash
mkdir -p ablation-reports
for feature in frequency bigram combined; do
  for segmentation in sustained first pht bocpd; do
    python3 -m running_phase_ablation.main \
      --running-trace traces/nginx_test_discovery_trace.jsonl \
      --feature-mode "$feature" \
      --segmentation-mode "$segmentation" \
      --window-mode count \
      --events-per-window 100 \
      --stabilization-windows 5 \
      --change-point-min-samples 10 \
      --bocpd-hazard 0.01 \
      --output "ablation-reports/nginx_${feature}_${segmentation}_count100.json"
  done
done
```

### Run all 12 with time windows

```bash
mkdir -p ablation-reports
for feature in frequency bigram combined; do
  for segmentation in sustained first pht bocpd; do
    python3 -m running_phase_ablation.main \
      --running-trace traces/nginx_test_discovery_trace.jsonl \
      --feature-mode "$feature" \
      --segmentation-mode "$segmentation" \
      --window-mode time \
      --window-seconds 0.001 \
      --similarity-threshold 0.8 \
      --stabilization-seconds 5 \
      --change-point-min-samples 10 \
      --bocpd-hazard 0.01 \
      --output "ablation-reports/nginx_${feature}_${segmentation}_time.json"
  done
done
```

### Repeat count mode with 50 events per window

Use the count-window command above with:

```bash
--events-per-window 50
```

and change the report suffix to `_count50`.

## Outputs

Reports are written to the requested `--output` path. By default, profiles are
written under:

```text
running-seccomp-ablation/<window-mode>/<window-size>/<feature-mode>/<segmentation-mode>/
```

Examples:

```text
running-seccomp-ablation/count/100/combined/sustained/
running-seccomp-ablation/count/100/combined/pht/
running-seccomp-ablation/time/0.001/frequency/bocpd/
```

Each compact report contains:

- `feature_mode`, `segmentation_mode`, and window configuration
- `segmentation_index` and `segmentation_time`
- `adaptive_threshold` and `change_point_score` for adaptive modes
- `similarities` and `dissimilarities`
- `running_syscalls`, which define R-SF
- syscall and bigram vocabularies
- `window_count`
- generated `seccomp_profile` path

Use `--include-windows` to include every window's frequency, bigram, and
combined vectors. This is useful for detailed plots but may require substantial
memory for large traces.
