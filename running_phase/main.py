from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from common.events import load_events
from running_phase.analyzer import AdaptivePageHinkley, RunningPhaseAnalyzer


def run_running_phase(
    trace_path: str,
    output_path: str,
    window_seconds: float,
    warmup: int,
    frequency_weight: float,
    bigram_weight: float,
) -> int:
    events = list(load_events(trace_path))
    result = RunningPhaseAnalyzer(
        window_seconds=window_seconds,
        frequency_weight=frequency_weight,
        bigram_weight=bigram_weight,
        detector=AdaptivePageHinkley(warmup=warmup),
    ).analyze(events)
    payload = asdict(result)
    payload["windows"] = [asdict(window) for window in result.windows]
    Path(output_path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Running-phase segmentation analysis")
    parser.add_argument("--running-trace", required=True, help="Analyze an existing trace for running-phase segmentation")
    parser.add_argument("--output", default="running_phase_report.json")
    parser.add_argument("--window-seconds", type=float, default=0.001)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--frequency-weight", type=float, default=0.5)
    parser.add_argument("--bigram-weight", type=float, default=0.5)
    args = parser.parse_args()

    return run_running_phase(
        args.running_trace,
        args.output,
        args.window_seconds,
        args.warmup,
        args.frequency_weight,
        args.bigram_weight,
    )


if __name__ == "__main__":
    raise SystemExit(main())
