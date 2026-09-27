from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from common.events import load_events
from running_phase.analyzer import RunningPhaseAnalyzer
from static_analyzer.seccomp_generator import generate_oci_seccomp_profile


def run_running_phase(
    trace_path: str,
    output_path: str,
    window_seconds: float,
    similarity_threshold: float,
    stabilization_seconds: float,
    seccomp_output: str | None = None,
) -> int:
    events = list(load_events(trace_path))
    result = RunningPhaseAnalyzer(
        window_seconds=window_seconds,
        similarity_threshold=similarity_threshold,
        stabilization_seconds=stabilization_seconds,
    ).analyze(events)
    payload = asdict(result)
    payload["windows"] = [asdict(window) for window in result.windows]
    Path(output_path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if seccomp_output is None:
        report_name = Path(output_path).stem.replace("_running_phase_report", "")
        seccomp_output = str(Path("running-seccomp") / f"{report_name}_seccomp.json")
    seccomp_path = Path(seccomp_output)
    seccomp_path.parent.mkdir(parents=True, exist_ok=True)
    seccomp_path.write_text(
        generate_oci_seccomp_profile(result.running_syscalls), encoding="utf-8"
    )
    print(json.dumps(payload, indent=2))
    print(f"Generated running-phase seccomp profile: {seccomp_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Running-phase segmentation analysis")
    parser.add_argument("--running-trace", required=True, help="Analyze an existing trace for running-phase segmentation")
    parser.add_argument("--output", default="running_phase_report.json")
    parser.add_argument("--window-seconds", type=float, default=0.001)
    parser.add_argument("--similarity-threshold", type=float, default=0.8)
    parser.add_argument("--stabilization-seconds", type=float, default=5.0)
    parser.add_argument(
        "--seccomp-output",
        default=None,
        help="Output path for the running-phase OCI seccomp profile",
    )
    args = parser.parse_args()

    return run_running_phase(
        args.running_trace,
        args.output,
        args.window_seconds,
        args.similarity_threshold,
        args.stabilization_seconds,
        args.seccomp_output,
    )


if __name__ == "__main__":
    raise SystemExit(main())
