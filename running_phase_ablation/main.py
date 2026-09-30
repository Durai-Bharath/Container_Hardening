from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from common.events import load_events
from running_phase_ablation.analyzer import AblationRunningPhaseAnalyzer
from static_analyzer.seccomp_generator import generate_oci_seccomp_profile

DEFAULT_PROFILE_ROOT = Path("running-seccomp-ablation")


def _report_payload(result, trace_path: str, seccomp_path: str, include_windows: bool) -> dict:
    report = {
        "feature_mode": result.feature_mode,
        "segmentation_mode": result.segmentation_mode,
        "window_mode": result.window_mode,
        "events_per_window": result.events_per_window,
        "segmentation_index": result.segmentation_index,
        "segmentation_time": result.segmentation_time,
        "adaptive_threshold": result.adaptive_threshold,
        "change_point_score": result.change_point_score,
        "similarities": result.similarities,
        "dissimilarities": result.dissimilarities,
        "running_syscalls": result.running_syscalls,
        "syscall_vocabulary": result.syscall_vocabulary,
        "bigram_vocabulary": result.bigram_vocabulary,
        "trace_path": trace_path,
        "seccomp_profile": seccomp_path,
    }
    if include_windows:
        report["windows"] = [
            {
                "start": window.start,
                "end": window.end,
                "syscalls": window.syscalls,
                "frequency": window.frequency,
                "bigrams": window.bigrams,
                "vector": window.vector,
            }
            for window in result.windows
        ]
    else:
        report["window_count"] = len(result.windows)
    return report


def run_ablation(
    trace_path: str,
    output_path: str,
    window_seconds: float,
    similarity_threshold: float,
    stabilization_seconds: float,
    feature_mode: str,
    segmentation_mode: str,
    window_mode: str,
    events_per_window: int,
    stabilization_windows: int,
    pht_delta: float,
    pht_threshold: float | None,
    change_point_min_samples: int,
    bocpd_hazard: float,
    include_windows: bool,
    seccomp_output: str | None = None,
) -> int:
    events = list(load_events(trace_path))
    if not events:
        raise ValueError(f"trace contains no syscall events: {trace_path}")
    result = AblationRunningPhaseAnalyzer(
        window_seconds=window_seconds,
        similarity_threshold=similarity_threshold,
        stabilization_seconds=stabilization_seconds,
        feature_mode=feature_mode,
        segmentation_mode=segmentation_mode,
        window_mode=window_mode,
        events_per_window=events_per_window,
        stabilization_windows=stabilization_windows,
        pht_delta=pht_delta,
        pht_threshold=pht_threshold,
        change_point_min_samples=change_point_min_samples,
        bocpd_hazard=bocpd_hazard,
    ).analyze(events)
    if seccomp_output is None:
        report_name = Path(output_path).stem.replace("_running_phase_report", "")
        seccomp_output = str(
            DEFAULT_PROFILE_ROOT
            / window_mode
            / (str(events_per_window) if window_mode == "count" else str(window_seconds))
            / feature_mode
            / segmentation_mode
            / f"{report_name}_seccomp.json"
        )
    seccomp_path = Path(seccomp_output)
    seccomp_path.parent.mkdir(parents=True, exist_ok=True)
    seccomp_path.write_text(
        generate_oci_seccomp_profile(result.running_syscalls), encoding="utf-8"
    )
    report = _report_payload(result, trace_path, str(seccomp_path), include_windows)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"Generated ablation seccomp profile: {seccomp_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Running-phase feature ablation analysis")
    parser.add_argument("--running-trace", required=True)
    parser.add_argument("--output", default="running_phase_ablation_report.json")
    parser.add_argument("--window-seconds", type=float, default=0.001)
    parser.add_argument("--similarity-threshold", type=float, default=0.8)
    parser.add_argument("--stabilization-seconds", type=float, default=5.0)
    parser.add_argument(
        "--feature-mode",
        choices=("frequency", "bigram", "combined"),
        default="combined",
    )
    parser.add_argument(
        "--segmentation-mode",
        choices=("sustained", "first", "pht", "bocpd"),
        default="sustained",
    )
    parser.add_argument(
        "--window-mode",
        choices=("time", "count"),
        default="time",
        help="Use wall-clock windows or fixed syscall-count windows",
    )
    parser.add_argument(
        "--events-per-window",
        type=int,
        default=100,
        help="Syscalls per window when --window-mode=count",
    )
    parser.add_argument(
        "--stabilization-windows",
        type=int,
        default=5,
        help="Consecutive similar windows required in count mode",
    )
    parser.add_argument("--pht-delta", type=float, default=0.0)
    parser.add_argument("--pht-threshold", type=float, default=None)
    parser.add_argument("--change-point-min-samples", type=int, default=10)
    parser.add_argument("--bocpd-hazard", type=float, default=0.01)
    parser.add_argument(
        "--include-windows",
        action="store_true",
        help="Include every per-window vector in the report",
    )
    parser.add_argument("--seccomp-output", default=None)
    args = parser.parse_args()
    return run_ablation(
        trace_path=args.running_trace,
        output_path=args.output,
        window_seconds=args.window_seconds,
        similarity_threshold=args.similarity_threshold,
        stabilization_seconds=args.stabilization_seconds,
        feature_mode=args.feature_mode,
        segmentation_mode=args.segmentation_mode,
        window_mode=args.window_mode,
        events_per_window=args.events_per_window,
        stabilization_windows=args.stabilization_windows,
        pht_delta=args.pht_delta,
        pht_threshold=args.pht_threshold,
        change_point_min_samples=args.change_point_min_samples,
        bocpd_hazard=args.bocpd_hazard,
        include_windows=args.include_windows,
        seccomp_output=args.seccomp_output,
    )


if __name__ == "__main__":
    raise SystemExit(main())
