from __future__ import annotations

import argparse
import json
from pathlib import Path
import shlex
from dataclasses import asdict
from typing import Set

from dynamic_phase.controller import DynamicAnalysisController, write_result
from dynamic_phase.docker_runner import DockerRunner
from dynamic_phase.events import load_events
from dynamic_phase.profiler import DynamicProfiler
from dynamic_phase.running_phase import AdaptivePageHinkley, RunningPhaseAnalyzer
from dynamic_phase.tracee_collector import TraceeCollector


def _static_names(path: str | None) -> Set[str]:
    if not path:
        return set()
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    names: Set[str] = set()
    for binary in payload.get("binaries", []):
        names.update(name for _, name in binary.get("final_unique_syscalls", []) if name)
    return names


def run_dynamic_trace(trace_path: str, static_report: str | None, output_path: str) -> int:
    events = list(load_events(trace_path))
    static_names = _static_names(static_report)
    profile = DynamicProfiler().profile(events, static_names)
    payload = {
        "event_count": profile.event_count,
        "dynamic_syscalls": sorted(profile.observed_syscalls),
        "initialize_syscalls": sorted(profile.initialize_syscalls),
    }
    Path(output_path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0


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


def run_dynamic(
    image: str,
    static_report: str,
    command: str,
    output_path: str,
    max_iterations: int,
    timeout: float,
    docker_command: str = "docker",
) -> int:
    static_names = _static_names(static_report)
    if not static_names:
        raise ValueError("static report contains no resolved syscall names")
    docker_args = shlex.split(docker_command)
    result = DynamicAnalysisController(
        runner=DockerRunner(docker_command=docker_args),
        collector_factory=lambda: TraceeCollector(
            docker_command=docker_args,
            startup_timeout=90.0,
            startup_settle=2.0,
        ),
        max_iterations=max_iterations,
        timeout=timeout,
    ).analyze(image, static_names, shlex.split(command))
    write_result(result, output_path)
    print(json.dumps({"output": output_path, "iterations": len(result.iterations)}, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Dynamic syscall profiling and running-phase analysis")
    parser.add_argument("--trace", help="Profile an existing newline-delimited JSON trace")
    parser.add_argument("--running-trace", help="Analyze an existing trace for running-phase segmentation")
    parser.add_argument("--image", help="Container image for Tracee-backed analysis")
    parser.add_argument("--static-report", help="Static analyzer JSON report")
    parser.add_argument("--command", default="", help="Workload command executed inside the image")
    parser.add_argument("--output", default="dynamic_phase_report.json")
    parser.add_argument("--window-seconds", type=float, default=0.001)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--frequency-weight", type=float, default=0.5)
    parser.add_argument("--bigram-weight", type=float, default=0.5)
    parser.add_argument("--max-iterations", type=int, default=10)
    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help=(
            "Seconds to profile each run. Daemons such as nginx never exit, so "
            "the window ending is expected and is not a failed iteration."
        ),
    )
    parser.add_argument("--docker-command", default="docker")
    args = parser.parse_args()
    selected = sum(bool(value) for value in (args.trace, args.running_trace, args.image))
    if selected > 1:
        parser.error("choose exactly one of --trace, --running-trace, or --image")
    if args.trace:
        return run_dynamic_trace(args.trace, args.static_report, args.output)
    if args.running_trace:
        return run_running_phase(
            args.running_trace,
            args.output,
            args.window_seconds,
            args.warmup,
            args.frequency_weight,
            args.bigram_weight,
        )
    if not args.image:
        parser.error("--image is required for dynamic analysis")
    if not args.static_report:
        parser.error("--static-report is required for dynamic analysis")
    if not args.command:
        parser.error("--command is required for dynamic analysis")
    return run_dynamic(
        args.image,
        args.static_report,
        args.command,
        args.output,
        args.max_iterations,
        args.timeout,
        args.docker_command,
    )


if __name__ == "__main__":
    raise SystemExit(main())