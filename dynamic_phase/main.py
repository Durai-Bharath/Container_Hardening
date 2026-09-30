from __future__ import annotations

import argparse
import json
from pathlib import Path
import shlex
import os
from typing import Set

from dynamic_phase.controller import DynamicAnalysisController
from dynamic_phase.docker_runner import DockerRunner
from dynamic_phase.tracee_collector import TraceeCollector
from static_analyzer.seccomp_generator import generate_oci_seccomp_profile


def _static_names(path: str | None) -> Set[str]:
    if not path:
        return set()

    payload = json.loads(Path(path).read_text(encoding="utf-8"))

    names: Set[str] = set()

    for syscall_group in payload.get("syscalls", []):
        names.update(
            name
            for name in syscall_group.get("names", [])
            if name
        )

    return names


def run_dynamic(
    image: str,
    static_report: str,
    command: str,
    timeout: float,
    baseline_syscalls: str | None = None,
    docker_command: str = "docker",
    docker_opts: str = "",
) -> int:
    static_names = _static_names(static_report)
    
    if baseline_syscalls:
        baseline = json.loads(Path(baseline_syscalls).read_text(encoding="utf-8"))
        static_names.update(baseline)
        
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
        timeout=timeout,
    ).analyze(image, static_names, shlex.split(command), docker_opts=shlex.split(docker_opts))
    
    if result.unresolved_failure:
        print(f"Validation failed: {result.unresolved_failure}")
        return 1

    if not result.dynamic_syscalls:
        print("No dynamic syscalls captured, zero events observed.")
        return 1

    image_name = image.split('/')[-1].split(':')[0]
    filename = f"{image_name}_seccomp.json"
    
    os.makedirs("dynamic-seccomp", exist_ok=True)
    os.makedirs("initialize-seccomp", exist_ok=True)
    
    dynamic_seccomp = generate_oci_seccomp_profile(result.dynamic_syscalls, "x86_64")
    Path(f"dynamic-seccomp/{filename}").write_text(dynamic_seccomp, encoding="utf-8")
    
    initialize_seccomp = generate_oci_seccomp_profile(result.initialize_syscalls, "x86_64")
    Path(f"initialize-seccomp/{filename}").write_text(initialize_seccomp, encoding="utf-8")
    
    print(f"Generated seccomp profiles: dynamic-seccomp/{filename} and initialize-seccomp/{filename}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Dynamic syscall profiling")
    parser.add_argument("--image", required=True, help="Container image for Tracee-backed analysis")
    parser.add_argument("--static-report", required=True, help="Static analyzer JSON report")
    parser.add_argument("--command", required=True, help="Workload command executed inside the image")
    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help=(
            "Seconds to profile each run. Daemons such as nginx never exit, so "
            "the window ending is expected and is not a failed iteration."
        ),
    )
    parser.add_argument(
        "--baseline-syscalls",
        default=None,
        help="Path to JSON array of baseline syscalls to inject",
    )
    parser.add_argument("--docker-opts", default="", help="Additional options for docker create (e.g., -e MYSQL_ROOT_PASSWORD=root)")
    parser.add_argument("--docker-command", default="docker")
    args = parser.parse_args()
    
    return run_dynamic(
        args.image,
        args.static_report,
        args.command,
        args.timeout,
        args.baseline_syscalls,
        args.docker_command,
        args.docker_opts,
    )


if __name__ == "__main__":
    raise SystemExit(main())