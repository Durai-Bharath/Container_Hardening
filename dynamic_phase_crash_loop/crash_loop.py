
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Iterable, Sequence

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from common.events import SyscallEvent
from dynamic_phase.tracee_collector import TraceeCollector

WORKLOAD_RUNNER = Path(__file__).with_name("workload-runner") / "workload_runner.py"
LOG_ACTION = "SCMP_ACT_LOG"


def _syscalls_from_payload(payload: object) -> set[str]:
    if isinstance(payload, list):
        return {str(value) for value in payload if value}
    if not isinstance(payload, dict):
        return set()
    names: set[str] = set()
    for group in payload.get("syscalls", []):
        if isinstance(group, dict) and group.get("action", "SCMP_ACT_ALLOW") == "SCMP_ACT_ALLOW":
            names.update(str(name) for name in group.get("names", []) if name)
    if not names:
        for binary in payload.get("binaries", []):
            if isinstance(binary, dict):
                names.update(str(name) for name in binary.get("final_unique_syscalls", []) if name)
    return names


def load_static_syscalls(path: str) -> set[str]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    names = _syscalls_from_payload(payload)
    if not names:
        raise ValueError(f"{path} contains no resolved syscall names")
    return names


def complain_profile(names: Iterable[str], architecture: str = "x86_64") -> dict:
    architectures = {
        "x86_64": "SCMP_ARCH_X86_64", "x86": "SCMP_ARCH_X86",
        "aarch64": "SCMP_ARCH_AARCH64", "arm": "SCMP_ARCH_ARM",
    }
    return {
        "defaultAction": LOG_ACTION,
        "architectures": [architectures.get(architecture, "SCMP_ARCH_X86_64")],
        "syscalls": [{"names": sorted(set(names)), "action": "SCMP_ACT_ALLOW"}],
    }


def enforcing_profile(names: Iterable[str], architecture: str = "x86_64") -> dict:
    profile = complain_profile(names, architecture)
    profile["defaultAction"] = "SCMP_ACT_ERRNO"
    return profile


def _run_command(command: Sequence[str], timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)


def run_loop(
    image: str, static_seccomp: str, output: str, config: str,
    max_iterations: int = 10, clean_passes: int = 2,
    readiness_timeout: int = 60, workload_timeout: int = 90,
    architecture: str = "x86_64",
    environment: Sequence[str] = (),
    collector_factory: Callable[[], TraceeCollector] = TraceeCollector,
) -> dict:
    static = load_static_syscalls(static_seccomp)
    candidate = set(static)
    dynamic_observed: set[str] = set()
    passes: list[dict] = []
    clean_count = 0
    with tempfile.TemporaryDirectory(prefix="seccomp-crash-loop-") as temp_dir:
        for iteration in range(1, max_iterations + 1):
            profile_path = Path(temp_dir) / f"candidate-{iteration}.json"
            metadata_path = Path(temp_dir) / f"metadata-{iteration}.json"
            profile_path.write_text(json.dumps(complain_profile(candidate, architecture), indent=2) + "\n", encoding="utf-8")
            command = [
                sys.executable, str(WORKLOAD_RUNNER), "--image", image,
                "--seccomp-profile", str(profile_path), "--config", config,
                "--timeout", str(readiness_timeout), "--workload-timeout", str(workload_timeout),
                "--metadata-file", str(metadata_path),
            ]
            for value in environment:
                command.extend(("--env", value))
            collector = collector_factory()
            try:
                collector.start()
            except Exception:
                if collector.process is not None:
                    collector.stop()
                raise
            try:
                workload = _run_command(command, timeout=readiness_timeout + workload_timeout + 30)
                if not metadata_path.exists():
                    raise RuntimeError(
                        f"workload pass {iteration} did not produce target identity"
                    )
                identity = json.loads(metadata_path.read_text(encoding="utf-8"))
                container_id = identity.get("container_id")
                if not isinstance(container_id, str) or not container_id:
                    raise RuntimeError(f"workload pass {iteration} returned invalid target identity")
                collector.bind(container_id)
            finally:
                events = collector.stop()
            discovered = {
                event.syscall for event in events
                if isinstance(event, SyscallEvent) and event.syscall
            }
            dynamic_observed.update(discovered)
            added = sorted(discovered - candidate)
            candidate.update(discovered)
            print(
                f"Iteration {iteration}: new syscalls={added or 'none'} "
                f"candidate_count={len(candidate)}",
                flush=True,
            )
            passes.append({
                "iteration": iteration, "workload_exit_code": workload.returncode,
                "workload_stdout": workload.stdout, "workload_stderr": workload.stderr,
                "observed_syscalls": sorted(discovered), "added_syscalls": added,
                "target_identity": identity,
            })
            if workload.returncode != 0:
                detail = (workload.stderr or workload.stdout).strip()
                raise RuntimeError(
                    f"workload failed on pass {iteration}"
                    + (f": {detail}" if detail else "")
                )
            clean_count = clean_count + 1 if not added else 0
            if clean_count >= clean_passes:
                break
        else:
            raise RuntimeError(f"did not converge after {max_iterations} passes")

    image_name = image.rsplit("/", 1)[-1].split(":", 1)[0]
    dynamic_profile = Path("dynamic-seccomp") / f"{image_name}_seccomp.json"
    initialize_profile = Path("initialize-seccomp") / f"{image_name}_seccomp.json"
    dynamic_profile.parent.mkdir(parents=True, exist_ok=True)
    initialize_profile.parent.mkdir(parents=True, exist_ok=True)
    dynamic_profile.write_text(
        json.dumps(enforcing_profile(dynamic_observed, architecture), indent=2) + "\n",
        encoding="utf-8",
    )
    initialize_profile.write_text(
        json.dumps(enforcing_profile(candidate, architecture), indent=2) + "\n",
        encoding="utf-8",
    )
    result = {
        "static_syscalls": sorted(static),
        "dynamic_syscalls": sorted(dynamic_observed),
        "initialize_syscalls": sorted(candidate),
        "iterations": passes,
        "dynamic_seccomp_profile": str(dynamic_profile),
        "initialize_seccomp_profile": str(initialize_profile),
    }
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--static-seccomp", required=True, help="static OCI seccomp profile")
    parser.add_argument("--output", default="dynamic_phase_crash_loop_report.json")
    parser.add_argument("--config", default=str(WORKLOAD_RUNNER.with_name("workloads.yaml")))
    parser.add_argument("--max-iterations", type=int, default=10)
    parser.add_argument("--clean-passes", type=int, default=2)
    parser.add_argument("--readiness-timeout", type=int, default=60)
    parser.add_argument("--workload-timeout", type=int, default=90)
    parser.add_argument("--tracee-docker-command", default="docker")
    parser.add_argument("--env", action="append", default=[],
                        help="target container environment variable (KEY=VALUE)")
    parser.add_argument("--architecture", default="x86_64")
    args = parser.parse_args()
    try:
        tracee_docker = tuple(shlex.split(args.tracee_docker_command))
        run_loop(image=args.image, static_seccomp=args.static_seccomp, output=args.output,
                 config=args.config, max_iterations=args.max_iterations,
                 clean_passes=args.clean_passes, readiness_timeout=args.readiness_timeout,
                 workload_timeout=args.workload_timeout,
                 architecture=args.architecture,
                 environment=args.env,
                 collector_factory=lambda: TraceeCollector(
                     docker_command=tracee_docker,
                     startup_timeout=90.0,
                     startup_settle=2.0,
                 ))
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"dynamic crash loop failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())