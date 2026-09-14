from __future__ import annotations

import json
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence, Set

from dynamic_phase.docker_runner import ContainerResult, DockerRunner
from dynamic_phase.events import SyscallEvent
from dynamic_phase.profiler import DynamicProfiler
from dynamic_phase.tracee_collector import TraceeCollector
from static_analyzer.seccomp_generator import generate_oci_seccomp_profile


@dataclass(frozen=True)
class DynamicIteration:
    iteration: int
    candidate_syscalls: tuple[str, ...]
    observed_syscalls: tuple[str, ...]
    exit_code: int
    timed_out: bool
    added_syscall: str | None
    logs: str


@dataclass(frozen=True)
class DynamicAnalysisResult:
    dynamic_syscalls: tuple[str, ...]
    initialize_syscalls: tuple[str, ...]
    iterations: tuple[DynamicIteration, ...]
    unresolved_failure: str | None = None


class DynamicAnalysisController:
    def __init__(
        self,
        runner: DockerRunner | None = None,
        collector_factory: Callable[[], TraceeCollector] = TraceeCollector,
        profiler: DynamicProfiler | None = None,
        max_iterations: int = 10,
        timeout: float = 60.0,
    ) -> None:
        self.runner = runner or DockerRunner()
        self.collector_factory = collector_factory
        self.profiler = profiler or DynamicProfiler()
        self.max_iterations = max_iterations
        self.timeout = timeout

    def analyze(
        self,
        image: str,
        static_syscalls: Iterable[str],
        command: Sequence[str],
        architecture: str = "x86_64",
    ) -> DynamicAnalysisResult:
        candidate = set(static_syscalls)
        observed: Set[str] = set()
        iterations = []
        unresolved: str | None = None
        with tempfile.TemporaryDirectory(prefix="dynamic-seccomp-") as directory:
            for number in range(1, self.max_iterations + 1):
                profile = Path(directory) / f"candidate-{number}.json"
                print(profile)
                profile.write_text(
                    generate_oci_seccomp_profile(candidate, architecture), encoding="utf-8"
                )
                container_id = self.runner.create(image, str(profile), command)
                collector = self.collector_factory()
                try:
                    # Tracee must be ready before the target starts to capture initialization.
                    collector.start(container_id)
                    self.runner.start(container_id)
                    result = self.runner.wait(container_id, self.timeout, remove=False)
                    events = collector.stop()
                    self.runner.remove(container_id)
                except Exception:
                    if collector.process is not None:
                        collector.stop()
                    self.runner.remove(container_id)
                    raise
                current = self.profiler.profile(events).observed_syscalls
                observed.update(current)
                added = self._find_missing_syscall(current, candidate)
                iterations.append(
                    DynamicIteration(
                        iteration=number,
                        candidate_syscalls=tuple(sorted(candidate)),
                        observed_syscalls=tuple(sorted(current)),
                        exit_code=result.exit_code,
                        timed_out=result.timed_out,
                        added_syscall=added,
                        logs=result.logs,
                    )
                )
                if result.exit_code == 0 and not result.timed_out and added is None:
                    break
                if result.timed_out and added is None:
                    # Daemon workload: container ran until timeout with all observed
                    # syscalls already in the candidate set — treat as clean success.
                    break
                if added is None:
                    unresolved = result.logs or f"container exited with code {result.exit_code}"
                    break
                candidate.add(added)
        initialize = candidate | observed
        return DynamicAnalysisResult(
            dynamic_syscalls=tuple(sorted(observed)),
            initialize_syscalls=tuple(sorted(initialize)),
            iterations=tuple(iterations),
            unresolved_failure=unresolved,
        )

    @staticmethod
    def _find_missing_syscall(observed: Set[str], candidate: Set[str]) -> str | None:
        missing = sorted(observed - candidate)
        return missing[0] if missing else None


def write_result(result: DynamicAnalysisResult, path: str) -> None:
    Path(path).write_text(json.dumps(asdict(result), indent=2) + "\n", encoding="utf-8")