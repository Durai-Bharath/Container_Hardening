from __future__ import annotations

import json
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence, Set

from dynamic_phase.docker_runner import ContainerResult, DockerRunner
from common.events import SyscallEvent
from dynamic_phase.profiler import DynamicProfiler
from dynamic_phase.tracee_collector import TraceeCollector
from static_analyzer.seccomp_generator import generate_oci_seccomp_profile


@dataclass(frozen=True)
class DynamicIteration:
    iteration: int
    phase: str
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
    missing_syscalls: tuple[str, ...] = ()
    unresolved_failure: str | None = None


class DynamicAnalysisController:
    def __init__(
        self,
        runner: DockerRunner | None = None,
        collector_factory: Callable[[], TraceeCollector] = TraceeCollector,
        profiler: DynamicProfiler | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.runner = runner or DockerRunner()
        self.collector_factory = collector_factory
        self.profiler = profiler or DynamicProfiler()
        self.timeout = timeout

    def analyze(
        self,
        image: str,
        static_syscalls: Iterable[str],
        command: Sequence[str],
        architecture: str = "x86_64",
    ) -> DynamicAnalysisResult:
        static = set(static_syscalls)
        iterations: list[DynamicIteration] = []
        with tempfile.TemporaryDirectory(prefix="dynamic-seccomp-") as directory:
            discovery_result, discovery_events = self._run_once(
                image, command, None
            )
            observed = self.profiler.profile(discovery_events).observed_syscalls
            missing = observed - static
            initialize = static | observed
            iterations.append(
                self._iteration(
                    1, "discovery", static, observed, discovery_result, missing
                )
            )

            profile = Path(directory) / "final.json"
            profile.write_text(
                generate_oci_seccomp_profile(initialize, architecture), encoding="utf-8"
            )
            validation_result, validation_events = self._run_once(
                image, command, str(profile)
            )
            validation_observed = self.profiler.profile(validation_events).observed_syscalls
            validation_missing = validation_observed - initialize
            iterations.append(
                self._iteration(
                    2,
                    "validation",
                    initialize,
                    validation_observed,
                    validation_result,
                    validation_missing,
                )
            )
            unresolved = None
            if validation_result.exit_code != 0 and not validation_result.timed_out:
                unresolved = validation_result.logs or (
                    f"restricted container exited with code {validation_result.exit_code}"
                )
        observed.update(validation_observed)
        return DynamicAnalysisResult(
            dynamic_syscalls=tuple(sorted(observed)),
            initialize_syscalls=tuple(sorted(initialize)),
            iterations=tuple(iterations),
            missing_syscalls=tuple(sorted(missing)),
            unresolved_failure=unresolved,
        )

    @staticmethod
    def _iteration(
        number: int,
        phase: str,
        candidate: Set[str],
        observed: Set[str],
        result: ContainerResult,
        missing: Set[str],
    ) -> DynamicIteration:
        return DynamicIteration(
            iteration=number,
            phase=phase,
            candidate_syscalls=tuple(sorted(candidate)),
            observed_syscalls=tuple(sorted(observed)),
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            added_syscall=sorted(missing)[0] if missing else None,
            logs=result.logs,
        )

    def _run_once(
        self,
        image: str,
        command: Sequence[str],
        seccomp_profile: str | None,
    ) -> tuple[ContainerResult, list[SyscallEvent]]:
        container_id = self.runner.create(image, seccomp_profile, command)
        collector = self.collector_factory()
        try:
            collector.start(container_id)
            self.runner.start(container_id)
            result = self.runner.wait(container_id, self.timeout, remove=False)
            events = collector.stop()
            self.runner.remove(container_id)
            return result, events
        except Exception:
            if collector.process is not None:
                collector.stop()
            self.runner.remove(container_id)
            raise