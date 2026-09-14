from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import uuid
from typing import Any, Mapping, Optional, Sequence

from common.events import SyscallEvent


class TraceeError(RuntimeError):
    pass


class TraceeCollector:
    """Run Aqua Security Tracee and parse its JSON syscall stream."""

    def __init__(
        self,
        tracee_image: str = "aquasec/tracee:latest",
        docker_command: Sequence[str] = ("docker",),
        privileged: bool = True,
        startup_timeout: float = 90.0,
        startup_settle: float = 2.0,
    ) -> None:
        self.tracee_image = tracee_image
        self.docker_command = tuple(docker_command)
        self.privileged = privileged
        self.startup_timeout = startup_timeout
        self.startup_settle = startup_settle
        self.process: Optional[subprocess.Popen[str]] = None
        self._stdout_path: Optional[str] = None
        self._stderr_path: Optional[str] = None
        self._container_id: Optional[str] = None
        self._run_name = f"tracee-{uuid.uuid4().hex[:12]}"

    def start(self, container_id: str | None = None) -> None:
        """Start Tracee before the target so initialization syscalls are captured.

        Scope is ``container=new`` because filtering by ID does not work for
        containers that already exist when Tracee attaches. Events are later
        restricted to ``container_id`` when it is known.
        """
        self._container_id = container_id
        command = [*self.docker_command, "run", "--name", self._run_name, "--rm"]
        if self.privileged:
            command.append("--privileged")
        command.extend(
            [
                "--pid=host",
                "--cgroupns=host",
                "-v",
                "/etc/os-release:/etc/os-release-host:ro",
                "-e",
                "LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host",
                "-v",
                "/lib/modules/:/lib/modules:ro",
                "-v",
                "/usr/src:/usr/src:ro",
                "-v",
                "/var/run/docker.sock:/var/run/docker.sock",
                self.tracee_image,
                "--scope",
                "container=new",
                "--events",
                "syscalls",
                "--output",
                "json",
            ]
        )
        try:
            stdout_handle = tempfile.NamedTemporaryFile(mode="w", delete=False)
            stderr_handle = tempfile.NamedTemporaryFile(mode="w", delete=False)
            self._stdout_path = stdout_handle.name
            self._stderr_path = stderr_handle.name
            self.process = subprocess.Popen(
                command,
                stdout=stdout_handle,
                stderr=stderr_handle,
                text=True,
                bufsize=1,
            )
            stdout_handle.close()
            stderr_handle.close()
        except OSError as exc:
            raise TraceeError(f"unable to start Tracee: {exc}") from exc
        self._wait_until_ready()

    def bind(self, container_id: str) -> None:
        """Remember the target container so stop() can drop other new-container events."""
        self._container_id = container_id

    def stop(self) -> list[SyscallEvent]:
        if self.process is None:
            return []
        self.process.terminate()
        try:
            self.process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.communicate()
        stdout = self._read_output(self._stdout_path)
        stderr = self._read_output(self._stderr_path)
        self._remove_output_files()
        self.process = None
        events = []
        for line in stdout.splitlines():
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            if not self._matches_container(payload):
                continue
            try:
                events.append(SyscallEvent.from_mapping(payload))
            except (TypeError, ValueError):
                continue
        return events

    def _wait_until_ready(self) -> None:
        if self.process is None:
            raise TraceeError("Tracee process was not started")
        started = time.monotonic()
        deadline = started + self.startup_timeout
        saw_ready = False
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                stderr = self._read_output(self._stderr_path)
                raise TraceeError(f"Tracee exited during startup: {stderr.strip()}")
            stderr = self._read_output(self._stderr_path)
            elapsed = time.monotonic() - started
            if self._looks_ready(stderr):
                saw_ready = True
            if saw_ready and elapsed >= self.startup_settle:
                return
            if elapsed >= max(self.startup_settle, 8.0) and self.process.poll() is None:
                return
            time.sleep(0.1)
        if self.process.poll() is not None:
            stderr = self._read_output(self._stderr_path)
            raise TraceeError(f"Tracee exited during startup: {stderr.strip()}")

    @staticmethod
    def _looks_ready(stderr: str) -> bool:
        lowered = stderr.lower()
        markers = (
            "tracee is ready",
            "start: probing",
            "probing started",
            "loaded bpf",
            "bpf loaded",
            "tracing started",
        )
        return any(marker in lowered for marker in markers)

    def _matches_container(self, payload: Mapping[str, Any]) -> bool:
        expected = (self._container_id or "").strip()
        if not expected:
            return True
        actual = _container_id_from_payload(payload)
        if not actual:
            return False
        return expected.startswith(actual) or actual.startswith(expected[:12])

    @staticmethod
    def _read_output(path: Optional[str]) -> str:
        if not path:
            return ""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                return handle.read()
        except OSError:
            return ""

    def _remove_output_files(self) -> None:
        for path in (self._stdout_path, self._stderr_path):
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass
        self._stdout_path = None
        self._stderr_path = None


def _container_id_from_payload(payload: Mapping[str, Any]) -> str:
    container = payload.get("container")
    if isinstance(container, Mapping):
        for key in ("id", "containerId", "container_id"):
            value = container.get(key)
            if value:
                return str(value)
    for key in ("containerId", "container_id"):
        value = payload.get(key)
        if value:
            return str(value)
    return ""
