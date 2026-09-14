from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Optional, Sequence


class DockerError(RuntimeError):
    pass


@dataclass(frozen=True)
class ContainerResult:
    container_id: str
    exit_code: int
    logs: str
    timed_out: bool = False


class DockerRunner:
    def __init__(self, docker_command: Sequence[str] = ("docker",)) -> None:
        self.docker_command = tuple(docker_command)

    def create(self, image: str, seccomp_profile: str, command: Sequence[str]) -> str:
        args = [
            *self.docker_command,
            "create",
            # "--security-opt",
            # f"seccomp={seccomp_profile}",
            image,
            *command,
        ]
        result = self._run(args)
        return result.stdout.strip()

    def start(self, container_id: str) -> None:
        """Start a created container without waiting for it to finish."""
        result = subprocess.run(
            [*self.docker_command, "start", container_id],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise DockerError(f"Docker start failed: {detail}")

    def wait(self, container_id: str, timeout: float, remove: bool = True) -> ContainerResult:
        """Wait for an already-running container to exit."""
        try:
            wait = subprocess.run(
                [*self.docker_command, "wait", container_id],
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            exit_code = int(wait.stdout.strip())
            logs = subprocess.run(
                [*self.docker_command, "logs", container_id],
                check=False,
                capture_output=True,
                text=True,
            )
            return ContainerResult(container_id, exit_code, logs.stdout + logs.stderr)
        except subprocess.TimeoutExpired:
            self.kill(container_id)
            return ContainerResult(container_id, -1, "container execution timed out", True)
        except (OSError, subprocess.CalledProcessError, DockerError, ValueError) as exc:
            raise DockerError(f"container execution failed: {exc}") from exc
        finally:
            if remove:
                self.remove(container_id)

    def start_and_wait(self, container_id: str, timeout: float, remove: bool = True) -> ContainerResult:
        """Convenience: start then wait."""
        self.start(container_id)
        return self.wait(container_id, timeout, remove)

    def kill(self, container_id: str) -> None:
        subprocess.run([*self.docker_command, "kill", container_id], check=False, capture_output=True)

    def remove(self, container_id: str) -> None:
        subprocess.run([*self.docker_command, "rm", "-f", container_id], check=False, capture_output=True)

    def _run(self, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(command, check=True, capture_output=True, text=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            if isinstance(exc, subprocess.CalledProcessError):
                detail = (exc.stderr or exc.stdout or "").strip()
                raise DockerError(f"Docker command failed: {detail or exc}") from exc
            raise DockerError(f"Docker command failed: {exc}") from exc
