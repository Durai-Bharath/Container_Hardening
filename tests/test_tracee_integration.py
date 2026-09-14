import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(
    os.environ.get("RUN_TRACE_INTEGRATION") == "1",
    "set RUN_TRACE_INTEGRATION=1 to run the real Docker/Tracee integration test",
)
class TraceeIntegrationTests(unittest.TestCase):
    def test_real_tracee_dynamic_analysis(self):
        docker_command = os.environ.get("DYNAMIC_DOCKER_COMMAND", "docker")
        docker_binary = docker_command.split()[0]
        if shutil.which(docker_binary) is None:
            self.skipTest(f"Docker command not found: {docker_binary}")
        with tempfile.TemporaryDirectory() as directory:
            static_report = Path(directory) / "static.json"
            output = Path(directory) / "dynamic.json"
            profile_path = Path(__file__).parents[1] / "static-seccomp" / "nginx_seccomp.json"
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            static_names = {
                name
                for group in profile.get("syscalls", [])
                for name in group.get("names", [])
            }
            static_names.update(
                {
                    "brk",
                    "execve",
                    "fstatfs",
                    "futex",
                    "getrandom",
                    "mmap",
                    "mprotect",
                    "munmap",
                    "openat",
                    "prctl",
                    "read",
                    "rt_sigaction",
                    "rt_sigprocmask",
                    "set_robust_list",
                    "set_tid_address",
                    "write",
                }
            )
            default_profile = json.loads(
                (Path(__file__).parents[1] / "deault-seccomp.json").read_text(encoding="utf-8")
            )
            static_names.update(
                name
                for group in default_profile.get("syscalls", [])
                for name in group.get("names", [])
            )
            static_report.write_text(
                json.dumps(
                    {
                        "binaries": [
                            {
                                "final_unique_syscalls": [
                                    [index, name] for index, name in enumerate(sorted(static_names))
                                ]
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            command = [
                "python3",
                "-m",
                "dynamic_phase.main",
                "--image",
                os.environ.get("DYNAMIC_TEST_IMAGE", "alpine:3.20"),
                "--command",
                "true",
                "--static-report",
                str(static_report),
                "--output",
                str(output),
                "--max-iterations",
                "3",
                "--timeout",
                "30",
                "--docker-command",
                docker_command,
            ]
            subprocess.run(command, check=True)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(payload["iterations"]), 1)
            self.assertIn("dynamic_syscalls", payload)
