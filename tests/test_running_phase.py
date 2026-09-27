import json
import tempfile
import unittest
from pathlib import Path

from common.events import SyscallEvent
from running_phase.analyzer import RunningPhaseAnalyzer
from running_phase.main import run_running_phase


class RunningPhaseTests(unittest.TestCase):
    def test_frequency_feature_ignores_syscall_order(self):
        analyzer = RunningPhaseAnalyzer(window_seconds=1)
        result = analyzer.analyze(
            [
                SyscallEvent(0.0, "read"),
                SyscallEvent(0.1, "write"),
                SyscallEvent(1.0, "write"),
                SyscallEvent(1.1, "read"),
            ]
        )

        self.assertAlmostEqual(result.dissimilarities[0], 0.0)
        self.assertEqual(result.windows[0].frequency, result.windows[1].frequency)
        self.assertNotIn("bigrams", result.windows[0].__dict__)

    def test_run_writes_report_and_running_seccomp_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trace_path = root / "trace.jsonl"
            report_path = root / "mysql_running_phase_report.json"
            profile_path = root / "running-seccomp" / "mysql_seccomp.json"
            trace_path.write_text(
                "\n".join(
                    [
                        json.dumps({"timestamp": 0.0, "syscall": "read"}),
                        json.dumps({"timestamp": 0.1, "syscall": "write"}),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            run_running_phase(
                str(trace_path),
                str(report_path),
                1.0,
                0.8,
                5.0,
                str(profile_path),
            )

            report = json.loads(report_path.read_text(encoding="utf-8"))
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            self.assertIn("frequency", report["windows"][0])
            self.assertNotIn("bigrams", report["windows"][0])
            self.assertEqual(profile["defaultAction"], "SCMP_ACT_ERRNO")
            self.assertEqual(profile["syscalls"][0]["names"], ["read", "write"])


if __name__ == "__main__":
    unittest.main()
