import json
import tempfile
import unittest

from dynamic_phase.controller import DynamicAnalysisController
from dynamic_phase.docker_runner import ContainerResult
from dynamic_phase.events import SyscallEvent, load_events
from dynamic_phase.profiler import DynamicProfiler
from dynamic_phase.running_phase import AdaptivePageHinkley, RunningPhaseAnalyzer
from dynamic_phase.tracee_collector import TraceeCollector


class DynamicPhaseTests(unittest.TestCase):
    def test_event_loader_normalizes_and_sorts_jsonl(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write(json.dumps({"time": 2, "name": "write", "args": [1]}) + "\n")
            handle.write(json.dumps({"timestamp": 1, "syscall": "read"}) + "\n")
            path = handle.name

        events = list(load_events(path))
        self.assertEqual([event.syscall for event in events], ["read", "write"])
        self.assertEqual(events[1].arguments, (1,))

    def test_dynamic_profile_builds_dsf_and_isf(self):
        events = [SyscallEvent(0.0, "read"), SyscallEvent(0.1, "write"), SyscallEvent(0.2, "read")]
        profile = DynamicProfiler().profile(events, {"read", "open"})
        self.assertEqual(profile.event_count, 3)
        self.assertEqual(profile.observed_syscalls, {"read", "write"})
        self.assertEqual(profile.initialize_syscalls, {"read", "write", "open"})

    def test_bigram_features_distinguish_order(self):
        analyzer = RunningPhaseAnalyzer(window_seconds=10)
        first = analyzer.extract_features(
            [SyscallEvent(0, "read"), SyscallEvent(1, "write")]
        )[0]
        second = analyzer.extract_features(
            [SyscallEvent(0, "write"), SyscallEvent(1, "read")]
        )[0]
        self.assertNotEqual(first.bigrams, second.bigrams)

    def test_page_hinkley_detects_adaptive_upward_change(self):
        detector = AdaptivePageHinkley(warmup=4, threshold_factor=2, delta=0.0)
        self.assertEqual(detector.detect([0.1, 0.11, 0.09, 0.1, 1.0, 1.0]), 4)

    def test_running_phase_falls_back_to_all_observed_syscalls(self):
        result = RunningPhaseAnalyzer(window_seconds=1).analyze(
            [SyscallEvent(0.0, "read"), SyscallEvent(0.1, "write")]
        )
        self.assertIsNone(result.segmentation_index)
        self.assertEqual(result.running_syscalls, ("read", "write"))

    def test_dynamic_and_running_phase_outputs_are_separate(self):
        from dynamic_phase.main import run_dynamic_trace, run_running_phase

        with tempfile.NamedTemporaryFile("w", delete=False) as trace:
            trace.write(json.dumps({"timestamp": 0, "syscall": "read"}) + "\n")
            trace.write(json.dumps({"timestamp": 1, "syscall": "write"}) + "\n")
            trace_path = trace.name
        with tempfile.NamedTemporaryFile(delete=False) as dynamic_output:
            dynamic_path = dynamic_output.name
        with tempfile.NamedTemporaryFile(delete=False) as running_output:
            running_path = running_output.name

        run_dynamic_trace(trace_path, None, dynamic_path)
        run_running_phase(trace_path, running_path, 1, 5, 0.5, 0.5)
        dynamic_payload = json.loads(open(dynamic_path, encoding="utf-8").read())
        running_payload = json.loads(open(running_path, encoding="utf-8").read())
        self.assertIn("dynamic_syscalls", dynamic_payload)
        self.assertNotIn("segmentation_index", dynamic_payload)
        self.assertIn("segmentation_index", running_payload)
        self.assertNotIn("dynamic_syscalls", running_payload)


class FakeCollector:
    def __init__(self, event_batches: list[list[SyscallEvent]]):
        self.event_batches = list(event_batches)
        self.process = object()
        self.started = False
        self.bound: list[str] = []

    def start(self, container_id: str | None = None) -> None:
        self.started = True
        if container_id:
            self.bound.append(container_id)

    def bind(self, container_id: str) -> None:
        self.bound.append(container_id)

    def stop(self) -> list[SyscallEvent]:
        self.process = None
        return self.event_batches.pop(0)


class FakeRunner:
    def __init__(self, results: list[ContainerResult]):
        self.results = list(results)
        self.created: list[str] = []
        self.started: list[str] = []

    def create(self, image: str, profile: str, command) -> str:
        ident = f"container-{len(self.created) + 1}"
        self.created.append(ident)
        return ident

    def start(self, container_id: str) -> None:
        self.started.append(container_id)

    def wait(self, container_id: str, timeout: float, remove: bool = True, kill_on_timeout: bool = True):
        return self.results.pop(0)

    def remove(self, container_id: str) -> None:
        return None


class ControllerLoopTests(unittest.TestCase):
    def test_daemon_discovery_is_followed_by_restricted_validation(self):
        runner = FakeRunner(
            [
                ContainerResult("container-1", -1, "profiling window elapsed; container still running", True),
                ContainerResult("container-2", -1, "profiling window elapsed; container still running", True),
            ]
        )
        collector_runs = [
            [SyscallEvent(1.0, "read"), SyscallEvent(1.1, "write")],
            [SyscallEvent(2.0, "read"), SyscallEvent(2.1, "write")],
        ]

        def factory() -> FakeCollector:
            return FakeCollector([collector_runs.pop(0)])

        result = DynamicAnalysisController(
            runner=runner,
            collector_factory=factory,
            max_iterations=5,
            timeout=1.0,
        ).analyze("nginx:latest", {"read", "write", "open"}, ["nginx"])
        self.assertEqual(len(result.iterations), 2)
        self.assertEqual(result.iterations[0].phase, "discovery")
        self.assertEqual(result.iterations[1].phase, "validation")
        self.assertTrue(result.iterations[0].timed_out)
        self.assertIsNone(result.iterations[0].added_syscall)
        self.assertTrue(result.iterations[1].timed_out)
        self.assertIsNone(result.unresolved_failure)
        self.assertEqual(result.dynamic_syscalls, ("read", "write"))
        self.assertEqual(result.missing_syscalls, ())
        self.assertEqual(runner.started, ["container-1", "container-2"])

    def test_successful_exit_with_missing_syscall_continues(self):
        runner = FakeRunner(
            [
                ContainerResult("container-1", 0, "", False),
                ContainerResult("container-2", 0, "", False),
            ]
        )
        event_runs = [
            [SyscallEvent(1.0, "read"), SyscallEvent(1.1, "getpid")],
            [SyscallEvent(2.0, "read"), SyscallEvent(2.1, "getpid")],
        ]

        def factory() -> FakeCollector:
            return FakeCollector([event_runs.pop(0)])

        result = DynamicAnalysisController(
            runner=runner,
            collector_factory=factory,
            max_iterations=5,
            timeout=1.0,
        ).analyze("alpine:3.20", {"read"}, ["true"])
        self.assertEqual(len(result.iterations), 2)
        self.assertEqual(result.iterations[0].added_syscall, "getpid")
        self.assertEqual(result.iterations[0].exit_code, 0)
        self.assertIsNone(result.iterations[1].added_syscall)

    def test_timeout_with_missing_syscall_continues(self):
        runner = FakeRunner(
            [
                ContainerResult("container-1", -1, "window elapsed", True),
                ContainerResult("container-2", 0, "", False),
            ]
        )
        event_runs = [
            [SyscallEvent(1.0, "read"), SyscallEvent(1.1, "clone3")],
            [SyscallEvent(2.0, "read"), SyscallEvent(2.1, "clone3")],
        ]

        def factory() -> FakeCollector:
            return FakeCollector([event_runs.pop(0)])

        result = DynamicAnalysisController(
            runner=runner,
            collector_factory=factory,
            max_iterations=5,
            timeout=1.0,
        ).analyze("alpine:3.20", {"read"}, ["true"])
        self.assertEqual(len(result.iterations), 2)
        self.assertEqual(result.iterations[0].added_syscall, "clone3")
        self.assertFalse(result.iterations[1].timed_out)

    def test_tracee_filters_events_to_bound_container(self):
        collector = TraceeCollector()
        collector.bind("abc123def456")
        self.assertTrue(
            collector._matches_container({"eventName": "write", "container": {"id": "abc123def456999"}})
        )
        self.assertFalse(
            collector._matches_container({"eventName": "write", "container": {"id": "ffffffffffff"}})
        )


if __name__ == "__main__":
    unittest.main()