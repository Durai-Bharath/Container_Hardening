import tempfile
import unittest

from static_analyzer.indirect.callgraph import CallGraph


class CallGraphTests(unittest.TestCase):
    def test_parse_syscall_node_variants(self):
        self.assertEqual(CallGraph.parse_syscall_node("syscall(56)"), 56)
        self.assertEqual(CallGraph.parse_syscall_node("syscall ( 56 )"), 56)
        self.assertEqual(CallGraph.parse_syscall_node(" syscall( 56 ) "), 56)
        self.assertIsNone(CallGraph.parse_syscall_node("syscall(foo)"))

    def test_callgraph_parse_and_dfs(self):
        data = "\n".join(
            [
                "functionA : functionB",
                "functionB : functionC",
                "functionC : syscall(2)",
            ]
        )
        with tempfile.NamedTemporaryFile("w+", delete=False) as handle:
            handle.write(data)
            path = handle.name

        graph = CallGraph.from_file(path)
        self.assertEqual(graph.get_syscalls_from_function("functionA"), {2})

    def test_callgraph_auto_detects_arrow_separator(self):
        data = "\n".join(
            [
                "funcA->@helper",
                "helper->syscall(9)",
            ]
        )
        with tempfile.NamedTemporaryFile("w+", delete=False) as handle:
            handle.write(data)
            path = handle.name

        graph = CallGraph.from_file(path)
        self.assertEqual(graph.get_syscalls_from_function("funcA"), {9})

    def test_cycle_handling(self):
        graph = CallGraph()
        graph.add_edge("a", "b")
        graph.add_edge("b", "a")
        graph.add_edge("b", "syscall(1)")
        self.assertEqual(graph.get_syscalls_from_function("a"), {1})

    def test_arrow_separator_with_inline_colon_asm(self):
        data = "\n".join(
            [
                'funcA->asm "mov %fs:0,$0", "=r"',
                "funcA->helper",
                "helper->syscall(42)",
            ]
        )
        with tempfile.NamedTemporaryFile("w+", delete=False) as handle:
            handle.write(data)
            path = handle.name

        graph = CallGraph.from_file(path)
        self.assertEqual(graph.get_syscalls_from_function("funcA"), {42})


if __name__ == "__main__":
    unittest.main()

