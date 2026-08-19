import unittest

from static_analyzer.analyzer import StaticAnalyzer
from static_analyzer.elf.elf_scanner import ELFMetadata
from static_analyzer.elf.symbol_extractor import ImportedSymbol
from static_analyzer.indirect.callgraph import CallGraph
from static_analyzer.indirect.glibc_analyzer import GlibcCallGraphAnalyzer
from static_analyzer.indirect.indirect_syscall_analyzer import IndirectSyscallAnalyzer
from static_analyzer.indirect.musl_analyzer import MuslCallGraphAnalyzer
from static_analyzer.models.result import DirectSyscallRecord
from static_analyzer.syscall.syscall_mapper import SyscallMapper


class IndirectAndUnionTests(unittest.TestCase):
    def setUp(self):
        self.mapper = SyscallMapper({"x86_64": {56: "clone", 288: "accept4", 60: "exit"}})

    def test_static_analyzer_auto_discovers_confine_graph(self):
        graph = StaticAnalyzer._load_callgraph(None, "glibc")
        self.assertIsNotNone(graph)
        self.assertTrue(graph.has_function("pthread_create"))

    def test_glibc_mapping(self):
        graph = CallGraph()
        graph.add_edge("pthread_create", "syscall(56)")
        analyzer = IndirectSyscallAnalyzer(
            mapper=self.mapper,
            glibc_analyzer=GlibcCallGraphAnalyzer(graph),
            musl_analyzer=MuslCallGraphAnalyzer(None),
        )
        metadata = ELFMetadata(
            path="/tmp/app",
            elf_class=64,
            architecture="x86_64",
            elf_type="ET_DYN",
            is_dynamic=True,
            interpreter="/lib64/ld-linux-x86-64.so.2",
            imported_functions=[ImportedSymbol("pthread_create", "STT_FUNC", "STB_GLOBAL")],
            undefined_symbols=["pthread_create"],
            needed_libraries=["libc.so.6"],
        )
        _, records = analyzer.analyze_binary(metadata)
        resolved = [r for r in records if r.syscall_number is not None]
        self.assertEqual(len(resolved), 1)
        self.assertEqual(resolved[0].syscall_number, 56)
        self.assertEqual(resolved[0].syscall_name, "clone")

    def test_static_binary_has_no_indirect_results(self):
        analyzer = IndirectSyscallAnalyzer(
            mapper=self.mapper,
            glibc_analyzer=GlibcCallGraphAnalyzer(None),
            musl_analyzer=MuslCallGraphAnalyzer(None),
        )
        metadata = ELFMetadata(
            path="/tmp/static-bin",
            elf_class=64,
            architecture="x86_64",
            elf_type="ET_EXEC",
            is_dynamic=False,
            interpreter=None,
            imported_functions=[],
            undefined_symbols=[],
            needed_libraries=[],
        )
        imports, records = analyzer.analyze_binary(metadata)
        self.assertEqual(imports, [])
        self.assertEqual(records, [])

    def test_final_union_keeps_sources(self):
        analyzer = StaticAnalyzer(mapper=self.mapper)
        direct = [
            DirectSyscallRecord(
                binary="a",
                section=".text",
                address="0x1",
                syscall_number=60,
                syscall_name="exit",
                resolution="static",
                classification="DIRECT_RESOLVED",
                confidence="high",
            )
        ]
        indirect = []
        entries = analyzer._build_static_syscall_entries("x86_64", direct, indirect)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].source, "direct")


if __name__ == "__main__":
    unittest.main()

