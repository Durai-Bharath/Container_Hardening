from __future__ import annotations

import os
from typing import List, Optional

from static_analyzer.direct.direct_syscall_analyzer import DirectSyscallAnalyzer
from static_analyzer.elf.elf_scanner import ELFScanner
from static_analyzer.indirect.callgraph import CallGraph
from static_analyzer.indirect.glibc_analyzer import GlibcCallGraphAnalyzer
from static_analyzer.indirect.indirect_syscall_analyzer import IndirectSyscallAnalyzer
from static_analyzer.indirect.musl_analyzer import MuslCallGraphAnalyzer
from static_analyzer.models.result import (
    AnalysisReport,
    BinaryAnalysisResult,
    StaticSyscallEntry,
)
from static_analyzer.syscall.syscall_mapper import SyscallMapper


class StaticAnalyzer:
    def __init__(
        self,
        mapper: SyscallMapper,
        glibc_callgraph_path: Optional[str] = None,
        musl_callgraph_path: Optional[str] = None,
    ) -> None:
        self.scanner = ELFScanner()
        self.mapper = mapper
        self.direct = DirectSyscallAnalyzer(mapper=mapper)
        glibc_graph = self._load_callgraph(glibc_callgraph_path, "glibc")
        musl_graph = self._load_callgraph(musl_callgraph_path, "musl")
        self.indirect = IndirectSyscallAnalyzer(
            mapper=mapper,
            glibc_analyzer=GlibcCallGraphAnalyzer(glibc_graph),
            musl_analyzer=MuslCallGraphAnalyzer(musl_graph),
        )

    @staticmethod
    def _load_callgraph(path: Optional[str], flavor: str) -> Optional[CallGraph]:
        if path:
            return CallGraph.from_file(path)

        candidate_names = {
            "glibc": [
                "glibc.callgraph",
                "glibc.2.23.callgraph",
                "glibc.2.31.callgraph",
            ],
            "musl": [
                "musllibc.callgraph",
            ],
        }
        for candidate in candidate_names.get(flavor, []):
            possible = os.path.join(os.path.dirname(__file__), "..", "confine", "libc-callgraphs", candidate)
            resolved = os.path.abspath(possible)
            if os.path.exists(resolved):
                return CallGraph.from_file(resolved)
        return None

    def analyze(self, input_path: str) -> AnalysisReport:
        binaries = self.scanner.discover(input_path)
        results: List[BinaryAnalysisResult] = []
        for metadata in binaries:
            imported_functions, indirect_syscalls = self.indirect.analyze_binary(metadata)
            direct_syscalls = self.direct.analyze_binary(metadata)
            static_syscalls = self._build_static_syscall_entries(
                metadata.architecture, direct_syscalls, indirect_syscalls
            )
            unique = {
                entry.number: entry.name
                for entry in sorted(static_syscalls, key=lambda item: item.number)
            }
            results.append(
                BinaryAnalysisResult(
                    binary=metadata.path,
                    architecture=metadata.architecture,
                    elf_class=metadata.elf_class,
                    elf_type=metadata.elf_type,
                    link_type=metadata.link_type,
                    interpreter=metadata.interpreter,
                    imported_functions=imported_functions,
                    direct_syscalls=direct_syscalls,
                    indirect_syscalls=indirect_syscalls,
                    static_syscalls=static_syscalls,
                    final_unique_syscalls=sorted(unique.items(), key=lambda item: item[0]),
                )
            )
        return AnalysisReport(
            input_path=input_path,
            architecture="x86_64",
            binaries=results,
        )

    def _build_static_syscall_entries(
        self,
        architecture: str,
        direct_syscalls,
        indirect_syscalls,
    ) -> List[StaticSyscallEntry]:
        entries: List[StaticSyscallEntry] = []
        seen = set()
        for item in direct_syscalls:
            if item.syscall_number is None:
                continue
            key = (item.syscall_number, "direct")
            if key in seen:
                continue
            seen.add(key)
            entries.append(
                StaticSyscallEntry(
                    number=item.syscall_number,
                    name=item.syscall_name
                    or self.mapper.name_for(item.syscall_number, architecture),
                    source="direct",
                )
            )
        for item in indirect_syscalls:
            if item.syscall_number is None:
                continue
            key = (item.syscall_number, "indirect")
            if key in seen:
                continue
            seen.add(key)
            entries.append(
                StaticSyscallEntry(
                    number=item.syscall_number,
                    name=item.syscall_name
                    or self.mapper.name_for(item.syscall_number, architecture),
                    source="indirect",
                )
            )
        return sorted(entries, key=lambda entry: (entry.number, entry.source))

