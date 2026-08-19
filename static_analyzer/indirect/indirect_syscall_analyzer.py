from __future__ import annotations

from typing import List

from static_analyzer.elf.elf_scanner import ELFMetadata
from static_analyzer.indirect.glibc_analyzer import GlibcCallGraphAnalyzer
from static_analyzer.indirect.musl_analyzer import MuslCallGraphAnalyzer
from static_analyzer.models.result import ImportedFunctionRecord, IndirectSyscallRecord
from static_analyzer.syscall.syscall_mapper import SyscallMapper


class IndirectSyscallAnalyzer:
    """Maps imported functions to syscalls through libc call graphs."""

    def __init__(
        self,
        mapper: SyscallMapper,
        glibc_analyzer: GlibcCallGraphAnalyzer,
        musl_analyzer: MuslCallGraphAnalyzer,
    ) -> None:
        self.mapper = mapper
        self.glibc_analyzer = glibc_analyzer
        self.musl_analyzer = musl_analyzer

    def analyze_binary(
        self, metadata: ELFMetadata
    ) -> tuple[List[ImportedFunctionRecord], List[IndirectSyscallRecord]]:
        imports = [
            ImportedFunctionRecord(
                binary=metadata.path,
                function=item.name,
                symbol_type=item.symbol_type,
                symbol_binding=item.symbol_binding,
                library=item.library,
            )
            for item in metadata.imported_functions
        ]

        libc = self._detect_libc(metadata)
        analyzer = self._select_analyzer(libc)
        records: List[IndirectSyscallRecord] = []

        for imported in imports:
            function = imported.function
            if analyzer is None:
                reason = (
                    "musl call graph unavailable"
                    if libc == "musl"
                    else "libc flavor unknown"
                )
                records.append(
                    IndirectSyscallRecord(
                        binary=metadata.path,
                        function=function,
                        syscall_number=None,
                        syscall_name=None,
                        callgraph_path=[function],
                        resolution=reason,
                        classification="INDIRECT_UNRESOLVED",
                    )
                )
                continue

            if not analyzer.has_function(function):
                records.append(
                    IndirectSyscallRecord(
                        binary=metadata.path,
                        function=function,
                        syscall_number=None,
                        syscall_name=None,
                        callgraph_path=[function],
                        resolution="function-not-in-callgraph",
                        classification="INDIRECT_UNRESOLVED",
                    )
                )
                continue

            syscall_paths = analyzer.analyze_function(function)
            if not syscall_paths:
                records.append(
                    IndirectSyscallRecord(
                        binary=metadata.path,
                        function=function,
                        syscall_number=None,
                        syscall_name=None,
                        callgraph_path=[function],
                        resolution="unresolved",
                        classification="INDIRECT_UNRESOLVED",
                    )
                )
                continue

            for syscall in syscall_paths:
                records.append(
                    IndirectSyscallRecord(
                        binary=metadata.path,
                        function=function,
                        syscall_number=syscall.number,
                        syscall_name=self.mapper.name_for(
                            syscall.number, metadata.architecture
                        ),
                        callgraph_path=syscall.path,
                        resolution="static",
                        classification="INDIRECT_RESOLVED",
                    )
                )
        return imports, records

    def _select_analyzer(self, libc: str):
        if libc == "glibc":
            return self.glibc_analyzer if self.glibc_analyzer.available() else None
        if libc == "musl":
            return self.musl_analyzer if self.musl_analyzer.available() else None
        return None

    @staticmethod
    def _detect_libc(metadata: ELFMetadata) -> str:
        interpreter = (metadata.interpreter or "").lower()
        needed = [lib.lower() for lib in metadata.needed_libraries]
        if "musl" in interpreter or any("musl" in lib for lib in needed):
            return "musl"
        if "ld-linux" in interpreter or any(lib.startswith("libc.so") for lib in needed):
            return "glibc"
        if metadata.link_type == "static":
            return "static"
        return "unknown"

