from __future__ import annotations

from typing import List, Optional

from static_analyzer.indirect.callgraph import CallGraph, SyscallPath


class BaseLibcCallGraphAnalyzer:
    def __init__(self, callgraph: Optional[CallGraph], libc_name: str) -> None:
        self.callgraph = callgraph
        self.libc_name = libc_name

    def available(self) -> bool:
        return self.callgraph is not None

    def analyze_function(self, function_name: str) -> List[SyscallPath]:
        if self.callgraph is None:
            return []
        return self.callgraph.get_syscalls_with_paths(function_name)

    def has_function(self, function_name: str) -> bool:
        if self.callgraph is None:
            return False
        return self.callgraph.has_function(function_name)


class GlibcCallGraphAnalyzer(BaseLibcCallGraphAnalyzer):
    def __init__(self, callgraph: Optional[CallGraph]) -> None:
        super().__init__(callgraph=callgraph, libc_name="glibc")

