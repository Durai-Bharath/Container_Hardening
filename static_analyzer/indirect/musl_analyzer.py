from __future__ import annotations

from typing import Optional

from static_analyzer.indirect.callgraph import CallGraph
from static_analyzer.indirect.glibc_analyzer import BaseLibcCallGraphAnalyzer


class MuslCallGraphAnalyzer(BaseLibcCallGraphAnalyzer):
    def __init__(self, callgraph: Optional[CallGraph]) -> None:
        super().__init__(callgraph=callgraph, libc_name="musl")

