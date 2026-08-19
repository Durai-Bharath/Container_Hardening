from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class ImportedFunctionRecord:
    binary: str
    function: str
    source: str = "ELF_DYNAMIC_SYMBOL"
    library: Optional[str] = None
    symbol_type: Optional[str] = None
    symbol_binding: Optional[str] = None


@dataclass
class DirectSyscallRecord:
    binary: str
    section: str
    address: str
    syscall_number: Optional[int]
    syscall_name: Optional[str]
    resolution: str
    classification: str
    confidence: str


@dataclass
class IndirectSyscallRecord:
    binary: str
    function: str
    syscall_number: Optional[int]
    syscall_name: Optional[str]
    callgraph_path: List[str]
    resolution: str
    classification: str


@dataclass
class StaticSyscallEntry:
    number: int
    name: Optional[str]
    source: str


@dataclass
class BinaryAnalysisResult:
    binary: str
    architecture: str
    elf_class: int
    elf_type: str
    link_type: str
    interpreter: Optional[str]
    imported_functions: List[ImportedFunctionRecord] = field(default_factory=list)
    direct_syscalls: List[DirectSyscallRecord] = field(default_factory=list)
    indirect_syscalls: List[IndirectSyscallRecord] = field(default_factory=list)
    static_syscalls: List[StaticSyscallEntry] = field(default_factory=list)
    final_unique_syscalls: List[Tuple[int, Optional[str]]] = field(default_factory=list)

    def compute_summary(self) -> Dict[str, int]:
        resolved_direct = [d for d in self.direct_syscalls if d.syscall_number is not None]
        unresolved_direct = [d for d in self.direct_syscalls if d.syscall_number is None]
        resolved_indirect = [i for i in self.indirect_syscalls if i.syscall_number is not None]
        unresolved_indirect = [i for i in self.indirect_syscalls if i.syscall_number is None]
        return {
            "direct_syscall_count": len(resolved_direct),
            "indirect_syscall_count": len(resolved_indirect),
            "unique_syscall_count": len(self.final_unique_syscalls),
            "unresolved_direct_syscall_count": len(unresolved_direct),
            "imported_function_count": len(self.imported_functions),
            "resolved_imported_function_count": len(
                {i.function for i in resolved_indirect}
            ),
            "unresolved_imported_function_count": len(
                {i.function for i in unresolved_indirect}
            ),
        }

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["summary"] = self.compute_summary()
        return payload


@dataclass
class AnalysisReport:
    input_path: str
    architecture: str
    binaries: List[BinaryAnalysisResult]

    def all_unique_syscalls(self) -> Set[int]:
        values: Set[int] = set()
        for binary in self.binaries:
            values.update(number for number, _ in binary.final_unique_syscalls)
        return values

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_path": self.input_path,
            "architecture": self.architecture,
            "binaries": [b.to_dict() for b in self.binaries],
            "global_unique_syscall_count": len(self.all_unique_syscalls()),
        }

