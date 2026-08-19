from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import DefaultDict, Dict, Iterable, List, Optional, Set, Tuple


SYSCALL_NODE_RE = re.compile(r"^\s*syscall\s*\(\s*(\d+)\s*\)\s*$")


@dataclass
class SyscallPath:
    number: int
    path: List[str]


class CallGraph:
    """Directed function call graph with syscall leaf parsing."""

    def __init__(self) -> None:
        self.graph: DefaultDict[str, Set[str]] = defaultdict(set)

    @classmethod
    def from_file(cls, path: str, separator: Optional[str] = None) -> "CallGraph":
        graph = cls()
        separators = [separator] if separator else [":", "->"]
        with open(path, "r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                chosen = None
                for candidate in separators:
                    if candidate and candidate in line:
                        chosen = candidate
                        break
                if chosen is None:
                    continue
                left, right = line.split(chosen, 1)
                caller = left.strip()
                callee = right.strip()
                if callee.startswith("@"):
                    callee = callee[1:]
                if caller and callee:
                    graph.add_edge(caller, callee)
        return graph

    def add_edge(self, caller: str, callee: str) -> None:
        self.graph[caller].add(callee)

    @staticmethod
    def parse_syscall_node(node: str) -> Optional[int]:
        match = SYSCALL_NODE_RE.match(node)
        if not match:
            return None
        return int(match.group(1))

    def get_syscalls_from_function(self, function: str) -> Set[int]:
        return {item.number for item in self.get_syscalls_with_paths(function)}

    def get_syscalls_with_paths(self, function: str) -> List[SyscallPath]:
        if function not in self.graph:
            return []

        found: Set[Tuple[int, Tuple[str, ...]]] = set()
        results: List[SyscallPath] = []
        visited_nodes: Set[str] = set()
        stack: List[Tuple[str, List[str]]] = [(function, [])]

        while stack:
            node, path = stack.pop()
            if node in visited_nodes:
                continue
            visited_nodes.add(node)

            syscall_num = self.parse_syscall_node(node)
            if syscall_num is not None:
                path_tuple = tuple(path + [node])
                marker = (syscall_num, path_tuple)
                if marker not in found:
                    found.add(marker)
                    results.append(SyscallPath(number=syscall_num, path=list(path_tuple)))
                continue

            for child in self.graph.get(node, set()):
                if child in visited_nodes:
                    continue
                stack.append((child, path + [node]))

        return results

    def has_function(self, function: str) -> bool:
        return function in self.graph

    def nodes(self) -> Iterable[str]:
        return self.graph.keys()

