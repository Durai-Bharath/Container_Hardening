from __future__ import annotations

import json
import os
import re
from typing import Dict, Optional


SYSCALL_DEFINE_RE = re.compile(r"^\s*#\s*define\s+__NR_([A-Za-z0-9_]+)\s+([0-9]+)\s*$")  # MACRO SYSCALLS (#define __NR_READ 0)


class SyscallMapper:
    """Resolves syscall numbers to names per architecture."""

    def __init__(self, arch_tables: Dict[str, Dict[int, str]]) -> None:
        self.arch_tables = arch_tables

    @classmethod
    def create_default(cls, custom_table_path: Optional[str] = None) -> "SyscallMapper":
        if custom_table_path:
            return cls._from_file(custom_table_path)

        arch_tables: Dict[str, Dict[int, str]] = {}
        x86_64_table = cls._load_from_header_paths(
            [
                "/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
                "/usr/include/asm/unistd_64.h",
            ]
        )
        if x86_64_table:
            arch_tables["x86_64"] = x86_64_table
        return cls(arch_tables=arch_tables)

    @classmethod
    def _from_file(cls, path: str) -> "SyscallMapper":
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        arch_tables: Dict[str, Dict[int, str]] = {}
        for arch, table in payload.items():
            arch_tables[arch] = {int(number): str(name) for number, name in table.items()}
        return cls(arch_tables)

    @classmethod
    def _load_from_header_paths(cls, paths: list[str]) -> Dict[int, str]:
        for path in paths:
            if not os.path.exists(path):
                continue
            table = cls._parse_unistd_header(path)
            if table:
                return table
        return {}

    @staticmethod
    def _parse_unistd_header(path: str) -> Dict[int, str]:
        table: Dict[int, str] = {}
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                match = SYSCALL_DEFINE_RE.match(line)
                if not match:
                    continue
                name = match.group(1)
                number = int(match.group(2))
                table[number] = name
        return table

    def name_for(self, number: Optional[int], architecture: str) -> Optional[str]:
        if number is None:
            return None
        table = self.arch_tables.get(architecture)
        if table is None:
            return None
        return table.get(number)

