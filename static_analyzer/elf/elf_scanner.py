from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Optional

from elftools.elf.elffile import ELFFile

from static_analyzer.elf.symbol_extractor import ImportedSymbol, SymbolExtractor


@dataclass
class ELFMetadata:
    path: str
    elf_class: int
    architecture: str
    elf_type: str
    is_dynamic: bool
    interpreter: Optional[str]
    imported_functions: List[ImportedSymbol]
    undefined_symbols: List[str]
    needed_libraries: List[str]

    @property
    def link_type(self) -> str:
        return "dynamic" if self.is_dynamic else "static"


class ELFScanner:
    ELF_MAGIC = b"\x7fELF"

    def discover(self, root: str) -> List[ELFMetadata]:
        matches: List[ELFMetadata] = []
        for current_root, _, files in os.walk(root):
            for file_name in files:
                path = os.path.join(current_root, file_name)
                if not self.is_elf(path):
                    continue
                metadata = self.extract_metadata(path)
                if metadata is not None:
                    matches.append(metadata)
        return matches

    def is_elf(self, path: str) -> bool:
        try:
            with open(path, "rb") as handle:
                return handle.read(4) == self.ELF_MAGIC
        except OSError:
            return False

    def extract_metadata(self, path: str) -> Optional[ELFMetadata]:
        try:
            with open(path, "rb") as handle:
                elffile = ELFFile(handle)
                elf_class = int(elffile.elfclass)
                machine = str(elffile["e_machine"])
                architecture = self._normalize_arch(machine)
                elf_type = str(elffile["e_type"])
                imported_functions = SymbolExtractor.extract_imported_functions(elffile)
                undefined = [symbol.name for symbol in imported_functions]
                needed = SymbolExtractor.extract_needed_libraries(elffile)
                interpreter = self._extract_interpreter(elffile)
                is_dynamic = self._is_dynamic(elffile)
                return ELFMetadata(
                    path=path,
                    elf_class=elf_class,
                    architecture=architecture,
                    elf_type=elf_type,
                    is_dynamic=is_dynamic,
                    interpreter=interpreter,
                    imported_functions=imported_functions,
                    undefined_symbols=undefined,
                    needed_libraries=needed,
                )
        except Exception:
            return None

    @staticmethod
    def _normalize_arch(machine: str) -> str:
        mapping = {
            "EM_X86_64": "x86_64",
            "EM_386": "x86",
            "EM_AARCH64": "aarch64",
            "EM_ARM": "arm",
        }
        return mapping.get(machine, machine.lower())

    @staticmethod
    def _is_dynamic(elffile) -> bool:
        for segment in elffile.iter_segments():
            if str(segment["p_type"]) == "PT_DYNAMIC":
                return True
        return False

    @staticmethod
    def _extract_interpreter(elffile) -> Optional[str]:
        for segment in elffile.iter_segments():
            if str(segment["p_type"]) == "PT_INTERP":
                return segment.get_interp_name()
        return None

