from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Set


@dataclass
class ImportedSymbol:
    name: str
    symbol_type: Optional[str]
    symbol_binding: Optional[str]
    library: Optional[str] = None


class SymbolExtractor:
    """Extract imported and dynamic symbol metadata from ELF files."""

    @staticmethod
    def extract_imported_functions(elffile) -> List[ImportedSymbol]:
        dynsym = elffile.get_section_by_name(".dynsym")
        if dynsym is None:
            return []

        imported: List[ImportedSymbol] = []
        seen: Set[str] = set()
        for symbol in dynsym.iter_symbols():
            name = symbol.name
            if not name or name in seen:
                continue
            info = symbol["st_info"]
            st_type = info["type"]
            st_bind = info["bind"]
            if symbol["st_shndx"] != "SHN_UNDEF":
                continue
            if st_type not in {"STT_FUNC", "STT_NOTYPE"}:
                continue
            imported.append(
                ImportedSymbol(
                    name=name,
                    symbol_type=st_type,
                    symbol_binding=st_bind,
                )
            )
            seen.add(name)
        return imported

    @staticmethod
    def extract_needed_libraries(elffile) -> List[str]:
        dynamic = elffile.get_section_by_name(".dynamic")
        if dynamic is None:
            return []
        libs: List[str] = []
        for tag in dynamic.iter_tags():
            if tag.entry.d_tag == "DT_NEEDED":
                libs.append(str(tag.needed))
        return libs

