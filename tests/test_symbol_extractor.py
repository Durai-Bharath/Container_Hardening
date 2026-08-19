import unittest

from static_analyzer.elf.symbol_extractor import SymbolExtractor


class FakeSymbol:
    def __init__(self, name, shndx, st_type, st_bind):
        self.name = name
        self._shndx = shndx
        self._st_type = st_type
        self._st_bind = st_bind

    def __getitem__(self, key):
        if key == "st_shndx":
            return self._shndx
        if key == "st_info":
            return {"type": self._st_type, "bind": self._st_bind}
        raise KeyError(key)


class FakeDynSym:
    def __init__(self, symbols):
        self._symbols = symbols

    def iter_symbols(self):
        return iter(self._symbols)


class FakeELF:
    def __init__(self, dynsym):
        self._dynsym = dynsym

    def get_section_by_name(self, name):
        if name == ".dynsym":
            return self._dynsym
        return None


class SymbolExtractorTests(unittest.TestCase):
    def test_imported_function_extraction(self):
        elf = FakeELF(
            FakeDynSym(
                [
                    FakeSymbol("open", "SHN_UNDEF", "STT_FUNC", "STB_GLOBAL"),
                    FakeSymbol("local", 1, "STT_FUNC", "STB_LOCAL"),
                    FakeSymbol("write", "SHN_UNDEF", "STT_NOTYPE", "STB_GLOBAL"),
                ]
            )
        )
        symbols = SymbolExtractor.extract_imported_functions(elf)
        names = {item.name for item in symbols}
        self.assertEqual(names, {"open", "write"})


if __name__ == "__main__":
    unittest.main()

