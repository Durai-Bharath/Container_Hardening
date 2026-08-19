import tempfile
import unittest

from static_analyzer.elf.elf_scanner import ELFScanner


class ELFScannerTests(unittest.TestCase):
    def test_elf_detection(self):
        scanner = ELFScanner()
        with tempfile.NamedTemporaryFile("wb", delete=False) as elf_file:
            elf_file.write(b"\x7fELF" + b"\x00" * 8)
            elf_path = elf_file.name
        with tempfile.NamedTemporaryFile("wb", delete=False) as text_file:
            text_file.write(b"not-elf")
            text_path = text_file.name

        self.assertTrue(scanner.is_elf(elf_path))
        self.assertFalse(scanner.is_elf(text_path))


if __name__ == "__main__":
    unittest.main()

