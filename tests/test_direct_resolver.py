import unittest

from capstone import CS_OP_IMM, CS_OP_REG

from static_analyzer.direct.direct_syscall_analyzer import DirectSyscallAnalyzer
from static_analyzer.syscall.syscall_mapper import SyscallMapper


class FakeOperand:
    def __init__(self, op_type, reg=None, imm=None):
        self.type = op_type
        self.reg = reg
        self.imm = imm


class FakeInstruction:
    def __init__(self, mnemonic, operands, reg_names):
        self.mnemonic = mnemonic
        self.operands = operands
        self._reg_names = reg_names

    def reg_name(self, reg):
        return self._reg_names[reg]


class DirectResolverTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = DirectSyscallAnalyzer(mapper=SyscallMapper({"x86_64": {60: "exit"}}))

    def test_mov_eax_immediate(self):
        instructions = [
            FakeInstruction(
                "mov",
                [FakeOperand(CS_OP_REG, reg=1), FakeOperand(CS_OP_IMM, imm=60)],
                {1: "eax"},
            ),
            FakeInstruction("syscall", [], {}),
        ]
        result = self.analyzer._resolve_syscall_number(instructions, 1)
        self.assertEqual(result.number, 60)
        self.assertEqual(result.resolution, "static")

    def test_xor_then_mov_ax(self):
        instructions = [
            FakeInstruction(
                "xor",
                [FakeOperand(CS_OP_REG, reg=1), FakeOperand(CS_OP_REG, reg=1)],
                {1: "eax"},
            ),
            FakeInstruction(
                "mov",
                [FakeOperand(CS_OP_REG, reg=2), FakeOperand(CS_OP_IMM, imm=1)],
                {2: "ax"},
            ),
            FakeInstruction("syscall", [], {}),
        ]
        result = self.analyzer._resolve_syscall_number(instructions, 2)
        self.assertEqual(result.number, 1)

    def test_wrapper_call_rdi_immediate(self):
        instructions = [
            FakeInstruction(
                "mov",
                [FakeOperand(CS_OP_REG, reg=1), FakeOperand(CS_OP_IMM, imm=1)],
                {1: "edi"},
            ),
            FakeInstruction(
                "mov",
                [FakeOperand(CS_OP_REG, reg=2), FakeOperand(CS_OP_IMM, imm=0)],
                {2: "eax"},
            ),
            FakeInstruction("call", [], {}),
        ]
        result = self.analyzer._resolve_syscall_number(
            instructions, 2, target_reg="rdi", architecture="x86_64"
        )
        self.assertEqual(result.number, 1)
        self.assertEqual(result.resolution, "static")

    def test_analyze_binary1(self):
        from static_analyzer.elf.elf_scanner import ELFScanner

        scanner = ELFScanner()
        binaries = scanner.discover("static_analyzer/test/binary1")
        self.assertEqual(len(binaries), 1)

        records = self.analyzer.analyze_binary(binaries[0])
        resolved_nums = {r.syscall_number for r in records if r.syscall_number is not None}
        # binary1 calls write(1), getpid(39), getppid(110), gettid(186), sched_yield(24), getpgid(121), getsid(124)
        expected_nums = {1, 39, 110, 186, 24, 121, 124}
        self.assertTrue(expected_nums.issubset(resolved_nums))


if __name__ == "__main__":
    unittest.main()

