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

    def test_unresolved_when_runtime_register(self):
        instructions = [
            FakeInstruction(
                "mov",
                [FakeOperand(CS_OP_REG, reg=1), FakeOperand(CS_OP_REG, reg=2)],
                {1: "eax", 2: "ebx"},
            ),
            FakeInstruction("syscall", [], {}),
        ]
        result = self.analyzer._resolve_syscall_number(instructions, 1)
        self.assertIsNone(result.number)
        self.assertEqual(result.resolution, "unresolved")


if __name__ == "__main__":
    unittest.main()

