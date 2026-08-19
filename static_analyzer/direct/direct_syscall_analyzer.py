from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_OP_IMM, CS_OP_REG, Cs
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile

from static_analyzer.elf.elf_scanner import ELFMetadata
from static_analyzer.models.result import DirectSyscallRecord
from static_analyzer.syscall.syscall_mapper import SyscallMapper


@dataclass
class ResolutionResult:
    number: Optional[int]
    confidence: str
    resolution: str


class DirectSyscallAnalyzer:
    """Disassembles executable sections and extracts x86 syscall instructions."""

    def __init__(self, mapper: SyscallMapper, backtrack_window: int = 15) -> None:
        self.mapper = mapper
        self.backtrack_window = backtrack_window

    def analyze_binary(self, metadata: ELFMetadata) -> List[DirectSyscallRecord]:
        if metadata.architecture not in {"x86_64", "x86"}:
            return []

        records: List[DirectSyscallRecord] = []
        with open(metadata.path, "rb") as handle:
            elffile = ELFFile(handle)
            for section in elffile.iter_sections():
                flags = section["sh_flags"]
                if (flags & SH_FLAGS.SHF_EXECINSTR) == 0:
                    continue
                code = section.data()
                if not code:
                    continue
                base_address = int(section["sh_addr"])
                instructions = list(self._disassemble(code, base_address, metadata.architecture))
                for index, instruction in enumerate(instructions):
                    if instruction.mnemonic != "syscall":
                        continue
                    resolution = self._resolve_syscall_number(instructions, index)
                    syscall_name = (
                        self.mapper.name_for(resolution.number, metadata.architecture)
                        if resolution.number is not None
                        else None
                    )
                    records.append(
                        DirectSyscallRecord(
                            binary=metadata.path,
                            section=section.name,
                            address=hex(instruction.address),
                            syscall_number=resolution.number,
                            syscall_name=syscall_name,
                            resolution=resolution.resolution,
                            classification=(
                                "DIRECT_RESOLVED"
                                if resolution.number is not None
                                else "DIRECT_UNRESOLVED"
                            ),
                            confidence=resolution.confidence,
                        )
                    )
        return records

    @staticmethod
    def _disassemble(code: bytes, base_address: int, architecture: str):
        mode = CS_MODE_64 if architecture == "x86_64" else CS_MODE_32
        engine = Cs(CS_ARCH_X86, mode)
        engine.detail = True
        return engine.disasm(code, base_address)

    def _resolve_syscall_number(self, instructions, syscall_index: int) -> ResolutionResult:
        start = max(0, syscall_index - self.backtrack_window)
        window = instructions[start:syscall_index]
        rax_value: Optional[int] = None
        confidence = "low"

        for insn in window:
            if self._is_call_or_ret(insn):
                rax_value = None
                confidence = "low"
                continue
            update = self._simulate_rax_update(insn, rax_value)
            if update is None:
                continue
            rax_value, op_confidence = update
            confidence = op_confidence

        if rax_value is None:
            return ResolutionResult(number=None, confidence="low", resolution="unresolved")
        return ResolutionResult(number=rax_value, confidence=confidence, resolution="static")

    def _simulate_rax_update(self, instruction, current_value: Optional[int]) -> Optional[Tuple[Optional[int], str]]:
        operands = instruction.operands
        mnemonic = instruction.mnemonic
        if mnemonic == "xor" and len(operands) == 2:
            if operands[0].type == CS_OP_REG and operands[1].type == CS_OP_REG:
                left = instruction.reg_name(operands[0].reg)
                right = instruction.reg_name(operands[1].reg)
                if left == right and left in {"eax", "rax"}:
                    return 0, "high"
            return None

        if mnemonic == "mov" and len(operands) == 2:
            if operands[0].type != CS_OP_REG:
                return None
            dest = instruction.reg_name(operands[0].reg)
            src = operands[1]
            if src.type != CS_OP_IMM:
                if dest in {"rax", "eax", "ax", "al"}:
                    return None, "low"
                return None
            imm = int(src.imm)
            if dest == "rax":
                return imm & ((1 << 64) - 1), "high"
            if dest == "eax":
                return imm & ((1 << 32) - 1), "high"
            if dest == "ax":
                if current_value is None:
                    return None, "low"
                updated = (current_value & ~0xFFFF) | (imm & 0xFFFF)
                return updated, "high"
            if dest == "al":
                if current_value is None:
                    return None, "low"
                updated = (current_value & ~0xFF) | (imm & 0xFF)
                return updated, "high"
            return None

        if mnemonic in {"add", "sub"} and len(operands) == 2:
            if operands[0].type != CS_OP_REG or operands[1].type != CS_OP_IMM:
                return None
            dest = instruction.reg_name(operands[0].reg)
            if dest not in {"rax", "eax"}:
                return None
            if current_value is None:
                return None, "low"
            imm = int(operands[1].imm)
            if mnemonic == "add":
                return current_value + imm, "medium"
            return current_value - imm, "medium"

        return None

    @staticmethod
    def _is_call_or_ret(instruction) -> bool:
        return instruction.mnemonic in {"call", "ret", "jmp"}

