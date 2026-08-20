from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from capstone import (
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    CS_OP_IMM,
    CS_OP_MEM,
    CS_OP_REG,
    Cs,
)
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from static_analyzer.elf.elf_scanner import ELFMetadata
from static_analyzer.models.result import DirectSyscallRecord
from static_analyzer.syscall.syscall_mapper import SyscallMapper

REG_CANONICAL: Dict[str, str] = {
    "rax": "rax",
    "eax": "rax",
    "ax": "rax",
    "al": "rax",
    "ah": "rax",
    "rdi": "rdi",
    "edi": "rdi",
    "di": "rdi",
    "dil": "rdi",
    "rsi": "rsi",
    "esi": "rsi",
    "si": "rsi",
    "sil": "rsi",
    "rdx": "rdx",
    "edx": "rdx",
    "dx": "rdx",
    "dl": "rdx",
    "dh": "rdx",
    "rcx": "rcx",
    "ecx": "rcx",
    "cx": "rcx",
    "cl": "rcx",
    "ch": "rcx",
    "r8": "r8",
    "r8d": "r8",
    "r8w": "r8",
    "r8b": "r8",
    "r9": "r9",
    "r9d": "r9",
    "r9w": "r9",
    "r9b": "r9",
    "r10": "r10",
    "r10d": "r10",
    "r10w": "r10",
    "r10b": "r10",
    "r11": "r11",
    "r11d": "r11",
    "r11w": "r11",
    "r11b": "r11",
    "rbx": "rbx",
    "ebx": "rbx",
    "bx": "rbx",
    "bl": "rbx",
    "bh": "rbx",
    "rbp": "rbp",
    "ebp": "rbp",
    "bp": "rbp",
    "bpl": "rbp",
}

SYSCALL_WRAPPER_NAMES: Set[str] = {
    "syscall",
    "syscall@plt",
    "__syscall",
    "__libc_syscall",
    "__syscall_cp",
    "__libc_syscall6",
    "__syscall6",
}


@dataclass
class ResolutionResult:
    number: Optional[int]
    confidence: str
    resolution: str


class DirectSyscallAnalyzer:
    """Disassembles executable sections and extracts direct and libc wrapper syscalls."""

    def __init__(self, mapper: SyscallMapper, backtrack_window: int = 20) -> None:
        self.mapper = mapper
        self.backtrack_window = backtrack_window

    def analyze_binary(self, metadata: ELFMetadata) -> List[DirectSyscallRecord]:
        if metadata.architecture not in {"x86_64", "x86", "aarch64", "arm"}:
            return []

        records: List[DirectSyscallRecord] = []
        try:
            with open(metadata.path, "rb") as handle:
                elffile = ELFFile(handle)
                got_symbols, func_symbols, plt_symbols = self._build_symbol_maps(
                    elffile, metadata.architecture
                )

                for section in elffile.iter_sections():
                    flags = section["sh_flags"]
                    if (flags & SH_FLAGS.SHF_EXECINSTR) == 0:
                        continue
                    if section.name.startswith(".plt"):
                        continue
                    code = section.data()
                    if not code:
                        continue
                    base_address = int(section["sh_addr"])
                    instructions = list(
                        self._disassemble(code, base_address, metadata.architecture)
                    )

                    for index, instruction in enumerate(instructions):
                        syscall_type = self._classify_syscall_instruction(
                            instruction,
                            metadata.architecture,
                            plt_symbols,
                            func_symbols,
                            got_symbols,
                        )
                        if syscall_type is None:
                            continue

                        target_reg = self._target_register_for(
                            syscall_type, metadata.architecture
                        )
                        resolution = self._resolve_syscall_number(
                            instructions,
                            index,
                            target_reg=target_reg,
                            architecture=metadata.architecture,
                        )
                        syscall_name = (
                            self.mapper.name_for(
                                resolution.number, metadata.architecture
                            )
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
        except Exception:
            return records

        return records

    @staticmethod
    def _build_symbol_maps(
        elffile: ELFFile, architecture: str
    ) -> Tuple[Dict[int, str], Dict[int, str], Dict[int, str]]:
        got_symbols: Dict[int, str] = {}
        func_symbols: Dict[int, str] = {}
        plt_symbols: Dict[int, str] = {}

        # 1. Relocations -> GOT offsets
        for section in elffile.iter_sections():
            if isinstance(section, RelocationSection):
                symtab = elffile.get_section(section["sh_link"])
                if symtab is None:
                    continue
                for reloc in section.iter_relocations():
                    sym_idx = reloc["r_info_sym"]
                    if sym_idx != 0:
                        symbol = symtab.get_symbol(sym_idx)
                        if symbol and symbol.name:
                            got_symbols[reloc["r_offset"]] = symbol.name

        # 2. Static and dynamic symbol tables
        for section in elffile.iter_sections():
            if section.name in [".symtab", ".dynsym"]:
                for sym in section.iter_symbols():
                    if sym["st_value"]:
                        name = sym.name
                        func_symbols[sym["st_value"]] = name
                        if "@plt" in name:
                            clean = name.split("@")[0]
                            plt_symbols[sym["st_value"]] = clean

        # 3. Disassemble PLT sections
        if architecture in {"x86_64", "x86"}:
            mode = CS_MODE_64 if architecture == "x86_64" else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)
            md.detail = True

            for section in elffile.iter_sections():
                if section.name in [".plt", ".plt.sec", ".plt.got"]:
                    code = section.data()
                    if not code:
                        continue
                    base_addr = int(section["sh_addr"])
                    curr_entry: Optional[int] = None
                    try:
                        for insn in md.disasm(code, base_addr):
                            if curr_entry is None or (insn.address % 16 == 0):
                                curr_entry = insn.address
                            if insn.mnemonic == "jmp" and len(insn.operands) == 1:
                                op = insn.operands[0]
                                target_got = None
                                if op.type == CS_OP_MEM:
                                    if architecture == "x86_64":
                                        target_got = (
                                            insn.address + insn.size + op.mem.disp
                                        )
                                    else:
                                        target_got = op.mem.disp
                                elif op.type == CS_OP_IMM:
                                    target_got = op.imm

                                if target_got and target_got in got_symbols:
                                    sym_name = got_symbols[target_got]
                                    if curr_entry is not None:
                                        plt_symbols[curr_entry] = sym_name
                                    plt_symbols[insn.address] = sym_name
                    except Exception:
                        continue

        return got_symbols, func_symbols, plt_symbols

    @staticmethod
    def _is_syscall_wrapper_name(name: Optional[str]) -> bool:
        if not name:
            return False
        clean = name.split("@")[0]
        return clean in SYSCALL_WRAPPER_NAMES or name in SYSCALL_WRAPPER_NAMES

    def _classify_syscall_instruction(
        self,
        instruction,
        architecture: str,
        plt_symbols: Dict[int, str],
        func_symbols: Dict[int, str],
        got_symbols: Dict[int, str],
    ) -> Optional[str]:
        mnemonic = instruction.mnemonic

        # Raw machine syscall instruction
        if mnemonic == "syscall":
            return "raw_syscall"
        if mnemonic == "int":
            if (
                hasattr(instruction, "operands")
                and len(instruction.operands) == 1
                and instruction.operands[0].type == CS_OP_IMM
                and instruction.operands[0].imm == 0x80
            ):
                return "raw_int80"
            if hasattr(instruction, "op_str") and "0x80" in instruction.op_str:
                return "raw_int80"
        if mnemonic == "sysenter":
            return "raw_sysenter"
        if mnemonic in {"svc", "swi"}:
            return "raw_svc"

        # Function calls to syscall wrappers
        if mnemonic in {"call", "jmp"} and hasattr(instruction, "operands"):
            operands = instruction.operands
            if len(operands) == 1:
                op = operands[0]
                callee_name: Optional[str] = None
                if op.type == CS_OP_IMM:
                    target_addr = op.imm
                    callee_name = plt_symbols.get(
                        target_addr
                    ) or func_symbols.get(target_addr)
                elif op.type == CS_OP_MEM:
                    if architecture == "x86_64":
                        target_got = (
                            instruction.address + instruction.size + op.mem.disp
                        )
                    else:
                        target_got = op.mem.disp
                    callee_name = got_symbols.get(target_got) or plt_symbols.get(
                        target_got
                    )

                if (
                    not callee_name
                    and hasattr(instruction, "op_str")
                    and "syscall" in instruction.op_str
                ):
                    callee_name = "syscall"

                if self._is_syscall_wrapper_name(callee_name):
                    return "wrapper_call"

        return None

    @staticmethod
    def _target_register_for(syscall_type: str, architecture: str) -> str:
        if syscall_type == "wrapper_call":
            if architecture == "x86_64":
                return "rdi"
            if architecture == "aarch64":
                return "x0"
            if architecture == "arm":
                return "r0"
            return "eax"

        # Raw machine instructions
        if architecture == "x86_64":
            return "rax"
        if architecture == "x86":
            return "eax"
        if architecture == "aarch64":
            return "x8"
        if architecture == "arm":
            return "r7"
        return "rax"

    @staticmethod
    def _disassemble(code: bytes, base_address: int, architecture: str):
        mode = CS_MODE_64 if architecture == "x86_64" else CS_MODE_32
        engine = Cs(CS_ARCH_X86, mode)
        engine.detail = True
        return engine.disasm(code, base_address)

    def _resolve_syscall_number(
        self,
        instructions,
        syscall_index: int,
        target_reg: str = "rax",
        architecture: str = "x86_64",
    ) -> ResolutionResult:
        start = max(0, syscall_index - self.backtrack_window)
        window = instructions[start:syscall_index]

        canonical_target = REG_CANONICAL.get(
            target_reg.lower(), target_reg.lower()
        )
        reg_state: Dict[str, int] = {}
        confidence_state: Dict[str, str] = {}
        stack_immediates: List[int] = []

        for insn in window:
            mnemonic = insn.mnemonic
            operands = getattr(insn, "operands", [])

            if self._is_call_or_ret(insn):
                # When checking raw syscall in rax, an unrelated call clobbers rax
                # Caller-saved registers are clobbered
                for clobbered in [
                    "rax",
                    "rcx",
                    "rdx",
                    "rsi",
                    "rdi",
                    "r8",
                    "r9",
                    "r10",
                    "r11",
                ]:
                    reg_state.pop(clobbered, None)
                    confidence_state.pop(clobbered, None)
                continue

            if mnemonic == "push" and len(operands) == 1:
                op = operands[0]
                if op.type == CS_OP_IMM:
                    stack_immediates.append(int(op.imm))
                continue

            if mnemonic == "xor" and len(operands) == 2:
                if (
                    operands[0].type == CS_OP_REG
                    and operands[1].type == CS_OP_REG
                ):
                    left_name = self._reg_name(insn, operands[0].reg)
                    right_name = self._reg_name(insn, operands[1].reg)
                    left_can = REG_CANONICAL.get(left_name, left_name)
                    right_can = REG_CANONICAL.get(right_name, right_name)
                    if left_name == right_name or left_can == right_can:
                        reg_state[left_can] = 0
                        confidence_state[left_can] = "high"
                    else:
                        reg_state.pop(left_can, None)
                        confidence_state.pop(left_can, None)
                continue

            if mnemonic in {"mov", "movabs"} and len(operands) == 2:
                if operands[0].type == CS_OP_REG:
                    dest_name = self._reg_name(insn, operands[0].reg)
                    dest_can = REG_CANONICAL.get(dest_name, dest_name)
                    src = operands[1]
                    if src.type == CS_OP_IMM:
                        imm = int(src.imm)
                        if dest_name in {
                            "al",
                            "dil",
                            "sil",
                            "dl",
                            "cl",
                            "r8b",
                            "r9b",
                            "r10b",
                            "r11b",
                            "bl",
                            "bpl",
                        }:
                            curr = reg_state.get(dest_can, 0)
                            reg_state[dest_can] = (curr & ~0xFF) | (imm & 0xFF)
                        elif dest_name in {
                            "ax",
                            "di",
                            "si",
                            "dx",
                            "cx",
                            "r8w",
                            "r9w",
                            "r10w",
                            "r11w",
                            "bx",
                            "bp",
                        }:
                            curr = reg_state.get(dest_can, 0)
                            reg_state[dest_can] = (curr & ~0xFFFF) | (
                                imm & 0xFFFF
                            )
                        elif dest_name in {
                            "eax",
                            "edi",
                            "esi",
                            "edx",
                            "ecx",
                            "r8d",
                            "r9d",
                            "r10d",
                            "r11d",
                            "ebx",
                            "ebp",
                        }:
                            reg_state[dest_can] = imm & 0xFFFFFFFF
                        else:
                            reg_state[dest_can] = imm
                        confidence_state[dest_can] = "high"
                    elif src.type == CS_OP_REG:
                        src_name = self._reg_name(insn, src.reg)
                        src_can = REG_CANONICAL.get(src_name, src_name)
                        if src_can in reg_state:
                            reg_state[dest_can] = reg_state[src_can]
                            confidence_state[dest_can] = confidence_state.get(
                                src_can, "high"
                            )
                        else:
                            reg_state.pop(dest_can, None)
                            confidence_state.pop(dest_can, None)
                    else:
                        reg_state.pop(dest_can, None)
                        confidence_state.pop(dest_can, None)
                continue

            if mnemonic in {"add", "sub"} and len(operands) == 2:
                if (
                    operands[0].type == CS_OP_REG
                    and operands[1].type == CS_OP_IMM
                ):
                    dest_name = self._reg_name(insn, operands[0].reg)
                    dest_can = REG_CANONICAL.get(dest_name, dest_name)
                    if dest_can in reg_state:
                        imm = int(operands[1].imm)
                        curr = reg_state[dest_can]
                        reg_state[dest_can] = (
                            (curr + imm) if mnemonic == "add" else (curr - imm)
                        )
                        confidence_state[dest_can] = "medium"
                continue

        if canonical_target in reg_state:
            return ResolutionResult(
                number=reg_state[canonical_target],
                confidence=confidence_state.get(canonical_target, "high"),
                resolution="static",
            )

        if architecture == "x86" and stack_immediates:
            return ResolutionResult(
                number=stack_immediates[-1],
                confidence="medium",
                resolution="static",
            )

        return ResolutionResult(
            number=None, confidence="low", resolution="unresolved"
        )

    @staticmethod
    def _reg_name(instruction, reg_id) -> str:
        if hasattr(instruction, "reg_name"):
            name = instruction.reg_name(reg_id)
            if name:
                return name.lower()
        return str(reg_id).lower()

    @staticmethod
    def _is_call_or_ret(instruction) -> bool:
        return instruction.mnemonic in {"call", "ret", "jmp"}
