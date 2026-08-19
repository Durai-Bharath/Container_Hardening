from __future__ import annotations

import argparse
import json
import re
import sys
from bisect import bisect_right
from collections import deque
from dataclasses import dataclass
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

from capstone import CS_ARCH_X86, CS_ARCH_ARM64, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section
from elftools.elf.relocation import RelocationSection
from elftools.elf.constants import SH_FLAGS

SYSCALL_NAME_BY_NUMBER: Dict[int, str] = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    4: "stat",
    5: "fstat",
    6: "lstat",
    7: "poll",
    8: "lseek",
    9: "mmap",
    10: "mprotect",
    11: "munmap",
    12: "brk",
    13: "rt_sigaction",
    14: "rt_sigprocmask",
    15: "rt_sigreturn",
    16: "ioctl",
    17: "pread64",
    18: "pwrite64",
    19: "readv",
    20: "writev",
    21: "access",
    22: "pipe",
    23: "select",
    24: "sched_yield",
    25: "mremap",
    26: "msync",
    27: "mincore",
    28: "madvise",
    29: "shmget",
    30: "shmat",
    31: "shmctl",
    32: "dup",
    33: "dup2",
    34: "pause",
    35: "nanosleep",
    36: "getitimer",
    37: "alarm",
    38: "setitimer",
    39: "getpid",
    40: "sendfile",
    41: "socket",
    42: "connect",
    43: "accept",
    44: "sendto",
    45: "recvfrom",
    46: "sendmsg",
    47: "recvmsg",
    48: "shutdown",
    49: "bind",
    50: "listen",
    51: "getsockname",
    52: "getpeername",
    53: "socketpair",
    54: "setsockopt",
    55: "getsockopt",
    56: "clone",
    57: "fork",
    58: "vfork",
    59: "execve",
    60: "exit",
    61: "wait4",
    62: "kill",
    63: "uname",
    64: "semget",
    65: "semop",
    66: "semctl",
    67: "shmdt",
    68: "msgget",
    69: "msgsnd",
    70: "msgrcv",
    71: "msgctl",
    72: "fcntl",
    73: "flock",
    74: "fsync",
    75: "fdatasync",
    76: "truncate",
    77: "ftruncate",
    78: "getdents",
    79: "getcwd",
    80: "chdir",
    81: "fchdir",
    82: "rename",
    83: "mkdir",
    84: "rmdir",
    85: "creat",
    86: "link",
    87: "unlink",
    88: "symlink",
    89: "readlink",
    90: "chmod",
    91: "fchmod",
    92: "chown",
    93: "fchown",
    94: "lchown",
    95: "umask",
    96: "gettimeofday",
    97: "getrlimit",
    98: "getrusage",
    99: "sysinfo",
    100: "times",
    101: "ptrace",
    102: "getuid",
    103: "syslog",
    104: "getgid",
    105: "setuid",
    106: "setgid",
    107: "geteuid",
    108: "getegid",
    109: "setpgid",
    110: "getppid",
    111: "getpgrp",
    112: "setsid",
    113: "setreuid",
    114: "setregid",
    115: "getgroups",
    116: "setgroups",
    117: "setresuid",
    118: "getresuid",
    119: "setresgid",
    120: "getresgid",
    121: "getpgid",
    122: "setfsuid",
    123: "setfsgid",
    124: "getsid",
    125: "capget",
    126: "capset",
    127: "rt_sigpending",
    128: "rt_sigtimedwait",
    129: "rt_sigqueueinfo",
    130: "rt_sigsuspend",
    131: "sigaltstack",
    132: "utime",
    133: "mknod",
    134: "uselib",
    135: "personality",
    136: "ustat",
    137: "statfs",
    138: "fstatfs",
    139: "sysfs",
    140: "getpriority",
    141: "setpriority",
    142: "sched_setparam",
    143: "sched_getparam",
    144: "sched_setscheduler",
    145: "sched_getscheduler",
    146: "sched_get_priority_max",
    147: "sched_get_priority_min",
    148: "sched_rr_get_interval",
    149: "mlock",
    150: "munlock",
    151: "mlockall",
    152: "munlockall",
    153: "vhangup",
    154: "modify_ldt",
    155: "pivot_root",
    156: "_sysctl",
    157: "prctl",
    158: "arch_prctl",
    159: "adjtimex",
    160: "setrlimit",
    161: "chroot",
    162: "sync",
    163: "acct",
    164: "settimeofday",
    165: "mount",
    166: "umount2",
    167: "swapon",
    168: "swapoff",
    169: "reboot",
    170: "sethostname",
    171: "setdomainname",
    172: "iopl",
    173: "ioperm",
    174: "create_module",
    175: "init_module",
    176: "delete_module",
    177: "get_kernel_syms",
    178: "query_module",
    179: "quotactl",
    180: "nfsservctl",
    181: "getpmsg",
    182: "putpmsg",
    183: "afs_syscall",
    184: "tuxcall",
    185: "security",
    186: "gettid",
    187: "readahead",
    188: "setxattr",
    189: "lsetxattr",
    190: "fsetxattr",
    191: "getxattr",
    192: "lgetxattr",
    193: "fgetxattr",
    194: "listxattr",
    195: "llistxattr",
    196: "flistxattr",
    197: "removexattr",
    198: "lremovexattr",
    199: "fremovexattr",
    200: "tkill",
    201: "time",
    202: "futex",
    203: "sched_setaffinity",
    204: "sched_getaffinity",
    205: "set_thread_area",
    206: "io_setup",
    207: "io_destroy",
    208: "io_getevents",
    209: "io_submit",
    210: "io_cancel",
    211: "get_thread_area",
    212: "lookup_dcookie",
    213: "epoll_create",
    214: "epoll_ctl_old",
    215: "epoll_wait_old",
    216: "remap_file_pages",
    217: "getdents64",
    218: "set_tid_address",
    219: "restart_syscall",
    220: "semtimedop",
    221: "fadvise64",
    222: "timer_create",
    223: "timer_settime",
    224: "timer_gettime",
    225: "timer_getoverrun",
    226: "timer_delete",
    227: "clock_settime",
    228: "clock_gettime",
    229: "clock_getres",
    230: "clock_nanosleep",
    231: "exit_group",
    232: "epoll_wait",
    233: "epoll_ctl",
    234: "tgkill",
    235: "utimes",
    236: "vserver",
    237: "mbind",
    238: "set_mempolicy",
    239: "get_mempolicy",
    240: "mq_open",
    241: "mq_unlink",
    242: "mq_timedsend",
    243: "mq_timedreceive",
    244: "mq_notify",
    245: "mq_getsetattr",
    246: "kexec_load",
    247: "waitid",
    248: "add_key",
    249: "request_key",
    250: "keyctl",
    251: "ioprio_set",
    252: "ioprio_get",
    253: "inotify_init",
    254: "inotify_add_watch",
    255: "inotify_rm_watch",
    256: "migrate_pages",
    257: "openat",
    258: "mkdirat",
    259: "mknodat",
    260: "fchownat",
    261: "futimesat",
    262: "newfstatat",
    263: "unlinkat",
    264: "renameat",
    265: "linkat",
    266: "symlinkat",
    267: "readlinkat",
    268: "fchmodat",
    269: "faccessat",
    270: "pselect6",
    271: "ppoll",
    272: "unshare",
    273: "set_robust_list",
    274: "get_robust_list",
    275: "splice",
    276: "tee",
    277: "sync_file_range",
    278: "vmsplice",
    279: "move_pages",
    280: "utimensat",
    281: "epoll_pwait",
    282: "signalfd",
    283: "timerfd_create",
    284: "eventfd",
    285: "fallocate",
    286: "timerfd_settime",
    287: "timerfd_gettime",
    288: "accept4",
    289: "signalfd4",
    290: "eventfd2",
    291: "epoll_create1",
    292: "dup3",
    293: "pipe2",
    294: "inotify_init1",
    295: "preadv",
    296: "pwritev",
    297: "rt_tgsigqueueinfo",
    298: "perf_event_open",
    299: "recvmmsg",
    300: "fanotify_init",
    301: "fanotify_mark",
    302: "prlimit64",
    303: "name_to_handle_at",
    304: "open_by_handle_at",
    305: "clock_adjtime",
    306: "syncfs",
    307: "sendmmsg",
    308: "setns",
    309: "getcpu",
    310: "process_vm_readv",
    311: "process_vm_writev",
    312: "kcmp",
    313: "finit_module",
    314: "sched_setattr",
    315: "sched_getattr",
    316: "renameat2",
    317: "seccomp",
    318: "getrandom",
    319: "memfd_create",
    320: "kexec_file_load",
    321: "bpf",
    322: "execveat",
    323: "userfaultfd",
    324: "membarrier",
    325: "mlock2",
    326: "copy_file_range",
    327: "preadv2",
    328: "pwritev2",
    329: "pkey_mprotect",
    330: "pkey_alloc",
    331: "pkey_free",
    332: "statx",
    333: "io_pgetevents",
    334: "rseq",
    424: "pidfd_send_signal",
    425: "io_uring_setup",
    426: "io_uring_enter",
    427: "io_uring_register",
    428: "open_tree",
    429: "move_mount",
    430: "fsopen",
    431: "fsconfig",
    432: "fsmount",
    433: "fspick",
    434: "pidfd_open",
    435: "clone3",
    436: "close_range",
    437: "openat2",
    438: "pidfd_getfd",
    439: "faccessat2",
    440: "process_madvise",
    441: "epoll_pwait2",
    442: "mount_setattr",
    443: "quotactl_fd",
    444: "landlock_create_ruleset",
    445: "landlock_add_rule",
    446: "landlock_restrict_self",
    447: "memfd_secret",
    448: "process_mrelease",
    449: "futex_waitv",
    450: "set_mempolicy_home_node",
    451: "cachestat"
}

# A small map of common libc wrapper names to syscall names.
WRAPPER_SYSCALL_MAP: Dict[str, str] = {
    "open": "open",
    "openat": "openat",
    "read": "read",
    "write": "write",
    "close": "close",
    "lseek": "lseek",
    "stat": "stat",
    "fstat": "fstat",
    "lstat": "lstat",
    "mkdir": "mkdir",
    "mkdirat": "mkdirat",
    "rmdir": "rmdir",
    "rename": "rename",
    "unlink": "unlink",
    "unlinkat": "unlinkat",
    "chmod": "chmod",
    "fchmod": "fchmod",
    "chown": "chown",
    "fchown": "fchown",
    "getcwd": "getcwd",
    "chdir": "chdir",
    "dup": "dup",
    "dup2": "dup2",
    "dup3": "dup3",
    "pipe": "pipe",
    "pipe2": "pipe2",
    "socket": "socket",
    "connect": "connect",
    "accept": "accept",
    "bind": "bind",
    "listen": "listen",
    "accept4": "accept4",
    "sendto": "sendto",
    "recvfrom": "recvfrom",
    "sendmsg": "sendmsg",
    "recvmsg": "recvmsg",
    "shutdown": "shutdown",
    "setsockopt": "setsockopt",
    "getsockopt": "getsockopt",
    "fork": "fork",
    "vfork": "vfork",
    "clone": "clone",
    "execve": "execve",
    "execveat": "execveat",
    "getpid": "getpid",
    "getuid": "getuid",
    "geteuid": "geteuid",
    "getgid": "getgid",
    "getegid": "getegid",
    "exit": "exit",
    "exit_group": "exit_group",
    "nanosleep": "nanosleep",
    "clock_gettime": "clock_gettime",
    "gettimeofday": "gettimeofday",
    "fcntl": "fcntl",
    "ioctl": "ioctl",
    "pread64": "pread64",
    "pwrite64": "pwrite64",
    "readv": "readv",
    "writev": "writev",
    "getdents": "getdents",
    "getdents64": "getdents64",
    "access": "access",
    "faccessat": "faccessat",
}

_WORD_PATTERN = re.compile(r"[-]?0x[0-9a-fA-F]+|\d+")
_MOV_TO_RAX_PATTERN = re.compile(r"(?:mov|movabs)\s+(?:rax|eax),\s*([\da-fx]+)")
_SYSCALL_ARG_REGISTERS = {"rax", "eax", "rax", "rdi", "edi", "rsi", "esi", "rdx", "edx", "rcx", "ecx", "r8", "r8d", "r9", "r9d"}


@dataclass
class Instruction:
    address: int
    mnemonic: str
    op_str: str


@dataclass
class FunctionAnalysis:
    name: str
    address: int
    size: int
    syscalls: Set[str]
    calls: Set[str]
    syscall_sites: Set[int]
    unresolved_calls: Set[int]


@dataclass
class AnalysisResult:
    files: List[str]
    direct_syscalls: Set[str]
    indirect_syscalls: Set[str]
    reachable_syscalls: Set[str]
    function_analysis: Dict[str, FunctionAnalysis]
    roots: List[str]
    reachable_functions: Set[str]
    warnings: List[str]
    architecture: str

    @property
    def allowed_syscalls(self) -> Set[str]:
        return set(sorted(self.reachable_syscalls))

    def to_dict(self) -> Dict[str, object]:
        functions = []
        edges = []
        for function in sorted(self.function_analysis.values(), key=lambda item: (item.name, item.address)):
            functions.append({
                "name": function.name,
                "address": hex(function.address),
                "size": function.size,
                "syscalls": sorted(function.syscalls),
                "syscall_sites": [hex(address) for address in sorted(function.syscall_sites)],
                "unresolved_calls": [hex(address) for address in sorted(function.unresolved_calls)],
                "reachable": function.name in self.reachable_functions,
            })
            for target in sorted(function.calls):
                edges.append({"caller": function.name, "callee": target})
        return {
            "files": self.files,
            "architecture": self.architecture,
            "roots": self.roots,
            "functions": functions,
            "call_graph": edges,
            "direct_syscalls": sorted(self.direct_syscalls),
            "indirect_syscalls": sorted(self.indirect_syscalls),
            "reachable_syscalls": sorted(self.reachable_syscalls),
            "static_seccomp_file": {
                "default_action": "deny",
                "allow": sorted(self.allowed_syscalls),
            },
            "warnings": sorted(self.warnings),
        }


def supported_architecture(elf: ELFFile) -> Tuple[int, str]:
    header = elf.header
    machine = header["e_machine"]
    klass = header["e_ident"]["EI_CLASS"]
    if machine == "EM_X86_64" or machine == "EM_386":
        mode = CS_MODE_64 if klass == "ELFCLASS64" else CS_MODE_32
        return CS_ARCH_X86, mode
    if machine == "EM_AARCH64":
        return CS_ARCH_ARM64, CS_MODE_ARM
    raise NotImplementedError(f"Unsupported ELF machine type: {machine}")


def iter_relocations(elf: ELFFile) -> Iterator[Tuple[int, str]]:
    for section in elf.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        symbol_table = elf.get_section(section["sh_link"])
        if not hasattr(symbol_table, "get_symbol"):
            continue
        for relocation in section.iter_relocations():
            try:
                symbol = symbol_table.get_symbol(relocation["r_info_sym"])
            except (IndexError, ValueError):
                continue
            if symbol is None:
                continue
            yield relocation["r_offset"], symbol.name


def get_plt_symbols(elf: ELFFile) -> Dict[int, str]:
    symbols: Dict[int, str] = {}
    relocation_names: List[str] = []
    for section in elf.iter_sections():
        if section.name != ".rela.plt" or not isinstance(section, RelocationSection):
            continue
        symbol_table = elf.get_section(section["sh_link"])
        if not hasattr(symbol_table, "get_symbol"):
            continue
        for relocation in section.iter_relocations():
            try:
                symbol = symbol_table.get_symbol(relocation["r_info_sym"])
            except (IndexError, ValueError):
                continue
            if symbol is not None and symbol.name:
                relocation_names.append(symbol.name)

    for section_name, entry_size, entry_offset in ((".plt.sec", 16, 0), (".plt", 16, 16)):
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        for index, name in enumerate(relocation_names):
            address = section["sh_addr"] + entry_offset + index * entry_size
            if address < section["sh_addr"] + section["sh_size"]:
                symbols[address] = name.split("@", 1)[0]
    return symbols


def get_executable_sections(elf: ELFFile) -> List[Section]:
    sections = []
    for section in elf.iter_sections():
        if section["sh_size"] and section["sh_flags"] & SH_FLAGS.SHF_EXECINSTR:
            sections.append(section)
    return sorted(sections, key=lambda section: section["sh_addr"])


def parse_symbol_functions(elf: ELFFile) -> List[FunctionAnalysis]:
    functions: Dict[int, FunctionAnalysis] = {}
    for section in elf.iter_sections():
        if section.name not in (".symtab", ".dynsym"):
            continue
        for symbol in section.iter_symbols():
            if symbol["st_info"]["type"] != "STT_FUNC":
                continue
            address = symbol["st_value"]
            size = symbol["st_size"] or 0
            name = symbol.name or f"func_{address:x}"
            if address == 0:
                continue
            if address in functions:
                continue
            functions[address] = FunctionAnalysis(name=name, address=address, size=size, syscalls=set(), calls=set(), syscall_sites=set(), unresolved_calls=set())
    return [functions[address] for address in sorted(functions)]


def disassemble_section(section: Section, arch: int, mode: int) -> List[Instruction]:
    code = section.data()
    address = section["sh_addr"]
    md = Cs(arch, mode)
    md.detail = True
    return [Instruction(ins.address, ins.mnemonic, ins.op_str) for ins in md.disasm(code, address)]


def parse_immediate_value(text: str) -> Optional[int]:
    value = text.strip()
    if not value:
        return None
    try:
        if value.startswith("0x") or value.startswith("-0x"):
            return int(value, 16)
        return int(value, 10)
    except ValueError:
        return None


def extract_constant_assignments(instruction: Instruction) -> Dict[str, int]:
    assignments: Dict[str, int] = {}
    if instruction.mnemonic not in {"mov", "movabs"}:
        return assignments

    operands = [operand.strip() for operand in instruction.op_str.split(",", 1)]
    if len(operands) != 2:
        return assignments

    destination, source = operands
    value = parse_immediate_value(source)
    if value is not None:
        assignments[destination] = value
    return assignments


def infer_syscall_name(instructions: Sequence[Instruction], idx: int) -> Optional[str]:
    candidate_syscall = instructions[idx]
    if candidate_syscall.mnemonic != "syscall" and not (
        candidate_syscall.mnemonic == "int" and candidate_syscall.op_str.strip() == "0x80"
    ):
        return None

    register_values: Dict[str, int] = {}
    for back in range(max(0, idx - 10), idx):
        instruction = instructions[back]
        register_values.update(extract_constant_assignments(instruction))

    for register in ("rax", "eax"):
        if register in register_values:
            return SYSCALL_NAME_BY_NUMBER.get(register_values[register], f"syscall_{register_values[register]}")

    for register in ("rdi", "edi"):
        if register in register_values:
            return SYSCALL_NAME_BY_NUMBER.get(register_values[register], f"syscall_{register_values[register]}")

    return "syscall_unknown"


def find_syscall_name_from_instruction_window(instructions: Sequence[Instruction], idx: int) -> Optional[str]:
    return infer_syscall_name(instructions, idx)


def parse_call_target(
    instruction: Instruction,
    relocations: Dict[int, str],
    functions: List[FunctionAnalysis],
    plt_symbols: Optional[Dict[int, str]] = None,
) -> Optional[str]:
    if not instruction.mnemonic.startswith("call"):
        return None
    op = instruction.op_str.strip()
    if op.endswith("@plt"):
        return op[: -len("@plt")]
    if op.startswith("0x"):
        try:
            address = int(op, 16)
            if plt_symbols and address in plt_symbols:
                return plt_symbols[address]
            return resolve_symbol_by_address(address, functions, relocations)
        except ValueError:
            return None
    if op.startswith("[rip") or op.startswith("qword ptr [rip"):
        return relocations.get(instruction.address)
    if op in {fn.name for fn in functions}:
        return op
    return None


def function_containing_address(functions: Sequence[FunctionAnalysis], address: int) -> Optional[FunctionAnalysis]:
    candidates = [fn for fn in functions if fn.address <= address < (fn.address + max(fn.size, 1))]
    if not candidates:
        return None
    return max(candidates, key=lambda fn: fn.address)


def function_instruction_ranges(functions: Sequence[FunctionAnalysis]) -> List[Tuple[int, int, FunctionAnalysis]]:
    ordered = sorted(functions, key=lambda fn: fn.address)
    ranges: List[Tuple[int, int, FunctionAnalysis]] = []
    for index, function in enumerate(ordered):
        start = function.address
        next_start = ordered[index + 1].address if index + 1 < len(ordered) else start + max(function.size, 1)
        end = max(start + max(function.size, 1), next_start)
        ranges.append((start, end, function))
    return ranges


def function_for_instruction(
    ranges: Sequence[Tuple[int, int, FunctionAnalysis]],
    address: int,
    starts: Optional[Sequence[int]] = None,
) -> Optional[FunctionAnalysis]:
    if not ranges:
        return None
    if starts is None:
        starts = [start for start, _, _ in ranges]
    index = bisect_right(starts, address) - 1
    if index < 0:
        return None
    start, end, function = ranges[index]
    return function if start <= address < end else None


def parse_call_immediate_target(instruction: Instruction) -> Optional[int]:
    op = instruction.op_str.strip()
    if not op.startswith("0x"):
        return None
    try:
        return int(op, 16)
    except ValueError:
        return None


def parse_register_name(operand: str) -> str:
    return operand.strip().lower().lstrip("%")


def infer_call_argument_constants(instructions: Sequence[Instruction], idx: int) -> Dict[str, int]:
    register_values: Dict[str, int] = {}
    for back in range(max(0, idx - 8), idx):
        instruction = instructions[back]
        register_values.update(extract_constant_assignments(instruction))
    return register_values


def infer_libc_syscall_wrapper(target: Optional[str], call_arguments: Dict[str, int]) -> Optional[str]:
    if target == "syscall":
        for register in ("rdi", "edi"):
            if register in call_arguments:
                syscall_number = call_arguments[register]
                return SYSCALL_NAME_BY_NUMBER.get(syscall_number, f"syscall_{syscall_number}")
    return None


def infer_wrapper_syscalls(
    functions: Sequence[FunctionAnalysis],
    function_by_name: Dict[str, FunctionAnalysis],
    instruction_map: Dict[str, List[Instruction]],
    call_edges: Dict[str, List[Tuple[str, Dict[str, int]]]],
) -> Set[str]:
    wrapper_syscalls: Set[str] = set()
    for function in functions:
        if not function.syscalls:
            continue
        for caller_name, call_arguments in call_edges.get(function.name, []):
            caller = function_by_name.get(caller_name)
            if caller is None:
                continue
            if function.syscalls == {"syscall_unknown"}:
                for argument_value in call_arguments.values():
                    syscall_name = SYSCALL_NAME_BY_NUMBER.get(argument_value)
                    if syscall_name is not None:
                        wrapper_syscalls.add(syscall_name)
            else:
                wrapper_syscalls.update(syscall for syscall in function.syscalls if syscall != "syscall_unknown")
    return wrapper_syscalls


def resolve_symbol_by_address(address: int, functions: List[FunctionAnalysis], relocations: Dict[int, str]) -> Optional[str]:
    if address in relocations:
        return relocations[address]
    candidates = [fn for fn in functions if fn.address <= address < (fn.address + max(fn.size, 1))]
    if candidates:
        return max(candidates, key=lambda fn: fn.address).name
    return None


def architecture_name(elf: ELFFile) -> str:
    machine = elf.header["e_machine"]
    if machine == "EM_X86_64":
        return "x86_64"
    if machine == "EM_386":
        return "i386"
    if machine == "EM_AARCH64":
        return "aarch64"
    return str(machine)


def analyze_single_elf(path: str) -> AnalysisResult:
    with open(path, "rb") as stream:
        elf = ELFFile(stream)
        arch, mode = supported_architecture(elf)
        executable_sections = get_executable_sections(elf)
        if not executable_sections:
            raise ValueError(f"No executable sections found in {path}")
        instructions = [
            instruction
            for section in executable_sections
            for instruction in disassemble_section(section, arch, mode)
        ]
        functions = parse_symbol_functions(elf)
        if not functions and instructions:
            start = min(instruction.address for instruction in instructions)
            end = max(instruction.address for instruction in instructions) + 1
            functions = [FunctionAnalysis(
                name="__stripped_code__",
                address=start,
                size=end - start,
                syscalls=set(),
                calls=set(),
                syscall_sites=set(),
                unresolved_calls=set(),
            )]
        relocations = {offset: name for offset, name in iter_relocations(elf)}
        plt_symbols = get_plt_symbols(elf)
        function_ranges = function_instruction_ranges(functions)
        function_by_name = {fn.name: fn for fn in functions}
        function_starts = [start for start, _, _ in function_ranges]
        instruction_map: Dict[str, List[Instruction]] = {fn.name: [] for fn in functions}
        call_edges: Dict[str, List[Tuple[str, Dict[str, int]]]] = {}
        wrapper_syscalls_detected: Set[str] = set()

        direct_syscalls = set()
        indirect_syscalls = set()
        for idx, instruction in enumerate(instructions):
            function = function_for_instruction(function_ranges, instruction.address, function_starts)
            if function is not None:
                instruction_map[function.name].append(instruction)

            if instruction.mnemonic == "syscall" or (
                instruction.mnemonic == "int" and instruction.op_str.strip() == "0x80"
            ):
                syscall_name = find_syscall_name_from_instruction_window(instructions, idx)
                direct_syscalls.add(syscall_name)
                if function:
                    function.syscalls.add(syscall_name)
                    function.syscall_sites.add(instruction.address)
            elif instruction.mnemonic.startswith("call"):
                target = parse_call_target(instruction, relocations, functions, plt_symbols)
                if target:
                    if function:
                        function.calls.add(target)
                        call_arguments = infer_call_argument_constants(instructions, idx)
                        call_edges.setdefault(target, []).append((function.name, call_arguments))
                        wrapper_syscall = infer_libc_syscall_wrapper(target, call_arguments)
                        if wrapper_syscall:
                            wrapper_syscalls_detected.add(wrapper_syscall)
                elif function:
                    function.unresolved_calls.add(instruction.address)

        for function in functions:
            if function.syscalls == {"syscall_unknown"} and function.name in call_edges:
                for caller_name, call_arguments in call_edges[function.name]:
                    for argument_value in call_arguments.values():
                        inferred = SYSCALL_NAME_BY_NUMBER.get(argument_value)
                        if inferred is None:
                            continue
                        function.syscalls.add(inferred)
                        direct_syscalls.add(inferred)
                        indirect_syscalls.add(inferred)
                        caller = function_by_name.get(caller_name)
                        if caller is not None:
                            caller.syscalls.add(inferred)

        inferred_wrapper_syscalls = infer_wrapper_syscalls(functions, function_by_name, instruction_map, call_edges)
        for function in functions:
            if function.syscalls and function.syscalls != {"syscall_unknown"}:
                continue
            if function.name in call_edges:
                for _, call_arguments in call_edges[function.name]:
                    for argument_value in call_arguments.values():
                        inferred = SYSCALL_NAME_BY_NUMBER.get(argument_value)
                        if inferred is not None:
                            function.syscalls.discard("syscall_unknown")
                            function.syscalls.add(inferred)

        for function in functions:
            if "syscall_unknown" in function.syscalls and len(function.syscalls) > 1:
                function.syscalls.discard("syscall_unknown")

        direct_syscalls = set()
        indirect_syscalls = set()
        indirect_syscalls.update(wrapper_syscalls_detected)
        for function in functions:
            if function.syscalls:
                direct_syscalls.update(function.syscalls)
            if function.calls:
                for call_name in function.calls:
                    if call_name in WRAPPER_SYSCALL_MAP:
                        indirect_syscalls.add(WRAPPER_SYSCALL_MAP[call_name])
                    if call_name in function_by_name and function_by_name[call_name].syscalls:
                        indirect_syscalls.update(function_by_name[call_name].syscalls)

        for syscall_name in inferred_wrapper_syscalls:
            indirect_syscalls.add(syscall_name)

        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym is not None:
            for symbol in dynsym.iter_symbols():
                name = symbol.name
                if name in WRAPPER_SYSCALL_MAP:
                    indirect_syscalls.add(WRAPPER_SYSCALL_MAP[name])

        reachable_functions = compute_reachable_functions(functions)
        reachable = compute_reachable_syscalls(functions, direct_syscalls, indirect_syscalls)
        roots = [fn.name for fn in functions if fn.name in ("_start", "main")]
        if not roots and functions:
            roots = [functions[0].name]
        warnings = []
        if functions and functions[0].name == "__stripped_code__":
            warnings.append("No local function symbols were found; using a synthetic code root")
        unknown_functions = [fn.name for fn in functions if fn.syscalls == {"syscall_unknown"}]
        if unknown_functions:
            warnings.append("Unknown syscall numbers detected in: " + ", ".join(sorted(unknown_functions)))
        unresolved = sum(len(fn.unresolved_calls) for fn in functions)
        if unresolved:
            warnings.append(f"{unresolved} unresolved call target(s) were excluded from the call graph")
        return AnalysisResult(
            files=[path],
            direct_syscalls=direct_syscalls,
            indirect_syscalls=indirect_syscalls,
            reachable_syscalls=reachable,
            function_analysis={fn.name: fn for fn in functions},
            roots=roots,
            reachable_functions=reachable_functions,
            warnings=warnings,
            architecture=architecture_name(elf),
        )


def compute_reachable_functions(functions: Sequence[FunctionAnalysis]) -> Set[str]:
    by_name = {fn.name: fn for fn in functions}
    roots = [fn.name for fn in functions if fn.name in ("_start", "main")]
    if not roots and functions:
        roots = [functions[0].name]
    reachable: Set[str] = set()
    queue = deque(roots)
    while queue:
        current = queue.popleft()
        if current in reachable:
            continue
        function = by_name.get(current)
        if function is None:
            continue
        reachable.add(current)
        queue.extend(call for call in function.calls if call in by_name)
    return reachable


def compute_reachable_syscalls(functions: List[FunctionAnalysis], direct: Set[str], indirect: Set[str]) -> Set[str]:
    by_name = {fn.name: fn for fn in functions}
    reachable_functions = compute_reachable_functions(functions)
    reachable: Set[str] = set()
    for function_name in reachable_functions:
        reachable.update(by_name[function_name].syscalls)
        for call_name in by_name[function_name].calls:
            syscall_name = WRAPPER_SYSCALL_MAP.get(call_name)
            if syscall_name:
                reachable.add(syscall_name)
    reachable.update(indirect)
    return reachable


def analyze_paths(paths: Sequence[str]) -> AnalysisResult:
    total_direct: Set[str] = set()
    total_indirect: Set[str] = set()
    total_reachable: Set[str] = set()
    roots: List[str] = []
    reachable_functions: Set[str] = set()
    warnings: List[str] = []
    architectures: Set[str] = set()
    function_analysis: Dict[str, FunctionAnalysis] = {}
    for path in paths:
        result = analyze_single_elf(path)
        total_direct.update(result.direct_syscalls)
        total_indirect.update(result.indirect_syscalls)
        total_reachable.update(result.reachable_syscalls)
        roots.extend(f"{path}:{root}" for root in result.roots)
        reachable_functions.update(result.reachable_functions)
        warnings.extend(f"{path}: {warning}" for warning in result.warnings)
        architectures.add(result.architecture)
        function_analysis.update(result.function_analysis)

    return AnalysisResult(
        files=list(paths),
        direct_syscalls=total_direct,
        indirect_syscalls=total_indirect,
        reachable_syscalls=total_reachable,
        function_analysis=function_analysis,
        roots=roots,
        reachable_functions=reachable_functions,
        warnings=sorted(warnings),
        architecture=next(iter(architectures)) if len(architectures) == 1 else "mixed",
    )


def generate_seccomp_profile(allowed_syscalls: Iterable[str]) -> str:
    allowed = set(allowed_syscalls)
    if "syscall_unknown" in allowed:
        raise ValueError("Cannot generate a seccomp profile with an unknown syscall")
    lines = [f"allow {syscall}" for syscall in sorted(allowed)]
    lines.append("deny")
    return "\n".join(lines) + "\n"


def generate_oci_seccomp_profile(allowed_syscalls: Iterable[str], architecture: str) -> str:
    architecture_names = {
        "x86_64": "SCMP_ARCH_X86_64",
        "i386": "SCMP_ARCH_X86",
        "aarch64": "SCMP_ARCH_AARCH64",
    }
    seccomp_architecture = architecture_names.get(architecture)
    if seccomp_architecture is None:
        raise ValueError(f"Unsupported seccomp architecture: {architecture}")
    allowed = sorted(set(allowed_syscalls))
    if "syscall_unknown" in allowed:
        raise ValueError("Cannot generate a seccomp profile with an unknown syscall")
    return json.dumps({
        "defaultAction": "SCMP_ACT_ERRNO",
        "architectures": [seccomp_architecture],
        "syscalls": [{
            "names": allowed,
            "action": "SCMP_ACT_ALLOW",
        }],
    }, indent=2) + "\n"


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Static ELF syscall analyzer for seccomp profiles.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Inspect ELF files for syscalls.")
    analyze_parser.add_argument("files", nargs="+", help="ELF binaries or shared libraries to analyze.")
    analyze_parser.add_argument("--json", action="store_true", help="Output the analysis result in JSON.")

    profile_parser = subparsers.add_parser("generate-profile", help="Generate a seccomp allowlist from ELF analysis.")
    profile_parser.add_argument("files", nargs="+", help="ELF binaries or shared libraries to analyze.")
    profile_parser.add_argument("--output", help="Write the generated profile to a file instead of stdout.")
    profile_parser.add_argument(
        "--format",
        choices=("oci", "text"),
        default="oci",
        help="Profile format: OCI/Docker seccomp JSON (default) or legacy text.",
    )

    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    result = analyze_paths(args.files)
    if args.command == "analyze":
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
            return 0
        print("Files:")
        for filename in result.files:
            print(f"  {filename}")
        print("Direct syscalls:")
        for syscall in sorted(result.direct_syscalls):
            print(f"  {syscall}")
        print("Indirect syscalls:")
        for syscall in sorted(result.indirect_syscalls):
            print(f"  {syscall}")
        print("Reachable syscalls:")
        for syscall in sorted(result.reachable_syscalls):
            print(f"  {syscall}")
        return 0

    if result.warnings:
        print("warning: static analysis has incomplete call-target information:", file=sys.stderr)
        for warning in result.warnings:
            print(f"  {warning}", file=sys.stderr)
    try:
        if args.format == "oci":
            profile = generate_oci_seccomp_profile(result.allowed_syscalls, result.architecture)
        else:
            profile = generate_seccomp_profile(result.allowed_syscalls)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(profile)
        print(f"Wrote seccomp profile to {args.output}")
    else:
        print(profile)
    return 0
