from __future__ import annotations

import argparse
import json
import re
from collections import deque
from dataclasses import dataclass
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

from capstone import CS_ARCH_X86, CS_ARCH_ARM64, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section
from elftools.elf.relocation import RelocationSection
from elftools.elf.constants import P_FLAGS

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


@dataclass
class AnalysisResult:
    files: List[str]
    direct_syscalls: Set[str]
    indirect_syscalls: Set[str]
    reachable_syscalls: Set[str]
    function_analysis: Dict[str, FunctionAnalysis]

    @property
    def allowed_syscalls(self) -> Set[str]:
        return set(sorted(self.reachable_syscalls))


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
        for relocation in section.iter_relocations():
            symbol = symbol_table.get_symbol(relocation["r_info_sym"])
            if symbol is None:
                continue
            yield relocation["r_offset"], symbol.name


def get_text_section(elf: ELFFile) -> Optional[Section]:
    for section in elf.iter_sections():
        if section.name == ".text":
            return section
    return None


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
            functions[address] = FunctionAnalysis(name=name, address=address, size=size, syscalls=set(), calls=set(), syscall_sites=set())
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


def parse_call_target(instruction: Instruction, relocations: Dict[int, str], functions: List[FunctionAnalysis]) -> Optional[str]:
    if not instruction.mnemonic.startswith("call"):
        return None
    op = instruction.op_str.strip()
    if op.endswith("@plt"):
        return op[: -len("@plt")]
    if op.startswith("0x"):
        try:
            address = int(op, 16)
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


def function_for_instruction(ranges: Sequence[Tuple[int, int, FunctionAnalysis]], address: int) -> Optional[FunctionAnalysis]:
    for start, end, function in ranges:
        if start <= address < end:
            return function
    return None


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


def analyze_single_elf(path: str) -> AnalysisResult:
    with open(path, "rb") as stream:
        elf = ELFFile(stream)
        arch, mode = supported_architecture(elf)
        text_section = get_text_section(elf)
        if text_section is None:
            raise ValueError(f"No .text section found in {path}")
        instructions = disassemble_section(text_section, arch, mode)
        functions = parse_symbol_functions(elf)
        relocations = {offset: name for offset, name in iter_relocations(elf)}
        function_ranges = function_instruction_ranges(functions)
        function_by_name = {fn.name: fn for fn in functions}
        instruction_map: Dict[str, List[Instruction]] = {fn.name: [] for fn in functions}
        call_edges: Dict[str, List[Tuple[str, Dict[str, int]]]] = {}

        direct_syscalls = set()
        indirect_syscalls = set()
        for idx, instruction in enumerate(instructions):
            function = function_for_instruction(function_ranges, instruction.address)
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
                target = parse_call_target(instruction, relocations, functions)
                if target:
                    if function:
                        function.calls.add(target)
                        call_arguments = infer_call_argument_constants(instructions, idx)
                        call_edges.setdefault(target, []).append((function.name, call_arguments))

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

        reachable = compute_reachable_syscalls(functions, direct_syscalls, indirect_syscalls)
        return AnalysisResult(
            files=[path],
            direct_syscalls=direct_syscalls,
            indirect_syscalls=indirect_syscalls,
            reachable_syscalls=reachable,
            function_analysis={fn.name: fn for fn in functions},
        )


def compute_reachable_syscalls(functions: List[FunctionAnalysis], direct: Set[str], indirect: Set[str]) -> Set[str]:
    by_name = {fn.name: fn for fn in functions}
    entrypoints = [fn.name for fn in functions if fn.name in ("_start", "main")]
    if not entrypoints:
        entrypoints = [functions[0].name] if functions else []

    reachable: Set[str] = set(direct)
    visited: Set[str] = set()
    queue = deque(entrypoints)
    while queue:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)
        function = by_name.get(current)
        if not function:
            continue
        reachable.update(function.syscalls)
        for call_name in function.calls:
            if call_name in by_name and call_name not in visited:
                queue.append(call_name)
    reachable.update(indirect)
    return reachable


def analyze_paths(paths: Sequence[str]) -> AnalysisResult:
    total_direct: Set[str] = set()
    total_indirect: Set[str] = set()
    function_analysis: Dict[str, FunctionAnalysis] = {}
    for path in paths:
        result = analyze_single_elf(path)
        total_direct.update(result.direct_syscalls)
        total_indirect.update(result.indirect_syscalls)
        function_analysis.update(result.function_analysis)

    reachable = set(total_direct) | set(total_indirect)
    return AnalysisResult(
        files=list(paths),
        direct_syscalls=total_direct,
        indirect_syscalls=total_indirect,
        reachable_syscalls=reachable,
        function_analysis=function_analysis,
    )


def generate_seccomp_profile(allowed_syscalls: Iterable[str]) -> str:
    lines = [f"allow {syscall}" for syscall in sorted(set(allowed_syscalls))]
    lines.append("deny")
    return "\n".join(lines) + "\n"


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Static ELF syscall analyzer for seccomp profiles.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Inspect ELF files for syscalls.")
    analyze_parser.add_argument("files", nargs="+", help="ELF binaries or shared libraries to analyze.")
    analyze_parser.add_argument("--json", action="store_true", help="Output the analysis result in JSON.")

    profile_parser = subparsers.add_parser("generate-profile", help="Generate a seccomp allowlist from ELF analysis.")
    profile_parser.add_argument("files", nargs="+", help="ELF binaries or shared libraries to analyze.")
    profile_parser.add_argument("--output", help="Write the generated profile to a file instead of stdout.")

    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    result = analyze_paths(args.files)
    if args.command == "analyze":
        if args.json:
            print(json.dumps({
                "files": result.files,
                "direct_syscalls": sorted(result.direct_syscalls),
                "indirect_syscalls": sorted(result.indirect_syscalls),
                "reachable_syscalls": sorted(result.reachable_syscalls),
            }, indent=2))
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

    profile = generate_seccomp_profile(result.allowed_syscalls)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(profile)
        print(f"Wrote seccomp profile to {args.output}")
    else:
        print(profile)
    return 0
