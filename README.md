# Seccomp Static Analyzer

This tool performs a conservative static analysis of Linux ELF programs. It disassembles executable code, constructs a function call graph, identifies direct `syscall` instructions and known libc-style wrappers, then computes the syscall requirements reachable from `_start` or `main`.

The JSON result is the Static Seccomp File (S-SF) produced by this phase. It includes the call graph, roots, syscall evidence, reachable functions, reachable syscalls, and warnings about analysis uncertainty. The analyzer does not claim to see code loaded at runtime, JIT-generated code, external processes, or unresolved function-pointer targets.

## Usage

Analyze ELF binaries and print allowed syscalls:

```bash
python3 -m static_analysis.cli analyze /path/to/binary /path/to/lib.so
```

Write the complete S-SF as JSON:

```bash
python3 -m static_analysis.cli analyze --json /path/to/binary > static-seccomp.json
```

Generate a basic text seccomp profile:

```bash
python3 -m static_analysis.cli generate-profile --output seccomp.txt /path/to/binary
```

Profile generation reports unresolved call targets as warnings and includes the recovered syscall requirements. Unknown syscall numbers still prevent profile generation. The initial implementation targets x86 ELF binaries (`x86_64` and `i386`); stripped or heavily dynamic binaries commonly produce warnings and should be validated against runtime traces before deployment.
