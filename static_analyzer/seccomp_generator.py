from __future__ import annotations

import json
from typing import Iterable


def generate_seccomp_profile(allowed_syscalls: Iterable[str]) -> str:
    """Generate a simple allow/deny text seccomp profile."""
    allowed = {s for s in allowed_syscalls if s and s != "syscall_unknown" and s != "unknown"}
    lines = [f"allow {syscall}" for syscall in sorted(allowed)]
    lines.append("deny")
    return "\n".join(lines) + "\n"


def generate_oci_seccomp_profile(allowed_syscalls: Iterable[str], architecture: str = "x86_64") -> str:
    """Generate a valid OCI-compliant seccomp JSON profile."""
    architecture_names = {
        "x86_64": "SCMP_ARCH_X86_64",
        "x86": "SCMP_ARCH_X86",
        "i386": "SCMP_ARCH_X86",
        "aarch64": "SCMP_ARCH_AARCH64",
        "arm": "SCMP_ARCH_ARM",
    }
    seccomp_architecture = architecture_names.get(architecture, "SCMP_ARCH_X86_64")
    allowed = sorted({s for s in allowed_syscalls if s and s != "syscall_unknown" and s != "unknown"})

    return json.dumps(
        {
            "defaultAction": "SCMP_ACT_ERRNO",
            "architectures": [seccomp_architecture],
            "syscalls": [
                {
                    "names": allowed,
                    "action": "SCMP_ACT_ALLOW",
                }
            ],
        },
        indent=2,
    ) + "\n"


__all__ = ["generate_seccomp_profile", "generate_oci_seccomp_profile"]
