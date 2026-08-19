from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Optional

from static_analyzer.analyzer import StaticAnalyzer
from static_analyzer.reports.reporter import Reporter
from static_analyzer.syscall.syscall_mapper import SyscallMapper

# confine package contains seccomp helper utilities used elsewhere in the project
# from confine.seccomp import Seccomp


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Static syscall analyzer for ELF binaries")
    parser.add_argument("--input", required=True, help="Path to extracted rootfs/app directory")
    parser.add_argument(
        "--glibc-callgraph",
        default=None,
        help="Path to glibc call graph file (e.g. glibc.callgraph)",
    )
    parser.add_argument(
        "--musl-callgraph",
        default=None,
        help="Path to musl call graph file (optional)",
    )
    parser.add_argument(
        "--syscall-table",
        default=None,
        help="Path to JSON syscall table override",
    )
    parser.add_argument(
        "--json-out",
        default="static_syscall_report.json",
        help="Output JSON report path",
    )
    parser.add_argument(
        "--text-out",
        default="static_syscall_report.txt",
        help="Output text report path",
    )
    # parser.add_argument(
    #     "--seccomp-out",
    #     default="seccomp_profile.json",
    #     help="Output seccomp JSON profile path (default: seccomp_profile.json)",
    # )
    return parser


def run(
    input_path: str,
    glibc_callgraph: Optional[str],
    musl_callgraph: Optional[str],
    syscall_table: Optional[str],
    json_out: str,
    text_out: str,
    # seccomp_out: Optional[str] = "seccomp_profile.json",
) -> int:
    mapper = SyscallMapper.create_default(custom_table_path=syscall_table)
    analyzer = StaticAnalyzer(
        mapper=mapper,
        glibc_callgraph_path=glibc_callgraph,
        musl_callgraph_path=musl_callgraph,
    )
    report = analyzer.analyze(input_path=input_path)
    json_payload = Reporter.to_json(report)
    text_payload = Reporter.to_text(report)

    Path(json_out).write_text(json_payload, encoding="utf-8")
    Path(text_out).write_text(text_payload, encoding="utf-8")
    print(text_payload)

    # Generate seccomp profile from the static analysis results.
    # Collect syscall names (fall back to mapper lookup when names are missing).
    # names: set[str] = set()
    # for binary in report.binaries:
    #     for number, name in binary.final_unique_syscalls:
    #         if name:
    #             names.add(name)
    #         else:
    #             mapped = mapper.name_for(number, report.architecture)
    #             if mapped:
    #                 names.add(mapped)

    # if names and seccomp_out:
    #     logger = logging.getLogger(__name__)
    #     sc = Seccomp(logger)
    #     # createProfileWhitelist produces a seccomp profile with defaultAction=SCMP_ACT_ERRNO
    #     # and explicit SCMP_ACT_ALLOW entries for the provided syscall names (safer default).
    #     profile_json = sc.createProfileWhitelist(sorted(names))
    #     Path(seccomp_out).write_text(profile_json, encoding="utf-8")
    #     print(f"Wrote seccomp profile to: {seccomp_out}")
    # else:
    #     print("No syscall names available to generate seccomp profile; skipping.")

    return 0


def main() -> int:
    parser = _build_arg_parser()
    args = parser.parse_args()
    return run(
        input_path=args.input,
        glibc_callgraph=args.glibc_callgraph,
        musl_callgraph=args.musl_callgraph,
        syscall_table=args.syscall_table,
        json_out=args.json_out,
        text_out=args.text_out,
        # seccomp_out=args.seccomp_out,
    )

