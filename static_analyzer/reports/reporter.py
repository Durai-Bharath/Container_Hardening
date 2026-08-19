from __future__ import annotations

import json
from typing import List

from static_analyzer.models.result import AnalysisReport, BinaryAnalysisResult


class Reporter:
    @staticmethod
    def to_json(report: AnalysisReport) -> str:
        return json.dumps(report.to_dict(), indent=2, sort_keys=False)

    @staticmethod
    def to_text(report: AnalysisReport) -> str:
        chunks: List[str] = []
        chunks.append("STATIC SYSCALL ANALYSIS")
        chunks.append("=======================")
        chunks.append(f"Input: {report.input_path}")
        chunks.append("")
        for binary in report.binaries:
            chunks.extend(Reporter._binary_block(binary))
            chunks.append("")
        return "\n".join(chunks).rstrip() + "\n"

    @staticmethod
    def _binary_block(binary: BinaryAnalysisResult) -> List[str]:
        summary = binary.compute_summary()
        rows: List[str] = [
            f"Binary: {binary.binary}",
            f"Architecture: {binary.architecture}",
            f"ELF Class: {binary.elf_class}",
            f"ELF Type: {binary.elf_type}",
            f"Linking: {binary.link_type}",
            "",
            "DIRECT SYSCALLS",
            "---------------",
        ]
        for record in binary.direct_syscalls:
            if record.syscall_number is None:
                rows.append(f"{record.address:<18} unresolved ({record.confidence})")
            else:
                name = record.syscall_name or "unknown"
                rows.append(
                    f"{record.syscall_number:<4} {name:<20} @ {record.address} ({record.confidence})"
                )
        if not binary.direct_syscalls:
            rows.append("(none)")

        rows.extend(["", "INDIRECT SYSCALLS", "-----------------"])
        resolved_indirect = [entry for entry in binary.indirect_syscalls if entry.syscall_number is not None]
        for record in resolved_indirect:
            path = " -> ".join(record.callgraph_path)
            name = record.syscall_name or "unknown"
            rows.append(f"{record.syscall_number:<4} {name:<20} <- {record.function} | {path}")
        if not resolved_indirect:
            rows.append("(none)")

        rows.extend(["", "FINAL STATIC SYSCALL SET", "------------------------"])
        for number, name in sorted(binary.final_unique_syscalls, key=lambda item: item[0]):
            rows.append(f"{number:<4} {name or 'unknown'}")
        if not binary.final_unique_syscalls:
            rows.append("(none)")

        rows.extend(
            [
                "",
                f"Direct syscall count: {summary['direct_syscall_count']}",
                f"Indirect syscall count: {summary['indirect_syscall_count']}",
                f"Unique syscall count: {summary['unique_syscall_count']}",
                f"Unresolved direct syscall count: {summary['unresolved_direct_syscall_count']}",
                f"Imported function count: {summary['imported_function_count']}",
                f"Resolved imported function count: {summary['resolved_imported_function_count']}",
                f"Unresolved imported function count: {summary['unresolved_imported_function_count']}",
            ]
        )
        return rows

