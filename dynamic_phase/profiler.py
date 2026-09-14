from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional, Set

from common.events import SyscallEvent


@dataclass(frozen=True)
class DynamicProfile:
    observed_syscalls: Set[str]
    initialize_syscalls: Set[str]
    event_count: int


class DynamicProfiler:
    """Build D-SF and I-SF from a normalized runtime trace."""

    def profile(
        self,
        events: Iterable[SyscallEvent],
        static_syscalls: Optional[Iterable[str]] = None,
    ) -> DynamicProfile:
        observed: Set[str] = set()
        count = 0
        for event in events:
            observed.add(event.syscall)
            count += 1
        static = set(static_syscalls or ())
        return DynamicProfile(
            observed_syscalls=observed,
            initialize_syscalls=static | observed,
            event_count=count,
        )