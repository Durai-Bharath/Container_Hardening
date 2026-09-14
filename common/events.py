from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Optional


@dataclass(frozen=True)
class SyscallEvent:
    """Normalized syscall event consumed by both dynamic and running phases."""

    timestamp: float
    syscall: str
    number: Optional[int] = None
    arguments: tuple[Any, ...] = field(default_factory=tuple)
    pid: Optional[int] = None
    process: Optional[str] = None

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "SyscallEvent":
        syscall = payload.get("syscall", payload.get("eventName", payload.get("name")))
        if not syscall:
            raise ValueError("syscall event requires a 'syscall' or 'name' field")
        arguments = payload.get("arguments", payload.get("args", ()))
        if isinstance(arguments, list) and arguments and isinstance(arguments[0], Mapping):
            arguments = tuple(argument.get("value") for argument in arguments)
        if isinstance(arguments, Mapping):
            arguments = tuple(arguments.values())
        elif isinstance(arguments, str) or not isinstance(arguments, Iterable):
            arguments = (arguments,)
        return cls(
            timestamp=float(payload.get("timestamp", payload.get("time", 0.0))),
            syscall=str(syscall),
            number=int(payload.get("number", payload.get("eventID")))
            if payload.get("number", payload.get("eventID")) is not None
            else None,
            arguments=tuple(arguments),
            pid=int(payload["pid"]) if payload.get("pid") is not None else None,
            process=payload.get("process", payload.get("comm")),
        )


def load_events(path: str) -> Iterator[SyscallEvent]:
    """Load newline-delimited JSON events in timestamp order."""

    events = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                events.append(SyscallEvent.from_mapping(json.loads(line)))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ValueError(f"invalid syscall event at line {line_number}: {exc}") from exc
    yield from sorted(events, key=lambda event: event.timestamp)