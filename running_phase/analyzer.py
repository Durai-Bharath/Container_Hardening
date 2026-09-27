from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

from common.events import SyscallEvent


@dataclass(frozen=True)
class FeatureWindow:
    start: float
    end: float
    frequency: Tuple[float, ...]
    syscalls: Tuple[str, ...]


@dataclass(frozen=True)
class RunningPhaseResult:
    segmentation_index: Optional[int]
    segmentation_time: Optional[float]
    dissimilarities: Tuple[float, ...]
    running_syscalls: Tuple[str, ...]
    windows: Tuple[FeatureWindow, ...]


def _cosine_distance(left: Sequence[float], right: Sequence[float]) -> float:
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if left_norm == 0.0 and right_norm == 0.0:
        return 0.0
    if left_norm == 0.0 or right_norm == 0.0:
        return 1.0
    similarity = sum(a * b for a, b in zip(left, right)) / (left_norm * right_norm)
    return 1.0 - max(-1.0, min(1.0, similarity))


class SimilarityThresholdDetector:
    """Detect the end of a sustained high-similarity window."""

    def __init__(self, threshold: float = 0.8, stabilization_seconds: float = 5.0) -> None:
        if not 0.0 < threshold <= 1.0 or stabilization_seconds <= 0:
            raise ValueError("threshold must be in (0, 1] and stabilization_seconds must be positive")
        self.threshold = threshold
        self.stabilization_seconds = stabilization_seconds

    def detect(self, similarities: Sequence[float], window_seconds: float) -> Optional[int]:
        required = max(1, math.ceil(self.stabilization_seconds / window_seconds))
        if len(similarities) < required:
            return None
        for end in range(required - 1, len(similarities)):
            start = end - required + 1
            if all(value >= self.threshold for value in similarities[start : end + 1]):
                return end + 1
        return None


class RunningPhaseAnalyzer:
    def __init__(
        self,
        window_seconds: float = 0.001,
        similarity_threshold: float = 0.8,
        stabilization_seconds: float = 5.0,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window_seconds = window_seconds
        self.detector = SimilarityThresholdDetector(similarity_threshold, stabilization_seconds)

    def analyze(self, events: Iterable[SyscallEvent]) -> RunningPhaseResult:
        ordered = sorted(events, key=lambda event: event.timestamp)
        windows = self.extract_features(ordered)
        dissimilarities = tuple(
            _cosine_distance(current.frequency, previous.frequency)
            for previous, current in zip(windows, windows[1:])
        )
        similarities = tuple(1.0 - value for value in dissimilarities)
        segmentation_index = self.detector.detect(similarities, self.window_seconds)
        running = self._running_syscalls(ordered, windows, segmentation_index)
        return RunningPhaseResult(
            segmentation_index=segmentation_index,
            segmentation_time=windows[segmentation_index].start if segmentation_index is not None else None,
            dissimilarities=dissimilarities,
            running_syscalls=tuple(running),
            windows=tuple(windows),
        )

    def extract_features(self, events: Sequence[SyscallEvent]) -> List[FeatureWindow]:
        if not events:
            return []
        vocabulary = sorted({event.syscall for event in events})
        start = events[0].timestamp
        grouped: List[List[SyscallEvent]] = []
        current: List[SyscallEvent] = []
        window_start = start
        for event in events:
            while event.timestamp >= window_start + self.window_seconds and current:
                grouped.append(current)
                current = []
                window_start += self.window_seconds
            current.append(event)
        if current:
            grouped.append(current)
        windows: List[FeatureWindow] = []
        for index, group in enumerate(grouped):
            counts = Counter(event.syscall for event in group)
            total = float(len(group))
            windows.append(
                FeatureWindow(
                    start=start + index * self.window_seconds,
                    end=start + (index + 1) * self.window_seconds,
                    frequency=tuple(counts[name] / total for name in vocabulary),
                    syscalls=tuple(sorted(counts)),
                )
            )
        return windows

    @staticmethod
    def _running_syscalls(events, windows, segmentation_index):
        if segmentation_index is None:
            return sorted({event.syscall for event in events})
        boundary = windows[segmentation_index].start
        return sorted({event.syscall for event in events if event.timestamp >= boundary})