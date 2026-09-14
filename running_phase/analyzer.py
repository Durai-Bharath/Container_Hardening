from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from statistics import fmean, pstdev
from typing import Iterable, List, Optional, Sequence, Tuple

from common.events import SyscallEvent


@dataclass(frozen=True)
class FeatureWindow:
    start: float
    end: float
    frequency: Tuple[float, ...]
    bigrams: Tuple[float, ...]
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


class AdaptivePageHinkley:
    """Page-Hinkley detector with a threshold calibrated from warm-up scores."""

    def __init__(self, warmup: int = 5, threshold_factor: float = 5.0, delta: float = 0.01) -> None:
        if warmup < 2 or threshold_factor <= 0 or delta < 0:
            raise ValueError("warmup must be >= 2, threshold_factor > 0, and delta >= 0")
        self.warmup = warmup
        self.threshold_factor = threshold_factor
        self.delta = delta

    def detect(self, values: Sequence[float]) -> Optional[int]:
        if len(values) <= self.warmup:
            return None
        baseline = list(values[: self.warmup])
        threshold = max(pstdev(baseline) * self.threshold_factor, self.delta)
        mean = fmean(baseline)
        cumulative = 0.0
        minimum = 0.0
        for index, value in enumerate(values[self.warmup :], self.warmup):
            mean = mean + (value - mean) / (index + 1)
            cumulative += value - mean - self.delta
            minimum = min(minimum, cumulative)
            if cumulative - minimum > threshold:
                return index
        return None


class RunningPhaseAnalyzer:
    def __init__(
        self,
        window_seconds: float = 0.001,
        frequency_weight: float = 0.5,
        bigram_weight: float = 0.5,
        detector: Optional[AdaptivePageHinkley] = None,
    ) -> None:
        if window_seconds <= 0 or frequency_weight < 0 or bigram_weight < 0:
            raise ValueError("window_seconds must be positive and weights cannot be negative")
        if frequency_weight + bigram_weight == 0:
            raise ValueError("at least one feature weight must be positive")
        self.window_seconds = window_seconds
        total = frequency_weight + bigram_weight
        self.frequency_weight = frequency_weight / total
        self.bigram_weight = bigram_weight / total
        self.detector = detector or AdaptivePageHinkley()

    def analyze(self, events: Iterable[SyscallEvent]) -> RunningPhaseResult:
        ordered = sorted(events, key=lambda event: event.timestamp)
        windows = self.extract_features(ordered)
        dissimilarities = tuple(
            self.frequency_weight * _cosine_distance(current.frequency, previous.frequency)
            + self.bigram_weight * _cosine_distance(current.bigrams, previous.bigrams)
            for previous, current in zip(windows, windows[1:])
        )
        detector_index = self.detector.detect(dissimilarities)
        segmentation_index = detector_index + 1 if detector_index is not None else None
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
        bigram_vocabulary = [(left, right) for left in vocabulary for right in vocabulary]
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
            sequence = [event.syscall for event in group]
            transitions = Counter(zip(sequence, sequence[1:]))
            total = float(len(group))
            windows.append(
                FeatureWindow(
                    start=start + index * self.window_seconds,
                    end=start + (index + 1) * self.window_seconds,
                    frequency=tuple(counts[name] / total for name in vocabulary),
                    bigrams=tuple(transitions[pair] / max(total - 1.0, 1.0) for pair in bigram_vocabulary),
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