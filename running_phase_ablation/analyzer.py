from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Literal, Optional, Sequence

from common.events import SyscallEvent
from running_phase_ablation.change_points import bocpd_change, page_hinkley_change

FeatureMode = Literal["frequency", "bigram", "combined"]
SegmentationMode = Literal["sustained", "first", "pht", "bocpd"]
WindowMode = Literal["time", "count"]


@dataclass(frozen=True)
class AblationWindow:
    start: float
    end: float
    syscalls: tuple[str, ...]
    frequency: tuple[float, ...]
    bigrams: tuple[float, ...]
    vector: tuple[float, ...]


@dataclass(frozen=True)
class AblationResult:
    feature_mode: str
    segmentation_mode: str
    window_mode: str
    events_per_window: Optional[int]
    adaptive_threshold: Optional[float]
    change_point_score: Optional[float]
    segmentation_index: Optional[int]
    segmentation_time: Optional[float]
    similarities: tuple[float, ...]
    dissimilarities: tuple[float, ...]
    running_syscalls: tuple[str, ...]
    syscall_vocabulary: tuple[str, ...]
    bigram_vocabulary: tuple[str, ...]
    windows: tuple[AblationWindow, ...]


def _cosine_similarity(left: Sequence[float], right: Sequence[float]) -> float:
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if left_norm == 0.0 and right_norm == 0.0:
        return 1.0
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    value = sum(a * b for a, b in zip(left, right)) / (left_norm * right_norm)
    return max(-1.0, min(1.0, value))


def _window_events(
    events: Sequence[SyscallEvent], window_seconds: float
) -> list[tuple[float, list[SyscallEvent]]]:
    if not events:
        return []
    start = events[0].timestamp
    groups: list[tuple[float, list[SyscallEvent]]] = []
    current: list[SyscallEvent] = []
    window_start = start
    for event in events:
        if event.timestamp >= window_start + window_seconds:
            if current:
                groups.append((window_start, current))
            current = []
            window_start = start + math.floor(
                (event.timestamp - start) / window_seconds
            ) * window_seconds
        current.append(event)
    if current:
        groups.append((window_start, current))
    return groups


def _count_windows(
    events: Sequence[SyscallEvent], events_per_window: int
) -> list[tuple[float, list[SyscallEvent]]]:
    return [
        (events[index].timestamp, list(events[index : index + events_per_window]))
        for index in range(0, len(events), events_per_window)
    ]


class AblationRunningPhaseAnalyzer:
    def __init__(
        self,
        window_seconds: float = 0.001,
        similarity_threshold: float = 0.8,
        stabilization_seconds: float = 5.0,
        feature_mode: FeatureMode = "combined",
        segmentation_mode: SegmentationMode = "sustained",
        window_mode: WindowMode = "time",
        events_per_window: int = 100,
        stabilization_windows: int = 5,
        pht_delta: float = 0.0,
        pht_threshold: Optional[float] = None,
        change_point_min_samples: int = 10,
        bocpd_hazard: float = 0.01,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if not 0.0 < similarity_threshold <= 1.0:
            raise ValueError("similarity_threshold must be in (0, 1]")
        if stabilization_seconds <= 0:
            raise ValueError("stabilization_seconds must be positive")
        if feature_mode not in {"frequency", "bigram", "combined"}:
            raise ValueError(f"unsupported feature mode: {feature_mode}")
        if segmentation_mode not in {"sustained", "first", "pht", "bocpd"}:
            raise ValueError(f"unsupported segmentation mode: {segmentation_mode}")
        if window_mode not in {"time", "count"}:
            raise ValueError(f"unsupported window mode: {window_mode}")
        if events_per_window <= 0:
            raise ValueError("events_per_window must be positive")
        if stabilization_windows <= 0:
            raise ValueError("stabilization_windows must be positive")
        if change_point_min_samples <= 0:
            raise ValueError("change_point_min_samples must be positive")
        if pht_delta < 0.0:
            raise ValueError("pht_delta must be non-negative")
        if pht_threshold is not None and pht_threshold < 0.0:
            raise ValueError("pht_threshold must be non-negative")
        if not 0.0 < bocpd_hazard < 1.0:
            raise ValueError("bocpd_hazard must be in (0, 1)")
        self.window_seconds = window_seconds
        self.similarity_threshold = similarity_threshold
        self.stabilization_seconds = stabilization_seconds
        self.feature_mode = feature_mode
        self.segmentation_mode = segmentation_mode
        self.window_mode = window_mode
        self.events_per_window = events_per_window
        self.stabilization_windows = stabilization_windows
        self.pht_delta = pht_delta
        self.pht_threshold = pht_threshold
        self.change_point_min_samples = change_point_min_samples
        self.bocpd_hazard = bocpd_hazard

    def analyze(self, events: Iterable[SyscallEvent]) -> AblationResult:
        ordered = sorted(events, key=lambda event: event.timestamp)
        groups = (
            _window_events(ordered, self.window_seconds)
            if self.window_mode == "time"
            else _count_windows(ordered, self.events_per_window)
        )
        syscall_vocabulary = tuple(sorted({event.syscall for event in ordered}))
        bigram_vocabulary = tuple(sorted({
            f"{left}>{right}"
            for _, group in groups
            for left, right in zip(
                (event.syscall for event in group),
                (event.syscall for event in group[1:]),
            )
        }))
        windows = self._features(groups, syscall_vocabulary, bigram_vocabulary)
        similarities = tuple(
            _cosine_similarity(current.vector, previous.vector)
            for previous, current in zip(windows, windows[1:])
        )
        dissimilarities = tuple(1.0 - value for value in similarities)
        segmentation_index, adaptive_threshold, change_point_score = self._segment(
            similarities, dissimilarities, len(windows)
        )
        running = self._running_syscalls(ordered, windows, segmentation_index)
        segmentation_time = (
            windows[segmentation_index].start
            if segmentation_index is not None
            else None
        )
        return AblationResult(
            feature_mode=self.feature_mode,
            segmentation_mode=self.segmentation_mode,
            window_mode=self.window_mode,
            events_per_window=(self.events_per_window if self.window_mode == "count" else None),
            adaptive_threshold=adaptive_threshold,
            change_point_score=change_point_score,
            segmentation_index=segmentation_index,
            segmentation_time=segmentation_time,
            similarities=similarities,
            dissimilarities=dissimilarities,
            running_syscalls=tuple(running),
            syscall_vocabulary=syscall_vocabulary,
            bigram_vocabulary=bigram_vocabulary,
            windows=tuple(windows),
        )

    def _features(
        self,
        groups: Sequence[tuple[float, Sequence[SyscallEvent]]],
        syscall_vocabulary: Sequence[str],
        bigram_vocabulary: Sequence[str],
    ) -> list[AblationWindow]:
        if not groups:
            return []
        windows: list[AblationWindow] = []
        for window_start, group in groups:
            syscall_counts = Counter(event.syscall for event in group)
            total = float(len(group))
            frequency = tuple(
                syscall_counts[name] / total for name in syscall_vocabulary
            )
            transitions = [
                f"{left.syscall}>{right.syscall}"
                for left, right in zip(group, group[1:])
            ]
            bigram_counts = Counter(transitions)
            transition_total = float(len(transitions))
            bigrams = tuple(
                bigram_counts[name] / transition_total
                if transition_total else 0.0
                for name in bigram_vocabulary
            )
            if self.feature_mode == "frequency":
                vector = frequency
            elif self.feature_mode == "bigram":
                vector = bigrams
            else:
                vector = frequency + bigrams
            windows.append(
                AblationWindow(
                    start=(
                        window_start
                        if self.window_mode == "time"
                        else group[0].timestamp
                    ),
                    end=(
                        window_start + self.window_seconds
                        if self.window_mode == "time"
                        else group[-1].timestamp
                    ),
                    syscalls=tuple(sorted(syscall_counts)),
                    frequency=frequency,
                    bigrams=bigrams,
                    vector=vector,
                )
            )
        return windows

    def _segment(
        self,
        similarities: Sequence[float],
        dissimilarities: Sequence[float],
        window_count: int,
    ) -> tuple[Optional[int], Optional[float], Optional[float]]:
        if not similarities:
            return None, None, None
        if self.segmentation_mode == "pht":
            index, threshold, score = page_hinkley_change(
                dissimilarities,
                delta=self.pht_delta,
                threshold=self.pht_threshold,
                min_samples=self.change_point_min_samples,
            )
            return (min(index, window_count - 1) if index is not None else None), threshold, score
        if self.segmentation_mode == "bocpd":
            index, threshold, score = bocpd_change(
                dissimilarities,
                hazard=self.bocpd_hazard,
                min_samples=self.change_point_min_samples,
            )
            return (min(index, window_count - 1) if index is not None else None), threshold, score
        if self.segmentation_mode == "first":
            for index, similarity in enumerate(similarities):
                if similarity >= self.similarity_threshold:
                    return index + 1, self.similarity_threshold, similarity
            return None, self.similarity_threshold, None
        required = (
            max(1, math.ceil(self.stabilization_seconds / self.window_seconds))
            if self.window_mode == "time"
            else self.stabilization_windows
        )
        if len(similarities) < required:
            return None, self.similarity_threshold, None
        for end in range(required - 1, len(similarities)):
            start = end - required + 1
            if all(
                value >= self.similarity_threshold
                for value in similarities[start : end + 1]
            ):
                return min(end + 1, window_count - 1), self.similarity_threshold, similarities[end]
        return None, self.similarity_threshold, None

    @staticmethod
    def _running_syscalls(
        events: Sequence[SyscallEvent],
        windows: Sequence[AblationWindow],
        segmentation_index: Optional[int],
    ) -> list[str]:
        if segmentation_index is None:
            return sorted({event.syscall for event in events})
        boundary = windows[segmentation_index].start
        return sorted({event.syscall for event in events if event.timestamp >= boundary})
