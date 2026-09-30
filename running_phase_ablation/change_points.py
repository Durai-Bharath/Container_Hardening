from __future__ import annotations

import math
from statistics import median
from typing import Optional, Sequence


def _scale(values: Sequence[float]) -> float:
    if not values:
        return 1e-6
    center = median(values)
    deviations = [abs(value - center) for value in values]
    scale = 1.4826 * median(deviations)
    if scale <= 1e-9:
        mean = sum(values) / len(values)
        scale = math.sqrt(sum((value - mean) ** 2 for value in values) / max(1, len(values) - 1))
    return max(scale, 1e-6)


def page_hinkley_change(
    values: Sequence[float],
    delta: float = 0.0,
    threshold: Optional[float] = None,
    min_samples: int = 10,
) -> tuple[Optional[int], float, Optional[float]]:
    """Detect a downward shift in dissimilarity with an adaptive threshold."""
    if not values:
        return None, 0.0, None
    history_size = min(len(values), max(2, min_samples))
    baseline = list(values[:history_size])
    adaptive_threshold = threshold
    if adaptive_threshold is None:
        adaptive_threshold = max(0.05, 3.0 * _scale(baseline))
    mean = sum(baseline) / len(baseline)
    cumulative = 0.0
    for index, value in enumerate(values[history_size:], history_size):
        cumulative = max(0.0, cumulative + mean - value - delta)
        if cumulative >= adaptive_threshold:
            return index + 1, adaptive_threshold, cumulative
        count = index + 1
        mean += (value - mean) / count
    return None, adaptive_threshold, None


def bocpd_change(
    values: Sequence[float],
    hazard: float = 0.01,
    min_samples: int = 10,
    max_run_length: int = 2048,
) -> tuple[Optional[int], float, Optional[float]]:
    """Bayesian online predictive change score for dissimilarity values.

    This uses a stable Gaussian predictive approximation rather than retaining
    an unbounded run-length posterior for every window.
    """
    if not values:
        return None, 0.0, None
    if not 0.0 < hazard < 1.0:
        raise ValueError("hazard must be in (0, 1)")
    history_size = min(len(values), max(2, min_samples))
    baseline = list(values[:history_size])
    mean = sum(baseline) / history_size
    variance = max(_scale(baseline) ** 2, 0.05)
    warmup_scores = [
        1.0 - math.exp(-0.5 * ((value - mean) ** 2) / variance)
        for value in baseline
    ]
    threshold = min(
        0.99,
        max(
            hazard * 2.0,
            median(warmup_scores) + 3.0 * _scale(warmup_scores),
            0.1,
        ),
    )
    count = history_size
    for index, value in enumerate(values[history_size:], history_size):
        predictive_variance = max(variance * (1.0 + 1.0 / count), 1e-6)
        score = 1.0 - math.exp(-0.5 * ((value - mean) ** 2) / predictive_variance)
        if score >= threshold:
            return index + 1, threshold, score
        count += 1
        difference = value - mean
        mean += difference / count
        variance = max(((count - 1) * variance + difference * (value - mean)) / count, 1e-6)
        if count >= max_run_length:
            count = history_size
            mean = sum(values[index - history_size + 1 : index + 1]) / history_size
            variance = max(_scale(values[index - history_size + 1 : index + 1]) ** 2, 0.05)
    return None, threshold, None
