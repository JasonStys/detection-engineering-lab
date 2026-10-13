"""Independent labeled replay evaluation with explicit event-detector denominators. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: catalog — line 68
# parameter: correlations — line 68
# parameter: rules — line 68
# variable: consumed — line 70
# variable: item — line 70
# variable: result — line 71
# variable: rule — line 73
# variable: by_id — line 76
# variable: rule — line 76
# variable: item — line 77
# variable: base — line 78
# definition: load_labels — line 87
# parameter: detectors — line 87
# parameter: events — line 87
# parameter: path — line 87
# variable: value — line 89
# variable: event — line 90
# variable: result — line 92
# variable: identity — line 93
# variable: labels — line 93
# variable: item — line 97
# definition: ratio — line 105
# parameter: denominator — line 105
# parameter: numerator — line 105
# definition: scores — line 110
# parameter: fn — line 110
# parameter: fp — line 110
# parameter: tn — line 110
# parameter: tp — line 110
# definition: evaluate — line 124
# parameter: events — line 125
# parameter: alerts — line 126
# parameter: labels — line 127
# parameter: detectors — line 128
# variable: alert — line 131
# variable: predictions — line 131
# variable: per_rule — line 132
# variable: totals — line 133
# variable: disagreements — line 134
# variable: identity — line 135
# variable: counts — line 136
# variable: event — line 137
# variable: actual — line 138
# variable: expected — line 138
# variable: index — line 139
# variable: left — line 149
# variable: right — line 149
# variable: totals — line 149
# definition: percentile — line 160
# parameter: quantile — line 160
# parameter: values — line 160
# END CODE MAP

from __future__ import annotations

from math import ceil
from pathlib import Path
from typing import Any

from detection.engine import Alert, Correlation
from detection.events import Event
from detection.io import Rejected, json_value, read_bytes
from detection.rules import Rule


def catalog(rules: list[Rule], correlations: list[Correlation]) -> dict[str, dict[str, Any]]:
    """Describe emitted detectors; consumed base rules are candidates, not independent alerts."""
    consumed = {item.base_rule for item in correlations}
    result = {
        rule.id: {"title": rule.title, "techniques": list(rule.techniques), "level": rule.level}
        for rule in rules
        if rule.id not in consumed
    }
    by_id = {rule.id: rule for rule in rules}
    for item in correlations:
        base = by_id[item.base_rule]
        result[item.id] = {
            "title": item.title,
            "techniques": list(base.techniques),
            "level": base.level,
        }
    return result


def load_labels(path: Path, events: list[Event], detectors: set[str]) -> dict[str, set[str]]:
    """Require one label list for every unique event, valid detector IDs and no extra identities."""
    value = json_value(read_bytes(path, 8 * 1024 * 1024))
    if not isinstance(value, dict) or set(value) != {event.id for event in events}:
        raise Rejected("labels must cover exactly the unique event identities")
    result: dict[str, set[str]] = {}
    for identity, labels in value.items():
        if (
            not isinstance(labels, list)
            or len(labels) > len(detectors)
            or not all(isinstance(item, str) and item in detectors for item in labels)
            or len(set(labels)) != len(labels)
        ):
            raise Rejected("invalid label list/detector")
        result[identity] = set(labels)
    return result


def ratio(numerator: int, denominator: int) -> float | None:
    """Undefined ratios return null, never NaN, infinity or a fabricated perfect score."""
    return numerator / denominator if denominator else None


def scores(tp: int, fp: int, fn: int, tn: int) -> dict[str, Any]:
    """Compute confusion counts and precision/recall/F1/FPR with explicit denominators."""
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "false_positive_rate": ratio(fp, fp + tn),
    }


def evaluate(
    events: list[Event],
    alerts: list[Alert],
    labels: dict[str, set[str]],
    detectors: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Compare predictions only after detection; universe is each unique event × emitted detector."""
    predictions = {(alert.event, alert.detector) for alert in alerts}
    per_rule: dict[str, Any] = {}
    totals = [0, 0, 0, 0]
    disagreements: list[dict[str, str]] = []
    for identity in sorted(detectors):
        counts = [0, 0, 0, 0]
        for event in events:
            expected, actual = identity in labels[event.id], (event.id, identity) in predictions
            index = 0 if expected and actual else 1 if actual else 2 if expected else 3
            counts[index] += 1
            if index in (1, 2):
                disagreements.append(
                    {
                        "event": event.id,
                        "detector": identity,
                        "outcome": "false_positive" if index == 1 else "false_negative",
                    }
                )
        totals = [left + right for left, right in zip(totals, counts, strict=True)]
        per_rule[identity] = scores(*counts)
    return {
        "universe": "unique event-detector pairs; correlations scored at crossing event",
        "pairs": len(events) * len(detectors),
        "micro": scores(*totals),
        "detectors": per_rule,
        "disagreements": disagreements,
    }


def percentile(values: list[float], quantile: float) -> float | None:
    """Nearest-rank percentile for nonempty measured samples; empty samples are unavailable."""
    if not values:
        return None
    return sorted(values)[max(0, ceil(quantile * len(values)) - 1)]
