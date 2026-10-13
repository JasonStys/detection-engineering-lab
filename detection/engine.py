"""Label-independent rule matching and inclusive event-time burst correlation. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: Key — line 94
# definition: Correlation — line 98
# variable: id — line 101
# variable: title — line 102
# variable: base_rule — line 103
# variable: group_by — line 104
# variable: distinct — line 105
# variable: threshold — line 106
# variable: window_seconds — line 107
# definition: Alert — line 111
# variable: detector — line 114
# variable: event — line 115
# variable: timestamp — line 116
# variable: evidence — line 117
# variable: span_seconds — line 118
# definition: record — line 120
# parameter: self — line 120
# variable: result — line 122
# definition: Window — line 128
# variable: queue — line 131
# variable: counts — line 132
# variable: latest — line 133
# definition: add — line 135
# parameter: config — line 135
# parameter: event — line 135
# parameter: key — line 135
# parameter: self — line 135
# variable: cutoff — line 137
# variable: old — line 139
# variable: old_key — line 139
# variable: before — line 144
# variable: proof — line 150
# variable: item — line 155
# variable: item — line 156
# definition: load_correlations — line 161
# parameter: path — line 161
# parameter: rules — line 161
# variable: value — line 163
# variable: items — line 171
# variable: rule — line 174
# variable: rule_ids — line 174
# variable: result — line 175
# variable: identities — line 176
# variable: item — line 177
# variable: group — line 202
# variable: names — line 203
# variable: name — line 207
# variable: name — line 210
# definition: typed — line 235
# parameter: value — line 235
# definition: detect — line 240
# parameter: correlations — line 241
# parameter: events — line 241
# parameter: rules — line 241
# variable: event — line 244
# variable: consumed — line 246
# variable: item — line 246
# variable: windows — line 247
# variable: alerts — line 248
# variable: samples — line 249
# variable: incomplete — line 250
# parameter: item — line 251
# variable: event — line 251
# variable: start — line 252
# variable: matched — line 253
# variable: rule — line 253
# variable: identity — line 254
# variable: config — line 256
# variable: names — line 259
# variable: name — line 260
# variable: incomplete — line 261
# variable: bucket — line 263
# variable: name — line 263
# variable: window — line 264
# variable: alert — line 265
# END CODE MAP

from __future__ import annotations

import re
from collections import Counter, deque
from dataclasses import asdict, dataclass, field
from itertools import islice
from pathlib import Path
from time import perf_counter_ns
from typing import Any

from detection.events import MAX_EVENTS, Event
from detection.io import Rejected, read_bytes, yaml_value
from detection.rules import Rule, Scalar

Key = tuple[str, Scalar]


@dataclass(frozen=True)
class Correlation:
    """One base-rule burst configuration: same groups, distinct values, inclusive rolling window."""

    id: str
    title: str
    base_rule: str
    group_by: tuple[str, ...]
    distinct: str
    threshold: int
    window_seconds: int


@dataclass(frozen=True)
class Alert:
    """Investigation candidate, not a confirmed incident; bounded supporting event identities."""

    detector: str
    event: str
    timestamp: str
    evidence: tuple[str, ...]
    span_seconds: float

    def record(self) -> dict[str, Any]:
        """Return JSON/SQL-ready alert metadata without raw telemetry or inferred identities."""
        result = asdict(self)
        result["evidence"] = list(self.evidence)
        return result


@dataclass
class Window:
    """Per-group candidate deque, multiplicities and latest representatives, bounded by input count."""

    queue: deque[tuple[Event, Key]] = field(default_factory=deque)
    counts: Counter[Key] = field(default_factory=Counter)
    latest: dict[Key, Event] = field(default_factory=dict)

    def add(self, event: Event, key: Key, config: Correlation) -> Alert | None:
        """Expire times strictly older than window; alert only on below-to-at-threshold crossing."""
        cutoff = event.epoch_us - config.window_seconds * 1_000_000
        while self.queue and self.queue[0][0].epoch_us < cutoff:
            old, old_key = self.queue.popleft()
            self.counts[old_key] -= 1
            if self.counts[old_key] == 0:
                del self.counts[old_key]
                del self.latest[old_key]
        before = len(self.counts)
        self.queue.append((event, key))
        self.counts[key] += 1
        self.latest[key] = event
        if before < config.threshold <= len(self.counts):
            # A crossing has exactly threshold distinct values; bounded proof, not the entire log.
            proof = tuple(islice(self.latest.values(), config.threshold))
            return Alert(
                config.id,
                event.id,
                event.timestamp,
                tuple(item.id for item in proof),
                (event.epoch_us - min(item.epoch_us for item in proof)) / 1_000_000,
            )
        return None


def load_correlations(path: Path, rules: list[Rule]) -> list[Correlation]:
    """Validate 1–8 lab correlations; this schema is explicitly not full Sigma correlation syntax."""
    value = yaml_value(read_bytes(path, 64 * 1024))
    if (
        not isinstance(value, dict)
        or set(value) != {"version", "correlations"}
        or type(value["version"]) is not int
        or value["version"] != 1
    ):
        raise Rejected("invalid correlation envelope/version")
    items = value["correlations"]
    if not isinstance(items, list) or not 1 <= len(items) <= 8:
        raise Rejected("correlation count outside limit")
    rule_ids = {rule.id for rule in rules}
    result: list[Correlation] = []
    identities = set(rule_ids)
    for item in items:
        if not isinstance(item, dict) or set(item) != {
            "id",
            "title",
            "base_rule",
            "group_by",
            "distinct",
            "threshold",
            "window_seconds",
        }:
            raise Rejected("invalid correlation fields")
        if (
            not isinstance(item["id"], str)
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", item["id"])
            or item["id"] in identities
        ):
            raise Rejected("invalid/duplicate correlation identity")
        identities.add(item["id"])
        if (
            not isinstance(item["title"], str)
            or not 1 <= len(item["title"]) <= 256
            or not isinstance(item["base_rule"], str)
            or item["base_rule"] not in rule_ids
        ):
            raise Rejected("invalid correlation title/base rule")
        group = item["group_by"]
        names = [*group, item["distinct"]] if isinstance(group, list) else []
        if (
            not isinstance(group, list)
            or not 1 <= len(group) <= 3
            or len(set(str(name) for name in group)) != len(group)
            or not all(
                isinstance(name, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name)
                for name in names
            )
        ):
            raise Rejected("invalid correlation field names")
        if (
            type(item["threshold"]) is not int
            or not 2 <= item["threshold"] <= 32
            or type(item["window_seconds"]) is not int
            or not 1 <= item["window_seconds"] <= 3600
        ):
            raise Rejected("invalid correlation threshold/window")
        result.append(
            Correlation(
                item["id"],
                item["title"],
                item["base_rule"],
                tuple(group),
                item["distinct"],
                item["threshold"],
                item["window_seconds"],
            )
        )
    return result


def typed(value: Scalar) -> Key:
    """Prevent bool/int and string/int values collapsing into a shared correlation bucket."""
    return type(value).__name__, value


def detect(
    events: list[Event], rules: list[Rule], correlations: list[Correlation]
) -> tuple[list[Alert], list[float], int]:
    """Match bounded unique normalized events in event-time order, without access to evaluation labels."""
    if len(events) > MAX_EVENTS or len({event.id for event in events}) != len(events):
        raise Rejected("detector expects bounded unique normalized events")
    consumed = {item.base_rule for item in correlations}
    windows: dict[tuple[str, tuple[Key, ...]], Window] = {}
    alerts: list[Alert] = []
    samples: list[float] = []
    incomplete = 0
    for event in sorted(events, key=lambda item: (item.epoch_us, item.id)):
        start = perf_counter_ns()
        matched = {rule.id for rule in rules if rule.matches(event)}
        for identity in sorted(matched - consumed):
            alerts.append(Alert(identity, event.id, event.timestamp, (event.id,), 0.0))
        for config in correlations:
            if config.base_rule not in matched:
                continue
            names = (*config.group_by, config.distinct)
            if any(name not in event.fields or event.fields[name] == "" for name in names):
                incomplete += 1
                continue
            bucket = config.id, tuple(typed(event.fields[name]) for name in config.group_by)
            window = windows.setdefault(bucket, Window())
            alert = window.add(event, typed(event.fields[config.distinct]), config)
            if alert is not None:
                alerts.append(alert)
        samples.append((perf_counter_ns() - start) / 1000)
    return alerts, samples, incomplete
