"""Normalize bounded JSONL telemetry and deduplicate stable identities. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: MAX_EVENTS — line 53
# variable: MAX_INPUT — line 54
# variable: MAX_LINE — line 55
# variable: SOURCES — line 56
# definition: Event — line 65
# variable: id — line 68
# variable: timestamp — line 69
# variable: epoch_us — line 70
# variable: product — line 71
# variable: service — line 72
# variable: fields — line 73
# definition: record — line 75
# parameter: self — line 75
# definition: normalize — line 85
# parameter: value — line 85
# variable: fields — line 89
# variable: identity — line 89
# variable: source — line 89
# variable: timestamp — line 89
# variable: key — line 90
# variable: instant — line 99
# variable: key — line 107
# variable: item — line 113
# variable: name — line 113
# variable: delta — line 124
# variable: epoch_us — line 125
# definition: load_events — line 136
# parameter: path — line 136
# variable: content — line 138
# variable: rows — line 139
# variable: unique — line 142
# variable: duplicates — line 143
# variable: row — line 144
# variable: event — line 147
# variable: duplicates — line 151
# parameter: event — line 154
# END CODE MAP

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any

from detection.io import Rejected, canonical, json_value, read_bytes

MAX_EVENTS = 50_000
MAX_INPUT = 16 * 1024 * 1024
MAX_LINE = 16 * 1024
SOURCES = {
    ("windows", "security"),
    ("windows", "process_creation"),
    ("linux", "auditd"),
    ("aws", "cloudtrail"),
}


@dataclass(frozen=True)
class Event:
    """Normalized immutable event identity/time/source and scalar fields; never ground-truth labels."""

    id: str
    timestamp: str
    epoch_us: int
    product: str
    service: str
    fields: Mapping[str, str | int | bool]

    def record(self) -> dict[str, Any]:
        """Return a stable serializable record without labels or ingest-machine metadata."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "source": {"product": self.product, "service": self.service},
            "fields": dict(self.fields),
        }


def normalize(value: Any) -> Event:
    """Require exact envelope, timezone-aware timestamp, supported source and bounded scalar fields."""
    if not isinstance(value, dict) or set(value) != {"id", "timestamp", "source", "fields"}:
        raise Rejected("unexpected event envelope")
    identity, timestamp, source, fields = (
        value[key] for key in ("id", "timestamp", "source", "fields")
    )
    if not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", identity):
        raise Rejected("invalid event identity")
    if not isinstance(timestamp, str) or not re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)", timestamp
    ):
        raise Rejected("expected an explicit ISO timestamp with timezone")
    try:
        instant = datetime.fromisoformat(timestamp).astimezone(UTC)
    except (ValueError, OverflowError) as error:
        raise Rejected("invalid event timestamp") from error
    if not 2000 <= instant.year <= 2100:
        raise Rejected("event time outside lab range")
    if not isinstance(source, dict) or set(source) != {"product", "service"}:
        raise Rejected("invalid source fields")
    if (
        not all(isinstance(source[key], str) for key in source)
        or (source["product"], source["service"]) not in SOURCES
    ):
        raise Rejected("unsupported event source")
    if not isinstance(fields, dict) or not 1 <= len(fields) <= 32:
        raise Rejected("invalid telemetry fields")
    for name, item in fields.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name):
            raise Rejected("invalid telemetry field name")
        if (
            type(item) not in (str, int, bool)
            or isinstance(item, str)
            and (len(item) > 4096 or "\x00" in item)
        ):
            raise Rejected("telemetry must use bounded scalar values")
        if type(item) is int and not -(2**63) <= item < 2**63:
            raise Rejected("telemetry integer outside range")
    delta = instant - datetime(2000, 1, 1, tzinfo=UTC)
    epoch_us = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
    return Event(
        identity,
        instant.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        epoch_us,
        source["product"],
        source["service"],
        MappingProxyType(dict(fields)),
    )


def load_events(path: Path) -> tuple[list[Event], int]:
    """Normalize JSONL, refuse conflicting duplicates, deduplicate identical IDs and sort deterministically."""
    content = read_bytes(path, MAX_INPUT)
    rows = content.splitlines()
    if not 1 <= len(rows) <= MAX_EVENTS:
        raise Rejected("event count outside limit")
    unique: dict[str, Event] = {}
    duplicates = 0
    for row in rows:
        if not row or len(row) > MAX_LINE:
            raise Rejected("empty or oversized JSONL record")
        event = normalize(json_value(row))
        if event.id in unique:
            if canonical(event.record()) != canonical(unique[event.id].record()):
                raise Rejected("conflicting event identity")
            duplicates += 1
        else:
            unique[event.id] = event
    return sorted(unique.values(), key=lambda event: (event.epoch_us, event.id)), duplicates
