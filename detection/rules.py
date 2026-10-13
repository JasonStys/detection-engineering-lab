"""Constrained Sigma rule compiler without eval, regex or silent unsupported syntax. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: Scalar — line 79
# definition: Predicate — line 83
# variable: field — line 86
# variable: mode — line 87
# variable: values — line 88
# variable: require_all — line 89
# definition: matches — line 91
# parameter: fields — line 91
# parameter: self — line 91
# variable: actual — line 95
# variable: results — line 96
# variable: expected — line 97
# variable: left — line 99
# variable: right — line 99
# variable: found — line 100
# variable: found — line 107
# definition: Rule — line 115
# variable: id — line 118
# variable: title — line 119
# variable: level — line 120
# variable: product — line 121
# variable: service — line 122
# variable: techniques — line 123
# variable: selection — line 124
# variable: exclude — line 125
# definition: matches — line 127
# parameter: event — line 127
# parameter: self — line 127
# variable: item — line 131
# variable: item — line 132
# definition: predicates — line 136
# parameter: value — line 136
# variable: result — line 140
# variable: seen — line 141
# variable: item — line 142
# variable: name — line 142
# variable: parts — line 145
# variable: field — line 146
# variable: modifiers — line 146
# variable: values — line 161
# variable: mode — line 164
# variable: expected — line 165
# variable: char — line 171
# definition: compile_rule — line 180
# parameter: value — line 180
# variable: required — line 182
# variable: name — line 203
# variable: item — line 223
# variable: source — line 227
# variable: item — line 231
# variable: tags — line 235
# variable: tag — line 241
# variable: detection — line 245
# variable: expected — line 251
# variable: tag — line 260
# definition: load_rules — line 266
# parameter: directory — line 266
# variable: paths — line 270
# variable: path — line 273
# variable: rules — line 273
# variable: rule — line 274
# END CODE MAP

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any
from uuid import UUID

from detection.events import SOURCES, Event
from detection.io import Rejected, read_bytes, yaml_value

Scalar = str | int | bool


@dataclass(frozen=True)
class Predicate:
    """One bounded field comparison; expected alternatives OR unless explicit all modifier."""

    field: str
    mode: str
    values: tuple[Scalar, ...]
    require_all: bool

    def matches(self, fields: Mapping[str, Scalar]) -> bool:
        """Missing fields never match, including negated filters; strings are case-insensitive."""
        if self.field not in fields:
            return False
        actual = fields[self.field]
        results = []
        for expected in self.values:
            if isinstance(actual, str) and isinstance(expected, str):
                left, right = actual.casefold(), expected.casefold()
                found = {
                    "exact": left == right,
                    "contains": right in left,
                    "startswith": left.startswith(right),
                    "endswith": left.endswith(right),
                }[self.mode]
            else:
                found = (
                    self.mode == "exact" and type(actual) is type(expected) and actual == expected
                )
            results.append(found)
        return all(results) if self.require_all else any(results)


@dataclass(frozen=True)
class Rule:
    """Compiled Sigma subset: explicit source, one selection and optional excluded filter."""

    id: str
    title: str
    level: str
    product: str
    service: str
    techniques: tuple[str, ...]
    selection: tuple[Predicate, ...]
    exclude: tuple[Predicate, ...]

    def matches(self, event: Event) -> bool:
        """Apply source before field comparisons; optional filter suppresses only a complete match."""
        if (event.product, event.service) != (self.product, self.service):
            return False
        return all(item.matches(event.fields) for item in self.selection) and not (
            self.exclude and all(item.matches(event.fields) for item in self.exclude)
        )


def predicates(value: Any) -> tuple[Predicate, ...]:
    """Compile map-AND, list-OR/all and exact/contains/start/end comparisons; reject wildcards/regex."""
    if not isinstance(value, dict) or not 1 <= len(value) <= 16:
        raise Rejected("selection must be a bounded nonempty field map")
    result = []
    seen: set[str] = set()
    for name, item in value.items():
        if not isinstance(name, str):
            raise Rejected("invalid selection key")
        parts = name.split("|")
        field, modifiers = parts[0], parts[1:]
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", field) or field in seen:
            raise Rejected("invalid or repeated selection field")
        seen.add(field)
        if modifiers not in (
            [],
            ["contains"],
            ["startswith"],
            ["endswith"],
            ["all"],
            ["contains", "all"],
            ["startswith", "all"],
            ["endswith", "all"],
        ):
            raise Rejected("unsupported Sigma modifier")
        values = item if isinstance(item, list) else [item]
        if not 1 <= len(values) <= 16:
            raise Rejected("selection value count outside limit")
        mode = modifiers[0] if modifiers and modifiers[0] != "all" else "exact"
        for expected in values:
            if type(expected) not in (str, int, bool):
                raise Rejected("unsupported Sigma value type")
            if type(expected) is int and not -(2**63) <= expected < 2**63:
                raise Rejected("Sigma integer outside range")
            if isinstance(expected, str) and (
                not expected or len(expected) > 256 or any(char in expected for char in "*?\x00")
            ):
                raise Rejected("empty, oversized or wildcard pattern unsupported")
            if mode != "exact" and not isinstance(expected, str):
                raise Rejected("string modifier needs string values")
        result.append(Predicate(field, mode, tuple(values), "all" in modifiers))
    return tuple(result)


def compile_rule(value: Any) -> Rule:
    """Validate authored rule metadata and the documented small Sigma grammar before compiling."""
    required = {
        "id",
        "title",
        "status",
        "description",
        "author",
        "date",
        "license",
        "logsource",
        "detection",
        "falsepositives",
        "level",
        "tags",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise Rejected("unexpected rule envelope")
    try:
        if str(UUID(value["id"])) != value["id"] or UUID(value["id"]).version != 4:
            raise Rejected("rule UUID must be canonical")
    except (ValueError, TypeError, AttributeError) as error:
        raise Rejected("invalid rule UUID") from error
    for name in ("title", "description", "author", "date"):
        if not isinstance(value[name], str) or not 1 <= len(value[name]) <= 1024:
            raise Rejected("invalid rule metadata")
    if len(value["title"]) > 256 or not re.fullmatch(r"\d{4}-\d\d-\d\d", value["date"]):
        raise Rejected("invalid title/date metadata")
    try:
        date.fromisoformat(value["date"])
    except ValueError as error:
        raise Rejected("invalid rule calendar date") from error
    if (
        value["status"] != "experimental"
        or value["license"] != "MIT"
        or not isinstance(value["level"], str)
        or value["level"] not in {"low", "medium", "high", "critical"}
    ):
        raise Rejected("unsupported rule status/license/level")
    if (
        not isinstance(value["falsepositives"], list)
        or not 1 <= len(value["falsepositives"]) <= 8
        or not all(
            isinstance(item, str) and 1 <= len(item) <= 512 for item in value["falsepositives"]
        )
    ):
        raise Rejected("rule must document bounded false-positive cases")
    source = value["logsource"]
    if (
        not isinstance(source, dict)
        or set(source) != {"product", "service"}
        or not all(isinstance(item, str) for item in source.values())
        or (source["product"], source["service"]) not in SOURCES
    ):
        raise Rejected("unsupported rule source")
    tags = value["tags"]
    if (
        not isinstance(tags, list)
        or not 1 <= len(tags) <= 8
        or not all(
            isinstance(tag, str) and re.fullmatch(r"attack\.t[0-9]{4}(?:\.[0-9]{3})?", tag)
            for tag in tags
        )
    ):
        raise Rejected("rule needs bounded ATT&CK technique tags")
    detection = value["detection"]
    if not isinstance(detection, dict) or set(detection) not in (
        {"selection", "condition"},
        {"selection", "filter", "condition"},
    ):
        raise Rejected("unsupported Sigma detection grammar")
    expected = "selection and not filter" if "filter" in detection else "selection"
    if detection["condition"] != expected:
        raise Rejected("unsupported Sigma condition")
    return Rule(
        value["id"],
        value["title"],
        value["level"],
        source["product"],
        source["service"],
        tuple(tag.removeprefix("attack.").upper() for tag in tags),
        predicates(detection["selection"]),
        predicates(detection["filter"]) if "filter" in detection else (),
    )


def load_rules(directory: Path) -> list[Rule]:
    """Load 1–32 regular YAML rules in sorted order, with unique identifiers."""
    if directory.is_symlink() or directory.is_junction() or not directory.is_dir():
        raise Rejected("rules must be a regular directory")
    paths = sorted(directory.glob("*.yml"))
    if not 1 <= len(paths) <= 32:
        raise Rejected("rule count outside limit")
    rules = [compile_rule(yaml_value(read_bytes(path, 64 * 1024))) for path in paths]
    if len({rule.id for rule in rules}) != len(rules):
        raise Rejected("duplicate rule identity")
    return rules
