"""Bounded regular-file, strict JSON and safe YAML readers. Created by Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: Rejected — line 57
# definition: read_bytes — line 61
# parameter: limit — line 61
# parameter: path — line 61
# variable: descriptor — line 66
# variable: stream — line 67
# variable: content — line 70
# definition: pairs — line 78
# parameter: items — line 78
# variable: result — line 80
# variable: name — line 81
# variable: value — line 81
# definition: nonfinite — line 88
# parameter: value — line 88
# definition: finite_float — line 93
# parameter: value — line 93
# variable: result — line 95
# definition: json_value — line 101
# parameter: content — line 101
# definition: canonical — line 111
# parameter: value — line 111
# definition: UniqueLoader — line 118
# definition: construct_mapping — line 121
# parameter: deep — line 121
# parameter: node — line 121
# parameter: self — line 121
# variable: result — line 125
# variable: key_node — line 126
# variable: value_node — line 126
# variable: key — line 127
# definition: yaml_value — line 134
# parameter: content — line 134
# variable: text — line 137
# variable: depth — line 138
# variable: documents — line 139
# variable: event — line 140
# variable: depth — line 144
# variable: depth — line 148
# variable: documents — line 150
# END CODE MAP

from __future__ import annotations

import json
import math
import os
import stat
from collections.abc import Hashable
from pathlib import Path
from typing import Any

import yaml


class Rejected(ValueError):
    """Input or output was refused; messages deliberately exclude raw log contents."""


def read_bytes(path: Path, limit: int) -> bytes:
    """Read at most limit bytes from a regular final path; refuse links and devices."""
    try:
        if path.is_symlink() or path.is_junction() or not stat.S_ISREG(path.lstat().st_mode):
            raise Rejected("input must be a regular file, not a link")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise Rejected("input changed file type")
            content = stream.read(limit + 1)
        if len(content) > limit:
            raise Rejected("input exceeds its size limit")
        return content
    except OSError as error:
        raise Rejected("input unavailable") from error


def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON keys instead of allowing ambiguous last-value-wins parsing."""
    result: dict[str, Any] = {}
    for name, value in items:
        if name in result:
            raise Rejected("duplicate JSON key")
        result[name] = value
    return result


def nonfinite(value: str) -> None:
    """Refuse NaN/Infinity even though Python's default JSON decoder accepts them."""
    raise Rejected("non-finite JSON value")


def finite_float(value: str) -> float:
    """Reject exponent-overflow infinities as well as explicitly named NaN/Infinity constants."""
    result = float(value)
    if not math.isfinite(result):
        raise Rejected("non-finite JSON number")
    return result


def json_value(content: bytes) -> Any:
    """Parse UTF-8 JSON with finite values and unambiguous keys; fail on deep/malformed data."""
    try:
        return json.loads(
            content, object_pairs_hook=pairs, parse_constant=nonfinite, parse_float=finite_float
        )
    except (UnicodeError, ValueError, RecursionError) as error:
        raise Rejected("invalid or ambiguous JSON") from error


def canonical(value: Any) -> bytes:
    """Encode finite, stable JSON for hashing and public-safe synthetic evidence."""
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


class UniqueLoader(yaml.SafeLoader):
    """Safe YAML loader with duplicate/merge-key rejection; anchors are refused before loading."""

    def construct_mapping(self, node: yaml.Node, deep: bool = False) -> dict[Hashable, Any]:
        """Only scalar string keys may populate a mapping; duplicate keys are rejected."""
        if not isinstance(node, yaml.MappingNode):
            raise Rejected("invalid YAML mapping")
        result: dict[Hashable, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key == "<<" or key in result:
                raise Rejected("duplicate, merged or invalid YAML key")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def yaml_value(content: bytes) -> Any:
    """Reject aliases, anchors, nesting >8, multiple documents and unsafe tags before use."""
    try:
        text = content.decode("utf-8")
        depth = 0
        documents = 0
        for event in yaml.parse(text):
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
                raise Rejected("YAML aliases and anchors are unsupported")
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
                if depth > 8:
                    raise Rejected("YAML nesting exceeds limit")
            elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
            elif isinstance(event, yaml.DocumentStartEvent):
                documents += 1
        if documents != 1:
            raise Rejected("expected one YAML document")
        return yaml.load(text, Loader=UniqueLoader)
    except (yaml.YAMLError, UnicodeError, RecursionError) as error:
        raise Rejected("invalid or unsafe YAML") from error
