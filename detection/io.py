"""Bounded regular-file, strict JSON and safe YAML readers. Created by Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: Rejected — line 57
# definition: read_bytes — line 61
# parameter: limit — line 61
# parameter: path — line 61
# variable: descriptor — line 66
# variable: stream — line 69
# variable: content — line 72
# definition: pairs — line 80
# parameter: items — line 80
# variable: result — line 82
# variable: name — line 83
# variable: value — line 83
# definition: nonfinite — line 90
# parameter: value — line 90
# definition: finite_float — line 95
# parameter: value — line 95
# variable: result — line 97
# definition: json_value — line 103
# parameter: content — line 103
# definition: canonical — line 113
# parameter: value — line 113
# definition: UniqueLoader — line 120
# definition: construct_mapping — line 123
# parameter: deep — line 123
# parameter: node — line 123
# parameter: self — line 123
# variable: result — line 127
# variable: key_node — line 128
# variable: value_node — line 128
# variable: key — line 129
# definition: yaml_value — line 136
# parameter: content — line 136
# variable: text — line 139
# variable: depth — line 140
# variable: documents — line 141
# variable: event — line 142
# variable: depth — line 146
# variable: depth — line 150
# variable: documents — line 152
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
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
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
