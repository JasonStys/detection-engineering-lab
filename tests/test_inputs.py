"""Schema, resource, ambiguity and untrusted-input safety regressions. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 66
# variable: BASE — line 67
# definition: test_json_rejections — line 87
# parameter: content — line 87
# definition: test_finite_json_number — line 93
# definition: test_invalid_calendar_metadata — line 98
# variable: rule — line 100
# definition: test_yaml_rejections — line 121
# parameter: content — line 121
# variable: index — line 148
# definition: test_bad_event — line 152
# parameter: field — line 152
# parameter: value — line 152
# variable: value_record — line 154
# definition: test_envelope_rejected — line 161
# parameter: value — line 161
# definition: test_utc_identity_immutability — line 167
# variable: value — line 169
# variable: event — line 171
# definition: test_valid_scalars_round_trip — line 186
# parameter: number — line 186
# parameter: text — line 186
# variable: event — line 188
# definition: test_input_file_and_duplicates — line 192
# parameter: tmp_path — line 192
# variable: path — line 194
# variable: duplicates — line 196
# variable: events — line 196
# variable: content — line 201
# definition: test_unsupported_predicates — line 235
# parameter: selection — line 235
# definition: test_invalid_rule_metadata — line 258
# parameter: field — line 258
# parameter: value — line 258
# variable: rule — line 260
# definition: test_rule_directory_checks — line 266
# parameter: tmp_path — line 266
# variable: content — line 272
# definition: test_invalid_correlation — line 296
# parameter: field — line 296
# parameter: tmp_path — line 296
# parameter: value — line 296
# variable: config — line 298
# variable: path — line 300
# definition: test_correlation_envelope — line 315
# parameter: config — line 315
# parameter: tmp_path — line 315
# variable: path — line 317
# END CODE MAP

import copy
from pathlib import Path

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from detection.engine import load_correlations
from detection.events import MAX_EVENTS, MAX_INPUT, MAX_LINE, load_events, normalize
from detection.io import Rejected, canonical, json_value, read_bytes, yaml_value
from detection.rules import compile_rule, load_rules, predicates

ROOT = Path(__file__).resolve().parents[1]
BASE = {
    "id": "event-1",
    "timestamp": "2026-01-01T00:00:00Z",
    "source": {"product": "windows", "service": "security"},
    "fields": {"EventID": 1102},
}


@pytest.mark.parametrize(
    "content",
    [
        b'{"x":1,"x":2}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":1e999}',
        b"\xff",
        b"{}x",
        b"[" * 2000,
    ],
)
def test_json_rejections(content):
    """Malformed, duplicate, non-finite and deeply recursive JSON must fail safely."""
    with pytest.raises(Rejected):
        json_value(content)


def test_finite_json_number():
    """Generic JSON parser accepts finite fractions even though event fields disallow floats."""
    assert json_value(b'{"finite":1.25}') == {"finite": 1.25}


def test_invalid_calendar_metadata():
    """A syntactically ISO-looking but impossible calendar date cannot enter a compiled rule."""
    rule = yaml_value((ROOT / "rules/windows_log_clear.yml").read_bytes())
    rule["date"] = "2026-02-30"
    with pytest.raises(Rejected, match="calendar"):
        compile_rule(rule)


@pytest.mark.parametrize(
    "content",
    [
        b"x: 1\nx: 2",
        b"x: &x a\ny: *x",
        b"---\nx: 1\n---\ny: 2",
        b"!!python/object/apply:os.system [echo]",
        b"1: a",
        b"<<: {}",
        b"x: " + b"[" * 10 + b"0" + b"]" * 10,
        b"\xff",
        b"",
        b"{[a]: b}",
    ],
)
def test_yaml_rejections(content):
    """Safe YAML refuses aliases, unsafe tags, duplicate/non-string keys and ambiguous documents."""
    with pytest.raises(Rejected):
        yaml_value(content)


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "../bad"),
        ("id", "x" * 65),
        ("timestamp", "2026-01-01T00:00:00"),
        ("timestamp", "2026-02-30T00:00:00Z"),
        ("timestamp", "1999-01-01T00:00:00Z"),
        ("timestamp", "2026-01-01T00:00:00+25:00"),
        ("timestamp", "9999-12-31T23:59:59-01:00"),
        ("source", {"product": [], "service": "security"}),
        ("source", {"product": "unsupported", "service": "security"}),
        ("source", {"product": "windows"}),
        ("fields", {}),
        ("fields", {"x": None}),
        ("fields", {"x": [1]}),
        ("fields", {"x": 1.0}),
        ("fields", {"x": 2**63}),
        ("fields", {"x": "\x00"}),
        ("fields", {"x": "a" * 4097}),
        ("fields", {"bad|key": 1}),
        ("fields", {str(index): 1 for index in range(33)}),
        ("fields", {1: "value"}),
    ],
)
def test_bad_event(field, value):
    """Envelope fields require supported types, bounded sizes and explicit timezones."""
    value_record = copy.deepcopy(BASE)
    value_record[field] = value
    with pytest.raises(Rejected):
        normalize(value_record)


@pytest.mark.parametrize("value", [None, [], {**BASE, "label": "malicious"}])
def test_envelope_rejected(value):
    """Labels and unsupported envelopes may not enter the detector's feature inputs."""
    with pytest.raises(Rejected):
        normalize(value)


def test_utc_identity_immutability():
    """Offset normalization and independent immutable fields prevent caller mutation from changing events."""
    value = copy.deepcopy(BASE)
    value["timestamp"] = "2025-12-31T19:00:00-05:00"
    event = normalize(value)
    assert event.timestamp == "2026-01-01T00:00:00.000000Z"
    value["fields"]["EventID"] = 1
    assert event.fields["EventID"] == 1102
    with pytest.raises(TypeError):
        event.fields["EventID"] = 2


@given(
    st.integers(min_value=-(2**63), max_value=2**63 - 1),
    st.text(
        alphabet=st.characters(blacklist_characters="\x00", blacklist_categories=("Cs",)),
        max_size=100,
    ),
)
def test_valid_scalars_round_trip(number, text):
    """Supported Unicode text, signed integers and booleans preserve exact types through normalization."""
    event = normalize({**BASE, "fields": {"Number": number, "Text": text, "Flag": True}})
    assert normalize(json_value(canonical(event.record()))).record() == event.record()


def test_input_file_and_duplicates(tmp_path):
    """Identical duplicates deduplicate; conflicts, empty lines, oversized lines and missing files reject."""
    path = tmp_path / "events.jsonl"
    path.write_bytes(canonical(BASE) * 2)
    events, duplicates = load_events(path)
    assert len(events) == 1 and duplicates == 1
    path.write_bytes(canonical(BASE) + canonical({**BASE, "fields": {"EventID": 1}}))
    with pytest.raises(Rejected, match="conflicting"):
        load_events(path)
    for content in (b"", b"\n", b" " * (MAX_LINE + 1), b"\n" * (MAX_EVENTS + 1)):
        path.write_bytes(content)
        with pytest.raises(Rejected):
            load_events(path)
    path.write_bytes(b"x" * (MAX_INPUT + 1))
    with pytest.raises(Rejected, match="size limit"):
        load_events(path)
    with pytest.raises(Rejected):
        read_bytes(tmp_path, 10)
    with pytest.raises(Rejected):
        read_bytes(tmp_path / "missing", 10)


@pytest.mark.parametrize(
    "selection",
    [
        {},
        [],
        {1: "x"},
        {"Bad|re": "x"},
        {"x": "*wildcard"},
        {"x": "?"},
        {"x": ""},
        {"x": "a" * 257},
        {"x": []},
        {"x": [None]},
        {"x|contains": 4},
        {"x": 2**63},
        {"x": "\x00"},
        {"x": list(range(17))},
        {"x": 1, "x|contains": "a"},
        {"bad name": "a"},
    ],
)
def test_unsupported_predicates(selection):
    """Unsupported Sigma constructs fail closed rather than silently broadening a detector."""
    with pytest.raises(Rejected):
        predicates(selection)


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "bad"),
        ("title", "x" * 257),
        ("date", "today"),
        ("author", None),
        ("status", "stable"),
        ("license", "unknown"),
        ("level", []),
        ("falsepositives", []),
        ("falsepositives", [None]),
        ("logsource", {"product": "unknown", "service": "x"}),
        ("tags", ["attack.invalid"]),
        ("detection", {"selection": {"x": 1}, "condition": "1 of selection*"}),
    ],
)
def test_invalid_rule_metadata(field, value):
    """Metadata, source and condition grammar must be validated independently of matching."""
    rule = yaml_value((ROOT / "rules/windows_log_clear.yml").read_bytes())
    rule[field] = value
    with pytest.raises(Rejected):
        compile_rule(rule)


def test_rule_directory_checks(tmp_path):
    """Empty directories, wrong envelopes and duplicate rule identities fail validation."""
    with pytest.raises(Rejected):
        load_rules(tmp_path)
    with pytest.raises(Rejected):
        compile_rule({})
    content = (ROOT / "rules/windows_log_clear.yml").read_bytes()
    (tmp_path / "a.yml").write_bytes(content)
    (tmp_path / "b.yml").write_bytes(content)
    with pytest.raises(Rejected, match="duplicate rule"):
        load_rules(tmp_path)


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "../bad"),
        ("id", "50000000-0000-4000-8000-000000000001"),
        ("title", []),
        ("base_rule", "missing"),
        ("group_by", []),
        ("group_by", ["x", "x"]),
        ("group_by", [[1]]),
        ("distinct", "bad|key"),
        ("threshold", True),
        ("threshold", 33),
        ("window_seconds", 0),
        ("window_seconds", 3601),
    ],
)
def test_invalid_correlation(tmp_path, field, value):
    """Correlation configuration has strict identifiers, fields, bounds and known base-rule references."""
    config = yaml_value((ROOT / "config/correlations.yml").read_bytes())
    config["correlations"][0][field] = value
    path = tmp_path / "config.yml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    with pytest.raises(Rejected):
        load_correlations(path, load_rules(ROOT / "rules"))


@pytest.mark.parametrize(
    "config",
    [
        {},
        {"version": True, "correlations": []},
        {"version": 1, "correlations": []},
        {"version": 1, "correlations": [None]},
    ],
)
def test_correlation_envelope(tmp_path, config):
    """Correlation schema versions, count and exact envelope are enforced."""
    path = tmp_path / "config.yml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    with pytest.raises(Rejected):
        load_correlations(path, load_rules(ROOT / "rules"))
