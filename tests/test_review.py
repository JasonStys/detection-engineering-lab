"""Independent comparison/triage workflow boundaries and actual CLI acceptance. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 57
# definition: save — line 60
# parameter: path — line 60
# parameter: value — line 60
# definition: snapshot — line 66
# definition: test_comparison_exact_snapshot_and_changes — line 85
# parameter: tmp_path — line 85
# variable: left — line 87
# variable: right — line 88
# variable: before — line 91
# variable: after — line 92
# variable: result — line 93
# variable: key — line 100
# variable: mismatch — line 101
# definition: test_reasoned_partial_triage_preserves_accuracy — line 107
# parameter: tmp_path — line 107
# variable: value — line 109
# variable: source — line 111
# variable: draft — line 112
# variable: decisions — line 123
# variable: result — line 124
# definition: test_triage_rejects_stale_and_ambiguous_decisions — line 138
# parameter: change — line 138
# parameter: tmp_path — line 138
# variable: value — line 140
# variable: source — line 142
# variable: draft — line 143
# variable: decision — line 144
# definition: test_malformed_reports_fail_closed — line 178
# parameter: tmp_path — line 178
# parameter: value — line 178
# definition: test_actual_replay_to_review_cli — line 184
# parameter: tmp_path — line 184
# variable: output — line 186
# variable: source — line 194
# definition: test_review_table_escapes_reason_and_keeps_original — line 244
# parameter: tmp_path — line 244
# variable: source — line 246
# variable: draft — line 247
# variable: reviewed — line 257
# variable: output — line 259
# END CODE MAP

import copy
import hashlib
import json
from pathlib import Path

import pytest

from detection.__main__ import main, run
from detection.io import Rejected, canonical
from detection.review import compare, publish, report, template, triage

ROOT = Path(__file__).resolve().parents[1]


def save(path: Path, value: object) -> Path:
    """Write a caller-owned synthetic JSON fixture, preserving exact bytes for independent hashes."""
    path.write_bytes(canonical(value))
    return path


def snapshot() -> dict:
    """Supply independent small replay identities without importing the detection implementation."""
    return {
        "schema": 1,
        "sha256": {
            "normalized_events": "a" * 64,
            "compiled_rules": "b" * 64,
            "correlations": "c" * 64,
            "labels": "d" * 64,
        },
        "detectors": {
            "rule-one": {"title": "Fictional sign-in"},
            "rule-two": {"title": "Fictional process"},
        },
        "alerts": [{"detector": "rule-one", "event": "event-one"}],
        "evaluation": {"micro": {"tp": 1, "fp": 0, "fn": 1}},
    }


def test_comparison_exact_snapshot_and_changes(tmp_path):
    """Report added/removed/persistent identities without modifying inputs or claiming resolution."""
    left = snapshot()
    right = copy.deepcopy(left)
    right["alerts"].append({"detector": "rule-two", "event": "event-two"})
    right["sha256"]["compiled_rules"] = "e" * 64
    before = save(tmp_path / "before.json", left)
    after = save(tmp_path / "after.json", right)
    result = compare(before, after)
    assert result["added_alerts"] == [("rule-two", "event-two")]
    assert result["persistent_alerts"] == [("rule-one", "event-one")]
    assert result["removed_alerts"] == [] and result["rule_snapshot_changed"]
    assert result["before_sha256"] == hashlib.sha256(before.read_bytes()).hexdigest()
    assert json.loads(before.read_bytes()) == left
    assert compare(after, before)["removed_alerts"] == [("rule-two", "event-two")]
    for key in ("normalized_events", "labels"):
        mismatch = copy.deepcopy(right)
        mismatch["sha256"][key] = "f" * 64
        with pytest.raises(Rejected):
            compare(before, save(after, mismatch))


def test_reasoned_partial_triage_preserves_accuracy(tmp_path):
    """A benign analyst assertion does not rewrite evaluation truth or the original alert snapshot."""
    value = snapshot()
    value["alerts"].append({"detector": "rule-two", "event": "event-two"})
    source = save(tmp_path / "report.json", value)
    draft = template(source)
    assert len(draft["available_alerts"]) == 2 and draft["decisions"] == []
    draft["decisions"] = [
        {
            "detector": "rule-one",
            "event": "event-one",
            "disposition": "benign",
            "analyst": "reviewer-one",
            "reason": "Confirmed scheduled fictional service activity",
        }
    ]
    decisions = save(tmp_path / "decisions.json", draft)
    result = triage(source, decisions)
    assert (result["reviewed"], result["unreviewed"]) == (1, 1)
    assert result["evaluation"] == value["evaluation"]
    assert result["alerts"][1]["disposition"] == "unreviewed"
    assert source.read_bytes() == canonical(value)
    publish(tmp_path / "review", result)
    assert (tmp_path / "review/review.json").is_file()
    with pytest.raises(Rejected):
        publish(tmp_path / "review", result)


@pytest.mark.parametrize(
    "change", ["digest", "duplicate", "unknown", "disposition", "empty-reason", "fields"]
)
def test_triage_rejects_stale_and_ambiguous_decisions(tmp_path, change):
    """Report digest, unique exact identities, known dispositions and reasons are mandatory."""
    value = snapshot()
    value["alerts"].append({"detector": "rule-two", "event": "event-two"})
    source = save(tmp_path / "source.json", value)
    draft = template(source)
    decision = {
        "detector": "rule-one",
        "event": "event-one",
        "disposition": "investigate",
        "analyst": "analyst",
        "reason": "Needs supporting context",
    }
    draft["decisions"] = [decision]
    if change == "digest":
        draft["report_sha256"] = "f" * 64
    if change == "duplicate":
        draft["decisions"].append(decision.copy())
    if change == "unknown":
        decision["event"] = "unknown"
    if change == "disposition":
        decision["disposition"] = []
    if change == "empty-reason":
        decision["reason"] = ""
    if change == "fields":
        decision["extra"] = "not allowed"
    with pytest.raises(Rejected):
        triage(source, save(tmp_path / "bad.json", draft))


@pytest.mark.parametrize(
    "value",
    [
        None,
        {"schema": True},
        {"schema": 1},
        {**snapshot(), "alerts": [{"detector": [], "event": "x"}]},
        {**snapshot(), "alerts": snapshot()["alerts"] * 2},
    ],
)
def test_malformed_reports_fail_closed(tmp_path, value):
    """Malformed supplied report shapes fail with fixed diagnostics, not raw errors or fabricated success."""
    with pytest.raises(Rejected):
        report(save(tmp_path / "bad.json", value))


def test_actual_replay_to_review_cli(tmp_path):
    """Drive a real replay, generate its review template, triage and compare through public CLI commands."""
    output = tmp_path / "replay"
    run(
        ROOT / "examples/events.jsonl",
        ROOT / "rules",
        ROOT / "config/correlations.yml",
        output,
        ROOT / "examples/labels.json",
    )
    source = output / "report.json"
    assert (
        main(["triage-template", "--report", str(source), "--out", str(tmp_path / "template")]) == 0
    )
    assert (
        main(
            [
                "triage",
                "--report",
                str(source),
                "--decisions",
                str(tmp_path / "template/review.json"),
                "--out",
                str(tmp_path / "triage"),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "compare",
                "--before",
                str(source),
                "--after",
                str(source),
                "--out",
                str(tmp_path / "comparison"),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "compare",
                "--before",
                str(source),
                "--after",
                str(tmp_path / "missing"),
                "--out",
                str(tmp_path / "failure"),
            ]
        )
        == 2
    )
    with pytest.raises(SystemExit):
        main(["compare", "--out", str(tmp_path / "invalid")])


def test_review_table_escapes_reason_and_keeps_original(tmp_path):
    """A malicious-looking analyst note stays literal data and cannot add executable report markup."""
    source = save(tmp_path / "source.json", snapshot())
    draft = template(source)
    draft["decisions"] = [
        {
            "detector": "rule-one",
            "event": "event-one",
            "disposition": "needs-context",
            "analyst": "reviewer",
            "reason": "<script>alert('fictional')</script>",
        }
    ]
    reviewed = triage(source, save(tmp_path / "notes.json", draft))
    publish(tmp_path / "safe", reviewed)
    output = (tmp_path / "safe/review.html").read_text(encoding="utf-8")
    assert "<table>" in output and "&lt;script&gt;" in output and "<script>" not in output
    assert json.loads(source.read_bytes()) == snapshot()
