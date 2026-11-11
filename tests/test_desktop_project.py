"""Actual desktop adapters exercise unchanged detection/core/SQLite exports with independent oracles. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: state — line 86
# parameter: tmp_path — line 86
# variable: value — line 88
# definition: run_case — line 95
# parameter: name — line 95
# parameter: parameters — line 95
# parameter: state — line 95
# parameter: tmp_path — line 95
# variable: stage — line 97
# variable: parameters — line 99
# variable: files — line 100
# variable: kind — line 100
# variable: summary — line 100
# variable: identity — line 101
# definition: test_real_replay_timeline_scan_and_original_metrics — line 105
# parameter: state — line 105
# parameter: tmp_path — line 105
# variable: files — line 107
# variable: identity — line 107
# variable: report — line 108
# variable: key — line 110
# variable: views — line 115
# variable: row — line 118
# variable: row — line 119
# variable: parameters — line 120
# variable: _ — line 122
# variable: scanned — line 122
# definition: test_real_rule_change_comparison_keeps_same_event_label_snapshot — line 127
# parameter: state — line 127
# parameter: tmp_path — line 127
# variable: _ — line 129
# variable: before — line 129
# variable: rules — line 130
# variable: path — line 132
# variable: parameters — line 134
# variable: _ — line 136
# variable: after — line 136
# variable: new — line 137
# variable: old — line 137
# variable: comparison — line 140
# variable: _ — line 141
# variable: files — line 141
# variable: result — line 142
# variable: changed — line 147
# definition: test_real_reasoned_triage_is_bound_and_does_not_modify_original — line 154
# parameter: state — line 154
# parameter: tmp_path — line 154
# variable: identity — line 156
# variable: original — line 156
# variable: parameters — line 157
# variable: report — line 158
# variable: row — line 159
# variable: selected — line 159
# variable: _ — line 170
# variable: reviewed — line 170
# variable: result — line 171
# variable: row — line 178
# variable: _ — line 181
# variable: cumulative — line 181
# variable: updated — line 182
# variable: row — line 185
# variable: changed — line 190
# variable: index — line 190
# definition: test_invalid_scenario_mode_input_never_becomes_a_successful_demo — line 205
# parameter: state — line 205
# parameter: tmp_path — line 205
# variable: parameters — line 209
# variable: malformed — line 213
# variable: parameters — line 215
# END CODE MAP

import hashlib
import json
import shutil

import pytest

from detection import desktop_project as project
from detection.desktop_state import Workspace
from detection.io import Rejected, canonical


@pytest.fixture
def state(tmp_path):
    """Use only a marked disposable synthetic workspace, outside the actual checkout and installation."""
    value = Workspace(tmp_path / "state", project.PRODUCT, project.ROOT)
    try:
        yield value
    finally:
        value.close()


def run_case(state, tmp_path, name="one", parameters=None):
    """Run actual existing core into a fresh stage and save the exact completed bundle."""
    stage = tmp_path / name
    stage.mkdir()
    parameters = parameters or project.scenario(project.SCENARIOS[0])
    kind, summary, files = project.analyze(state, parameters, stage)
    identity = state.save(kind, summary, parameters, files)
    return identity, files


def test_real_replay_timeline_scan_and_original_metrics(state, tmp_path):
    """Independent known exercise counts and actual normalized SQLite rows distinguish replay from unlabeled scan."""
    identity, files = run_case(state, tmp_path)
    report = json.loads(files["report.json"])
    assert report["events"] == 71 and len(report["alerts"]) == 10
    assert {key: report["evaluation"]["micro"][key] for key in ("tp", "fp", "fn")} == {
        "tp": 7,
        "fp": 3,
        "fn": 2,
    }
    views = project.views(files)
    assert len(views["Normalized event timeline"]) == 71
    assert len(views["Investigation candidates"]) == 10
    assert any("Audit" in project.cells(row)[1] for row in views["Investigation candidates"])
    assert any(project.cells(row)[1] == "linux" for row in views["Normalized event timeline"])
    parameters = project.scenario(project.SCENARIOS[1])
    parameters["labels"] = str(tmp_path / "labels-are-not-read.json")
    _, scanned = run_case(state, tmp_path, "scan", parameters)
    assert json.loads(scanned["report.json"])["evaluation"] is None
    assert state.files(identity) == files


def test_real_rule_change_comparison_keeps_same_event_label_snapshot(state, tmp_path):
    """An actual changed Sigma literal removes two candidates; comparison does not call them resolved incidents."""
    _, before = run_case(state, tmp_path)
    rules = tmp_path / "candidate-rules"
    shutil.copytree(project.ROOT / "rules", rules)
    path = rules / "windows_log_clear.yml"
    path.write_text(path.read_text().replace("EventID: 1102", "EventID: 9999"))
    parameters = project.scenario(project.SCENARIOS[0])
    parameters["rules"] = str(rules)
    _, after = run_case(state, tmp_path, "candidate", parameters)
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    old.write_bytes(before["report.json"])
    new.write_bytes(after["report.json"])
    comparison = {**parameters, "mode": project.MODES[2], "before": str(old), "after": str(new)}
    _, files = run_case(state, tmp_path, "compare", comparison)
    result = json.loads(files["review.json"])
    assert len(result["removed_alerts"]) == 2 and len(result["persistent_alerts"]) == 8
    assert result["added_alerts"] == [] and result["rule_snapshot_changed"] is True
    assert len(project.views(files)["Rule-change review"]) == 10
    assert "do not establish incident resolution" in result["note"]
    changed = json.loads(after["report.json"])
    changed["sha256"]["normalized_events"] = "a" * 64
    new.write_bytes(canonical(changed))
    with pytest.raises(Rejected, match="identical"):
        run_case(state, tmp_path, "incompatible", comparison)


def test_real_reasoned_triage_is_bound_and_does_not_modify_original(state, tmp_path):
    """GUI-supplied analyst assertions pass through the exact report hash/identity/reason core guard."""
    identity, original = run_case(state, tmp_path)
    parameters = project.scenario(project.SCENARIOS[0])
    report = json.loads(original["report.json"])
    selected = next(row for row in report["alerts"] if row["event"] == "clear-maintenance")
    parameters.update(
        {
            "mode": project.MODES[3],
            "_run": str(identity),
            "_row": canonical(selected).decode(),
            "analyst": "fixture-reviewer",
            "disposition": "benign",
            "reason": "Documented fictional maintenance; confirm owner evidence in real work.",
        }
    )
    _, reviewed = run_case(state, tmp_path, "triage", parameters)
    result = json.loads(reviewed["review.json"])
    assert result["reviewed"] == 1 and result["unreviewed"] == 9
    assert result["report_sha256"] == hashlib.sha256(original["report.json"]).hexdigest()
    assert result["evaluation"] == report["evaluation"]
    assert len(project.views(reviewed)["Analyst dispositions"]) == 10
    assert state.files(identity) == original
    parameters["_row"] = canonical(
        next(row for row in report["alerts"] if row["event"] == "clear-suspicious")
    ).decode()
    parameters["disposition"] = "needs-context"
    _, cumulative = run_case(state, tmp_path, "second-assertion", parameters)
    updated = json.loads(cumulative["review.json"])
    assert updated["reviewed"] == 2 and updated["unreviewed"] == 8
    assert (
        next(row for row in updated["alerts"] if row["event"] == "clear-maintenance")["disposition"]
        == "benign"
    )
    assert cumulative["source-report.json"] == original["report.json"]
    assert updated["evaluation"] == report["evaluation"]
    for index, changed in enumerate(
        [
            {"reason": ""},
            {"_run": "missing"},
            {"_run": "99"},
            {"_row": "null"},
            {"disposition": "automatically-safe"},
            {"_row": canonical({**selected, "event": "not-emitted"}).decode()},
        ]
    ):
        with pytest.raises(Rejected):
            run_case(state, tmp_path, f"invalid-{index}", {**parameters, **changed})
    assert len(state.history()) == 3


def test_invalid_scenario_mode_input_never_becomes_a_successful_demo(state, tmp_path):
    """Malformed/unsupported paths and modes fail and retain the original evidence rather than silently seed data."""
    with pytest.raises(Rejected):
        project.scenario("unknown")
    parameters = project.scenario(project.SCENARIOS[0])
    parameters["mode"] = "execute-code"
    with pytest.raises(Rejected):
        run_case(state, tmp_path, "mode", parameters)
    malformed = tmp_path / "malformed.jsonl"
    malformed.write_bytes(b'{"unsupported":"envelope"}\n')
    parameters = project.scenario(project.SCENARIOS[0])
    parameters["events"] = str(malformed)
    with pytest.raises(Rejected):
        run_case(state, tmp_path, "malformed", parameters)
    assert state.history() == []
