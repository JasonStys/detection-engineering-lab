"""Real detection replay, timeline, report comparison and reasoned triage adapter for the desktop. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 80
# variable: PRODUCT — line 81
# variable: TITLE — line 82
# variable: PROFILE — line 83
# variable: VERSION — line 84
# variable: COLUMNS — line 85
# variable: RESOURCES — line 86
# variable: MODES — line 101
# variable: REVIEW_MODE — line 102
# variable: ACTIVE_FIELDS — line 103
# variable: FIELDS — line 109
# variable: SCENARIOS — line 120
# variable: HELP — line 121
# definition: scenario — line 124
# parameter: name — line 124
# definition: analyze — line 140
# parameter: parameters — line 141
# parameter: stage — line 141
# parameter: state — line 141
# variable: mode — line 144
# variable: output — line 145
# variable: result — line 147
# variable: summary — line 154
# variable: micro — line 158
# variable: precision — line 159
# variable: recall — line 160
# variable: summary — line 161
# variable: result — line 163
# variable: summary — line 165
# variable: identity — line 168
# variable: selected — line 169
# variable: files — line 172
# variable: original — line 175
# variable: decisions — line 177
# variable: fingerprint — line 178
# variable: cumulative — line 179
# variable: previous — line 180
# variable: previous_files — line 183
# variable: previous_review — line 186
# variable: cumulative — line 191
# variable: key — line 194
# variable: row — line 196
# variable: result — line 216
# variable: summary — line 219
# variable: path — line 225
# definition: views — line 229
# parameter: files — line 229
# variable: result — line 232
# variable: connection — line 233
# variable: timeline — line 236
# variable: row — line 238
# variable: row — line 245
# variable: result — line 249
# variable: group — line 254
# variable: detector — line 255
# variable: event — line 255
# variable: source — line 260
# variable: row — line 266
# definition: cells — line 271
# parameter: row — line 271
# variable: source — line 273
# END CODE MAP

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from .__main__ import run
from .desktop_state import Workspace
from .io import Rejected, canonical, json_value, read_bytes
from .review import compare, publish, triage

ROOT = Path(__file__).resolve().parents[1]
PRODUCT = "detection-engineering-lab"
TITLE = "Detection Engineering Workbench"
PROFILE = "DetectionEngineeringLab"
VERSION = "1.1.1"
COLUMNS = ("Event UTC", "Detector / source", "Event identity", "Disposition / change")
RESOURCES = (
    "examples/events.jsonl",
    "examples/labels.json",
    "config/correlations.yml",
    "config/sigma-schema.json",
    "detection/schema.sql",
    "rules/cloud_logging.yml",
    "rules/linux_cron.yml",
    "rules/windows_auth_failure.yml",
    "rules/windows_log_clear.yml",
    "rules/windows_powershell.yml",
    "notices.txt",
    "app.ico",
    "python314.dll",
)
MODES = ("Replay with labels", "Unlabeled scan", "Compare report files", "Review selected alert")
REVIEW_MODE = MODES[3]
ACTIVE_FIELDS = {
    MODES[0]: ("events", "labels", "rules", "correlations"),
    MODES[1]: ("events", "rules", "correlations"),
    MODES[2]: ("before", "after"),
    MODES[3]: ("analyst", "disposition", "reason"),
}
FIELDS = (
    ("events", "Authorized normalized events (JSONL)", "file"),
    ("labels", "Independent truth labels (replay only)", "file"),
    ("rules", "Reviewed constrained Sigma rule directory", "directory"),
    ("correlations", "Reviewed correlation configuration (YAML)", "file"),
    ("before", "Earlier report JSON (comparison only)", "file"),
    ("after", "Later report JSON (comparison only)", "file"),
    ("analyst", "Asserted analyst (triage only)", "text"),
    ("disposition", "Disposition: investigate / benign / confirmed-signal / needs-context", "text"),
    ("reason", "Reason for this alert's disposition (triage only)", "text"),
)
SCENARIOS = ("Fictional mixed-estate replay", "Unlabeled authorized-input workflow")
HELP = "Replay keeps truth labels separate from detection. Scan has no accuracy score. Choose only supported normalized JSONL and constrained Sigma/YAML; arbitrary EVTX, shell commands and full Sigma syntax are unsupported. Investigation candidates are not confirmed incidents. Select an alert and fill analyst/disposition/reason to create an immutable reasoned review; it never edits labels or original accuracy. Timeline rows show normalized supporting context. Compare reports only when event/label fingerprints match. State/exports are plaintext local evidence, not authenticated identities. No telemetry, live collection, enforcement, background network or AI service."


def scenario(name: str) -> dict[str, str]:
    """Prepare an optional scenario in the real application; it uses the same handlers as authorized files."""
    if name not in SCENARIOS:
        raise Rejected("unknown prepared scenario")
    return {
        "mode": MODES[0] if name == SCENARIOS[0] else MODES[1],
        "events": str(ROOT / "examples/events.jsonl"),
        "labels": str(ROOT / "examples/labels.json"),
        "rules": str(ROOT / "rules"),
        "correlations": str(ROOT / "config/correlations.yml"),
        "analyst": "",
        "disposition": "needs-context",
        "reason": "",
    }


def analyze(
    state: Workspace, parameters: dict[str, str], stage: Path
) -> tuple[str, str, dict[str, bytes]]:
    """Call actual existing core APIs; retained reports and accuracy are never fabricated by the GUI."""
    mode = parameters["mode"]
    output = stage / "bundle"
    if mode in MODES[:2]:
        result = run(
            Path(parameters["events"]),
            Path(parameters["rules"]),
            Path(parameters["correlations"]),
            output,
            Path(parameters["labels"]) if mode == MODES[0] else None,
        )
        summary = f"{result['events']} events; {len(result['alerts'])} candidates; " + (
            "labeled replay" if result["evaluation"] else "not evaluated"
        )
        if result["evaluation"]:
            micro = result["evaluation"]["micro"]
            precision = "undefined" if micro["precision"] is None else f"{micro['precision']:.1%}"
            recall = "undefined" if micro["recall"] is None else f"{micro['recall']:.1%}"
            summary += f"; supplied labels: TP {micro['tp']} / FP {micro['fp']} / FN {micro['fn']}; precision {precision}, recall {recall}"
    elif mode == MODES[2]:
        result = compare(Path(parameters["before"]), Path(parameters["after"]))
        publish(output, result)
        summary = f"{len(result['added_alerts'])} added / {len(result['removed_alerts'])} removed; removals are not incident resolutions"
    elif mode == MODES[3]:
        try:
            identity = int(parameters["_run"])
            selected = json_value(parameters["_row"].encode())
        except (ValueError, KeyError) as error:
            raise Rejected("select a saved original detection alert before triage") from error
        files = state.files(identity)
        if "report.json" not in files or not isinstance(selected, dict):
            raise Rejected("select an original detection alert, not a review summary")
        original = stage / "original.json"
        original.write_bytes(files["report.json"])
        decisions = stage / "decisions.json"
        fingerprint = hashlib.sha256(files["report.json"]).hexdigest()
        cumulative = {}
        for previous in state.history():
            if previous["kind"] != MODES[3]:
                continue
            previous_files = state.files(previous["id"])
            if "review.json" not in previous_files:
                continue
            previous_review = json_value(previous_files["review.json"])
            if (
                previous_review.get("operation") == "triage"
                and previous_review.get("report_sha256") == fingerprint
            ):
                cumulative = {
                    (row["detector"], row["event"]): {
                        key: row[key]
                        for key in ("detector", "event", "disposition", "analyst", "reason")
                    }
                    for row in previous_review["alerts"]
                    if row["disposition"] != "unreviewed"
                }
                break
        cumulative[(selected.get("detector"), selected.get("event"))] = {
            "detector": selected.get("detector"),
            "event": selected.get("event"),
            "disposition": parameters["disposition"],
            "analyst": parameters["analyst"],
            "reason": parameters["reason"],
        }
        decisions.write_bytes(
            canonical(
                {
                    "schema": 1,
                    "report_sha256": fingerprint,
                    "decisions": list(cumulative.values()),
                }
            )
        )
        result = triage(original, decisions)
        publish(output, result)
        (output / "source-report.json").write_bytes(files["report.json"])
        summary = f"{result['reviewed']} reviewed / {result['unreviewed']} unreviewed; original evidence unchanged"
    else:
        raise Rejected("unsupported desktop operation")
    return (
        mode,
        summary,
        {path.name: read_bytes(path, 32 * 1024 * 1024) for path in output.iterdir()},
    )


def views(files: dict[str, bytes]) -> dict[str, list[dict[str, Any]]]:
    """Expose actual alerts and normalized event timeline, or actual comparison/review results."""
    if "report.json" in files:
        result = json_value(files["report.json"])
        connection = sqlite3.connect(":memory:")
        with closing(connection):
            connection.deserialize(files["evidence.sqlite3"])
            timeline = [
                json.loads(row[0])
                for row in connection.execute(
                    "SELECT normalized_json FROM event ORDER BY timestamp,id"
                )
            ]
        return {
            "Investigation candidates": [
                {**row, "detector_title": result["detectors"][row["detector"]]["title"]}
                for row in result["alerts"]
            ],
            "Normalized event timeline": timeline,
        }
    result = json_value(files["review.json"])
    if result["operation"] == "compare":
        return {
            "Rule-change review": [
                {"state": group.replace("_", " "), "detector": detector, "event": event}
                for group in ("added_alerts", "removed_alerts", "persistent_alerts")
                for detector, event in result[group]
            ]
        }
    if "source-report.json" not in files:
        return {"Analyst dispositions": result["alerts"]}
    source = json_value(files["source-report.json"])
    if hashlib.sha256(files["source-report.json"]).hexdigest() != result["report_sha256"]:
        raise Rejected("triage source report hash mismatch")
    return {
        "Analyst dispositions": [
            {**row, "detector_title": source["detectors"][row["detector"]]["title"]}
            for row in result["alerts"]
        ]
    }


def cells(row: dict[str, Any]) -> tuple[str, str, str, str]:
    """Provide stable text columns without interpreting event fields or treating strings as commands."""
    source = row.get("source", {})
    return (
        str(row.get("timestamp", "")),
        str(row.get("detector_title", row.get("detector", source.get("product", "")))),
        str(row.get("event", row.get("id", ""))),
        str(row.get("disposition", row.get("state", "candidate"))),
    )
