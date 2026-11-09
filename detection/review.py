"""Snapshot-bound offline alert triage and rule-change review without changing detection evidence. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: LIMIT — line 82
# variable: STATES — line 83
# definition: text — line 86
# parameter: maximum — line 86
# parameter: value — line 86
# definition: report — line 93
# parameter: path — line 93
# variable: raw — line 95
# variable: value — line 96
# variable: alerts — line 103
# variable: detectors — line 103
# variable: hashes — line 103
# variable: key — line 111
# variable: identities — line 118
# variable: identity — line 119
# variable: item — line 121
# variable: identity — line 128
# definition: compare — line 135
# parameter: after — line 135
# parameter: before — line 135
# variable: left — line 137
# variable: left_hash — line 137
# variable: right — line 138
# variable: right_hash — line 138
# variable: key — line 141
# variable: a — line 144
# variable: old — line 144
# variable: a — line 145
# variable: new — line 145
# variable: key — line 159
# definition: template — line 167
# parameter: source — line 167
# variable: fingerprint — line 169
# variable: value — line 169
# variable: a — line 175
# definition: triage — line 181
# parameter: decisions — line 181
# parameter: source — line 181
# variable: fingerprint — line 183
# variable: value — line 183
# variable: review — line 184
# variable: rows — line 192
# variable: a — line 195
# variable: available — line 195
# variable: reviewed — line 196
# variable: row — line 197
# variable: identity — line 206
# variable: detector — line 232
# variable: event — line 232
# definition: publish — line 239
# parameter: destination — line 239
# parameter: value — line 239
# variable: parent — line 241
# variable: p — line 247
# variable: payload — line 251
# variable: rows — line 252
# variable: rows — line 254
# variable: group — line 256
# variable: detector — line 257
# variable: event — line 257
# variable: table — line 259
# variable: key — line 263
# variable: row — line 266
# variable: data — line 268
# variable: name — line 268
# variable: stream — line 284
# END CODE MAP

from __future__ import annotations

import hashlib
import html
import os
import re
from pathlib import Path
from typing import Any

from detection.io import Rejected, canonical, json_value, read_bytes

LIMIT = 32 * 1024 * 1024
STATES = {"investigate", "benign", "confirmed-signal", "needs-context"}


def text(value: Any, maximum: int = 128) -> str:
    """Accept bounded printable evidence labels, never executable templates or control characters."""
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or not value.isprintable():
        raise Rejected("invalid review text")
    return value


def report(path: Path) -> tuple[dict[str, Any], str]:
    """Validate a bounded supplied replay report and fingerprint its exact original bytes."""
    raw = read_bytes(path, LIMIT)
    value = json_value(raw)
    if (
        not isinstance(value, dict)
        or type(value.get("schema")) is not int
        or value.get("schema") != 1
    ):
        raise Rejected("unsupported replay report")
    hashes, detectors, alerts = value.get("sha256"), value.get("detectors"), value.get("alerts")
    if (
        not isinstance(hashes, dict)
        or not isinstance(detectors, dict)
        or not isinstance(alerts, list)
        or len(alerts) > 300000
    ):
        raise Rejected("invalid replay report structure")
    for key in ("normalized_events", "compiled_rules", "correlations"):
        if not isinstance(hashes.get(key), str) or not re.fullmatch(r"[a-f0-9]{64}", hashes[key]):
            raise Rejected("missing replay fingerprint")
    if "labels" in hashes and (
        not isinstance(hashes["labels"], str) or not re.fullmatch(r"[a-f0-9]{64}", hashes["labels"])
    ):
        raise Rejected("invalid label fingerprint")
    identities = set()
    for identity in detectors:
        text(identity)
    for item in alerts:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("detector"), str)
            or item.get("detector") not in detectors
        ):
            raise Rejected("unknown alert detector")
        identity = (text(item["detector"]), text(item.get("event")))
        if identity in identities:
            raise Rejected("duplicate alert identity")
        identities.add(identity)
    return value, hashlib.sha256(raw).hexdigest()


def compare(before: Path, after: Path) -> dict[str, Any]:
    """Compare rules against identical event/label snapshots; removals are not incident resolutions."""
    left, left_hash = report(before)
    right, right_hash = report(after)
    if any(
        left["sha256"].get(key) != right["sha256"].get(key)
        for key in ("normalized_events", "labels")
    ):
        raise Rejected("comparison requires identical event and label snapshots")
    old = {(a["detector"], a["event"]) for a in left["alerts"]}
    new = {(a["detector"], a["event"]) for a in right["alerts"]}
    return {
        "schema": 1,
        "author": "Jason Stys",
        "operation": "compare",
        "before_sha256": left_hash,
        "after_sha256": right_hash,
        "added_alerts": sorted(new - old),
        "removed_alerts": sorted(old - new),
        "persistent_alerts": sorted(old & new),
        "detectors_added": sorted(right["detectors"].keys() - left["detectors"].keys()),
        "detectors_removed": sorted(left["detectors"].keys() - right["detectors"].keys()),
        "rule_snapshot_changed": any(
            left["sha256"][key] != right["sha256"][key]
            for key in ("compiled_rules", "correlations")
        ),
        "evaluation_before": left.get("evaluation"),
        "evaluation_after": right.get("evaluation"),
        "note": "Supplied report fingerprints bind this review; they are not publisher authentication. Removed alerts do not establish incident resolution.",
    }


def template(source: Path) -> dict[str, Any]:
    """Create a copyable empty triage document bound to one exact report, with actionable alert identities."""
    value, fingerprint = report(source)
    return {
        "schema": 1,
        "report_sha256": fingerprint,
        "decisions": [],
        "available_alerts": [
            {"detector": a["detector"], "event": a["event"]} for a in value["alerts"]
        ],
        "instructions": "Copy detector/event into decisions with disposition, analyst and reason. Unreviewed alerts remain visible; this never edits labels or detection results.",
    }


def triage(source: Path, decisions: Path) -> dict[str, Any]:
    """Apply reasoned local analyst assertions to exact emitted alert identities; preserve evaluation unchanged."""
    value, fingerprint = report(source)
    review = json_value(read_bytes(decisions, LIMIT))
    if (
        not isinstance(review, dict)
        or type(review.get("schema")) is not int
        or review.get("schema") != 1
        or review.get("report_sha256") != fingerprint
    ):
        raise Rejected("triage does not match the exact replay report")
    rows = review.get("decisions")
    if not isinstance(rows, list) or len(rows) > len(value["alerts"]):
        raise Rejected("invalid triage decision count")
    available = {(a["detector"], a["event"]) for a in value["alerts"]}
    reviewed: dict[tuple[str, str], dict[str, str]] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "detector",
            "event",
            "disposition",
            "analyst",
            "reason",
        }:
            raise Rejected("invalid triage decision fields")
        identity = (text(row["detector"]), text(row["event"]))
        if (
            identity not in available
            or identity in reviewed
            or not isinstance(row["disposition"], str)
            or row["disposition"] not in STATES
        ):
            raise Rejected("unknown, duplicate or unsupported triage decision")
        reviewed[identity] = {
            "disposition": text(row["disposition"]),
            "analyst": text(row["analyst"]),
            "reason": text(row["reason"], 500),
        }
    return {
        "schema": 1,
        "author": "Jason Stys",
        "operation": "triage",
        "report_sha256": fingerprint,
        "reviewed": len(reviewed),
        "unreviewed": len(available) - len(reviewed),
        "alerts": [
            {
                "detector": detector,
                "event": event,
                **reviewed.get((detector, event), {"disposition": "unreviewed"}),
            }
            for detector, event in sorted(available)
        ],
        "evaluation": value.get("evaluation"),
        "note": "Dispositions are local analyst assertions, not authenticated identities or confirmed incidents. Detection evidence and label-derived accuracy remain unchanged.",
    }


def publish(destination: Path, value: dict[str, Any]) -> None:
    """Write a new private JSON/inert HTML review bundle; never replace original reports or user directories."""
    parent = destination.absolute().parent
    if (
        destination.exists()
        or destination.is_symlink()
        or destination.is_junction()
        or not parent.is_dir()
        or any(p.is_symlink() or p.is_junction() for p in (parent, *parent.parents))
    ):
        raise Rejected("review output requires a new directory under an unlinked existing parent")
    destination.mkdir(mode=0o700)
    payload = canonical(value)
    rows = value.get("alerts", value.get("available_alerts", []))
    if value.get("operation") == "compare":
        rows = [
            {"detector": detector, "event": event, "disposition": group.replace("_", " ")}
            for group in ("added_alerts", "removed_alerts", "persistent_alerts")
            for detector, event in value[group]
        ]
    table = "".join(
        "<tr>"
        + "".join(
            "<td>" + html.escape(str(row.get(key, ""))) + "</td>"
            for key in ("disposition", "detector", "event", "analyst", "reason")
        )
        + "</tr>"
        for row in rows
    )
    for name, data in (
        ("review.json", payload),
        (
            "review.html",
            (
                '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
                '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">'
                "<title>Detection review — Jason Stys</title><style>body{font:16px/1.5 system-ui;max-width:1100px;margin:2rem auto;padding:1rem;color:#17304b;background:#f4f7fa}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:white;padding:1.5rem}a{color:#194d7a}</style>"
                '<h1>Detection workflow review</h1><p>Created by Jason Stys. Offline local assertions; original detection output and accuracy are unchanged.</p><div style="overflow-x:auto"><table><caption>Exact alert identities and review outcomes</caption><thead><tr><th>State/change</th><th>Detector</th><th>Event</th><th>Analyst</th><th>Reason</th></tr></thead><tbody>'
                + table
                + "</tbody></table></div><details><summary>Fingerprints and full machine-readable evidence</summary><pre>"
                + html.escape(payload.decode())
                + '</pre></details><footer><a href="https://github.com/JasonStys/detection-engineering-lab">Source and help</a></footer></html>'
            ).encode(),
        ),
    ):
        with (destination / name).open("xb") as stream:
            os.chmod(stream.name, 0o600)
            stream.write(data)
