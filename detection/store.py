"""New-directory-only evidence export, bound SQL inserts and inert escaped HTML. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: STYLE — line 56
# definition: html_report — line 67
# parameter: report — line 67
# variable: escaped — line 69
# variable: evaluation — line 70
# variable: micro — line 71
# variable: rows — line 72
# variable: identity — line 73
# variable: item — line 73
# variable: counts — line 74
# variable: cells — line 75
# variable: key — line 77
# variable: css_hash — line 82
# variable: policy — line 83
# variable: accuracy — line 86
# variable: key — line 88
# variable: payload — line 91
# definition: database — line 114
# parameter: alerts — line 114
# parameter: events — line 114
# parameter: path — line 114
# parameter: report — line 114
# variable: connection — line 116
# variable: event — line 132
# variable: alert — line 145
# definition: export — line 155
# parameter: alerts — line 156
# parameter: destination — line 156
# parameter: events — line 156
# parameter: report — line 156
# variable: parent — line 159
# variable: path — line 168
# variable: temporary — line 170
# variable: stage — line 171
# variable: item — line 180
# END CODE MAP

from __future__ import annotations

import base64
import hashlib
import html
import os
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path
from typing import Any

from detection.engine import Alert
from detection.events import Event
from detection.io import Rejected, canonical, read_bytes

STYLE = """body{margin:0;background:#101827;color:#edf2fc;font:16px/1.6 system-ui,sans-serif}
main{max-width:1100px;margin:auto;padding:32px}a{color:#83d4fa}h1{font-size:2.3rem}
table{width:100%;border-collapse:collapse}th,td{padding:12px;text-align:left;border-bottom:1px solid #455369}
caption{text-align:left;color:#b4c5dd}pre{white-space:pre-wrap;overflow-wrap:anywhere;padding:20px;background:#17243a}
.note{border-left:4px solid #f1bb65;padding:12px;background:#17243a}.cards{display:flex;gap:16px;flex-wrap:wrap}
.card{flex:1;min-width:150px;border:1px solid #455369;padding:16px}.card strong{display:block;font-size:1.8rem}
.scroll{overflow-x:auto}summary{cursor:pointer;padding:16px}footer{margin-top:32px;color:#b4c5dd}
@media(max-width:600px){main{padding:16px}h1{font-size:1.7rem}td,th{padding:8px}}
"""


def html_report(report: dict[str, Any]) -> str:
    """Escape all report data; static accessible HTML has hash-authorized CSS, no scripts or remote assets."""
    escaped = html.escape
    evaluation = report.get("evaluation")
    micro = evaluation["micro"] if evaluation else None
    rows = []
    for identity, item in report["detectors"].items():
        counts = evaluation["detectors"][identity] if evaluation else None
        cells = "".join(
            f"<td>{escaped(str(counts[key])) if counts else 'Not evaluated'}</td>"
            for key in ("tp", "fp", "fn")
        )
        rows.append(
            f"<tr><td>{escaped(item['title'])}<br><small>{escaped(identity)}</small></td><td>{escaped(', '.join(item['techniques']))}</td>{cells}</tr>"
        )
    css_hash = base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode()
    policy = (
        f"default-src 'none'; style-src 'sha256-{css_hash}'; base-uri 'none'; form-action 'none'"
    )
    accuracy = (
        f"<p>Micro precision: {micro['precision']:.1%} · recall: {micro['recall']:.1%} · F1: {micro['f1']:.1%}</p>"
        if micro and all(micro[key] is not None for key in ("precision", "recall", "f1"))
        else "<p>Accuracy unavailable: unlabeled input or undefined denominator.</p>"
    )
    payload = escaped(canonical(report).decode())
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{escaped(policy, quote=True)}">
<title>Detection replay · Jason Stys</title><style>{STYLE}</style></head>
<body><main><p>OFFLINE · DEFENSIVE · SYNTHETIC REPLAY</p><h1>Detection Engineering Lab</h1>
<p class="note">Investigation candidates, not confirmed incidents. Synthetic replay accuracy does not predict production accuracy. No data is uploaded.</p>
<div class="cards"><div class="card">Unique events<strong>{escaped(str(report.get("events", "Not available")))}</strong></div>
<div class="card">Investigation candidates<strong>{len(report.get("alerts", []))}</strong></div>
<div class="card">False positives<strong>{escaped(str(micro["fp"])) if micro else "Not evaluated"}</strong></div>
<div class="card">Missed detections<strong>{escaped(str(micro["fn"])) if micro else "Not evaluated"}</strong></div></div>
{accuracy}<h2>Rule-level results</h2><div class="scroll"><table>
<caption>One decision per unique event and emitted detector. Correlations are scored at the threshold-crossing event.</caption>
<thead><tr><th scope="col">Detector</th><th scope="col">ATT&amp;CK</th><th scope="col">TP</th><th scope="col">FP</th><th scope="col">FN</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>
<h2>How to read this report</h2><p>TP: labeled detection found. FP: benign labeled event matched. FN: labeled behavior missed. Review supporting events in the local evidence database before taking action. Missing correlation fields and duplicates are counted below.</p>
<details><summary>Measured timing, disagreements and normalized-snapshot fingerprints</summary><pre>{payload}</pre></details>
<footer>Created by Jason Stys · <a href="https://github.com/JasonStys">GitHub portfolio</a> ·
<a href="https://www.linkedin.com/in/jason-stys-31b30b351/">Contact on LinkedIn</a><br>Not a live SIEM, autonomous response system, or compliance certification.</footer>
</main></body></html>
"""


def database(path: Path, events: list[Event], alerts: list[Alert], report: dict[str, Any]) -> None:
    """Build a fresh SQLite database with trusted schema, bound values and integrity checks."""
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript(
            read_bytes(Path(__file__).with_name("schema.sql"), 32 * 1024).decode()
        )
        with connection:
            connection.execute("INSERT INTO run VALUES (?, ?)", (1, canonical(report).decode()))
            connection.executemany(
                "INSERT INTO event VALUES (?, ?, ?, ?, ?)",
                (
                    (
                        event.id,
                        event.timestamp,
                        event.product,
                        event.service,
                        canonical(event.record()).decode(),
                    )
                    for event in events
                ),
            )
            connection.executemany(
                "INSERT INTO alert VALUES (?, ?, ?, ?, ?)",
                (
                    (
                        alert.detector,
                        alert.event,
                        alert.timestamp,
                        canonical(alert.evidence).decode(),
                        alert.span_seconds,
                    )
                    for alert in alerts
                ),
            )
        if (
            connection.execute("PRAGMA integrity_check").fetchone() != ("ok",)
            or connection.execute("PRAGMA foreign_key_check").fetchall()
        ):
            raise Rejected("evidence database integrity failure")


def export(
    destination: Path, events: list[Event], alerts: list[Alert], report: dict[str, Any]
) -> None:
    """Publish three completed files to a newly created directory; never overwrite user files."""
    parent = destination.absolute().parent
    if (
        destination.exists()
        or destination.is_symlink()
        or destination.is_junction()
        or not parent.is_dir()
    ):
        raise Rejected("output must be a new directory under an existing parent")
    # Reject linked ancestors. Trusted owner-controlled parent is still required to prevent races.
    if any(path.is_symlink() or path.is_junction() for path in (parent, *parent.parents)):
        raise Rejected("output parent must not contain links")
    with tempfile.TemporaryDirectory(prefix=".detection-stage-", dir=parent) as temporary:
        stage = Path(temporary)
        database(stage / "evidence.sqlite3", events, alerts, report)
        (stage / "report.json").write_bytes(canonical(report))
        (stage / "report.html").write_text(html_report(report), encoding="utf-8", newline="\n")
        try:
            destination.mkdir(mode=0o700)
        except FileExistsError as error:
            raise Rejected("output was created by another process") from error
        try:
            for item in stage.iterdir():
                os.replace(item, destination / item.name)
        except OSError:
            # Keep a partial directory inspectable after I/O failure; never remove user-owned files.
            raise Rejected("output export failed; inspect the new directory") from None
