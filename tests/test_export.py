"""End-to-end CLI, inert HTML, SQL binding and non-overwrite output tests. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 55
# definition: replay — line 58
# parameter: destination — line 58
# definition: test_end_to_end — line 69
# parameter: tmp_path — line 69
# variable: destination — line 71
# variable: report — line 72
# variable: value — line 75
# variable: connection — line 77
# variable: before — line 90
# definition: test_xss_and_sql_binding — line 98
# parameter: tmp_path — line 98
# variable: report — line 100
# variable: text — line 107
# variable: event — line 112
# variable: alert — line 120
# variable: path — line 121
# variable: connection — line 123
# definition: test_scan_has_no_accuracy_claim — line 128
# parameter: tmp_path — line 128
# variable: report — line 130
# variable: labeled — line 136
# definition: test_cli — line 141
# parameter: capsys — line 141
# parameter: tmp_path — line 141
# variable: arguments — line 143
# definition: test_output_failure_preserves_original — line 167
# parameter: tmp_path — line 167
# variable: report — line 169
# variable: sentinel — line 172
# definition: test_links_are_refused — line 189
# parameter: tmp_path — line 189
# variable: source — line 191
# variable: link — line 193
# variable: linked_directory — line 197
# END CODE MAP

import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import pytest

from detection.__main__ import main, run
from detection.engine import Alert
from detection.events import normalize
from detection.io import Rejected, read_bytes
from detection.store import database, export, html_report

ROOT = Path(__file__).resolve().parents[1]


def replay(destination):
    """Run the whole pipeline with reviewed fixtures and a caller-owned new output location."""
    return run(
        ROOT / "examples/events.jsonl",
        ROOT / "rules",
        ROOT / "config/correlations.yml",
        destination,
        ROOT / "examples/labels.json",
    )


def test_end_to_end(tmp_path):
    """Normalized records, report fingerprints and SQLite foreign keys survive full replay/export."""
    destination = tmp_path / "demo"
    report = replay(destination)
    assert json.loads((destination / "report.json").read_bytes()) == report
    assert len(report["sha256"]) == 4 and all(
        len(value) == 64 for value in report["sha256"].values()
    )
    with closing(sqlite3.connect(destination / "evidence.sqlite3")) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert not connection.execute("PRAGMA foreign_key_check").fetchall()
        assert connection.execute("SELECT COUNT(*) FROM event").fetchone() == (71,)
        assert connection.execute("SELECT COUNT(*) FROM alert").fetchone() == (
            len(report["alerts"]),
        )
        assert (
            "DROP TABLE"
            in connection.execute(
                "SELECT normalized_json FROM event WHERE id = ?", ("injection-string",)
            ).fetchone()[0]
        )
    before = (destination / "report.json").read_bytes()
    with pytest.raises(Rejected, match="new directory"):
        replay(destination)
    assert (destination / "report.json").read_bytes() == before
    if os.name != "nt":
        assert destination.stat().st_mode & 0o777 == 0o700


def test_xss_and_sql_binding(tmp_path):
    """Titles, IDs and telemetry containing HTML/SQL syntax remain inert data in both output formats."""
    report = {
        "detectors": {
            "<script>x</script>": {"title": "<img src=x onerror=alert(1)>", "techniques": ["T1110"]}
        },
        "dangerous": "</pre><script>evil()</script>",
        "events": "<script>evil()</script>",
    }
    text = html_report(report)
    assert "<script>" not in text and "<img " not in text
    assert "&lt;script&gt;" in text and "Content-Security-Policy" in text
    assert "default-src &#x27;none&#x27;" in text
    assert "style-src &#x27;sha256-" in text
    event = normalize(
        {
            "id": "safe-id",
            "timestamp": "2026-01-01T00:00:00Z",
            "source": {"product": "linux", "service": "auditd"},
            "fields": {"Text": "'); DROP TABLE event;--"},
        }
    )
    alert = Alert("'); DROP TABLE alert;--", event.id, event.timestamp, (event.id,), 0)
    path = tmp_path / "evidence.sqlite3"
    database(path, [event], [alert], report)
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("SELECT detector FROM alert").fetchone() == (alert.detector,)
        assert connection.execute("SELECT COUNT(*) FROM event").fetchone() == (1,)


def test_scan_has_no_accuracy_claim(tmp_path):
    """Unlabeled scan produces no score or label fingerprint; detector outputs match labeled replay."""
    report = run(
        ROOT / "examples/events.jsonl",
        ROOT / "rules",
        ROOT / "config/correlations.yml",
        tmp_path / "scan",
    )
    labeled = replay(tmp_path / "replay")
    assert report["evaluation"] is None and "labels" not in report["sha256"]
    assert report["alerts"] == labeled["alerts"]


def test_cli(tmp_path, capsys):
    """Success, missing inputs and incompatible replay/scan label flags return clear safe errors."""
    arguments = [
        "replay",
        "--events",
        str(ROOT / "examples/events.jsonl"),
        "--rules",
        str(ROOT / "rules"),
        "--correlations",
        str(ROOT / "config/correlations.yml"),
        "--labels",
        str(ROOT / "examples/labels.json"),
        "--out",
        str(tmp_path / "cli"),
    ]
    assert main(arguments) == 0
    assert json.loads(capsys.readouterr().out)["events"] == 71
    assert main(arguments) == 2
    assert "Rejected" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        main(["scan", *arguments[1:]])
    with patch("detection.__main__.run", side_effect=sqlite3.Error("SENSITIVE")):
        assert main(arguments) == 2
    assert "SENSITIVE" not in capsys.readouterr().err


def test_output_failure_preserves_original(tmp_path):
    """Bad output parents and disk errors never delete or overwrite unrelated user data."""
    report = {"detectors": {}}
    with pytest.raises(Rejected):
        export(tmp_path / "missing" / "out", [], [], report)
    sentinel = tmp_path / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    with (
        patch("detection.store.os.replace", side_effect=OSError),
        pytest.raises(Rejected, match="export failed"),
    ):
        export(tmp_path / "partial", [], [], report)
    assert sentinel.read_text() == "keep"
    with patch("detection.store.database", side_effect=sqlite3.Error), pytest.raises(sqlite3.Error):
        export(tmp_path / "failed", [], [], report)
    assert not (tmp_path / "failed").exists()


@pytest.mark.skipif(
    os.name == "nt",
    reason="Creating symlinks requires Windows developer mode/admin; Unix CI covers it",
)
def test_links_are_refused(tmp_path):
    """Input/output final links and linked output ancestors cannot bypass regular-path checks."""
    source = tmp_path / "input"
    source.write_bytes(b"{}")
    link = tmp_path / "link"
    link.symlink_to(source)
    with pytest.raises(Rejected):
        read_bytes(link, 10)
    linked_directory = tmp_path / "directory-link"
    linked_directory.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(Rejected):
        export(linked_directory / "out", [], [], {"detectors": {}})
