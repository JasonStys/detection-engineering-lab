"""Offline CLI for bounded synthetic replay or explicitly authorized normalized telemetry. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: run — line 56
# parameter: events_path — line 57
# parameter: rules_path — line 58
# parameter: correlations_path — line 59
# parameter: output — line 60
# parameter: labels_path — line 61
# variable: started — line 64
# variable: duplicates — line 65
# variable: events — line 65
# variable: rules — line 66
# variable: correlations — line 67
# variable: detectors — line 68
# variable: labels — line 69
# variable: alerts — line 70
# variable: incomplete — line 70
# variable: samples — line 70
# variable: snapshots — line 71
# variable: event — line 72
# variable: rule — line 73
# variable: item — line 74
# variable: identity — line 77
# variable: values — line 77
# variable: hashes — line 78
# variable: name — line 79
# variable: value — line 79
# variable: report — line 81
# variable: item — line 88
# definition: main — line 102
# parameter: argv — line 102
# variable: parser — line 104
# variable: args — line 111
# variable: report — line 115
# END CODE MAP

from __future__ import annotations

import argparse
import hashlib
import sqlite3
import sys
from dataclasses import asdict
from pathlib import Path
from time import perf_counter
from typing import Any

from detection.engine import detect, load_correlations
from detection.evaluate import catalog, evaluate, load_labels, percentile
from detection.events import load_events
from detection.io import Rejected, canonical
from detection.rules import load_rules
from detection.store import export


def run(
    events_path: Path,
    rules_path: Path,
    correlations_path: Path,
    output: Path,
    labels_path: Path | None = None,
) -> dict[str, Any]:
    """Validate inputs, detect without labels, evaluate/export; fingerprint the exact normalized snapshot."""
    started = perf_counter()
    events, duplicates = load_events(events_path)
    rules = load_rules(rules_path)
    correlations = load_correlations(correlations_path, rules)
    detectors = catalog(rules, correlations)
    labels = load_labels(labels_path, events, set(detectors)) if labels_path else None
    alerts, samples, incomplete = detect(events, rules, correlations)
    snapshots: dict[str, Any] = {
        "normalized_events": [event.record() for event in events],
        "compiled_rules": [asdict(rule) for rule in rules],
        "correlations": [asdict(item) for item in correlations],
    }
    if labels is not None:
        snapshots["labels"] = {identity: sorted(values) for identity, values in labels.items()}
    hashes = {
        name: hashlib.sha256(canonical(value)).hexdigest() for name, value in snapshots.items()
    }
    report: dict[str, Any] = {
        "schema": 1,
        "author": "Jason Stys",
        "events": len(events),
        "duplicates_ignored": duplicates,
        "incomplete_correlation_candidates": incomplete,
        "detectors": detectors,
        "alerts": [item.record() for item in alerts],
        "evaluation": evaluate(events, alerts, labels, detectors) if labels is not None else None,
        "sha256": hashes,
        "timing": {
            "per_event_detector_p50_us": percentile(samples, 0.50),
            "per_event_detector_p95_us": percentile(samples, 0.95),
            "pre_export_wall_seconds": perf_counter() - started,
            "note": "Per-event processing excludes parse/sort/export; span_seconds is proof event-time span, not SOC response latency.",
        },
    }
    export(output, events, alerts, report)
    return report


def main(argv: list[str] | None = None) -> int:
    """CLI: replay requires labels; scan emits unevaluated candidates. Errors omit raw telemetry."""
    parser = argparse.ArgumentParser(description="Offline Detection Engineering Lab · Jason Stys")
    parser.add_argument("mode", choices=("replay", "scan"))
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--rules", type=Path, default=Path("rules"))
    parser.add_argument("--correlations", type=Path, default=Path("config/correlations.yml"))
    parser.add_argument("--labels", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if (args.mode == "replay") != (args.labels is not None):
        parser.error("replay requires --labels; scan forbids --labels")
    try:
        report = run(args.events, args.rules, args.correlations, args.out, args.labels)
    except (Rejected, OSError, sqlite3.Error) as error:
        print(
            f"Rejected: {error if isinstance(error, Rejected) else 'local I/O or database failure'}",
            file=sys.stderr,
        )
        return 2
    print(
        canonical(
            {
                "events": report["events"],
                "alerts": len(report["alerts"]),
                "evaluation": report["evaluation"]["micro"] if report["evaluation"] else None,
            }
        ).decode(),
        end="",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
