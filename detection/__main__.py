"""Offline CLI for bounded synthetic replay or explicitly authorized normalized telemetry. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: run — line 61
# parameter: events_path — line 62
# parameter: rules_path — line 63
# parameter: correlations_path — line 64
# parameter: output — line 65
# parameter: labels_path — line 66
# variable: started — line 69
# variable: duplicates — line 70
# variable: events — line 70
# variable: rules — line 71
# variable: correlations — line 72
# variable: detectors — line 73
# variable: labels — line 74
# variable: alerts — line 75
# variable: incomplete — line 75
# variable: samples — line 75
# variable: snapshots — line 76
# variable: event — line 77
# variable: rule — line 78
# variable: item — line 79
# variable: identity — line 82
# variable: values — line 82
# variable: hashes — line 83
# variable: name — line 84
# variable: value — line 84
# variable: report — line 86
# variable: item — line 93
# definition: main — line 107
# parameter: argv — line 107
# variable: parser — line 109
# variable: args — line 120
# variable: value — line 127
# variable: review — line 141
# variable: review — line 149
# variable: review — line 157
# variable: report — line 168
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
from detection.review import compare, publish, template, triage
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
    parser.add_argument("mode", choices=("replay", "scan", "compare", "triage-template", "triage"))
    parser.add_argument("--events", type=Path)
    parser.add_argument("--rules", type=Path, default=Path("rules"))
    parser.add_argument("--correlations", type=Path, default=Path("config/correlations.yml"))
    parser.add_argument("--labels", type=Path)
    parser.add_argument("--before", type=Path)
    parser.add_argument("--after", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--decisions", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.mode in {"replay", "scan"}:
        if args.events is None or (args.mode == "replay") != (args.labels is not None):
            parser.error(
                "replay requires --events/--labels; scan requires --events and forbids --labels"
            )
        if any(
            value is not None for value in (args.before, args.after, args.report, args.decisions)
        ):
            parser.error("review arguments cannot be mixed with replay/scan")
    elif args.events is not None or args.labels is not None:
        parser.error("review operations do not read events or evaluation labels")
    try:
        if args.mode not in {"replay", "scan"}:
            if (
                args.mode == "compare"
                and args.before
                and args.after
                and args.report is None
                and args.decisions is None
            ):
                review = compare(args.before, args.after)
            elif (
                args.mode == "triage-template"
                and args.report
                and args.decisions is None
                and args.before is None
                and args.after is None
            ):
                review = template(args.report)
            elif (
                args.mode == "triage"
                and args.report
                and args.decisions
                and args.before is None
                and args.after is None
            ):
                review = triage(args.report, args.decisions)
            else:
                parser.error(
                    "compare requires --before/--after; triage-template requires --report; triage requires --report/--decisions"
                )
            publish(args.out, review)
            print(
                canonical({"operation": args.mode, "output": "new review bundle"}).decode(), end=""
            )
            return 0
        assert args.events is not None
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
