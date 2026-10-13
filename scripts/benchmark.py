"""Measured synthetic detector benchmark, not a production SIEM capacity claim. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 26
# definition: main — line 30
# variable: rules — line 37
# variable: correlations — line 38
# variable: events — line 39
# variable: index — line 53
# variable: times — line 56
# variable: _ — line 57
# variable: start — line 58
# variable: _ — line 63
# variable: peak — line 63
# variable: p95 — line 65
# variable: result — line 66
# END CODE MAP

from __future__ import annotations

import json
import sys
import tracemalloc
from pathlib import Path
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> int:
    """Gate 10,000 mixed events at p95 <5s and traced peak <64MiB; timing and memory runs separated."""
    from detection.engine import detect, load_correlations
    from detection.evaluate import percentile
    from detection.events import normalize
    from detection.rules import load_rules

    rules = load_rules(ROOT / "rules")
    correlations = load_correlations(ROOT / "config/correlations.yml", rules)
    events = [
        normalize(
            {
                "id": f"bench-{index:05d}",
                "timestamp": "2026-01-01T00:00:00Z",
                "source": {"product": "windows", "service": "security"},
                "fields": {
                    "EventID": 4625 if index % 5 == 0 else 4624,
                    "SourceIp": f"192.0.2.{index % 200}",
                    "Hostname": "lab-benchmark",
                    "TargetUserName": f"fictional-user-{index}",
                },
            }
        )
        for index in range(10_000)
    ]
    detect(events, rules, correlations)
    times = []
    for _ in range(10):
        start = perf_counter()
        detect(events, rules, correlations)
        times.append(perf_counter() - start)
    tracemalloc.start()
    detect(events, rules, correlations)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    p95 = percentile(times, 0.95)
    result = {
        "events": len(events),
        "iterations": 10,
        "p95_seconds": p95,
        "min_seconds": min(times),
        "traced_detector_peak_bytes": peak,
        "scope": "Normalized events already in memory; excludes ingestion, export, interpreter/native memory",
    }
    print(json.dumps(result, sort_keys=True))
    if p95 is None or p95 >= 5 or peak >= 64 * 1024 * 1024:
        raise SystemExit("Synthetic performance regression budget exceeded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
