"""Independent semantic oracle, Sigma matching and labeled replay regressions. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 80
# variable: RULES — line 81
# variable: CONFIG — line 82
# definition: auth — line 85
# parameter: host — line 85
# parameter: identity — line 85
# parameter: ip — line 85
# parameter: seconds — line 85
# parameter: user — line 85
# variable: instant — line 87
# definition: test_string_modes — line 109
# parameter: expected — line 109
# parameter: mode — line 109
# parameter: value — line 109
# variable: predicate — line 111
# definition: test_boolean_integer_and_all — line 116
# definition: test_labeled_replay_known_limits — line 125
# variable: duplicates — line 127
# variable: events — line 127
# variable: detectors — line 128
# variable: labels — line 129
# variable: alerts — line 130
# variable: incomplete — line 130
# variable: samples — line 130
# variable: result — line 131
# variable: item — line 135
# definition: test_window_boundary_grouping_and_reset — line 144
# variable: events — line 146
# variable: i — line 146
# variable: t — line 146
# variable: _ — line 147
# variable: first — line 147
# variable: late — line 149
# variable: i — line 151
# variable: i — line 153
# variable: i — line 155
# variable: later — line 155
# definition: test_correlation_against_naive_oracle — line 168
# parameter: rows — line 168
# variable: events — line 170
# variable: host — line 172
# variable: i — line 172
# variable: seconds — line 172
# variable: user — line 172
# variable: config — line 174
# variable: expected — line 183
# variable: history — line 184
# parameter: item — line 185
# variable: event — line 185
# variable: candidates — line 186
# variable: item — line 188
# variable: before — line 192
# variable: item — line 192
# variable: after — line 193
# variable: alerts — line 197
# variable: alert — line 198
# variable: alert — line 200
# definition: test_bad_labels — line 206
# parameter: labels — line 206
# parameter: tmp_path — line 206
# variable: path — line 208
# definition: test_undefined_scores_and_empty_samples — line 214
# END CODE MAP

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from detection.engine import Correlation, detect, load_correlations, typed
from detection.evaluate import catalog, evaluate, load_labels, percentile, scores
from detection.events import load_events, normalize
from detection.io import Rejected, canonical
from detection.rules import Predicate, load_rules

ROOT = Path(__file__).resolve().parents[1]
RULES = load_rules(ROOT / "rules")
CONFIG = load_correlations(ROOT / "config/correlations.yml", RULES)


def auth(identity, seconds, user, host="lab-ws", ip="192.0.2.10"):
    """Construct an owned normalized fictional failed logon; never authenticate anywhere."""
    instant = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
    return normalize(
        {
            "id": identity,
            "timestamp": instant.isoformat(),
            "source": {"product": "windows", "service": "security"},
            "fields": {"EventID": 4625, "SourceIp": ip, "Hostname": host, "TargetUserName": user},
        }
    )


@pytest.mark.parametrize(
    "mode,value,expected",
    [
        ("exact", "ABCD", True),
        ("contains", "xxABCDxx", True),
        ("startswith", "ABCDxx", True),
        ("endswith", "xxABCD", True),
        ("contains", "other", False),
        ("exact", 1, False),
    ],
)
def test_string_modes(mode, value, expected):
    """String matching is literal and case-insensitive with strict types and missing-field nonmatches."""
    predicate = Predicate("Field", mode, ("abcd",), False)
    assert predicate.matches({"Field": value}) is expected
    assert not predicate.matches({})


def test_boolean_integer_and_all():
    """Boolean/int equality is not interchangeable; lists OR unless the all modifier is explicit."""
    assert not Predicate("Field", "exact", (True,), False).matches({"Field": 1})
    assert Predicate("Field", "exact", (1,), False).matches({"Field": 1})
    assert Predicate("Field", "contains", ("ab", "cd"), True).matches({"Field": "AB_CD"})
    assert not Predicate("Field", "contains", ("ab", "cd"), True).matches({"Field": "AB"})
    assert typed(True) != typed(1) != typed("1")


def test_labeled_replay_known_limits():
    """Regression contract includes known false positives/misses, not a misleading all-perfect accuracy gate."""
    events, duplicates = load_events(ROOT / "examples/events.jsonl")
    detectors = catalog(RULES, CONFIG)
    labels = load_labels(ROOT / "examples/labels.json", events, set(detectors))
    alerts, samples, incomplete = detect(events, RULES, CONFIG)
    result = evaluate(events, alerts, labels, detectors)
    assert duplicates == 1 and len(events) == 71 and incomplete == 1
    assert len(alerts) == 10 and len(samples) == len(events)
    assert result["micro"] == scores(7, 3, 2, 343)
    assert {(item["event"], item["outcome"]) for item in result["disagreements"]} == {
        ("clear-maintenance", "false_positive"),
        ("ps-admin", "false_positive"),
        ("cron-package", "false_positive"),
        ("ps-tab-blindspot", "false_negative"),
        ("cron-user-blindspot", "false_negative"),
    }


def test_window_boundary_grouping_and_reset():
    """Inclusive 60s threshold, host/IP separation, repeated users and second crossing are explicit."""
    events = [auth(f"a-{i}", t, f"user-{i}") for i, t in enumerate((0, 20, 40, 60))]
    first, _, _ = detect(list(reversed(events)), RULES, CONFIG)
    assert len(first) == 1 and first[0].event == "a-3" and first[0].span_seconds == 60
    late = events[:3] + [auth("late", 60.000001, "user-3")]
    assert not detect(late, RULES, CONFIG)[0]
    assert not detect([auth(f"repeat-{i}", i, "same") for i in range(5)], RULES, CONFIG)[0]
    assert not detect(
        [auth(f"host-{i}", i, f"user-{i}", host=f"host-{i}") for i in range(4)], RULES, CONFIG
    )[0]
    later = [auth(f"b-{i}", 120 + i, f"new-{i}") for i in range(4)]
    assert len(detect(events + later, RULES, CONFIG)[0]) == 2
    with pytest.raises(Rejected):
        detect(events + [events[0]], RULES, CONFIG)


@given(
    st.lists(
        st.tuples(st.integers(0, 180), st.integers(0, 8), st.integers(0, 2)),
        min_size=1,
        max_size=80,
    )
)
def test_correlation_against_naive_oracle(rows):
    """Property-test optimized deque/counter against independently recomputed inclusive windows."""
    events = [
        auth(f"event-{i:03d}", seconds, f"user-{user}", host=f"host-{host}")
        for i, (seconds, user, host) in enumerate(rows)
    ]
    config = Correlation(
        "property-burst",
        "Oracle case",
        CONFIG[0].base_rule,
        ("SourceIp", "Hostname"),
        "TargetUserName",
        4,
        60,
    )
    expected = []
    history = []
    for event in sorted(events, key=lambda item: (item.epoch_us, item.id)):
        candidates = [
            item
            for item in history
            if item.fields["Hostname"] == event.fields["Hostname"]
            and event.epoch_us - item.epoch_us <= 60_000_000
        ]
        before = {item.fields["TargetUserName"] for item in candidates}
        after = before | {event.fields["TargetUserName"]}
        if len(before) < 4 <= len(after):
            expected.append(event.id)
        history.append(event)
    alerts = detect(events, RULES, [config])[0]
    assert [alert.event for alert in alerts] == expected
    assert detect(list(reversed(events)), RULES, [config])[0] == alerts
    assert all(len(alert.evidence) == 4 for alert in alerts)


@pytest.mark.parametrize(
    "labels", [{}, {"one": ["unknown"]}, {"one": ["valid", "valid"]}, {"one": None}, {"one": [[1]]}]
)
def test_bad_labels(tmp_path, labels):
    """Evaluation requires exact coverage and known nonduplicate detector identities."""
    path = tmp_path / "labels.json"
    path.write_bytes(canonical(labels))
    with pytest.raises(Rejected):
        load_labels(path, [auth("one", 0, "user")], {"valid"})


def test_undefined_scores_and_empty_samples():
    """Undefined ratios are null; nearest-rank percentiles and event-pair denominators are explicit."""
    assert scores(0, 0, 0, 0)["f1"] is None
    assert percentile([], 0.95) is None
    assert percentile([4, 1, 2, 3], 0.95) == 4
    assert scores(1, 1, 1, 7)["false_positive_rate"] == 0.125
