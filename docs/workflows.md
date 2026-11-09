# Rule comparison and analyst review

Created by Jason Stys. These offline workflows consume supplied replay reports and
produce new JSON/HTML bundles; they never edit the original replay, labels, raw
events or SQLite evidence. A report hash binds the selected bytes, not publisher
authenticity. Keep reports and analyst reasons in private owner-controlled storage.

## Rule author: compare a candidate

Run the same telemetry/labels through a baseline and candidate rule set, using a new
output directory for each. Then compare their reports:

```text
python -m detection compare --before out/baseline/report.json --after out/candidate/report.json --out out/rule-review
```

The normalized event and label fingerprints must match exactly. Added, removed and
persistent `(detector,event)` pairs are explicit, with detector additions/removals,
rule/correlation snapshot changes and the original evaluations side by side.
An alert disappearing does not prove an incident resolved. Unlabeled scan reports
remain unevaluated; comparison never creates accuracy labels.

## Analyst: document a disposition

```text
python -m detection triage-template --report out/baseline/report.json --out out/review-draft
```

Copy `out/review-draft/review.json` to your own private decisions file. Its
`available_alerts` list identifies exact emitted pairs. Add entries to `decisions`:

```json
{"detector":"exact detector ID","event":"exact event ID","disposition":"investigate","analyst":"reviewer-one","reason":"Correlate the fictional service change with this sign-in burst"}
```

Keep the supplied `schema` and `report_sha256`. Supported dispositions are
`investigate`, `benign`, `confirmed-signal` and `needs-context`.

```text
python -m detection triage --report out/baseline/report.json --decisions out/my-decisions.json --out out/analyst-review
```

Open the new `review.html`; download/use `review.json` locally. Partial review is
allowed and unreviewed alerts remain explicit. A benign/confirmed assertion does
not rewrite ground truth or alter precision/recall. Names are local assertions,
not authenticated reviewer identities or an independent incident verdict.

Stale report hashes, unknown/duplicate alert pairs, unsupported dispositions, missing
reasons, invalid report fingerprints and reused output directories are rejected.
Inputs are capped at 32 MiB and 300,000 alert identities. Comparison is O(A log A)
with sets/sorting, and triage O(A + D) plus deterministic output sorting. Like the
existing replay, this is not a live SIEM, response agent or multi-user service.
