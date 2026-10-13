# Input and output contracts

## Normalized event v1

Each UTF-8 JSONL row has exactly `id`, `timestamp`, `source`, `fields`. Example:

```json
{"id":"fictional-1","timestamp":"2026-01-01T00:00:00Z","source":{"product":"windows","service":"security"},"fields":{"EventID":4625,"Hostname":"lab-ws","SourceIp":"192.0.2.10","TargetUserName":"fictional-user"}}
```

IDs: ASCII letters/digits/underscore/hyphen, 1–64 chars. Times: ISO date/time with Z or numeric offset, 0–6 fractional digits, UTC-normalized year 2000–2100. Invalid dates, overflow and naive time reject. Ordering is `(UTC integer microseconds, id)`; tied times therefore have deterministic ID-based crossing semantics, not inferred causal order.

Source pairs: `windows/security`, `windows/process_creation`, `linux/auditd`, `aws/cloudtrail`. Fields: 1–32 distinct ASCII names, letter first then letters/digits/underscore up to 64 chars. Values: string (≤4096 chars, no NUL), signed 64-bit integer or boolean. No float/null/list/object. EventID integers and strings differ; adapters must normalize types intentionally. Source/field names are case-sensitive; rule string **values** are case-insensitive. Missing fields do not match positive predicates. Missing/empty correlation group or distinct fields skip that candidate and increment a quality counter, never produce invented users.

Identical duplicate IDs after normalization are ignored. Same ID with different content rejects the whole batch. Blank rows, invalid UTF-8, duplicate JSON keys, non-finite numbers and resource violations reject before export. Labels in the envelope reject. Extra scalar fields are stored, so **a normalization contract is not a secret/PII scrubber**.

## Rule grammar

Authored rules include canonical UUIDv4, bounded title/description/author/date, experimental status, MIT license, explicit source, nonempty false positives, severity and ATT&CK tags. Conditions are only `selection` or `selection and not filter`. Selection/filter maps are AND; scalar lists are OR unless `|all`. Modifiers: `contains`, `startswith`, `endswith`, optionally followed by `all`, or exact `all`. Literals only: no wildcards, regex, arbitrary boolean expressions, aliases, YAML merges, unsafe tags or automatic backend conversion. Empty predicates and repeated fields reject. YAML files ≤64KiB, nesting ≤8, one document.

`config/correlations.yml` is **lab-specific schema version 1**, not Sigma correlation YAML. Every item has exact id/title/base_rule/group_by/distinct/threshold/window_seconds. Base-rule matches feed correlations and are not emitted standalone. No per-user allowlists or trust inferred from a username.

## Correlation semantics

For each matching base event, independently group by exact typed SourceIp and Hostname. Expire candidates strictly older than `current time −60s`; a candidate exactly 60s old counts. Count distinct exact typed TargetUserName values, not attempts. Emit when the count crosses from below four to at least four **after expiration**. While it remains above threshold there are no repeat alerts. Once expiration drops it below threshold, another crossing can alert. No claim that a new attack is thereby identified; event timestamps can be forged and batches omit outside-window history.

Proof stores a recent representative event per distinct value, not all attempts. `span_seconds` is crossing event minus earliest proof event. It is **not end-to-end detection latency, incident response time or processing latency**. Per-event timing samples measure detector cost separately. Multiple correlations increment incomplete candidates independently.

## Independent evaluation

`labels.json`: exactly one list per unique event ID; list contains known emitted detector IDs without duplicates. Negatives are `[]`. Unknown/missing/extra identities or labels reject. Truth for a correlation is attached only to the chosen crossing event, not every candidate. Labels are manually authored scenario expectations, not complete real-world ground truth.

Universe: unique events × emitted detectors (71×5=355 here). TP/FP/FN/TN have explicit denominators. Precision=TP/(TP+FP); recall=TP/(TP+FN); F1=2TP/(2TP+FP+FN); FPR=FP/(FP+TN). Micro sums counts across detectors. Undefined denominators yield JSON null. TN can be inflated by unrelated-source negatives; inspect per-rule counts and realistic subsets, not just aggregate FPR. `scan` never emits an accuracy estimate.

## Evidence and errors

`report.json`: schema version, author, counts, detectors, alert metadata, optional evaluation, normalized-snapshot SHA256s and measured timings. `report.html`: static escaped view with local hash-authorized CSS and no scripts. `evidence.sqlite3`: raw normalized fields in `event`, candidates in `alert`, whole report in `run`. Foreign keys and integrity checks are enabled. Values are bound SQL parameters; only the trusted bundled schema executes as SQL.

Destination must be nonexistent under an existing owner-controlled parent with no linked ancestors. No overwrite. A pre-publish validation/write failure leaves no destination; a failure during final moves can leave a partial new directory, which the caller inspects. This is not an OS security sandbox or defense against another privileged user racing/modifying a parent. Generic OS/SQLite error messages hide sensitive contents. CLI exits 0 on success and 2 on usage/input/I/O failures. A successful replay does **not** mean zero detection misses; inspect evaluation.
