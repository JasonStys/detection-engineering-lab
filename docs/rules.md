# Rules, scenarios and triage

All rules are authored by Jason Stys and marked experimental. Sigma is a portable description format; this lab executes only its documented subset, not arbitrary community rules.

| Rule / detector | Signals | Current ATT&CK mapping | Important limits |
| --- | --- | --- | --- |
| `windows_log_clear.yml` (…0001) | Security EventID integer 1102 | T1685.005 | Administrative clearing matches; clearing other logs or missing telemetry can evade it |
| `windows_powershell.yml` (…0002) | powershell/pwsh image suffix AND spaced `-enc`/`-encodedcommand` literal | T1059.001 | Legitimate encoded scripts match; tabs, other switch abbreviations, host APIs and nonmatching image paths evade |
| `cloud_logging.yml` (…0003) | StopLogging/DeleteTrail unless explicit AccessDenied | T1685.002 | Authorized maintenance matches; missing/other error codes do **not** prove a successful change; other APIs/providers unsupported |
| `linux_cron.yml` (…0004) | write plus /etc/cron. path prefix | T1053.003 | Package updates match; per-user spool/crontab and alternate paths evade; case-insensitive value matching can overmatch Linux paths |
| `windows_auth_failure.yml` (…0005) + `auth-burst` | 4625 base; four users/IP/host/60s | T1110 | Shared gateway users and approved tests can match; distributed/slow/same-user attempts evade; authentication string field case is not normalized |

Source telemetry indicates behavior, not intent. ATT&CK mappings are educational associations, not proof that an adversary or named group caused an event. Current official pages reviewed 2026-10-13 moved legacy log-clearing/cloud-log IDs into T1685; see [research](research.md) for references.

## Scenario ledger

`scripts/scenarios.py` creates the corpus independently from detection. 72 input rows, 71 unique events, one identical duplicate. Reverse chronological input tests stable sorting. Forty background logon successes provide negatives without pretending a representative base rate. Fictional tenant/host names and RFC documentation IP ranges contain no real customer or attack traffic.

- **7 expected hits:** suspicious audit clear, two encoded argument cases (including mixed case), two cloud logging candidates, system cron write, four-user burst crossing exactly at 60s.
- **3 expected false positives:** legitimate audit maintenance, legitimate encoded administration, package cron configuration write. Labels are benign despite matching rule features.
- **2 expected misses:** tab-delimited encoded switch and per-user cron spool write. Those behaviors belong to the rule's intended wider technique coverage but are not covered by its narrow lexical pattern.
- Other negatives exercise denied cloud calls, normal trail reads, cron reads, repeated-user password typos, slow distinct-user failures, wrong source and HTML/SQL-looking strings kept as inert data.
- One matched failure lacks group fields; its candidate is skipped and counted explicitly. Duplicate processing cannot artificially push a correlation over threshold.

The regression test checks these **known** outcomes, including false positives/misses. Passing tests means implemented semantics match documented expectations, not comprehensive coverage. The tiny authored corpus can overfit; do not present its score as detection efficacy in operational environments.

## Human triage

1. Read the report's quality counters and per-rule disagreements; do not prioritize by level alone.
2. Locate the crossing event and all proof identities in the local database. Check source authenticity and timestamps outside this lab.
3. Review surrounding activity, change tickets and approved work using your organization's authorized tools. Missing ErrorCode is uncertainty, not success proof.
4. Record confirmed-benign/uncertain/confirmed-malicious reasoning separately. Never change ground truth solely to improve this lab's score.
5. Tune only with documented rationale and new independent positive, negative and evasion cases. This lab has no autonomous blocking, credential capture or active response.
