# Primary-source research and provenance

Reviewed 2026-10-13. Sources informed implementation; links are references, not instructions to execute example attacker commands.

| Official source | Applied decision |
| --- | --- |
| [Sigma detection specification v2.1.0](https://github.com/SigmaHQ/sigma-specification/blob/ba9251aa834b11a70dbf80836b453dba99c5159e/specification/sigma-rules-specification.md) | Source boundaries, case-insensitive literal values, map AND/list OR, explicit filters, metadata and constrained subset |
| [Official schema](https://github.com/SigmaHQ/sigma-specification/blob/ba9251aa834b11a70dbf80836b453dba99c5159e/json-schema/sigma-detection-rule-schema.json) | Offline draft-2020-12 validation of authored rules, separate from semantic testing |
| [Sigma specification license](https://github.com/SigmaHQ/sigma-specification/blob/ba9251aa834b11a70dbf80836b453dba99c5159e/LICENSE) | Vendored schema is public domain; attribution and exact commit retained |
| [Microsoft security event 1102](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102) | Windows security audit log clearing candidate |
| [AWS CloudTrail guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html) | Cloud logging context; explicit normalized adapter contract instead of pretending to ingest every native record |
| [MITRE Clear Windows Event Logs T1685.005](https://attack.mitre.org/techniques/T1685/005/) | Current log-clearing mapping, replacing legacy T1070.001 reference |
| [MITRE Disable or Modify Cloud Log T1685.002](https://attack.mitre.org/techniques/T1685/002/) | Current cloud logging mapping, replacing legacy T1562.008 reference |
| [MITRE PowerShell T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Narrow lexical rule and documented wider technique blind spots |
| [MITRE Cron T1053.003](https://attack.mitre.org/techniques/T1053/003/) | System vs user cron coverage distinction |
| [MITRE Brute Force T1110](https://attack.mitre.org/techniques/T1110/) | Failed-logon burst association; no adversary attribution or intent verdict |
| [Python SQLite documentation](https://docs.python.org/3.12/library/sqlite3.html) | Parameter binding, explicit transactions and connection lifecycle |
| [GitHub Actions security guidance](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions) | Least privilege, full action SHAs, no persisted checkout credentials or privileged untrusted PR execution |
| [NIST SSDF SP800-218](https://csrc.nist.gov/pubs/sp/800/218/final) | Documented requirements, verification and vulnerability response practices; no certification claim |
| [DiskCache advisory PYSEC-2026-2447](https://osv.dev/vulnerability/PYSEC-2026-2447) | Remove initial pySigma dependency chain instead of suppressing an unfixed unsafe-pickle advisory |

Vendored `config/sigma-schema.json` originates from SigmaHQ/sigma-specification commit `ba9251aa834b11a70dbf80836b453dba99c5159e`, blob `018af59a36bacc4b986676ec888fb2cb1a971736`. Saved UTF-8 LF SHA256: `eb95ddb1bc2503145a6e84511e38990f74fe9a843067065a23d3763457fb2d95`. The validator enforces that checksum. Public-domain content is separate from this project's authored MIT code. No Sigma community rule set was copied; all five rules are authored for this lab. No pySigma runtime/compiler backend compatibility is claimed.

Official scanner releases and archive digests are pinned in `tools.lock.json`. Checkout/setup-python/CodeQL references use complete reviewed official commit IDs. Hash pinning does not certify safety; current audits and semantic tests are still required.

Government/military relevance is demonstrated through defensive evidence, reproducible validation, documented trust boundaries and human triage. Enterprise relevance includes DevSecOps gates, false-positive reasoning and runbooks. These are conceptual engineering demonstrations, not a FedRAMP authorization, ATO, FIPS claim or compliance audit.
