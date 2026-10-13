# Threat model and security review

Protected assets: integrity of local evidence, confidentiality of user-supplied authorized logs, safe parser execution and CI token boundaries. Threat inputs: malformed/tampered telemetry, rule/config files, misleading labels and output path substitution. Trust: reviewed source/schema, owner-controlled checkout and input/output directories, OS/Python/SQLite and pinned dependency providers. No network targets are in scope.

| Threat | Implemented defense and tests | Residual risk |
| --- | --- | --- |
| YAML code execution/alias amplification | SafeLoader, no aliases/anchors/merge keys, duplicate-key and depth/file-size limits | Parser defects; libraries require updates |
| Input ambiguity/label leakage | Exact envelope, strict types, duplicate JSON rejection, labels separate from immutable features | Forged source values or incorrect labels cannot be authenticated |
| Memory/time denial of service | Input, row, count, field, rule/correlation/threshold limits; measured bounded benchmark | Batch state can still be large at maximum combinations; benchmark is one synthetic shape |
| SQL injection | Trusted local schema, parameterized values, STRICT tables, foreign-key/integrity checks; hostile-string tests | Local database is not encrypted or a multi-user service |
| HTML injection/tracking | All data escaped; no scripts/forms/remote resources; CSS allowed only by fixed hash; XSS tests | Clicking author links navigates to external services at the viewer's choice |
| Accidental output destruction | New destination required, links refused, temporary staging, overwrite/failure/sentinel tests | Final three moves are not atomic; privileged/local-owner path races are outside scope |
| Supply chain/secrets | Hash-locked packages, full action SHAs, verified official scanner archives, scoped permissions, no checkout credentials persisted, CodeQL | Hashes establish identity, not absence of defects; no security tool proves universal safety |

Developer review found and fixed tuple/list JSON round-trip inconsistency and checked exponent-overflow JSON rejection. The initial pySigma dev dependency introduced DiskCache advisory PYSEC-2026-2447/CVE-2025-69872 without a published fix; we **removed that dependency**, used pinned official schema validation and rebuilt/audited the lock. No advisory suppression. Some unrelated shared dev dependencies remain because mypy or pip-audit need them; `pip check` verifies consistency.

Regular-file checks refuse final symlinks/junctions; POSIX O_NOFOLLOW helps final-file races. Output ancestors are checked, but there is no claim of secure operation in a hostile shared directory. Use your own trusted workspace. POSIX output directory mode is 0700; Windows uses inherited account ACLs, not bespoke access controls. Protect the parent yourself. Temporary directories are cleaned after owned staging; no arbitrary user directory is recursively removed.

No authentication, daemon, remote telemetry collection, online threat intelligence, live scanning, exploit/payload execution or production SOC integration. The names `scan` and “encoded” describe offline data processing, not scanning computers or decoding/running commands. Network use is confined to developer setup/security feeds and optional explicit clicks on author links.

Never commit real resumes, identifiers, credentials, API keys or operational logs; ignored databases/output directories are defense-in-depth, not a guarantee. Public checked-in reports are synthetic only. Report vulnerabilities via [SECURITY.md](../SECURITY.md).
