# Detection Engineering Lab handbook

By Jason Stys.

Evaluate defensive detections against bounded recorded event snapshots. Compare rule revisions and explain analyst triage decisions with reproducible evidence instead of changing live collectors or blocking hosts.

Add hash-bound analyst dispositions and same-event rule/label comparisons with immutable alert evidence and inert HTML review.

Connects rule changes to reviewable outcomes without rewriting original detections or hiding uncertainty.

## Read the documentation

| Edition | Audience and contents |
| --- | --- |
| [project-guide.docx](reports/project-guide.docx) | User and developer guide: purpose, current usage, design, boundaries and source references. |

The editable Markdown remains the maintenance source. The Word files are readable editions. See [publication identities and review](reports/publications.json) and the [documentation refresh record](reports/documentation-refresh-2026-11-09.md).

## Current usage and help

[README quick start](../README.md) is the entry point. Use the project-specific guides below before changing inputs, operating modes or deployment assumptions.

### Usage and operations

- [runbook](runbook.md)
- [workflows](workflows.md)

### Design and contracts

- [architecture](architecture.md)
- [contracts](contracts.md)
- [research](research.md)
- [threat model](threat-model.md)

### Security and validation

- [testing](testing.md)

## Historical results and reproduction

The reviewed source is [`7629605841823ebc7a56317ec2addac6d5ab3e38`](https://github.com/JasonStys/detection-engineering-lab/tree/7629605841823ebc7a56317ec2addac6d5ab3e38). The observed functional workflow baseline is `7629605841823ebc7a56317ec2addac6d5ab3e38`; those observations are recorded at `2026-11-10T05:25:40.628667+00:00`. They do not certify an unrun later revision.

- [Detailed recorded validation](reports/workflows-2026-11-09.md)
- [Current Actions](https://github.com/JasonStys/detection-engineering-lab/actions) records later integration checks separately.
- Preserve dated measurements and follow the existing testing guide to reproduce them; a test-source inventory alone does not establish execution.

## Practical boundaries

- Analyst names and dispositions are local assertions, not authenticated reviewers or incident verdicts.
- Supplied local event/rule/label snapshots are not authenticated acquisition or publisher attestation.
- Comparisons preserve original detections; they do not prove that an undetected event is benign.

## Maintaining these editions

Update the editable usage/design/test documents first. Rebuild and visually review every Word page and workbook tab before replacing an edition; verify the exact binary digests and evidence source in publications.json. Keep account data, logs with secrets, installed-app state and private test stores out of documentation. Source and release assets retain their existing security and licensing boundaries.
