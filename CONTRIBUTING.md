# Contributing

Use owned/synthetic data, no active target interactions. Add independent positive, benign, edge and evasion cases when changing detections. Do not rewrite truth to hide misses. Preserve documented correlation and schema semantics or version the contract.

Install hash-locked development dependencies; run [validation commands](docs/testing.md). Maintain function/class contracts and regenerate AST line headers after formatting. Stage new files and refresh the README file guide. Keep all documentation and measured evidence in `docs/`. Never include operational logs, private accounts, key material or unreviewed generated binary artifacts.

Explain changes, test outcomes, limitations and security trade-offs in your pull request. Untrusted PR jobs have no deployment credentials and cannot modify repository source. A maintainer must inspect code, CodeQL findings and actual CI status before merging. Contact/author: [Jason Stys](https://github.com/JasonStys).
