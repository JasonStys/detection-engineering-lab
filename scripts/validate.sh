#!/usr/bin/env bash
# Jason Stys: fail-fast cross-platform quality gate. No functions, secrets or shell variables.
# Steps: style/types, symbol maps, generated fixtures, official Sigma, tests, benchmark (lines below).
set -euo pipefail
python -m ruff check .
python -m ruff format --check .
python -m mypy
python scripts/code_map.py --check
python scripts/file_guide.py --check
python scripts/scenarios.py --check
python scripts/validate_rules.py
python -m pytest --cov=detection --cov-report=term-missing --cov-report=json:out/coverage.json --junitxml=out/junit.xml
python scripts/benchmark.py
