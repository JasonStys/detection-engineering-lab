"""Maintain an exhaustive README summary of tracked files, excluding ignored private outputs. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 30
# variable: BEGIN — line 31
# variable: END — line 32
# variable: SPECIAL — line 33
# definition: description — line 58
# parameter: path — line 58
# variable: content — line 62
# variable: summary — line 64
# variable: line — line 73
# definition: main — line 81
# variable: parser — line 83
# variable: args — line 85
# variable: files — line 86
# variable: rows — line 94
# variable: path — line 96
# variable: path — line 98
# variable: original — line 99
# variable: first — line 100
# variable: last — line 100
# variable: expected — line 101
# END CODE MAP

import argparse
import ast
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BEGIN = "<!-- BEGIN FILE GUIDE -->"
END = "<!-- END FILE GUIDE -->"
SPECIAL = {
    "docs/reports/project-guide.docx": "Reviewed Word project guide bound to the documented source revision.",
    "docs/reports/publications.json": "Exact Office digests, visual review scopes and immutable source baselines.",
    ".gitattributes": "Portable LF text and binary database handling.",
    ".gitignore": "Excludes environments, databases, keys, caches and local evidence.",
    "LICENSE": "MIT license for authored code and rules.",
    "pyproject.toml": "Runtime metadata and strict lint/type/test/coverage gates.",
    "requirements-dev.in": "Reviewed direct development dependencies.",
    "requirements-dev.lock": "Complete hash-locked development dependency graph.",
    "requirements-runtime.in": "Minimal reviewed replay runtime dependency.",
    "requirements-runtime.lock": "Hash-locked portable runtime installation.",
    "tools.lock.json": "Official scanner versions, URLs and verified archive digests.",
    "config/sigma-schema.json": "Pinned public-domain official Sigma detection rule schema.",
    "config/correlations.yml": "Distinct-user threshold, rolling window and source/host grouping.",
    "examples/events.jsonl": "Fictional mixed-source input with disorder and one exact duplicate; no labels.",
    "examples/labels.json": "Independently authored benign/positive truth, separate from features.",
    "docs/reports/replay.json": "Measured synthetic replay counts, disagreements, timings and snapshot hashes.",
    "docs/reports/demo.html": "Offline synthetic demonstration report with escaped data and hash-authorized CSS.",
    "detection/schema.sql": "STRICT indexed evidence tables and foreign-key constraints.",
    "scripts/validate.sh": "Fail-fast cross-platform quality, semantic and benchmark checks.",
    ".github/workflows/ci.yml": "Four OS/Python validation lanes and unsuppressed security gates; no artifact/cache uploads.",
    ".github/workflows/codeql.yml": "Least-privilege Python security-extended CodeQL analysis.",
}


def description(path: str) -> str:
    """Require a meaningful summary for every tracked file; unknown formats fail instead of being omitted."""
    if path in SPECIAL:
        return SPECIAL[path]
    content = (ROOT / path).read_text(encoding="utf-8")
    if path.endswith(".py"):
        summary = ast.get_docstring(ast.parse(content))
        if summary:
            return summary.splitlines()[0]
    elif path.endswith(".md"):
        return content.splitlines()[0].lstrip("# ") + "."
    elif path.startswith("rules/") and path.endswith(".yml"):
        return (
            next(
                line.removeprefix("title: ")
                for line in content.splitlines()
                if line.startswith("title: ")
            )
            + "; experimental authored Sigma rule."
        )
    raise ValueError(f"Missing tracked-file summary: {path}")


def main() -> int:
    """Generate or check a git-backed file index; only README's marked generated section is modified."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    files = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        .decode()
        .rstrip("\0")
        .split("\0")
    )
    if not files or files == [""]:
        raise ValueError("Stage intended source files before generating the file guide")
    rows = ["| File | Purpose |", "| --- | --- |"]
    rows.extend(
        f"| [{path}]({path}) | {description(path).replace('|', '/')} |" for path in sorted(files)
    )
    path = ROOT / "README.md"
    original = path.read_text(encoding="utf-8")
    first, last = original.index(BEGIN) + len(BEGIN), original.index(END)
    expected = original[:first] + "\n\n" + "\n".join(rows) + "\n\n" + original[last:]
    if args.check:
        if expected != original:
            raise SystemExit("README file guide is stale; stage files and regenerate")
    else:
        path.write_text(expected, encoding="utf-8", newline="\n")
    print(f"README inventory current: {len(files)} tracked files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
