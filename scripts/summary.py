"""Small CI job summaries without uploading Actions artifacts or sensitive telemetry. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: main — line 20
# variable: lines — line 22
# variable: path — line 27
# variable: totals — line 29
# variable: path — line 31
# variable: suite — line 34
# variable: summary — line 40
# variable: destination — line 42
# variable: stream — line 43
# END CODE MAP

import json
import os
from pathlib import Path
from xml.etree import ElementTree


def main() -> int:
    """Summarize trusted pytest/coverage output; missing files are reported, not falsely called successful."""
    lines = [
        "## Detection lab validation",
        "",
        "Synthetic telemetry only. No artifact/cache uploads.",
    ]
    path = Path("out/coverage.json")
    if path.is_file():
        totals = json.loads(path.read_text())["totals"]
        lines.append(f"Branch-inclusive coverage: {totals['percent_covered']:.2f}%")
    path = Path("out/junit.xml")
    if path.is_file():
        # This file comes only from pytest in this job, not from an uploaded/user XML document.
        suite = ElementTree.parse(path).getroot()[0]
        lines.append(
            f"Tests={suite.get('tests')}, failures={suite.get('failures')}, errors={suite.get('errors')}, skipped={suite.get('skipped')}"
        )
    else:
        lines.append("Test results unavailable: inspect earlier failed steps.")
    summary = "\n".join(lines) + "\n"
    print(summary)
    if destination := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(destination).open("a", encoding="utf-8") as stream:
            stream.write(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
