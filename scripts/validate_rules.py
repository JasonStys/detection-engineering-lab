"""Validate authored Sigma against pinned official schema and stricter lab grammar. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 18
# definition: main — line 22
# variable: local — line 27
# variable: content — line 28
# variable: schema — line 34
# variable: validator — line 36
# variable: path — line 37
# END CODE MAP

import hashlib
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> int:
    """Check official schema offline; separately validate semantics of the supported subset."""
    from detection.io import json_value, read_bytes, yaml_value
    from detection.rules import load_rules

    local = load_rules(ROOT / "rules")
    content = read_bytes(ROOT / "config/sigma-schema.json", 64 * 1024)
    if (
        hashlib.sha256(content).hexdigest()
        != "eb95ddb1bc2503145a6e84511e38990f74fe9a843067065a23d3763457fb2d95"
    ):
        raise ValueError("Pinned official schema drift; review upstream before updating")
    schema = json_value(content)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for path in sorted((ROOT / "rules").glob("*.yml")):
        validator.validate(yaml_value(read_bytes(path, 64 * 1024)))
    print(f"Official Sigma schema and constrained compiler accepted {len(local)} rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
