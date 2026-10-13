"""Development-gate drift, schema verification and code-map idempotence. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 30
# definition: test_official_schema — line 33
# definition: test_schema_checksum_drift — line 38
# definition: changed — line 42
# parameter: limit — line 42
# parameter: path — line 42
# definition: test_generated_data — line 57
# variable: content — line 59
# variable: name — line 59
# definition: test_exact_code_map — line 63
# variable: source — line 65
# variable: result — line 66
# variable: tree — line 68
# variable: definition — line 69
# variable: node — line 69
# END CODE MAP

import ast
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.code_map import mapped
from scripts.scenarios import files
from scripts.validate_rules import main as validate_rules

ROOT = Path(__file__).resolve().parents[1]


def test_official_schema():
    """All authored rules pass the pinned upstream draft-2020-12 schema and constrained compiler."""
    assert validate_rules() == 0


def test_schema_checksum_drift():
    """Schema provenance changes require deliberate review, not accidental acceptance of modified metadata."""
    from detection.io import read_bytes

    def changed(path, limit):
        """Mutate only the vendored schema bytes while preserving rule input for this negative test."""
        return (
            read_bytes(path, limit) + b" "
            if path.name == "sigma-schema.json"
            else read_bytes(path, limit)
        )

    with (
        patch("detection.io.read_bytes", side_effect=changed),
        pytest.raises(ValueError, match="schema drift"),
    ):
        validate_rules()


def test_generated_data():
    """Stored synthetic events and independently authored labels reproduce byte-for-byte."""
    for name, content in files().items():
        assert (ROOT / "examples" / name).read_bytes() == content


def test_exact_code_map():
    """Generated headers stabilize and point at actual AST definition and variable line numbers."""
    source = '"""Example."""\nvalue = 1\n\ndef example(argument):\n    """Contract."""\n    local = argument\n    return local\n'
    result = mapped(source)
    assert mapped(result) == result
    tree = ast.parse(result)
    definition = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef))
    assert f"# definition: example — line {definition.lineno}" in result
    assert "# parameter: argument — line" in result
