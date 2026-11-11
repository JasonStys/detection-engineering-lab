"""Actual opened-device and POSIX regular-to-FIFO replacement regressions for bounded readers. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: MODULE — line 33
# variable: FUNCTION — line 34
# variable: HAS_LIMIT — line 35
# definition: test_opened_device_is_refused_and_its_descriptor_is_closed — line 38
# parameter: monkeypatch — line 38
# parameter: tmp_path — line 38
# variable: module — line 40
# variable: target — line 41
# variable: original_open — line 43
# variable: descriptors — line 44
# definition: swapped — line 46
# parameter: args — line 46
# parameter: flags — line 46
# parameter: kwargs — line 46
# parameter: path — line 46
# variable: descriptor — line 48
# definition: test_regular_path_replaced_by_real_fifo_cannot_block_before_fstat — line 68
# parameter: tmp_path — line 68
# variable: script — line 70
# variable: completed — line 93
# END CODE MAP

import importlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

MODULE = "detection.io"
FUNCTION = "read_bytes"
HAS_LIMIT = True


def test_opened_device_is_refused_and_its_descriptor_is_closed(tmp_path, monkeypatch):
    """A preceding regular-file check cannot authorize the different actual opened NUL/devnull descriptor."""
    module = importlib.import_module(MODULE)
    target = tmp_path / "input.json"
    target.write_text("{}", encoding="utf-8")
    original_open = os.open
    descriptors = []

    def swapped(path, flags, *args, **kwargs):
        """Open the real harmless OS null device only at this owned target's acquisition boundary."""
        descriptor = original_open(
            os.devnull if Path(path) == target else path, flags, *args, **kwargs
        )
        if Path(path) == target:
            descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(module.os, "open", swapped)
    with pytest.raises(ValueError):
        getattr(module, FUNCTION)(target, 32) if HAS_LIMIT else getattr(module, FUNCTION)(target)
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    assert target.read_text(encoding="utf-8") == "{}"


@pytest.mark.skipif(
    os.name != "posix",
    reason="Actual no-writer FIFO swap requires POSIX; Windows still tests real opened NUL rejection",
)
def test_regular_path_replaced_by_real_fifo_cannot_block_before_fstat(tmp_path):
    """A real no-writer FIFO replacement must fail closed in a bounded child instead of hanging at open."""
    script = r"""
import importlib, os, pathlib, sys
module = importlib.import_module(sys.argv[1])
reader = getattr(module, sys.argv[2])
target = pathlib.Path(sys.argv[3]) / "regular-input.json"
target.write_text("{}", encoding="utf-8")
original_open = os.open
changed = False
def swap(path, flags, *args, **kwargs):
    global changed
    if pathlib.Path(path) == target and not changed:
        changed = True
        target.unlink()
        os.mkfifo(target)
    return original_open(path, flags, *args, **kwargs)
module.os.open = swap
try:
    reader(target, 32) if sys.argv[4] == "1" else reader(target)
except ValueError:
    assert changed and target.is_fifo()
else:
    raise AssertionError("A replaced FIFO was treated as regular JSON evidence")
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, MODULE, FUNCTION, str(tmp_path), "1" if HAS_LIMIT else "0"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )
    assert completed.returncode == 0, "Owned FIFO child failed its closed-input assertion"
