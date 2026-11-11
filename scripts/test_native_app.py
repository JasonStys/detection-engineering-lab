"""Run the real frozen workbench twice with an owned synthetic profile and exact bundle persistence. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 55
# variable: PRODUCT — line 56
# variable: EXECUTABLE — line 57
# variable: VERSION — line 58
# definition: gone — line 61
# parameter: pid — line 61
# variable: kernel — line 65
# variable: handle — line 71
# definition: launch — line 82
# parameter: executable — line 83
# parameter: metadata — line 83
# parameter: output — line 83
# parameter: profile — line 83
# parameter: reopen — line 83
# variable: arguments — line 86
# variable: environment — line 89
# variable: key — line 90
# variable: child — line 93
# variable: code — line 100
# variable: path — line 101
# variable: stream — line 102
# variable: payload — line 103
# variable: receipt — line 106
# definition: main — line 121
# variable: executable — line 125
# variable: metadata — line 126
# variable: source — line 127
# variable: stream — line 136
# variable: digest — line 137
# variable: destination — line 142
# variable: temporary — line 144
# variable: scratch — line 145
# variable: profile — line 149
# variable: first — line 150
# variable: second — line 151
# variable: path — line 155
# variable: summary — line 157
# END CODE MAP

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PRODUCT = "detection-engineering-lab"
EXECUTABLE = "DetectionEngineeringLab.exe"
VERSION = "1.1.0"


def gone(pid: int) -> bool:
    """Query only this known child PID on Windows; never use Python os.kill for a zero-signal probe."""
    if sys.platform != "win32":
        raise OSError("owned Windows process probe requires Windows")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_uint]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    kernel.WaitForSingleObject.restype = ctypes.c_uint
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.OpenProcess(0x1000 | 0x100000, False, pid)
    if not handle:
        if ctypes.get_last_error() == 87:
            return True
        raise OSError("owned child state unavailable")
    try:
        return kernel.WaitForSingleObject(handle, 0) == 0
    finally:
        kernel.CloseHandle(handle)


def launch(
    executable: Path, profile: Path, output: Path, metadata: dict[str, Any], *, reopen: bool
) -> dict[str, Any]:
    """Launch the actual EXE without Python/Node/provider environment and require its frozen child to exit."""
    arguments = [str(executable), "--profile", str(profile), "--acceptance-output", str(output)]
    if reopen:
        arguments.append("--acceptance-reopen")
    environment = {
        key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP") if key in os.environ
    }
    environment["PATH"] = str(Path(os.environ.get("SYSTEMROOT", "C:/Windows")) / "System32")
    child = subprocess.Popen(
        arguments,
        cwd=profile.parent,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    code = child.wait(timeout=80)
    path = output / "acceptance.json"
    with path.open("rb") as stream:
        payload = stream.read(65537)
    if len(payload) > 65536:
        raise AssertionError("native receipt exceeds byte limit")
    receipt = json.loads(payload)
    assert code == 0 and receipt["passed"] is True and receipt["synthetic"] is True
    assert receipt["product"] == PRODUCT and receipt["version"] == VERSION
    assert receipt["python_version"] == "3.14.10"
    assert receipt["python_dll_sha256"] == metadata["resources"]["python314.dll"]
    assert (
        receipt["source"] == metadata["source"]
        and receipt["source_dirty"] is metadata["source_dirty"]
    )
    assert type(receipt["pid"]) is int and receipt["pid"] > 0 and receipt["parent_pid"] == child.pid
    assert gone(receipt["pid"]), "frozen service/mainloop survived the owned bootloader"
    assert receipt["reopen"] is reopen
    return receipt


def main() -> None:
    """Verify byte/source identity, two real native launches and identical saved bundles; never install/publish."""
    if os.name != "nt":
        raise RuntimeError("frozen application acceptance targets Windows")
    executable = ROOT / "release/portable" / EXECUTABLE
    metadata = json.loads((ROOT / "release/native-release.json").read_bytes())
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    assert (
        metadata["source"] == source
        and metadata["version"] == VERSION
        and metadata["product"] == PRODUCT
    )
    assert type(metadata["source_dirty"]) is bool
    if os.environ.get("CI"):
        assert metadata["source_dirty"] is False, "CI must test a clean source checkout"
    with executable.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    assert (
        executable.with_name(EXECUTABLE + ".sha256").read_text(encoding="ascii")
        == digest + "  " + EXECUTABLE + "\n"
    )
    destination = ROOT / "out/native-acceptance"
    destination.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="owned-offline-native-") as temporary:
        scratch = Path(temporary).resolve()
        assert scratch.parent == Path(tempfile.gettempdir()).resolve() and scratch.name.startswith(
            "owned-offline-native-"
        )
        profile = scratch / "synthetic-profile"
        first = launch(executable, profile, scratch / "first", metadata, reopen=False)
        second = launch(executable, profile, scratch / "reopen", metadata, reopen=True)
        assert first["bundles"] == second["bundles"], (
            "restart did not retain exact original/analyst evidence"
        )
        for path in (scratch / "first").glob("*.png"):
            shutil.copyfile(path, destination / path.name)
        summary = {
            "schema": 1,
            "product": PRODUCT,
            "version": VERSION,
            "source": source,
            "source_dirty": metadata["source_dirty"],
            "executable_sha256": digest,
            "first": first,
            "reopen": second,
            "passed": True,
            "cleanup": "both owned frozen PIDs and bootloaders exited; only fresh synthetic temporary profile removed",
        }
        (destination / "acceptance.json").write_text(
            json.dumps(summary, indent=2) + "\n", encoding="utf-8"
        )
    print(
        json.dumps(
            {
                "native_application": PRODUCT,
                "passed": True,
                "source_dirty": metadata["source_dirty"],
                "saved_bundles": len(first["bundles"]),
            }
        )
    )


if __name__ == "__main__":
    main()
