"""Build the complete real offline workbench as one Windows portable executable. Jason Stys.

No publication, installation, shortcut change, host collection or Docker action.
"""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 73
# definition: icon — line 77
# parameter: path — line 77
# variable: size — line 79
# variable: pixels — line 80
# variable: y — line 81
# variable: x — line 82
# variable: shield — line 83
# variable: check — line 86
# variable: color — line 89
# variable: bitmap — line 97
# definition: notices — line 109
# parameter: path — line 109
# variable: root — line 113
# variable: tcl_version — line 116
# variable: tk_version — line 117
# variable: value — line 118
# variable: runtime_notices — line 120
# variable: library — line 121
# variable: title — line 121
# variable: channel — line 125
# variable: raw — line 127
# variable: raw — line 131
# variable: sources — line 137
# variable: name — line 141
# variable: suffix — line 141
# variable: distribution — line 142
# variable: entry — line 143
# variable: matches — line 143
# variable: blocks — line 149
# variable: source — line 149
# variable: title — line 149
# variable: _ — line 150
# variable: data — line 150
# variable: data — line 152
# variable: title — line 152
# definition: main — line 155
# variable: version — line 162
# variable: source — line 165
# variable: dirty — line 166
# variable: output — line 169
# variable: release — line 169
# variable: resource_paths — line 174
# variable: name — line 184
# variable: metadata — line 186
# variable: name — line 194
# variable: path — line 194
# variable: command — line 200
# variable: name — line 221
# variable: path — line 221
# variable: command — line 224
# variable: command — line 225
# variable: executable — line 236
# variable: stream — line 237
# variable: digest — line 238
# END CODE MAP

import hashlib
import importlib.metadata
import json
import os
import struct
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def icon(path: Path) -> None:
    """Generate an authored blue shield/check icon as build output, without shipping a graphics dependency."""
    size = 64
    pixels = bytearray()
    for y in reversed(range(size)):
        for x in range(size):
            shield = (
                8 <= x <= 55 and 5 <= y <= 42 or 42 < y <= 59 and abs(x - 31.5) < (60 - y) * 1.4
            )
            check = (
                15 <= x <= 29 and abs(y - (x + 8)) < 3 or 27 <= x <= 48 and abs(y - (65 - x)) < 3
            )
            color = (
                (255, 255, 255, 255)
                if shield and check
                else (220, 100, 24, 255)
                if shield
                else (0, 0, 0, 0)
            )
            pixels.extend(color)
    bitmap = (
        struct.pack("<IIIHHIIIIII", 40, size, size * 2, 1, 32, 0, len(pixels), 0, 0, 0, 0)
        + pixels
        + bytes(size * size // 8)
    )
    path.write_bytes(
        struct.pack("<HHH", 0, 1, 1)
        + struct.pack("<BBBBHHII", size, size, 0, 0, 1, 32, len(bitmap), 22)
        + bitmap
    )


def notices(path: Path) -> None:
    """Retain actual Python, Tcl/Tk, PyYAML and bootloader notices, including Tcl9 DLL-embedded resources."""
    import tkinter

    root = tkinter.Tk()
    root.withdraw()
    try:
        tcl_version = root.tk.call("info", "patchlevel")
        tk_version = root.tk.call("package", "require", "Tk")
        if not all(str(value).startswith(("8.6.", "9.0.")) for value in (tcl_version, tk_version)):
            raise ValueError("Review a different Tcl/Tk runtime family before packaging")
        runtime_notices = []
        for title, library in [
            ("Tcl " + str(tcl_version), root.tk.call("info", "library")),
            ("Tk " + str(tk_version), root.tk.eval("set tk_library")),
        ]:
            channel = root.tk.call("open", str(library) + "/license.terms", "rb")
            try:
                raw = root.tk.call("read", channel, 65537)
            finally:
                root.tk.call("close", channel)
            if isinstance(raw, str):
                raw = raw.encode("utf-8")
            if not isinstance(raw, bytes) or not 100 < len(raw) <= 65536:
                raise ValueError("Actual runtime notice is missing or outside its byte bound")
            runtime_notices.append((title, raw))
    finally:
        root.destroy()
    sources = [
        ("Authored application — MIT", ROOT / "LICENSE"),
        ("Python runtime", Path(sys.base_prefix) / "LICENSE.txt"),
    ]
    for name, suffix in [("pyinstaller", "licenses/COPYING.txt"), ("pyyaml", "licenses/LICENSE")]:
        distribution = importlib.metadata.distribution(name)
        matches = [entry for entry in distribution.files or [] if str(entry).endswith(suffix)]
        if len(matches) != 1:
            raise ValueError("Review runtime license inventory before packaging")
        sources.append(
            (name + " license and applicable exception", Path(distribution.locate_file(matches[0])))
        )
    blocks = [(title, source.read_bytes()) for title, source in sources] + runtime_notices
    if any(len(data) > 2 * 1024 * 1024 for _, data in blocks):
        raise ValueError("Bundled license exceeds byte bound")
    path.write_bytes(b"\n\n".join(title.encode("utf-8") + b"\n" + data for title, data in blocks))


def main() -> None:
    """Freeze exact allowlisted public resources and bind actual source/dirty state without publishing."""
    if sys.platform != "win32" or sys.version_info[:3] != (3, 14, 10):
        raise RuntimeError("This portable recipe requires patched Windows CPython3.14.10")
    from detection import desktop_project as project
    from detection.io import read_bytes

    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    if version != project.VERSION:
        raise ValueError("Native version coherence failed")
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(
        subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip()
    )
    release, output = ROOT / "release", ROOT / "out"
    release.mkdir(exist_ok=True)
    output.mkdir(exist_ok=True)
    notices(release / "notices.txt")
    icon(output / "app.ico")
    resource_paths = {
        name: (
            release / name
            if name == "notices.txt"
            else output / name
            if name == "app.ico"
            else Path(sys.base_prefix) / name
            if name == "python314.dll"
            else ROOT / name
        )
        for name in project.RESOURCES
    }
    metadata = {
        "schema": 1,
        "product": project.PRODUCT,
        "version": version,
        "source": source,
        "source_dirty": dirty,
        "resources": {
            name: hashlib.sha256(read_bytes(path, 32 * 1024 * 1024)).hexdigest()
            for name, path in resource_paths.items()
        },
    }
    (release / "native-release.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf8"
    )
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--icon",
        str(output / "app.ico"),
        "--name",
        "DetectionEngineeringLab",
        "--distpath",
        "release/portable",
        "--workpath",
        "out/native-build",
        "--specpath",
        "out",
        "--paths",
        str(ROOT),
    ]
    for name, path in resource_paths.items():
        if name == "python314.dll":
            continue  # PyInstaller collects the actual interpreter DLL as a binary, not duplicate data.
        command += ["--add-data", str(path) + os.pathsep + Path(name).parent.as_posix()]
    command += [
        "--add-data",
        str(release / "native-release.json") + os.pathsep + ".",
        "scripts/native_entry.py",
    ]
    subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        env={**os.environ, "PYINSTALLER_CONFIG_DIR": str(output / "native-freezer-cache")},
    )
    executable = release / "portable/DetectionEngineeringLab.exe"
    with executable.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    executable.with_name(executable.name + ".sha256").write_text(
        digest + "  " + executable.name + "\n", encoding="ascii"
    )
    print("Portable candidate built; source_dirty=" + str(dirty) + "; not published or installed")


if __name__ == "__main__":
    main()
