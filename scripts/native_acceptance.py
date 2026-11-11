"""Exercise the same real frozen Tk controls/core on an explicit synthetic profile; no arbitrary scripts. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: capture — line 92
# parameter: target — line 92
# parameter: window — line 92
# variable: load — line 98
# variable: gdi — line 99
# variable: user — line 99
# variable: pointer — line 100
# variable: arguments — line 101
# variable: library — line 101
# variable: name — line 101
# variable: result — line 101
# variable: function — line 119
# variable: handle — line 122
# variable: rectangle — line 123
# variable: height — line 126
# variable: width — line 126
# variable: source — line 129
# variable: destination — line 130
# variable: bitmap — line 131
# variable: previous — line 132
# variable: pixels — line 137
# variable: header — line 138
# variable: raw — line 145
# variable: scanlines — line 146
# variable: row — line 147
# variable: column — line 149
# variable: offset — line 150
# definition: chunk — line 153
# parameter: data — line 153
# parameter: name — line 153
# definition: exercise — line 175
# parameter: output — line 175
# parameter: reopen — line 175
# parameter: window — line 175
# variable: deadline — line 178
# variable: receipt — line 179
# definition: finish — line 197
# parameter: error — line 197
# variable: data — line 204
# variable: name — line 204
# variable: row — line 206
# definition: checked — line 213
# parameter: callback — line 213
# definition: wait — line 222
# parameter: callback — line 222
# definition: original — line 232
# variable: files — line 234
# variable: report — line 235
# variable: key — line 237
# definition: reviewed — line 262
# variable: review — line 264
# variable: original_report — line 266
# variable: row — line 269
# definition: cumulative — line 288
# variable: review — line 290
# variable: row — line 293
# variable: parent — line 305
# variable: exported — line 311
# variable: path — line 312
# variable: invalid — line 316
# definition: rejected — line 324
# definition: layout — line 331
# variable: original — line 333
# variable: button — line 356
# variable: name — line 356
# variable: button — line 361
# definition: begin — line 377
# END CODE MAP

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import struct
import sys
import time
import zlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

from detection import desktop_project as project
from detection.io import json_value

if TYPE_CHECKING:
    from detection.desktop import Workbench


def capture(window: Workbench, target: Path) -> None:
    """Capture only this owned synthetic Tk window via PrintWindow, never the user's whole desktop."""
    if sys.platform != "win32":
        raise OSError("native screenshot acceptance targets Windows")
    from ctypes import wintypes

    load = ctypes.WinDLL
    user, gdi = load("user32", use_last_error=True), load("gdi32", use_last_error=True)
    pointer = ctypes.c_void_p
    for library, name, arguments, result in [
        (user, "GetAncestor", [pointer, ctypes.c_uint], pointer),
        (user, "GetWindowDC", [pointer], pointer),
        (gdi, "CreateCompatibleDC", [pointer], pointer),
        (gdi, "CreateCompatibleBitmap", [pointer, ctypes.c_int, ctypes.c_int], pointer),
        (gdi, "SelectObject", [pointer, pointer], pointer),
        (gdi, "DeleteObject", [pointer], ctypes.c_int),
        (gdi, "DeleteDC", [pointer], ctypes.c_int),
        (user, "ReleaseDC", [pointer, pointer], ctypes.c_int),
        (user, "PrintWindow", [pointer, pointer, ctypes.c_uint], ctypes.c_int),
        (user, "GetWindowRect", [pointer, ctypes.POINTER(wintypes.RECT)], ctypes.c_int),
        (
            gdi,
            "GetDIBits",
            [pointer, pointer, ctypes.c_uint, ctypes.c_uint, pointer, pointer, ctypes.c_uint],
            ctypes.c_int,
        ),
    ]:
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result
    window.root.update_idletasks()
    handle = user.GetAncestor(window.root.winfo_id(), 2)
    rectangle = wintypes.RECT()
    if not user.GetWindowRect(handle, ctypes.byref(rectangle)):
        raise OSError("owned window bounds unavailable")
    width, height = rectangle.right - rectangle.left, rectangle.bottom - rectangle.top
    if not 1 <= width <= 4096 or not 1 <= height <= 4096:
        raise OSError("owned screenshot outside bounded dimensions")
    source = user.GetWindowDC(handle)
    destination = gdi.CreateCompatibleDC(source)
    bitmap = gdi.CreateCompatibleBitmap(source, width, height)
    previous = gdi.SelectObject(destination, bitmap)
    try:
        if not user.PrintWindow(handle, destination, 2):
            raise OSError("owned window rendering unavailable")
        gdi.SelectObject(destination, previous)
        pixels = ctypes.create_string_buffer(width * height * 4)
        header = ctypes.create_string_buffer(
            struct.pack(
                "<IiiHHIIiiII", 40, width, -height, 1, 32, 0, width * height * 4, 0, 0, 0, 0
            )
        )
        if gdi.GetDIBits(source, bitmap, 0, height, pixels, header, 0) != height:
            raise OSError("owned screenshot pixels incomplete")
        raw = pixels.raw
        scanlines = bytearray()
        for row in range(height):
            scanlines.append(0)
            for column in range(width):
                offset = (row * width + column) * 4
                scanlines.extend((raw[offset + 2], raw[offset + 1], raw[offset]))

        def chunk(name: bytes, data: bytes) -> bytes:
            """Encode a bounded standard PNG chunk with its actual CRC."""
            return (
                struct.pack(">I", len(data))
                + name
                + data
                + struct.pack(">I", zlib.crc32(name + data))
            )

        target.write_bytes(
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(scanlines)))
            + chunk(b"IEND", b"")
        )
    finally:
        gdi.SelectObject(destination, previous)
        gdi.DeleteObject(bitmap)
        gdi.DeleteDC(destination)
        user.ReleaseDC(handle, source)


def exercise(window: Workbench, output: Path, reopen: bool) -> None:
    """Drive real widgets/handlers/mainloop with independent labeled oracles and preserve actual receipts."""
    output.mkdir(mode=0o700)
    deadline = time.monotonic() + 55
    receipt: dict[str, Any] = {
        "schema": 1,
        "product": project.PRODUCT,
        "version": project.VERSION,
        **window.identity,
        "pid": os.getpid(),
        "parent_pid": os.getppid(),
        "synthetic": True,
        "reopen": reopen,
        "passed": False,
        "steps": [],
    }

    (output / "acceptance.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")

    receipt["tcl_version"] = window.root.tk.call("info", "patchlevel")
    receipt["tk_version"] = window.root.tk.call("package", "require", "Tk")

    def finish(error: bool = False) -> None:
        """Write value-free outcome and exact synthetic bundle hashes, then request the normal graceful exit."""
        receipt["passed"] = not error
        window.acceptance_result = not error
        receipt["bundles"] = {
            str(row["id"]): {
                name: hashlib.sha256(data).hexdigest()
                for name, data in window.state.files(row["id"]).items()
            }
            for row in window.state.history()
        }
        (output / "acceptance.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )
        window.exit()

    def checked(callback: Any) -> None:
        """Turn a real assertion/handler failure into a failed receipt without leaving an invisible owned app."""
        try:
            callback()
        except Exception:
            receipt["failure"] = "native acceptance assertion or operation failed"
            receipt["failure_stage"] = callback.__name__
            finish(True)

    def wait(callback: Any) -> None:
        """Wait for this one owned operation; do not retry analyses or discard failed samples."""
        if time.monotonic() > deadline:
            receipt["failure"] = "owned operation deadline exceeded"
            finish(True)
        elif window.busy:
            window.root.after(60, lambda: wait(callback))
        else:
            checked(callback)

    def original() -> None:
        """Require independent known replay counts and actual displayed/filterable alert context."""
        files = window.state.files(1)
        report = json_value(files["report.json"])
        assert report["events"] == 71 and len(report["alerts"]) == 10
        assert {key: report["evaluation"]["micro"][key] for key in ("tp", "fp", "fn")} == {
            "tp": 7,
            "fp": 3,
            "fn": 2,
        }
        assert len(window.current["Normalized event timeline"]) == 71
        window.search.set("clear-maintenance")
        assert len(window.table.get_children()) == 1
        window.table.selection_set("0")
        window.inspect()
        layout()
        capture(window, output / "investigation.png")
        receipt["steps"].append("real-labeled-core-timeline-filter")
        assert window.review_button is not None
        window.review_button.invoke()
        assert window.mode.get() == project.MODES[3] and window.authorized.get() is False
        window.values["analyst"].set("fictional-training-reviewer")
        window.values["disposition"].set("benign")
        window.values["reason"].set(
            "Scheduled maintenance in the fictional exercise; verify owner context before a real disposition."
        )
        window.authorized.set(True)
        window.run_button.invoke()
        wait(reviewed)

    def reviewed() -> None:
        """Bind one reasoned disposition to the real report while preserving original metrics and other unreviewed alerts."""
        review = json_value(window.state.files(2)["review.json"])
        assert review["reviewed"] == 1 and review["unreviewed"] == 9
        original_report = json_value(window.state.files(1)["report.json"])
        assert review["evaluation"] == original_report["evaluation"]
        assert (
            next(row for row in review["alerts"] if row["event"] == "clear-maintenance")[
                "disposition"
            ]
            == "benign"
        )
        window.history_table.selection_set("1")
        window.open_button.invoke()
        window.search.set("clear-suspicious")
        window.table.selection_set("0")
        assert window.review_button is not None
        window.review_button.invoke()
        window.values["disposition"].set("needs-context")
        window.values["reason"].set(
            "Suspicious fictional clearing needs supporting owner context; no incident verdict is asserted."
        )
        window.authorized.set(True)
        window.run_button.invoke()
        wait(cumulative)

    def cumulative() -> None:
        """Carry prior review forward while preserving both immutable earlier bundles and original accuracy."""
        review = json_value(window.state.files(3)["review.json"])
        assert review["reviewed"] == 2 and review["unreviewed"] == 8
        assert (
            next(row for row in review["alerts"] if row["event"] == "clear-maintenance")[
                "disposition"
            ]
            == "benign"
        )
        assert (
            review["evaluation"] == json_value(window.state.files(1)["report.json"])["evaluation"]
        )
        window.search.set("clear-maintenance")
        window.table.selection_set("0")
        window.inspect()
        capture(window, output / "reasoned-review.png")
        parent = output / "private-export"
        parent.mkdir()
        from unittest.mock import patch

        with patch("tkinter.filedialog.askdirectory", return_value=str(parent)):
            window.export_button.invoke()
        exported = next(parent.iterdir())
        assert {path.name: path.read_bytes() for path in exported.iterdir()} == window.state.files(
            3
        )
        receipt["steps"].append("real-bound-triage-exact-private-export")
        invalid = output / "malformed.jsonl"
        invalid.write_bytes(b'{"not":"supported telemetry"}\n')
        window.load_prepared()
        window.values["events"].set(str(invalid))
        window.authorized.set(True)
        window.run_button.invoke()
        wait(rejected)

    def rejected() -> None:
        """A malformed input must preserve all completed analyses rather than overwrite them with a demo."""
        assert len(window.state.history()) == 3
        assert "rejected" in window.status.get().lower()
        receipt["steps"].append("malformed-input-retained-prior-evidence")
        finish()

    def layout() -> None:
        """Real minimum-width layout keeps every lifecycle control fully visible even with long status text."""
        original = window.status.get()
        window.root.geometry("980x700")
        window.status.set(
            original
            + " Synthetic long-message layout check: existing evidence remains available and Exit waits for the owned operation."
        )
        window.root.update()
        receipt["layout"] = {
            "root": [window.root.winfo_width(), window.root.winfo_height()],
            "status": [
                window.status_label.winfo_width(),
                window.status_label.winfo_height(),
                window.status_label.winfo_reqheight(),
                int(window.status_label.cget("wraplength")),
            ],
            "buttons": {
                name: [
                    button.winfo_width(),
                    button.winfo_reqwidth(),
                    button.winfo_rootx() - window.root.winfo_rootx(),
                    button.winfo_rooty() - window.root.winfo_rooty(),
                    button.winfo_height(),
                ]
                for name, button in window.footer_buttons.items()
            },
        }
        assert int(window.status_label.cget("wraplength")) <= window.status_label.winfo_width()
        assert window.status_label.winfo_height() >= window.status_label.winfo_reqheight()
        for button in window.footer_buttons.values():
            assert button.winfo_width() >= button.winfo_reqwidth()
            assert button.winfo_rootx() >= window.root.winfo_rootx()
            assert (
                button.winfo_rootx() + button.winfo_width()
                <= window.root.winfo_rootx() + window.root.winfo_width()
            )
            assert (
                button.winfo_rooty() + button.winfo_height()
                <= window.root.winfo_rooty() + window.root.winfo_height()
            )
        window.status.set(original)
        window.root.geometry("1260x860")
        window.root.update()
        receipt["steps"].append("real-minimum-width-long-status-all-lifecycle-controls-visible")

    def begin() -> None:
        """Use the actual Run button and permission guard; reopen never replays or silently reseeds a project."""
        if reopen:
            assert len(window.state.history()) == 3
            window.history_table.selection_set("1")
            window.open_button.invoke()
            assert len(window.current["Investigation candidates"]) == 10
            window.history_table.selection_set("3")
            window.open_button.invoke()
            assert json_value(window.state.files(3)["review.json"])["reviewed"] == 2
            receipt["steps"].append("actual-process-reopen-persisted-three-bundles")
            finish()
            return
        assert window.state.history() == []
        window.run_button.invoke()
        assert not window.busy and window.state.history() == []
        window.authorized.set(True)
        window.run_button.invoke()
        wait(original)

    checked(begin)
