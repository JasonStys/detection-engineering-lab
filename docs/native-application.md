# Detection Engineering native workbench

Created by Jason Stys · [GitHub](https://github.com/JasonStys) · [Contact](https://www.linkedin.com/in/jason-stys-31b30b351/)

This is the actual project in a Windows graphical application, not a separate demonstration or fixed-report launcher. The portable `DetectionEngineeringLab.exe` bundles Python, Tk, PyYAML, the original detection engine and the authored rules/examples. An end user opens one executable; no Python, Node, Docker, cloud account or setup commands are needed. Publication and desktop-shortcut installation are separate reviewed steps; this repository supplies their build and acceptance boundary.

## Work with your own authorized evidence

1. Open **Inputs and analysis**. Choose a prepared fictional scenario, or choose your supported normalized event JSONL, reviewed rule directory and correlation YAML. Only fields relevant to the selected operation are shown. Prepared scenarios merely fill these same controls; they do not automatically run or replace your files.
2. Select **Replay with labels** to evaluate against a separate independently authored labels JSON file. Select **Unlabeled scan** to investigate without a ground-truth score. Labels never enter detection, and an unlabeled result never invents accuracy. Acknowledge permission after editing inputs; any input or mode edit clears that acknowledgement. This is an operator assertion, not authentication.
3. Choose **Run selected analysis**. One owned background worker calls the existing core while the native window remains responsive. Completed outputs are stored atomically. A rejected input does not silently run a sample, substitute an empty result or overwrite an earlier analysis.
4. In **Findings and timeline**, choose investigation candidates or the normalized event timeline. Search literal detector titles, event identities or context; select a row to inspect the exact record. The displayed table is capped at 5,000 matching rows; the complete bounded output remains in the private bundle. Labeled TP/FP/FN and precision/recall describe the supplied small exercise, not production detection effectiveness.
5. Select an original emitted alert and choose **Review selected original alert**. Enter an asserted analyst, a supported disposition and a reason, acknowledge permission, then run. The existing core binds the decision to the exact original report hash and emitted detector/event. A new immutable review carries assertions from the latest retained review of that exact report; other candidates remain explicitly unreviewed. Original detection output and label-derived accuracy are unchanged. A triage export includes that original report JSON for traceability. Retain/export the original replay if you also need its normalized SQLite timeline.
6. **Compare report files** accepts earlier/later report JSON files only when normalized-event and label fingerprints match. It reports added/removed/persistent candidates and rule changes; a removed candidate is not an incident resolution. Unsupported Sigma features still fail closed.
7. **Export selected analysis bundle** creates a new directory under your selected private parent. Replay exports the original core JSON, inert HTML and SQLite; comparison/triage exports its actual review bundle. Existing files are never overwritten. Review sensitive content before sharing.

**Saved analyses** opens exact retained bytes without rerunning detection. Explicit **Remove selected local analysis** asks for confirmation and checks the selected bundle hash before deleting only its local SQLite rows. Original inputs and exported copies are untouched. Export first if you need retention: removing the latest review can remove assertions that would otherwise carry into a later cumulative review. Removal is logical retention control, not forensic erasure; SQLite pages/backups can retain data and allocated disk space can be reused rather than immediately shrunk.

**Exit application**, or the window's close decoration, waits for the owned worker/transaction before releasing the profile. No invisible listener, service or helper is adopted or left running after the tested normal exit. Help and readable runtime licenses are available inside the application.

## Privacy, limits and durable state

Windows default: `%LOCALAPPDATA%\JasonStys\DetectionEngineeringLab`. The marker, exclusive instance lock and `history.sqlite` live outside the executable, source checkout and installation directory. The location is version-independent. Existing CLI input/output paths and new-directory export behavior remain unchanged; native startup refuses unknown nonempty directories rather than treating old CLI output as a new profile.

State is **plaintext OS-owner data**. It is not hidden from an administrator, local malware or another process with filesystem permission. No production accounts, tenants, live telemetry, automatic network calls, model API, remote collector or response command were added. Event fields are data and never executed. Use authorized local files and protect exports/backups. No app-level authentication or administrator-proof audit claim is made.

The native history retains at most 20 runs and 128 MiB of bundle payloads, with 64 MiB per bundle, 32 MiB per file and eight files per bundle. SQLite/parameter metadata and filesystem overhead add space. Limits reject new work without automatically evicting previous evidence. Export and explicitly manage local retention when full. Original core input/rule limits remain in force. These finite bounds are not a latency, disk-failure or denial-of-service guarantee.

Back up the entire profile after a clean exit. Replace/update the executable only after exit and retain the backup. Existing native history is reopened, not reseeded. No real populated-user upgrade was exercised in this synthetic acceptance. Removing the executable does not remove the profile. `--profile PATH` is an advanced explicit workspace choice; the default desktop launch needs no arguments. macOS/Linux source GUI use requires an available Tk/SQLite runtime; frozen packages tested here target Windows x64 only, not mobile.

## Build and verify

Use a separate environment from a reviewed **CPython 3.14.10** SDK. The build refuses older interpreter versions. Do not upgrade global Python or change registry/PATH just to build this application.

```text
python -m pip install --require-hashes -r requirements-dev.lock -r requirements-native.lock
python scripts/build_native.py
python scripts/test_native_app.py
```

The recipe includes only exact allowlisted public resource files, an authored icon and actual Python/Tcl/Tk/PyYAML/bootloader notices. The reference SDK uses Tcl/Tk 9.0.4 with DLL-embedded zipfs libraries. The notice collector reads actual runtime notices, including conventional 8.6 layouts, rather than assuming an old directory. PyInstaller 6.22.3 supports the Tcl9 layout. Resource metadata binds the actual `python314.dll`; frozen startup and consumer receipts require patched 3.14.10 and matching DLL bytes. Git source and dirty state are explicit. Checksums/resource coherence are not Authenticode signatures or publisher authentication.

The actual package test uses fresh explicitly synthetic profiles, real Tk widgets/handlers/mainloop and the existing engine. It uses independent known oracles, a permission negative, two cumulative reviews, malformed-input rejection, exact export, normal exit and a second process reopening identical bundle hashes. Its child PATH contains no Python/Node and provider/account environment variables are not inherited. Acceptance flags cannot enter a normal profile; no arbitrary scripts, plugins or auth bypass are supplied. Screenshots capture only that owned synthetic window. These tests do not claim independent OS accessibility automation or a real-user upgrade.

The worker/mainloop separation follows [Python's Tk threading model](https://docs.python.org/3.14/library/tkinter.html#threading-model). Bundle lookup follows [PyInstaller's runtime resource guidance](https://pyinstaller.org/en/stable/runtime-information.html); its [one-file model](https://pyinstaller.org/en/stable/operating-mode.html#how-the-one-file-program-works) explains why durable data stays outside extraction. [Dated validation](reports/native-application-2026-11-10.md) separates local candidate observations from hosted/release proof.
