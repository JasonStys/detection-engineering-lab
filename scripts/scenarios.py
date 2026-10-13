"""Reproducible synthetic telemetry and independently authored truth, never detector-derived. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 41
# variable: IDS — line 42
# definition: scenarios — line 51
# variable: events — line 53
# variable: labels — line 54
# definition: add — line 56
# parameter: identity — line 57
# parameter: seconds — line 58
# parameter: product — line 59
# parameter: service — line 60
# parameter: fields — line 61
# parameter: expected — line 62
# variable: timestamp — line 65
# variable: index — line 189
# variable: seconds — line 189
# variable: index — line 203
# variable: index — line 216
# variable: index — line 244
# definition: files — line 256
# variable: events — line 258
# variable: labels — line 258
# variable: event — line 262
# definition: main — line 268
# variable: parser — line 270
# variable: args — line 272
# variable: content — line 273
# variable: name — line 273
# variable: path — line 274
# END CODE MAP

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
IDS = {
    "clear": "50000000-0000-4000-8000-000000000001",
    "ps": "50000000-0000-4000-8000-000000000002",
    "cloud": "50000000-0000-4000-8000-000000000003",
    "cron": "50000000-0000-4000-8000-000000000004",
    "burst": "auth-burst",
}


def scenarios() -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    """Create separate truth from case design; include deliberate lexical misses and legitimate matches."""
    events: list[dict[str, Any]] = []
    labels: dict[str, list[str]] = {}

    def add(
        identity: str,
        seconds: int,
        product: str,
        service: str,
        fields: dict[str, Any],
        expected: str | None = None,
    ) -> None:
        """Append one fictional event with a manual expectation stored only in the label file."""
        timestamp = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
        events.append(
            {
                "id": identity,
                "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                "source": {"product": product, "service": service},
                "fields": fields,
            }
        )
        labels[identity] = [IDS[expected]] if expected else []

    add(
        "clear-suspicious",
        1,
        "windows",
        "security",
        {"EventID": 1102, "Hostname": "lab-ws-01"},
        "clear",
    )
    add("clear-maintenance", 2, "windows", "security", {"EventID": 1102, "Hostname": "lab-ws-02"})
    add(
        "ps-suspicious",
        3,
        "windows",
        "process_creation",
        {
            "Image": "C:\\Windows\\powershell.exe",
            "CommandLine": "powershell.exe -enc SYNTHETIC_NOT_EXECUTABLE",
        },
        "ps",
    )
    add(
        "ps-mixed-case",
        4,
        "windows",
        "process_creation",
        {
            "Image": "C:\\Tools\\PWSH.EXE",
            "CommandLine": "pwsh.exe -EncodedCommand SYNTHETIC_NOT_EXECUTABLE",
        },
        "ps",
    )
    add(
        "ps-admin",
        5,
        "windows",
        "process_creation",
        {
            "Image": "C:\\Tools\\pwsh.exe",
            "CommandLine": "pwsh.exe -enc SYNTHETIC_ADMIN_PLACEHOLDER",
        },
    )
    add(
        "ps-tab-blindspot",
        6,
        "windows",
        "process_creation",
        {"Image": "C:\\Tools\\pwsh.exe", "CommandLine": "pwsh.exe\t-enc\tSYNTHETIC_NOT_EXECUTABLE"},
        "ps",
    )
    add(
        "ps-benign",
        7,
        "windows",
        "process_creation",
        {
            "Image": "C:\\Tools\\pwsh.exe",
            "CommandLine": "pwsh.exe -File maintenance-placeholder.ps1",
        },
    )
    add(
        "cloud-stop",
        8,
        "aws",
        "cloudtrail",
        {"EventName": "StopLogging", "Region": "lab-region"},
        "cloud",
    )
    add(
        "cloud-delete",
        9,
        "aws",
        "cloudtrail",
        {"EventName": "DeleteTrail", "Region": "lab-region"},
        "cloud",
    )
    add(
        "cloud-denied",
        10,
        "aws",
        "cloudtrail",
        {"EventName": "StopLogging", "ErrorCode": "AccessDenied"},
    )
    add("cloud-query", 11, "aws", "cloudtrail", {"EventName": "DescribeTrails"})
    add(
        "cron-suspicious",
        12,
        "linux",
        "auditd",
        {"Operation": "write", "Path": "/etc/cron.d/lab-placeholder"},
        "cron",
    )
    add(
        "cron-package",
        13,
        "linux",
        "auditd",
        {"Operation": "write", "Path": "/etc/cron.daily/package-placeholder"},
    )
    add(
        "cron-read",
        14,
        "linux",
        "auditd",
        {"Operation": "read", "Path": "/etc/cron.d/lab-placeholder"},
    )
    add(
        "cron-user-blindspot",
        15,
        "linux",
        "auditd",
        {"Operation": "write", "Path": "/var/spool/cron/lab-user"},
        "cron",
    )
    for index, seconds in enumerate((20, 40, 60, 80)):
        add(
            f"burst-{index}",
            seconds,
            "windows",
            "security",
            {
                "EventID": 4625,
                "SourceIp": "192.0.2.10",
                "Hostname": "lab-ws-01",
                "TargetUserName": f"fictional-user-{index}",
            },
            "burst" if index == 3 else None,
        )
    for index in range(5):
        add(
            f"typo-{index}",
            25 + index,
            "windows",
            "security",
            {
                "EventID": 4625,
                "SourceIp": "192.0.2.20",
                "Hostname": "lab-ws-02",
                "TargetUserName": "same-fictional-user",
            },
        )
    for index in range(4):
        add(
            f"slow-{index}",
            100 + 61 * index,
            "windows",
            "security",
            {
                "EventID": 4625,
                "SourceIp": "192.0.2.30",
                "Hostname": "lab-ws-03",
                "TargetUserName": f"fictional-user-{index}",
            },
        )
    add(
        "missing-group",
        45,
        "windows",
        "security",
        {"EventID": 4625, "TargetUserName": "fictional-user"},
    )
    add("wrong-source", 46, "linux", "auditd", {"EventID": 1102})
    add(
        "injection-string",
        47,
        "linux",
        "auditd",
        {"Operation": "read", "Path": "<script>alert('fictional')</script>'; DROP TABLE event;--"},
    )
    for index in range(40):
        add(
            f"background-{index:02d}",
            300 + index,
            "windows",
            "security",
            {"EventID": 4624, "Hostname": f"lab-ws-{index % 4:02d}"},
        )
    # Out-of-order input and one exact duplicate exercise normalization, not oracle leakage.
    return list(reversed(events)) + [dict(events[0])], labels


def files() -> dict[str, bytes]:
    """Return deterministic generated fixture bytes for creation or drift verification."""
    events, labels = scenarios()
    return {
        "events.jsonl": b"".join(
            (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()
            for event in events
        ),
        "labels.json": (json.dumps(labels, indent=2, sort_keys=True) + "\n").encode(),
    }


def main() -> int:
    """Generate fixtures or fail --check when manually changed data diverges from source cases."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for name, content in files().items():
        path = ROOT / "examples" / name
        if args.check:
            if not path.is_file() or path.read_bytes() != content:
                raise SystemExit(f"Synthetic fixture drift: {name}")
        else:
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(content)
    print("Synthetic fixtures current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
