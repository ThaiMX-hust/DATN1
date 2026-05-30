"""Load, normalize, and group target command-line test cases."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .models import TargetCase
from .utils import safe_name


def normalize_shell(value: Any) -> str:
    """Return the canonical executable name for a supported shell value."""
    shell = str(value or "cmd.exe").strip().lower()
    aliases = {
        "cmd": "cmd.exe",
        "cmd.exe": "cmd.exe",
        "powershell": "powershell.exe",
        "powershell.exe": "powershell.exe",
        "pwsh": "pwsh.exe",
        "pwsh.exe": "pwsh.exe",
    }
    if shell not in aliases:
        raise ValueError(f"Unsupported shell: {value!r}. Supported: cmd.exe, powershell.exe, pwsh.exe")
    return aliases[shell]


def make_unique_test_id(base: str, used: set[str]) -> str:
    """Return a unique test id while preserving the model-level identifier."""
    candidate = str(base).strip() or "test"
    if candidate not in used:
        used.add(candidate)
        return candidate
    suffix = 2
    while f"{candidate}_{suffix}" in used:
        suffix += 1
    unique = f"{candidate}_{suffix}"
    used.add(unique)
    return unique


def load_cases(config_path: Path) -> list[TargetCase]:
    """Read the input JSON file and convert each item into a TargetCase."""
    with config_path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)

    if isinstance(data, dict) and isinstance(data.get("tests"), list):
        data = data["tests"]
    if not isinstance(data, list):
        raise ValueError("Input config must be a JSON array or an object with a 'tests' array.")

    used_test_ids: set[str] = set()
    cases: list[TargetCase] = []
    for idx, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Test case #{idx} is not an object.")
        technique_id = str(item.get("technique_id") or item.get("target_technical") or "").strip()
        required_values = {
            "target_commandline": item.get("target_commandline"),
            "target_rule": item.get("target_rule"),
            "technique_id": technique_id,
        }
        missing = [field_name for field_name, value in required_values.items() if not str(value or "").strip()]
        if missing:
            raise ValueError(f"Test case #{idx} missing required field(s): {', '.join(missing)}")

        test_id = make_unique_test_id(
            str(item.get("test_id") or f"{safe_name(technique_id)}_{idx:03d}"),
            used_test_ids,
        )
        timeout_seconds = item.get("timeout_seconds")
        if timeout_seconds is not None:
            timeout_seconds = int(timeout_seconds)
            if timeout_seconds < 1:
                raise ValueError(f"Test case #{idx} timeout_seconds must be >= 1")

        cases.append(
            TargetCase(
                index=idx,
                test_id=test_id,
                target_commandline=str(item["target_commandline"]),
                target_rule=str(item["target_rule"]),
                technique_id=technique_id,
                mutation=str(item.get("mutation") or ""),
                shell=normalize_shell(item.get("shell", "cmd.exe")),
                timeout_seconds=timeout_seconds,
                raw=dict(item),
            )
        )
    return cases


def select_cases(cases: list[TargetCase], offset: int, limit: int | None) -> list[TargetCase]:
    """Apply offset and limit arguments to the loaded test cases."""
    if offset < 0:
        raise ValueError("--offset must be >= 0")
    selected = cases[offset:]
    if limit is not None:
        if limit < 1:
            raise ValueError("--limit must be >= 1")
        selected = selected[:limit]
    return selected


def group_by_technique(cases: list[TargetCase]) -> dict[str, list[TargetCase]]:
    """Group test cases by technique id."""
    grouped: dict[str, list[TargetCase]] = defaultdict(list)
    for case in cases:
        grouped[case.technique_id].append(case)
    return dict(grouped)


def technique_dir_map(techniques: list[str]) -> dict[str, str]:
    """Build stable output directory names for technique groups."""
    used: dict[str, str] = {}
    result: dict[str, str] = {}
    for technique in techniques:
        dirname = safe_name(technique)
        existing = used.get(dirname.lower())
        if existing is not None and existing != technique:
            raise ValueError(
                f"technique_id values {existing!r} and {technique!r} both map to output folder {dirname!r}"
            )
        used[dirname.lower()] = technique
        result[technique] = dirname
    return result
