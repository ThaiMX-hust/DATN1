"""Small shared helpers for paths, JSON, names, and value conversion."""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


def resolve_path(path_text: str | Path | None, base_dir: Path) -> Path | None:
    """Resolve an optional path relative to a base directory."""
    if not path_text:
        return None
    path = Path(os.path.expandvars(str(path_text))).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (base_dir / path).resolve()


def now_batch_id() -> str:
    """Return a timestamp string suitable for batch output folders."""
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f")


def iso_now() -> str:
    """Return the current local time in ISO 8601 format."""
    return datetime.now().astimezone().isoformat()


def safe_name(value: str) -> str:
    """Return a filesystem-safe name from arbitrary text."""
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return cleaned.strip("_") or "item"


def write_json(path: Path, data: Any) -> None:
    """Write JSON using stable ASCII formatting."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n", encoding="ascii")


def parse_json_file(path: Path) -> Any:
    """Read JSON from a path, treating missing or empty files as an empty list."""
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def value_by_key(obj: Any, names: set[str]) -> Any:
    """Return a case-insensitive dictionary value by any candidate key."""
    if not isinstance(obj, dict):
        return None
    lowered_names = {name.lower() for name in names}
    for key, value in obj.items():
        if str(key).lower() in lowered_names and value not in (None, ""):
            return value
    return None


def string_value(value: Any) -> str:
    """Convert a value to string while preserving empty values as empty text."""
    if value in (None, ""):
        return ""
    return str(value)


def int_or_none(value: Any) -> int | None:
    """Convert a value to int, returning None when conversion is not possible."""
    try:
        if value in (None, ""):
            return None
        return int(str(value))
    except ValueError:
        return None


def join_notes(*parts: str | None) -> str:
    """Join non-empty note fragments with a semicolon."""
    return "; ".join(str(part).strip() for part in parts if str(part or "").strip())


def runner_parent_matches(parent_commandline: str) -> bool:
    """Return whether a parent command line appears to be this runner."""
    if not parent_commandline:
        return False
    lowered = parent_commandline.lower()
    script_names = {
        Path(sys.argv[0]).name.lower(),
        "run_target_commandline_zircolite_tests.py",
        "sigma_fuzzer",
    }
    return any(script_name and script_name in lowered for script_name in script_names)
