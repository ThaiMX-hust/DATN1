"""Load machine-specific path settings from a project JSON file."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .utils import resolve_path


DEFAULT_PATH_CONFIG = Path("config/paths.json")
DEFAULT_OUTPUT_DIR = "data/target_commandline_tests"
DEFAULT_RULES_DIR = "rules"


@dataclass(frozen=True)
class PathConfig:
    """Resolved paths loaded from the optional project path config."""

    source_path: Path | None = None
    base_dir: Path | None = None
    input_config: Path | None = None
    output_dir: Path | None = None
    rules_dir: Path | None = None
    zircolite_path: Path | None = None
    python_exe: str | None = None
    ruleset: Path | None = None
    zircolite_config: Path | None = None


def _text_or_none(value: Any) -> str | None:
    """Return non-empty text values and ignore null or blank values."""
    if value in (None, ""):
        return None
    text = str(value).strip()
    return text or None


def _mapping_value(data: dict[str, Any], *names: str) -> Any:
    """Return the first non-empty value from a mapping by candidate names."""
    for name in names:
        value = data.get(name)
        if value not in (None, ""):
            return value
    return None


def _nested_mapping(data: dict[str, Any], name: str) -> dict[str, Any]:
    """Return a nested mapping or an empty mapping when it is absent."""
    value = data.get(name)
    return value if isinstance(value, dict) else {}


def _optional_path(value: Any, base_dir: Path) -> Path | None:
    """Resolve a path config value relative to the effective base directory."""
    text = _text_or_none(value)
    return resolve_path(text, base_dir) if text else None


def _resolve_config_file(path: str | Path | None, cwd: Path) -> Path | None:
    """Resolve the requested path config file or auto-detect the default one."""
    if path is None:
        candidate = cwd / DEFAULT_PATH_CONFIG
        return candidate.resolve() if candidate.exists() else None
    requested = resolve_path(path, cwd)
    return requested.resolve() if requested else None


def load_path_config(path: str | Path | None, cwd: Path) -> PathConfig:
    """Load path settings from JSON, returning an empty config when absent."""
    config_path = _resolve_config_file(path, cwd)
    if config_path is None:
        return PathConfig()
    if not config_path.exists():
        raise FileNotFoundError(f"path config file not found: {config_path}")

    with config_path.open("r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Path config must be a JSON object.")

    config_dir = config_path.parent
    base_dir = _optional_path(_mapping_value(data, "base_dir", "project_root"), config_dir)
    effective_base_dir = base_dir or cwd
    zircolite = _nested_mapping(data, "zircolite")

    return PathConfig(
        source_path=config_path,
        base_dir=base_dir,
        input_config=_optional_path(_mapping_value(data, "input_config", "test_config"), effective_base_dir),
        output_dir=_optional_path(_mapping_value(data, "output_dir"), effective_base_dir),
        rules_dir=_optional_path(_mapping_value(data, "rules_dir"), effective_base_dir),
        zircolite_path=_optional_path(
            _mapping_value(data, "zircolite_path") or _mapping_value(zircolite, "path"),
            effective_base_dir,
        ),
        python_exe=_text_or_none(_mapping_value(data, "python_exe") or _mapping_value(zircolite, "python_exe")),
        ruleset=_optional_path(
            _mapping_value(data, "ruleset") or _mapping_value(zircolite, "ruleset"),
            effective_base_dir,
        ),
        zircolite_config=_optional_path(
            _mapping_value(data, "zircolite_config") or _mapping_value(zircolite, "config"),
            effective_base_dir,
        ),
    )
