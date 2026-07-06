"""Rebuild result reports from EVTX files that were already exported."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from .cases import group_by_technique, load_cases, select_cases, technique_dir_map
from .detection import classify_results, run_zircolite_for_technique
from .models import CaseResult, RunnerConfig, SYSMON_EVENT_ID, SYSMON_LOG_NAME, TargetCase
from .reports import case_result_to_dict, technique_summary_to_dict, write_result_csv, write_result_json
from .runner import evtx_name_for_case, restored_result_for_case
from .utils import iso_now


@dataclass(frozen=True)
class EvtxRestoreSelection:
    """Cases restored from existing EVTX files and accounting details."""

    results_by_technique: dict[str, list[CaseResult]]
    matched_count: int
    missing_count: int
    ignored_evtx_count: int
    ignored_evtx_paths: list[Path]


@dataclass(frozen=True)
class RebuildOutput:
    """Paths and counts produced by a rebuild run."""

    batch_dir: Path
    evtx_dir: Path
    result_csv: Path
    requested_csv: Path
    result_json: Path
    selected_count: int
    matched_count: int
    missing_count: int
    ignored_evtx_count: int


def resolve_evtx_dir(path: Path) -> tuple[Path, Path]:
    """Return the report directory and EVTX directory for a batch or EVTX path."""
    if not path.exists() or not path.is_dir():
        raise ValueError(f"batch/EVTX folder does not exist: {path}")

    nested_evtx_dir = path / "evtx"
    if nested_evtx_dir.is_dir():
        return path, nested_evtx_dir

    if any(path.glob("*.evtx")):
        batch_dir = path.parent if path.name.lower() == "evtx" else path
        return batch_dir, path

    raise ValueError(f"folder does not contain an evtx directory or EVTX files: {path}")


def latest_batch_dir(output_dir: Path) -> Path:
    """Return the newest batch directory under output_dir that has EVTX files."""
    if not output_dir.exists() or not output_dir.is_dir():
        raise ValueError(f"output folder does not exist: {output_dir}")

    candidates = [
        path
        for path in output_dir.iterdir()
        if path.is_dir() and (path / "evtx").is_dir() and any((path / "evtx").glob("*.evtx"))
    ]
    if not candidates:
        raise ValueError(f"no batch folder with EVTX files found under: {output_dir}")
    return max(candidates, key=lambda path: (path.stat().st_mtime_ns, path.name.lower()))


def _actual_evtx_by_name(evtx_dir: Path) -> dict[str, Path]:
    """Index EVTX files by lowercase filename."""
    paths_by_name: dict[str, Path] = {}
    for evtx_path in sorted(evtx_dir.glob("*.evtx"), key=lambda path: path.name.lower()):
        key = evtx_path.name.lower()
        if key in paths_by_name:
            raise ValueError(f"duplicate EVTX filename differing only by case: {evtx_path.name}")
        paths_by_name[key] = evtx_path
    return paths_by_name


def restore_results_from_existing_evtx(
    cases: list[TargetCase],
    batch_dir: Path,
    evtx_dir: Path,
    dir_map: dict[str, str],
    include_missing: bool = False,
) -> EvtxRestoreSelection:
    """Create CaseResult objects from EVTX files already present on disk."""
    actual_evtx = _actual_evtx_by_name(evtx_dir)
    expected_names = {evtx_name_for_case(case, dir_map).lower() for case in cases}
    ignored_evtx_paths = [path for name, path in actual_evtx.items() if name not in expected_names]

    results_by_technique: dict[str, list[CaseResult]] = {}
    matched_count = 0
    missing_count = 0
    for case in cases:
        evtx_path = actual_evtx.get(evtx_name_for_case(case, dir_map).lower())
        if evtx_path is None:
            missing_count += 1
            if not include_missing:
                continue

        result = restored_result_for_case(case, evtx_path, batch_dir)
        if evtx_path is None:
            result.note = f"no matching EVTX found in {evtx_dir}"
        else:
            matched_count += 1
            result.note = "rebuilt from existing EVTX; execution was not rerun"
        results_by_technique.setdefault(case.technique_id, []).append(result)

    return EvtxRestoreSelection(
        results_by_technique=results_by_technique,
        matched_count=matched_count,
        missing_count=missing_count,
        ignored_evtx_count=len(ignored_evtx_paths),
        ignored_evtx_paths=ignored_evtx_paths,
    )


def copy_requested_csv(batch_dir: Path, csv_name: str) -> Path:
    """Copy result.csv to the requested CSV filename when needed."""
    canonical_csv = batch_dir / "result.csv"
    requested_csv = batch_dir / csv_name
    if requested_csv.resolve() != canonical_csv.resolve():
        shutil.copy2(canonical_csv, requested_csv)
    return requested_csv


def rebuild_results_from_evtx(
    config: RunnerConfig,
    batch_dir: Path,
    include_missing: bool = False,
    csv_name: str = "results.csv",
) -> RebuildOutput:
    """Run detection against existing EVTX files and rewrite result reports."""
    batch_dir, evtx_dir = resolve_evtx_dir(batch_dir)
    selected_cases = select_cases(load_cases(config.config_path), config.offset, config.limit)
    full_grouped = group_by_technique(selected_cases)
    dir_map = technique_dir_map(list(full_grouped))
    restore = restore_results_from_existing_evtx(
        selected_cases,
        batch_dir,
        evtx_dir,
        dir_map,
        include_missing=include_missing,
    )
    if restore.matched_count == 0 and not include_missing:
        raise ValueError(
            "no EVTX files matched the selected cases; check --config, --offset/--limit, and --batch-dir"
        )

    batch_metadata = {
        "batch_id": batch_dir.name,
        "created_at": iso_now(),
        "rebuilt_from_evtx": True,
        "config": str(config.config_path),
        "path_config": str(config.path_config_path) if config.path_config_path else None,
        "selected_count": len(selected_cases),
        "matched_evtx_count": restore.matched_count,
        "missing_evtx_count": restore.missing_count,
        "ignored_evtx_count": restore.ignored_evtx_count,
        "include_missing": include_missing,
        "source_batch_dir": str(batch_dir),
        "evtx_dir": str(evtx_dir),
        "execute": False,
        "sysmon_log_name": SYSMON_LOG_NAME,
        "sysmon_event_id": SYSMON_EVENT_ID,
        "zircolite_path": str(config.zircolite_path) if config.zircolite_path else None,
        "ruleset": str(config.ruleset) if config.ruleset else None,
        "rules_dir": str(config.rules_dir) if config.rules_dir else None,
        "base_dir": str(config.base_dir),
        "save_debug_artifacts": config.save_debug_artifacts,
    }

    all_rows: list[dict[str, object]] = []
    all_results: list[CaseResult] = []
    technique_summaries: list[dict[str, object]] = []
    for technique_id in full_grouped:
        results = restore.results_by_technique.get(technique_id, [])
        if not results:
            continue

        zircolite = run_zircolite_for_technique(
            technique_id,
            [Path(result.evtx_path) for result in results if result.evtx_path],
            batch_dir,
            config,
        )
        classify_results(results, zircolite, config.rules_dir)

        for result in results:
            all_rows.append(case_result_to_dict(result, batch_dir.name))
            all_results.append(result)
        technique_summaries.append(technique_summary_to_dict(technique_id, results, zircolite))

    write_result_csv(batch_dir, all_results, config.rules_dir)
    write_result_json(batch_dir, batch_metadata, all_rows, technique_summaries)
    requested_csv = copy_requested_csv(batch_dir, csv_name)

    return RebuildOutput(
        batch_dir=batch_dir,
        evtx_dir=evtx_dir,
        result_csv=batch_dir / "result.csv",
        requested_csv=requested_csv,
        result_json=batch_dir / "result.json",
        selected_count=len(selected_cases),
        matched_count=restore.matched_count,
        missing_count=restore.missing_count,
        ignored_evtx_count=restore.ignored_evtx_count,
    )
