"""Build report CSV rows from an existing Zircolite JSON result file."""

from __future__ import annotations

import csv
import ntpath
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .cases import group_by_technique, load_cases, select_cases, technique_dir_map
from .detection import classify_results, detection_events
from .excel_templates import TEMPLATE_HEADERS
from .models import CaseResult, ExecutionResult, TargetCase, ZircoliteRun
from .reports import result_csv_row
from .runner import evtx_name_for_case
from .utils import parse_json_file, value_by_key


@dataclass(frozen=True)
class ZircoliteCsvBuildResult:
    """Summary of a CSV build from existing Zircolite output."""

    output_path: Path
    selected_count: int
    written_count: int
    scanned_count: int
    missing_count: int
    detected_count: int
    ignored_detection_logfile_count: int


def load_zircolite_detections(results_path: Path) -> list[Any]:
    """Read Zircolite JSON output and return its detection list."""
    data = parse_json_file(results_path)
    detections = data if isinstance(data, list) else data.get("detections", []) if isinstance(data, dict) else []
    return detections if isinstance(detections, list) else []


def original_logfile_name(event: dict[str, Any]) -> str:
    """Return the basename of a Zircolite event OriginalLogfile field."""
    value = value_by_key(event, {"OriginalLogfile", "original_logfile", "original_log_file"})
    if value in (None, ""):
        return ""
    return ntpath.basename(str(value).replace("/", "\\"))


def detected_evtx_names(detections: list[Any]) -> set[str]:
    """Return lowercase EVTX filenames referenced by Zircolite detections."""
    names: set[str] = set()
    for detection in detections:
        if not isinstance(detection, dict):
            continue
        for event in detection_events(detection):
            name = original_logfile_name(event)
            if name:
                names.add(name.lower())
    return names


def evtx_names_from_dir(evtx_dir: Path) -> set[str]:
    """Return lowercase EVTX filenames present in a directory."""
    if not evtx_dir.exists() or not evtx_dir.is_dir():
        raise ValueError(f"EVTX folder does not exist: {evtx_dir}")
    return {path.name.lower() for path in evtx_dir.glob("*.evtx") if path.is_file()}


def restored_result(case: TargetCase, evtx_name: str, evtx_dir: Path | None) -> CaseResult:
    """Create a CaseResult for a case whose EVTX was already scanned."""
    result = CaseResult(case=case)
    result.can_execute = True
    result.evtx_name = evtx_name
    result.evtx_path = str(evtx_dir / evtx_name) if evtx_dir is not None else evtx_name
    result.execution = ExecutionResult(
        started=True,
        status="RESTORED_ZIRCOLITE",
        note="rebuilt from existing Zircolite results; execution was not rerun",
    )
    result.note = result.execution.note
    return result


def missing_result(case: TargetCase, expected_evtx_name: str, evtx_dir: Path | None) -> CaseResult:
    """Create a CaseResult for an input case that lacks a matching EVTX."""
    result = CaseResult(case=case)
    location = str(evtx_dir) if evtx_dir is not None else "Zircolite results"
    result.execution = ExecutionResult(
        started=False,
        status="MISSING_EVTX",
        note=f"no matching EVTX {expected_evtx_name!r} found in {location}",
    )
    result.final_status = "execution_failed"
    result.note = result.execution.note
    return result


def build_case_results_from_zircolite(
    cases: list[TargetCase],
    detections: list[Any],
    rules_dir: Path | None = None,
    evtx_dir: Path | None = None,
    include_missing: bool = False,
    detected_only: bool = False,
) -> tuple[list[CaseResult], int, int, int, int]:
    """Build classified CaseResult objects from selected cases and detections.

    Returns results plus counts for scanned, missing, detected, and ignored detection logfile names.
    """
    grouped = group_by_technique(cases)
    dir_map = technique_dir_map(list(grouped))
    expected_by_name = {evtx_name_for_case(case, dir_map).lower(): case for case in cases}
    names_with_detections = detected_evtx_names(detections)
    ignored_detection_logfile_count = len(names_with_detections - set(expected_by_name))

    if evtx_dir is not None:
        scanned_names = evtx_names_from_dir(evtx_dir) & set(expected_by_name)
    elif detected_only:
        scanned_names = names_with_detections & set(expected_by_name)
    else:
        scanned_names = set(expected_by_name)

    results: list[CaseResult] = []
    scanned_count = 0
    missing_count = 0
    for case in cases:
        expected_name = evtx_name_for_case(case, dir_map)
        if expected_name.lower() in scanned_names:
            scanned_count += 1
            results.append(restored_result(case, expected_name, evtx_dir))
            continue
        missing_count += 1
        if include_missing:
            results.append(missing_result(case, expected_name, evtx_dir))

    zircolite = ZircoliteRun(True, None, "OK", None, detections=detections)
    classify_results(results, zircolite, rules_dir)
    detected_count = sum(1 for result in results if result.triggered_rules)
    return results, scanned_count, missing_count, detected_count, ignored_detection_logfile_count


def write_zircolite_result_csv(output_path: Path, results: list[CaseResult], rules_dir: Path | None) -> None:
    """Write a tab-delimited CSV matching reports.write_result_csv shape."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(TEMPLATE_HEADERS)
        for result in results:
            writer.writerow(result_csv_row(result, rules_dir))


def build_csv_from_zircolite_results(
    input_path: Path,
    zircolite_results_path: Path,
    output_path: Path,
    rules_dir: Path | None = None,
    evtx_dir: Path | None = None,
    offset: int = 0,
    limit: int | None = None,
    include_missing: bool = False,
    detected_only: bool = False,
) -> ZircoliteCsvBuildResult:
    """Build a report CSV from input cases and an already-created Zircolite result file."""
    cases = select_cases(load_cases(input_path), offset, limit)
    detections = load_zircolite_detections(zircolite_results_path)
    results, scanned_count, missing_count, detected_count, ignored_detection_logfile_count = (
        build_case_results_from_zircolite(
            cases,
            detections,
            rules_dir=rules_dir,
            evtx_dir=evtx_dir,
            include_missing=include_missing,
            detected_only=detected_only,
        )
    )
    write_zircolite_result_csv(output_path, results, rules_dir)
    return ZircoliteCsvBuildResult(
        output_path=output_path,
        selected_count=len(cases),
        written_count=len(results),
        scanned_count=scanned_count,
        missing_count=missing_count,
        detected_count=detected_count,
        ignored_detection_logfile_count=ignored_detection_logfile_count,
    )
