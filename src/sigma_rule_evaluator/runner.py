"""Coordinate case execution, EVTX export, detection, and result writing."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from .cases import group_by_technique, load_cases, select_cases, technique_dir_map
from .detection import classify_results, run_zircolite_for_technique
from .execution import (
    command_execution_accepted,
    command_execution_failure_reason,
    execute_command,
    validate_payload_execution,
)
from .log_collection import collect_process_tree, export_evtx_by_process_tree, latest_sysmon_record_id
from .models import CaseResult, RunnerConfig, SYSMON_EVENT_ID, SYSMON_LOG_NAME, TargetCase, ZircoliteRun
from .reports import (
    case_evidence_to_dict,
    case_result_to_dict,
    technique_summary_to_dict,
    write_result_csv,
    write_result_json,
)
from .utils import iso_now, join_notes, now_batch_id, safe_name, write_json


@dataclass(frozen=True)
class ResumeFromEvtx:
    """Selection details when continuing after the newest matching EVTX."""

    batch_dir: Path
    last_evtx_path: Path | None
    last_case: TargetCase | None
    skipped_count: int
    ignored_evtx_count: int = 0
    evtx_paths_by_name: dict[str, Path] | None = None


def execution_order(cases: list[TargetCase]) -> list[TargetCase]:
    """Return the exact case order used by the runner."""
    grouped = group_by_technique(cases)
    return [case for technique_cases in grouped.values() for case in technique_cases]


def evtx_name_for_case(case: TargetCase, dir_map: dict[str, str]) -> str:
    """Return the EVTX filename used by the runner for one case."""
    return f"{dir_map[case.technique_id]}__{safe_name(case.test_id)}.evtx"


def select_cases_after_last_evtx(
    cases: list[TargetCase],
    resume_batch_dir: Path,
    dir_map: dict[str, str],
) -> tuple[list[TargetCase], ResumeFromEvtx]:
    """Return cases after the newest EVTX that maps to the current execution order."""
    if not resume_batch_dir.exists() or not resume_batch_dir.is_dir():
        raise ValueError(f"--resume-from-batch must be an existing batch folder: {resume_batch_dir}")

    ordered_cases = execution_order(cases)
    filename_to_position: dict[str, int] = {}
    for position, case in enumerate(ordered_cases):
        filename = evtx_name_for_case(case, dir_map).lower()
        if filename in filename_to_position:
            raise ValueError(
                "Cannot resume safely because multiple cases map to the same EVTX filename: "
                f"{evtx_name_for_case(case, dir_map)!r}"
            )
        filename_to_position[filename] = position

    evtx_dir = resume_batch_dir / "evtx"
    evtx_paths = sorted(
        evtx_dir.glob("*.evtx") if evtx_dir.exists() else [],
        key=lambda path: (path.stat().st_mtime_ns, path.name.lower()),
    )

    last_match: tuple[int, Path] | None = None
    ignored_evtx_count = 0
    evtx_paths_by_name: dict[str, Path] = {}
    for evtx_path in evtx_paths:
        filename = evtx_path.name.lower()
        position = filename_to_position.get(filename)
        if position is None:
            ignored_evtx_count += 1
            continue
        evtx_paths_by_name[filename] = evtx_path
        last_match = (position, evtx_path)

    if last_match is None:
        return cases, ResumeFromEvtx(
            batch_dir=resume_batch_dir,
            last_evtx_path=None,
            last_case=None,
            skipped_count=0,
            ignored_evtx_count=ignored_evtx_count,
            evtx_paths_by_name=evtx_paths_by_name,
        )

    last_position, last_evtx_path = last_match
    remaining_cases = ordered_cases[last_position + 1 :]
    return remaining_cases, ResumeFromEvtx(
        batch_dir=resume_batch_dir,
        last_evtx_path=last_evtx_path,
        last_case=ordered_cases[last_position],
        skipped_count=last_position + 1,
        ignored_evtx_count=ignored_evtx_count,
        evtx_paths_by_name=evtx_paths_by_name,
    )


def restored_result_for_case(
    case: TargetCase,
    evtx_path: Path | None,
    resume_batch_dir: Path,
) -> CaseResult:
    """Build a case result from an existing resume EVTX, or fail when it is missing."""
    result = CaseResult(case=case)
    if evtx_path is None:
        result.execution.status = "MISSING_RESUME_EVTX"
        result.zircolite_status = "NOT_EXECUTED"
        result.final_status = "execution_failed"
        result.note = f"no EVTX found for prior resume case in {resume_batch_dir / 'evtx'}"
        return result

    result.execution.status = "RESTORED_EVTX"
    result.can_execute = True
    result.evtx_path = str(evtx_path)
    result.evtx_name = evtx_path.name
    result.note = "restored from existing EVTX; execution was not rerun"
    return result


def run_case(case: TargetCase, evtx_path: Path, config: RunnerConfig) -> CaseResult:
    """Run one target command and collect process-tree evidence for it."""
    result = CaseResult(case=case)
    if not config.execute:
        result.execution.status = "DRY_RUN_READY"
        result.note = "dry-run only; add --execute to run"
        result.final_status = "not_testable"
        return result

    latest_before, error = latest_sysmon_record_id(config.record_read_timeout_seconds)
    if latest_before is None:
        result.execution.status = "FAILED_PRECHECK"
        result.note = f"failed to read start RecordID: {error}"
        result.zircolite_status = "NOT_EXECUTED"
        result.final_status = "execution_failed"
        return result

    result.start_record_id = latest_before
    timeout_seconds = case.timeout_seconds or config.timeout_seconds
    result.execution = execute_command(case, timeout_seconds)
    if not result.execution.started:
        result.note = result.execution.note or "runner failed to launch executor"
        result.zircolite_status = "NOT_EXECUTED"
        result.final_status = "execution_failed"
        return result
    if not command_execution_accepted(result.execution):
        result.note = command_execution_failure_reason(result.execution)
        result.zircolite_status = "NOT_EXECUTED"
        result.final_status = "execution_failed"
        return result

    if config.flush_wait_seconds > 0:
        time.sleep(config.flush_wait_seconds)

    root_event, process_tree, tree_error = collect_process_tree(
        result.start_record_id,
        case,
        result.execution.pid,
        config.process_tree_quiescence_seconds,
        config.process_tree_max_wait_seconds,
        config.record_read_timeout_seconds,
    )
    result.process_tree_events = process_tree
    if root_event:
        result.root_process_guid = root_event.process_guid
        result.root_process_commandline = root_event.commandline
    if not root_event or not process_tree:
        result.note = join_notes(result.execution.note, tree_error)
        result.zircolite_status = "NOT_EXECUTED"
        result.final_status = "execution_failed"
        return result

    validation = validate_payload_execution(result.execution, root_event, process_tree)
    if not validation.can_execute:
        result.note = join_notes(result.execution.note, validation.note)
        result.zircolite_status = "NOT_EXECUTED"
        result.final_status = "execution_failed"
        return result

    latest_after, error = latest_sysmon_record_id(config.record_read_timeout_seconds)
    result.end_record_id = latest_after if latest_after is not None else max(
        event.event_record_id for event in process_tree
    )
    if error:
        result.note = join_notes(result.execution.note, f"failed to read end RecordID: {error}")

    process_guids = {event.process_guid for event in process_tree if event.process_guid}
    ok, export_error = export_evtx_by_process_tree(
        evtx_path,
        result.start_record_id,
        result.end_record_id,
        process_guids,
        config.export_timeout_seconds,
    )
    if not ok:
        result.note = join_notes(result.execution.note, f"EVTX export failed: {export_error}")
        result.zircolite_status = "NOT_EXECUTED"
        result.final_status = "execution_failed"
        return result

    result.can_execute = True
    result.evtx_path = str(evtx_path)
    result.evtx_name = evtx_path.name
    result.note = join_notes(result.execution.note, result.note)
    return result


def run_target_batch(config: RunnerConfig) -> int:
    """Run the selected cases and write the batch result JSON."""
    selected_cases = select_cases(load_cases(config.config_path), config.offset, config.limit)
    full_grouped = group_by_technique(selected_cases)
    dir_map = technique_dir_map(list(full_grouped))
    resume_from_evtx: ResumeFromEvtx | None = None
    cases_to_run = selected_cases
    restored_results_by_technique: dict[str, list[CaseResult]] = {}
    if config.resume_from_batch:
        cases_to_run, resume_from_evtx = select_cases_after_last_evtx(
            selected_cases,
            config.resume_from_batch,
            dir_map,
        )
        if resume_from_evtx.last_case:
            restored_cases = execution_order(selected_cases)[: resume_from_evtx.skipped_count]
            evtx_paths_by_name = resume_from_evtx.evtx_paths_by_name or {}
            for case in restored_cases:
                evtx_path = evtx_paths_by_name.get(evtx_name_for_case(case, dir_map).lower())
                result = restored_result_for_case(case, evtx_path, resume_from_evtx.batch_dir)
                restored_results_by_technique.setdefault(case.technique_id, []).append(result)
    grouped_to_run = group_by_technique(cases_to_run)

    batch_id = now_batch_id()
    batch_dir = config.output_dir / batch_id
    batch_dir.mkdir(parents=True, exist_ok=True)
    batch_metadata = {
        "batch_id": batch_id,
        "created_at": iso_now(),
        "config": str(config.config_path),
        "path_config": str(config.path_config_path) if config.path_config_path else None,
        "selected_count": len(selected_cases),
        "execute_count": len(cases_to_run),
        "restored_count": sum(len(results) for results in restored_results_by_technique.values()),
        "execute": config.execute,
        "sysmon_log_name": SYSMON_LOG_NAME,
        "sysmon_event_id": SYSMON_EVENT_ID,
        "process_tree_quiescence_seconds": config.process_tree_quiescence_seconds,
        "process_tree_max_wait_seconds": config.process_tree_max_wait_seconds,
        "zircolite_path": str(config.zircolite_path) if config.zircolite_path else None,
        "ruleset": str(config.ruleset) if config.ruleset else None,
        "rules_dir": str(config.rules_dir) if config.rules_dir else None,
        "base_dir": str(config.base_dir),
        "zircolite_jsononly": config.zircolite_jsononly,
        "save_debug_artifacts": config.save_debug_artifacts,
        "resume_from_batch": str(config.resume_from_batch) if config.resume_from_batch else None,
        "resume_after_evtx": (
            str(resume_from_evtx.last_evtx_path)
            if resume_from_evtx and resume_from_evtx.last_evtx_path
            else None
        ),
        "resume_after_test_id": (
            resume_from_evtx.last_case.test_id
            if resume_from_evtx and resume_from_evtx.last_case
            else None
        ),
        "resume_skipped_count": resume_from_evtx.skipped_count if resume_from_evtx else 0,
        "resume_ignored_evtx_count": resume_from_evtx.ignored_evtx_count if resume_from_evtx else 0,
    }

    if resume_from_evtx:
        if resume_from_evtx.last_case and resume_from_evtx.last_evtx_path:
            print(
                "[+] Resume from "
                f"{resume_from_evtx.batch_dir}: last EVTX={resume_from_evtx.last_evtx_path.name} "
                f"-> [{resume_from_evtx.last_case.index}] {resume_from_evtx.last_case.test_id}; "
                f"restoring {resume_from_evtx.skipped_count} prior case(s)"
            )
        else:
            print(f"[+] Resume from {resume_from_evtx.batch_dir}: no matching EVTX found; running all selected cases")
        if resume_from_evtx.ignored_evtx_count:
            print(f"[+] Ignored {resume_from_evtx.ignored_evtx_count} EVTX file(s) that do not match this config")

    print(
        f"[+] Loaded {len(selected_cases)} selected case(s) in {len(full_grouped)} technique group(s); "
        f"executing {len(cases_to_run)} case(s)"
    )
    print(f"[+] Output: {batch_dir}")

    all_rows: list[dict[str, object]] = []
    all_results: list[CaseResult] = []
    technique_summaries: list[dict[str, object]] = []
    for technique_id in full_grouped:
        restored_results = restored_results_by_technique.get(technique_id, [])
        technique_cases = grouped_to_run.get(technique_id, [])
        print(
            f"\n[{technique_id}] cases={len(restored_results) + len(technique_cases)} "
            f"(restored={len(restored_results)}, execute={len(technique_cases)})"
        )

        results: list[CaseResult] = list(restored_results)
        for result in restored_results:
            evtx_name = Path(result.evtx_path).name if result.evtx_path else "<missing>"
            print(f"  [{result.case.index}] {result.case.test_id}: restored evtx={evtx_name}")
            if result.note:
                print(f"    note={result.note}")
        for case in technique_cases:
            test_stem = safe_name(case.test_id)
            print(f"  [{case.index}] {case.test_id}: {case.target_commandline}")
            evtx_path = batch_dir / "evtx" / f"{dir_map[technique_id]}__{test_stem}.evtx"
            result = run_case(case, evtx_path, config)
            results.append(result)
            evtx_name = Path(result.evtx_path).name if result.evtx_path else "<none>"
            print(
                f"    {result.execution.status} | records={result.start_record_id}-{result.end_record_id} "
                f"| evtx={evtx_name}"
            )
            if result.note:
                print(f"    note={result.note}")

        zircolite = (
            run_zircolite_for_technique(
                technique_id,
                [Path(result.evtx_path) for result in results if result.evtx_path],
                batch_dir,
                config,
            )
            if config.execute
            else ZircoliteRun(False, None, "NOT_RUN", None, note="dry-run")
        )
        classify_results(results, zircolite, config.rules_dir)

        for result in results:
            if config.save_debug_artifacts:
                evidence_path = batch_dir / "debug" / "cases" / f"{safe_name(result.case.test_id)}.json"
                write_json(evidence_path, case_evidence_to_dict(result, batch_id))
            row = case_result_to_dict(result, batch_id)
            all_rows.append(row)
            all_results.append(result)
            print(
                f"    result {result.case.test_id}: {row['final_status']} | "
                f"rules={row['triggered_rule_count']} | target_match={row['matched_target_rule']}"
            )

        technique_summaries.append(technique_summary_to_dict(technique_id, results, zircolite))

    write_result_csv(batch_dir, all_results, config.rules_dir)
    write_result_json(batch_dir, batch_metadata, all_rows, technique_summaries)
    print(f"\n[+] Result CSV  : {batch_dir / 'result.csv'}")
    print(f"\n[+] Result JSON : {batch_dir / 'result.json'}")
    return 0
