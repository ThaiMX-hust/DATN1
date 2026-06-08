"""Coordinate case execution, EVTX export, detection, and result writing."""

from __future__ import annotations

import time
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
    cases = select_cases(load_cases(config.config_path), config.offset, config.limit)
    grouped = group_by_technique(cases)
    dir_map = technique_dir_map(list(grouped))

    batch_id = now_batch_id()
    batch_dir = config.output_dir / batch_id
    batch_dir.mkdir(parents=True, exist_ok=True)
    batch_metadata = {
        "batch_id": batch_id,
        "created_at": iso_now(),
        "config": str(config.config_path),
        "path_config": str(config.path_config_path) if config.path_config_path else None,
        "selected_count": len(cases),
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
    }

    print(f"[+] Loaded {len(cases)} case(s) in {len(grouped)} technique group(s)")
    print(f"[+] Output: {batch_dir}")

    all_rows: list[dict[str, object]] = []
    all_results: list[CaseResult] = []
    technique_summaries: list[dict[str, object]] = []
    for technique_id, technique_cases in grouped.items():
        print(f"\n[{technique_id}] cases={len(technique_cases)}")

        results: list[CaseResult] = []
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
