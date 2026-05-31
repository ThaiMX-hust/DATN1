"""Convert run results into JSON-ready report dictionaries."""

from __future__ import annotations

import csv
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .detection import rule_label, sigma_rule_identity, target_rule_matches
from .excel_templates import TEMPLATE_HEADERS
from .log_collection import eventlog_process_tree_query, eventlog_recordid_query
from .models import CaseResult, ZircoliteRun
from .utils import write_json


def execution_error(result: CaseResult) -> str | None:
    """Return the best available execution error message for a case result."""
    error = result.execution.note or result.note
    if result.execution.status in {"FAILED_LAUNCH", "FAILED_TIMEOUT"} and not error:
        error = result.execution.stderr
    if not error and result.execution.stderr:
        error = result.execution.stderr
    return error.strip() if error else None


def process_tree_commandlines(result: CaseResult) -> list[str]:
    """Return unique command lines from a case process tree in event order."""
    commandlines: list[str] = []
    seen: set[str] = set()
    for event in result.process_tree_events:
        if not event.commandline or event.commandline in seen:
            continue
        seen.add(event.commandline)
        commandlines.append(event.commandline)
    return commandlines


def triggered_rule_to_dict(rule: Any) -> dict[str, Any]:
    """Serialize a triggered Zircolite rule alert."""
    return {
        "rule_id": rule.id,
        "rule_title": rule.title,
        "rule_name": rule.rule_name,
        "sigmafile": rule.sigmafile,
        "level": rule.level,
        "process_guid": rule.process_guid,
        "parent_process_guid": rule.parent_process_guid,
        "commandline": rule.commandline,
        "parent_commandline": rule.parent_commandline,
        "image": rule.image,
        "parent_image": rule.parent_image,
        "original_logfile": rule.original_logfile,
        "event_record_id": rule.event_record_id,
    }


def case_result_to_dict(result: CaseResult, batch_id: str) -> dict[str, Any]:
    """Serialize the public summary row for a case result."""
    rules = [triggered_rule_to_dict(rule) for rule in result.triggered_rules]
    return {
        "batch_id": batch_id,
        "test_id": result.case.test_id,
        "technique_id": result.case.technique_id,
        "mutation": result.case.mutation,
        "target_commandline": result.case.target_commandline,
        "target_rule": result.case.target_rule,
        "shell": result.case.shell,
        "can_execute": result.can_execute,
        "execution_status": result.execution.status,
        "launch_commandline": result.execution.launch_commandline,
        "shell_wrapped": result.execution.shell_wrapped,
        "payload_observed": result.execution.payload_observed,
        "payload_validation_status": result.execution.payload_validation_status,
        "exit_code": result.execution.exit_code,
        "timeout": result.execution.timed_out,
        "execution_error": execution_error(result),
        "start_record_id": result.start_record_id,
        "end_record_id": result.end_record_id,
        "evtx_path": result.evtx_path or "",
        "root_process_guid": result.root_process_guid,
        "root_process_commandline": result.root_process_commandline,
        "process_tree_commandlines": process_tree_commandlines(result),
        "zircolite_status": result.zircolite_status,
        "triggered_rule_count": len(result.triggered_rules),
        "triggered_rules": rules,
        "matched_target_rule": result.matched_target_rule,
        "final_status": result.final_status,
        "note": result.note,
    }


def case_evidence_to_dict(result: CaseResult, batch_id: str) -> dict[str, Any]:
    """Serialize detailed evidence for a case debug artifact."""
    process_guids = {event.process_guid for event in result.process_tree_events if event.process_guid}
    record_query = None
    if result.start_record_id is not None and result.end_record_id is not None:
        if process_guids:
            record_query = eventlog_process_tree_query(result.start_record_id, result.end_record_id, process_guids)
        else:
            record_query = eventlog_recordid_query(result.start_record_id, result.end_record_id)
    return {
        "batch_id": batch_id,
        "case": {
            "index": result.case.index,
            "test_id": result.case.test_id,
            "target_commandline": result.case.target_commandline,
            "target_rule": result.case.target_rule,
            "technique_id": result.case.technique_id,
            "mutation": result.case.mutation,
            "shell": result.case.shell,
            "timeout_seconds": result.case.timeout_seconds,
            "raw": result.case.raw,
        },
        "execution": result.execution.__dict__,
        "can_execute": result.can_execute,
        "payload_observed": result.execution.payload_observed,
        "payload_validation_status": result.execution.payload_validation_status,
        "root_process_guid": result.root_process_guid,
        "root_process_commandline": result.root_process_commandline,
        "process_tree": [asdict(event) for event in result.process_tree_events],
        "record_range": {
            "start_record_id": result.start_record_id,
            "end_record_id": result.end_record_id,
            "query": record_query,
            "evtx_path": result.evtx_path,
        },
        "zircolite": {
            "status": result.zircolite_status,
            "triggered_rules": [rule.__dict__ for rule in result.triggered_rules],
            "matched_target_rule": result.matched_target_rule,
        },
        "summary": case_result_to_dict(result, batch_id),
    }


def markdown_cell(value: Any) -> str:
    """Escape a value for safe use inside a Markdown table cell."""
    text = str(value or "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.replace("|", "\\|").replace("\n", "<br>")


def technique_summary_to_dict(
    technique_id: str,
    results: list[CaseResult],
    zircolite: ZircoliteRun,
) -> dict[str, Any]:
    """Serialize the grouped summary for one technique id."""
    return {
        "technique_id": technique_id,
        "case_count": len(results),
        "evtx_count": sum(1 for result in results if result.evtx_path),
        "zircolite": {
            "ran": zircolite.ran,
            "exit_code": zircolite.exit_code,
            "status": zircolite.status,
            "result_path": zircolite.result_path,
            "detection_count": len(zircolite.detections),
            "note": zircolite.note,
        },
        "final_status_counts": dict(Counter(result.final_status for result in results)),
        "test_ids": [result.case.test_id for result in results],
    }


def csv_bool(value: bool) -> str:
    """Return a spreadsheet-friendly boolean value."""
    return "TRUE" if value else "FALSE"


def target_rule_commandline(result: CaseResult, rules_dir: Path | None) -> str:
    """Return the command line that triggered the target rule, when present."""
    for rule in result.triggered_rules:
        if target_rule_matches(rule, result.case.target_rule, rules_dir):
            return rule.commandline or rule.parent_commandline
    return ""


def trigger_rule_summary(result: CaseResult) -> str:
    """Return a compact semicolon-separated list of triggered rule labels."""
    return "; ".join(rule_label(rule) for rule in result.triggered_rules if rule_label(rule))


def result_csv_row(result: CaseResult, rules_dir: Path | None) -> list[str]:
    """Convert one case result to the requested tabular CSV shape."""
    rule_id, title = sigma_rule_identity(result.case.target_rule, str(rules_dir or Path("rules")))
    return [
        result.case.technique_id,
        result.case.target_rule,
        title,
        rule_id,
        target_rule_commandline(result, rules_dir),
        result.case.target_commandline,
        csv_bool(result.can_execute),
        csv_bool(result.final_status in {"bypass_target_rule", "bypass_all_rules"}),
        csv_bool(result.final_status == "bypass_all_rules"),
        trigger_rule_summary(result),
    ]


def write_result_csv(batch_dir: Path, results: list[CaseResult], rules_dir: Path | None) -> None:
    """Write the requested tab-delimited result CSV file."""
    csv_path = batch_dir / "result.csv"
    with csv_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(TEMPLATE_HEADERS)
        for result in results:
            writer.writerow(result_csv_row(result, rules_dir))


def write_result_json(
    batch_dir: Path,
    batch: dict[str, Any],
    cases: list[dict[str, Any]],
    techniques: list[dict[str, Any]],
) -> None:
    """Write the complete batch result JSON file."""
    write_json(
        batch_dir / "result.json",
        {
            "batch": batch,
            "counts": dict(Counter(row["final_status"] for row in cases)),
            "techniques": techniques,
            "cases": cases,
        },
    )
