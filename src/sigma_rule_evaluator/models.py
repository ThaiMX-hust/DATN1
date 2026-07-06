"""Shared data models and constants for Sigma rule evaluation runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


SYSMON_LOG_NAME = "Microsoft-Windows-Sysmon/Operational"
SYSMON_EVENT_ID = 1


@dataclass(frozen=True)
class RunnerConfig:
    """Runtime configuration resolved from CLI arguments."""

    config_path: Path
    output_dir: Path
    base_dir: Path
    path_config_path: Path | None = None
    rules_dir: Path | None = None
    resume_from_batch: Path | None = None
    offset: int = 0
    limit: int | None = None
    execute: bool = False
    timeout_seconds: int = 2
    flush_wait_seconds: float = 1.0 # đợi sau khi cmdline chạy để sysmon thu log
    record_read_timeout_seconds: int = 15 # thời gian tối đa chờ đọc record
    export_timeout_seconds: int = 60
    process_tree_quiescence_seconds: float = 2.0   # thơi gian chờ process tree khong phát sinh thêm event
    process_tree_max_wait_seconds: float = 15.0 # thời gian tối đa chờ process tree
    no_zircolite: bool = False
    zircolite_path: Path | None = None
    python_exe: str | None = None
    ruleset: Path | None = None
    zircolite_config: Path | None = None
    zircolite_timeout_seconds: int = 180
    save_debug_artifacts: bool = False


@dataclass
class TargetCase:
    """One target command-line test case loaded from input JSON."""

    index: int
    test_id: str
    target_commandline: str
    target_rule: str
    technique_id: str
    mutation: str
    shell: str
    timeout_seconds: int | None
    raw: dict[str, Any]


@dataclass
class ExecutionResult:
    """Execution metadata captured after launching a target command."""

    started: bool = False
    pid: int | None = None
    start_time: str | None = None
    end_time: str | None = None
    duration_ms: int | None = None
    exit_code: int | None = None
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""
    status: str = "NOT_RUN"
    note: str = ""
    launch_commandline: str = ""
    shell_wrapped: bool = False
    payload_observed: bool = False
    payload_validation_status: str = ""



@dataclass
class RuleInfo:
    """Rule metadata and matching process details from a detection alert."""

    id: str = ""
    title: str = ""
    rule_name: str = ""
    sigmafile: str = ""
    level: str = ""
    process_guid: str = ""
    parent_process_guid: str = ""
    commandline: str = ""
    parent_commandline: str = ""
    image: str = ""
    parent_image: str = ""
    original_logfile: str = ""
    event_record_id: int | None = None


@dataclass
class SysmonProcessEvent:
    """Normalized Sysmon Event ID 1 process-create data."""

    event_record_id: int
    time_created: str = ""
    process_guid: str = ""
    parent_process_guid: str = ""
    process_id: int | None = None
    parent_process_id: int | None = None
    commandline: str = ""
    parent_commandline: str = ""
    image: str = ""
    parent_image: str = ""


@dataclass
class CaseResult:
    """Full execution, evidence, and detection result for one target case."""

    case: TargetCase
    execution: ExecutionResult = field(default_factory=ExecutionResult)
    can_execute: bool = False
    start_record_id: int | None = None
    end_record_id: int | None = None
    evtx_path: str | None = None
    evtx_name: str | None = None
    root_process_guid: str | None = None
    root_process_commandline: str | None = None
    process_tree_events: list[SysmonProcessEvent] = field(default_factory=list)
    zircolite_status: str = "NOT_RUN"
    triggered_rules: list[RuleInfo] = field(default_factory=list)
    matched_target_rule: bool = False
    final_status: str = "not_testable"
    note: str = ""


@dataclass
class ZircoliteRun:
    """Outcome and parsed detections from one Zircolite invocation."""

    ran: bool
    exit_code: int | None
    status: str
    result_path: str | None
    detections: list[Any] = field(default_factory=list)
    note: str = ""
