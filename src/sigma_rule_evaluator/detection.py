"""Run Zircolite detections and match alerts back to executed cases."""

from __future__ import annotations

import ntpath
import shutil
import subprocess
import sys
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Any

from .models import CaseResult, RuleInfo, RunnerConfig, ZircoliteRun
from .utils import int_or_none, join_notes, parse_json_file, safe_name, string_value, value_by_key


def build_zircolite_command(config: RunnerConfig, evtx_dir: Path, output_path: Path) -> list[str]:
    """Build the Zircolite command line for a temporary EVTX directory."""
    if config.zircolite_path is None:
        raise ValueError("--zircolite-path is required unless --no-zircolite is used")
    if config.ruleset is None:
        raise ValueError("--ruleset is required unless --no-zircolite is used")

    if config.zircolite_path.suffix.lower() == ".py":
        python_exe = config.python_exe or sys.executable
        cmd = [python_exe, str(config.zircolite_path)]
    else:
        cmd = [str(config.zircolite_path)]

    cmd.extend(["--evtx", str(evtx_dir), "--ruleset", str(config.ruleset), "--outfile", str(output_path)])
    return cmd


def validate_zircolite_paths(config: RunnerConfig) -> str:
    """Return an error message when a configured Zircolite path is missing."""
    if config.zircolite_path is None:
        return "--zircolite-path is required unless --no-zircolite is used"
    if not config.zircolite_path.exists():
        return f"Zircolite path does not exist: {config.zircolite_path}"
    if config.zircolite_path.suffix.lower() == ".py" and config.python_exe:
        python_exe = Path(config.python_exe)
        if not python_exe.exists():
            return f"Zircolite python_exe does not exist: {python_exe}"
    if config.ruleset is None:
        return "--ruleset is required unless --no-zircolite is used"
    if not config.ruleset.exists():
        return f"Zircolite ruleset does not exist: {config.ruleset}"
    if config.zircolite_config and not config.zircolite_config.exists():
        return f"Zircolite config does not exist: {config.zircolite_config}"
    return ""


def run_zircolite_for_technique(
    technique: str,
    evtx_paths: list[Path],
    batch_dir: Path,
    config: RunnerConfig,
) -> ZircoliteRun:
    """Run Zircolite once for all EVTX files in a technique group."""
    if config.no_zircolite:
        return ZircoliteRun(False, None, "NOT_RUN", None, note="--no-zircolite set")
    if not config.zircolite_path:
        return ZircoliteRun(False, None, "NOT_RUN", None, note="--zircolite-path not provided")
    if not config.ruleset:
        return ZircoliteRun(False, None, "NOT_RUN", None, note="--ruleset not provided")
    if not evtx_paths:
        return ZircoliteRun(False, None, "NO_EVTX", None, note="no exported EVTX files")
    path_error = validate_zircolite_paths(config)
    if path_error:
        return ZircoliteRun(False, None, "ZIRCOLITE_FAILED", None, note=path_error)

    debug_dir = batch_dir / "debug" / "zircolite" / safe_name(technique)
    result_path: str | None = None

    with tempfile.TemporaryDirectory(prefix="sigma_rule_evaluator_zircolite_") as temp_root_text:
        temp_root = Path(temp_root_text)
        evtx_dir = temp_root / "evtx"
        evtx_dir.mkdir(parents=True, exist_ok=True)
        for evtx_path in evtx_paths:
            shutil.copy2(evtx_path, evtx_dir / evtx_path.name)

        output_path = temp_root / "zircolite_results.json"
        cmd = build_zircolite_command(config, evtx_dir, output_path)
        cwd = str(config.zircolite_path.parent) if config.zircolite_path is not None else None

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=config.zircolite_timeout_seconds,
                cwd=cwd,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ZircoliteRun(True, None, "ZIRCOLITE_TIMEOUT", None)
        except OSError as exc:
            return ZircoliteRun(True, None, "ZIRCOLITE_FAILED", None, note=str(exc))

        if config.save_debug_artifacts:
            debug_dir.mkdir(parents=True, exist_ok=True)
            (debug_dir / "stdout.txt").write_text(proc.stdout or "", encoding="utf-8", errors="replace")
            (debug_dir / "stderr.txt").write_text(proc.stderr or "", encoding="utf-8", errors="replace")

        if not output_path.exists():
            if (proc.stdout or "").strip().startswith(("[", "{")):
                output_path.write_text(proc.stdout, encoding="utf-8", errors="replace")
            else:
                note = proc.stderr.strip() or proc.stdout.strip() or "Zircolite did not create output file"
                return ZircoliteRun(True, proc.returncode, "ZIRCOLITE_FAILED", None, note=note)

        if config.save_debug_artifacts:
            debug_result_path = debug_dir / "results.json"
            shutil.copy2(output_path, debug_result_path)
            result_path = str(debug_result_path)

        try:
            data = parse_json_file(output_path)
        except Exception as exc:
            return ZircoliteRun(True, proc.returncode, "ZIRCOLITE_FAILED", result_path, note=str(exc))

    detections = data if isinstance(data, list) else data.get("detections", [])
    if not isinstance(detections, list):
        detections = []
    return ZircoliteRun(True, proc.returncode, "OK", result_path, detections=detections)


def extract_rule_info(detection: dict[str, Any]) -> RuleInfo:
    """Extract rule metadata from a Zircolite detection object."""
    sources = [detection]
    for key in ("rule", "Rule", "metadata", "meta"):
        value = detection.get(key)
        if isinstance(value, dict):
            sources.append(value)

    def first(names: set[str]) -> str:
        """Return the first non-empty value found under candidate names."""
        for source in sources:
            value = value_by_key(source, names)
            if value not in (None, ""):
                return string_value(value)
        return ""

    title = first({"title", "name", "rule_title", "ruletitle", "sigma_title"})
    rule_name = first({"rule_name", "rulename", "sigma_name"})
    return RuleInfo(
        id=first({"id", "rule_id", "ruleid", "rule_uuid", "sigma_id", "sigmaid"}),
        title=title,
        rule_name=rule_name,
        sigmafile=first({"sigmafile", "rule_file", "rulefile", "filename"}),
        level=first({"rule_level", "level"}),
    )


def rule_label(rule: RuleInfo) -> str:
    """Return a readable display label for a rule."""
    label = rule.rule_name or rule.title or rule.id or rule.sigmafile
    if rule.id and label != rule.id:
        return f"{label} ({rule.id})"
    return label


def normalize_rule_token(value: str) -> str:
    """Normalize a rule identifier or title for equality checks."""
    return value.strip().strip('"').strip("'").lower()


@lru_cache(maxsize=512)
def sigma_rule_identity(rule_token: str, rules_dir_text: str = "rules") -> tuple[str, str]:
    """Look up a Sigma rule id and title from a target rule token."""
    token = rule_token.strip().strip('"').strip("'")
    if not token:
        return "", ""
    raw_path = Path(token)
    rules_dir = Path(rules_dir_text)
    candidates: list[Path] = []
    if raw_path.suffix.lower() in {".yml", ".yaml"}:
        candidates.append(raw_path)
        candidates.append(rules_dir / raw_path.name)
    else:
        candidates.extend(
            [
                raw_path.with_suffix(".yml"),
                raw_path.with_suffix(".yaml"),
                rules_dir / f"{token}.yml",
                rules_dir / f"{token}.yaml",
            ]
        )

    for path in candidates:
        if not path.exists() or not path.is_file():
            continue
        rule_id = ""
        title = ""
        try:
            lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or ":" not in stripped:
                continue
            key, value = stripped.split(":", 1)
            normalized_key = key.strip().lower()
            normalized_value = value.strip().strip('"').strip("'")
            if normalized_key == "id" and not rule_id:
                rule_id = normalized_value
            elif normalized_key == "title" and not title:
                title = normalized_value
            if rule_id and title:
                return rule_id, title
        if rule_id or title:
            return rule_id, title
    return "", ""


def target_rule_matches(rule: RuleInfo, target_rule: str, rules_dir: Path | None = None) -> bool:
    """Return whether a triggered rule matches the case target rule."""
    target = normalize_rule_token(target_rule)
    if not target:
        return False
    rule_id, rule_title = sigma_rule_identity(target_rule, str(rules_dir or Path("rules")))
    target_candidates = {target}
    for candidate in (rule_id, rule_title):
        normalized = normalize_rule_token(candidate)
        if normalized:
            target_candidates.add(normalized)

    rule_candidates = [
        rule.id,
        rule.title,
        rule.rule_name,
        rule.sigmafile,
        Path(rule.sigmafile).stem if rule.sigmafile else "",
        ntpath.splitext(ntpath.basename(rule.sigmafile.replace("/", "\\")))[0] if rule.sigmafile else "",
    ]
    return any(normalize_rule_token(candidate) in target_candidates for candidate in rule_candidates if candidate)


def original_logfile_matches(event: dict[str, Any], evtx_name: str) -> bool:
    """Check whether a detection event came from the case EVTX file."""
    original = value_by_key(event, {"OriginalLogfile", "original_logfile", "original_log_file"})
    if not original:
        return False
    return ntpath.basename(str(original).replace("/", "\\")) == evtx_name


def detection_events(detection: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the event dictionaries contained in a detection record."""
    matches = detection.get("matches")
    if isinstance(matches, list):
        return [item for item in matches if isinstance(item, dict)]
    return [detection]


def process_tree_guids(result: CaseResult) -> set[str]:
    """Return all ProcessGuid values collected for a case."""
    return {event.process_guid for event in result.process_tree_events if event.process_guid}


def process_tree_commandlines(result: CaseResult) -> set[str]:
    """Return all command lines collected for a case process tree."""
    commandlines: set[str] = set()
    for event in result.process_tree_events:
        if event.commandline:
            commandlines.add(event.commandline)
    return commandlines


def event_in_process_tree(event: dict[str, Any], result: CaseResult) -> bool:
    """Check whether a detection event belongs to the collected process tree."""
    known_guids = process_tree_guids(result)
    process_guid = string_value(value_by_key(event, {"ProcessGuid", "process_guid"}))
    parent_process_guid = string_value(value_by_key(event, {"ParentProcessGuid", "parent_process_guid"}))
    if process_guid and process_guid in known_guids:
        return True
    if parent_process_guid and parent_process_guid in known_guids:
        return True

    commandline = string_value(value_by_key(event, {"CommandLine", "command_line"}))
    parent_commandline = string_value(value_by_key(event, {"ParentCommandLine", "parent_command_line"}))
    known_commandlines = process_tree_commandlines(result)
    return bool(
        (commandline and commandline in known_commandlines)
        or (parent_commandline and parent_commandline in known_commandlines)
    )


def rule_info_for_event(rule: RuleInfo, event: dict[str, Any]) -> RuleInfo:
    """Attach event-level process fields to extracted rule metadata."""
    return RuleInfo(
        id=rule.id,
        title=rule.title,
        rule_name=rule.rule_name,
        sigmafile=rule.sigmafile,
        level=rule.level,
        process_guid=string_value(value_by_key(event, {"ProcessGuid", "process_guid"})),
        parent_process_guid=string_value(value_by_key(event, {"ParentProcessGuid", "parent_process_guid"})),
        commandline=string_value(value_by_key(event, {"CommandLine", "command_line"})),
        parent_commandline=string_value(value_by_key(event, {"ParentCommandLine", "parent_command_line"})),
        image=string_value(value_by_key(event, {"Image"})),
        parent_image=string_value(value_by_key(event, {"ParentImage", "parent_image"})),
        original_logfile=string_value(value_by_key(event, {"OriginalLogfile", "original_logfile", "original_log_file"})),
        event_record_id=int_or_none(value_by_key(event, {"EventRecordID", "event_record_id"})),
    )


def alert_key(rule: RuleInfo) -> tuple[str, str, str, str, str, str]:
    """Return a stable de-duplication key for a rule alert."""
    return (
        rule.id.lower(),
        rule.title.lower(),
        rule.rule_name.lower(),
        rule.sigmafile.lower(),
        rule.process_guid.lower(),
        rule.commandline.lower(),
    )


def collect_triggered_rules_for_case(detections: list[Any], result: CaseResult) -> list[RuleInfo]:
    """Collect unique triggered rules that belong to one case result."""
    rules: list[RuleInfo] = []
    seen: set[tuple[str, str, str, str, str, str]] = set()
    for detection in detections:
        if not isinstance(detection, dict):
            continue
        rule = extract_rule_info(detection)
        for event in detection_events(detection):
            if not result.evtx_name or not original_logfile_matches(event, result.evtx_name):
                continue
            if result.process_tree_events and not event_in_process_tree(event, result):
                continue
            alert = rule_info_for_event(rule, event)
            key = alert_key(alert)
            if key in seen:
                continue
            seen.add(key)
            rules.append(alert)
    return rules


def classify_results(
    case_results: list[CaseResult],
    zircolite: ZircoliteRun,
    rules_dir: Path | None = None,
) -> None:
    """Assign final status values after Zircolite has run for a group."""
    for result in case_results:
        if result.final_status == "execution_failed" or (result.execution.started and not result.can_execute):
            result.final_status = "execution_failed"
            result.zircolite_status = "NOT_EXECUTED"
            continue
        if result.final_status == "not_testable" and not result.evtx_name:
            result.zircolite_status = zircolite.status if zircolite.status != "OK" else "NOT_TESTABLE"
            continue
        if not result.evtx_name:
            result.final_status = "not_testable"
            result.zircolite_status = "NOT_TESTABLE"
            continue
        if zircolite.status != "OK":
            result.final_status = "not_testable"
            result.zircolite_status = zircolite.status
            result.note = join_notes(result.note, zircolite.note)
            continue

        result.triggered_rules = collect_triggered_rules_for_case(zircolite.detections, result)
        result.matched_target_rule = any(
            target_rule_matches(rule, result.case.target_rule, rules_dir) for rule in result.triggered_rules
        )
        if result.matched_target_rule:
            result.zircolite_status = "MATCHED_TARGET_RULE"
            result.final_status = "matched_target_rule"
        elif result.triggered_rules:
            result.zircolite_status = "TRIGGERED_OTHER_RULE"
            result.final_status = "bypass_target_rule"
        else:
            result.zircolite_status = "NOT_DETECTED"
            result.final_status = "bypass_all_rules"
