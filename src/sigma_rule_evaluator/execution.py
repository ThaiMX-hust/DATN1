"""Execute target command lines through the configured Windows shell."""

from __future__ import annotations

import os
import ntpath
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Sequence

from .models import ExecutionResult, SysmonProcessEvent, TargetCase


ACCEPTED_NONZERO_PATTERNS = (
    "the system cannot find the file specified",
    "the system cannot find the path specified",
    "cannot find path",
    "could not find file",
    "no such file or directory",
    "file not found",
    "path not found",
)

FAILED_COMMAND_PATTERNS = (
    "is not recognized as an internal or external command",
    "is not recognized as the name of a cmdlet",
    "is not a valid statement",
    "invalid argument",
    "was not found",
    "commandnotfoundexception",
    "the syntax of the command is incorrect",
    "parsererror",
    "missing expression after",
    "unexpected token",
    "missing closing",
    "incomplete string",
    "access is denied"
)


@dataclass(frozen=True)
class ShellInvocation:
    """Resolved process invocation for a target case."""

    popen_args: list[str] | str
    launch_commandline: str
    shell_wrapped: bool


@dataclass(frozen=True)
class PayloadValidation:
    """Outcome of checking whether the launched command produced useful evidence."""

    can_execute: bool
    payload_observed: bool
    status: str
    note: str = ""


SHELL_PROCESS_NAMES = {"cmd.exe", "powershell.exe", "pwsh.exe"}


def first_command_token(commandline: str) -> str:
    """Return the executable-looking first token from a Windows command line."""
    stripped = commandline.strip()
    if not stripped:
        return ""
    if stripped[0] in {"'", '"'}:
        quote = stripped[0]
        end_index = stripped.find(quote, 1)
        return stripped[1:end_index] if end_index >= 0 else stripped[1:]
    return stripped.split(maxsplit=1)[0]


def command_starts_with_shell(commandline: str, shell: str) -> bool:
    """Return whether commandline already starts with the configured shell executable."""
    token = first_command_token(commandline)
    return ntpath.basename(token).lower() == shell.lower()


def commandline_from_args(args: Sequence[str] | str) -> str:
    """Return a readable launch command line from Popen arguments."""
    if isinstance(args, str):
        return args
    return " ".join(args)


def build_shell_invocation(case: TargetCase) -> ShellInvocation:
    """Build the shell invocation used to run one target case."""
    commandline = case.target_commandline
    if case.shell == "cmd.exe":
        if command_starts_with_shell(commandline, case.shell):
            return ShellInvocation(commandline, commandline, False)
        args = ["cmd.exe", "/c", commandline]
        return ShellInvocation(args, commandline_from_args(args), True)
    if case.shell == "powershell.exe":
        if command_starts_with_shell(commandline, case.shell):
            return ShellInvocation(commandline, commandline, False)
        args = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", commandline]
        return ShellInvocation(args, commandline_from_args(args), True)
    if case.shell == "pwsh.exe":
        if command_starts_with_shell(commandline, case.shell):
            return ShellInvocation(commandline, commandline, False)
        args = ["pwsh.exe", "-NoProfile", "-Command", commandline]
        return ShellInvocation(args, commandline_from_args(args), True)
    raise ValueError(f"Unsupported shell: {case.shell}")


def build_shell_command(case: TargetCase) -> list[str] | str:
    """Build Popen arguments for one target case."""
    return build_shell_invocation(case).popen_args


def execution_text(result: ExecutionResult) -> str:
    """Return normalized process output used for execution classification."""
    return "\n".join(part for part in (result.stdout, result.stderr, result.note) if part).lower()


def has_any_pattern(text: str, patterns: tuple[str, ...]) -> bool:
    """Return whether text contains any known classification pattern."""
    return any(pattern in text for pattern in patterns)


def first_matching_pattern(text: str, patterns: tuple[str, ...]) -> str:
    """Return matching known classification patterns as a compact note."""
    return "; ".join(pattern for pattern in patterns if pattern in text)


def command_execution_accepted(result: ExecutionResult) -> bool:
    """Return whether a command execution is accepted for Sysmon collection."""
    if not result.started:
        return False
    if result.timed_out:
        return True
    if result.exit_code == 0:
        return True

    text = execution_text(result)
    if has_any_pattern(text, FAILED_COMMAND_PATTERNS):
        return False
    if has_any_pattern(text, ACCEPTED_NONZERO_PATTERNS):
        return True
    return True


def command_execution_failure_reason(result: ExecutionResult) -> str:
    """Return the reason a command execution is not accepted."""
    if not result.started:
        return result.note or "process was not started"
    text = execution_text(result)
    if has_any_pattern(text, FAILED_COMMAND_PATTERNS):
        return "command failed before useful execution: missing binary or syntax error"
    return "command execution was not accepted for Sysmon collection"


def same_process(left: SysmonProcessEvent, right: SysmonProcessEvent) -> bool:
    """Return whether two Sysmon rows refer to the same process event."""
    if left.process_guid and right.process_guid:
        return left.process_guid == right.process_guid
    return left.event_record_id == right.event_record_id


def payload_event_observed(root_event: SysmonProcessEvent, process_tree: list[SysmonProcessEvent]) -> bool:
    """Return whether a non-shell child process appears in the collected tree."""
    for event in process_tree:
        if same_process(event, root_event):
            continue
        image_name = ntpath.basename(event.image).lower()
        if image_name and image_name not in SHELL_PROCESS_NAMES:
            return True
    return False


def child_event_observed(root_event: SysmonProcessEvent, process_tree: list[SysmonProcessEvent]) -> bool:
    """Return whether the collected tree contains any child process."""
    return any(not same_process(event, root_event) for event in process_tree)


def validate_payload_execution(
    execution: ExecutionResult,
    root_event: SysmonProcessEvent,
    process_tree: list[SysmonProcessEvent],
) -> PayloadValidation:
    """Classify whether execution produced usable process-tree evidence."""
    text = execution_text(execution)
    error_pattern = first_matching_pattern(text, FAILED_COMMAND_PATTERNS)
    payload_observed = payload_event_observed(root_event, process_tree)
    execution.payload_observed = payload_observed

    if error_pattern:
        status = "command_output_error"
        execution.payload_validation_status = status
        return PayloadValidation(False, payload_observed, status, error_pattern)

    if execution.exit_code == 0:
        status = "exit_0"
        execution.payload_validation_status = status
        return PayloadValidation(True, payload_observed, status)

    if payload_observed:
        status = "nonzero_exit_payload_observed"
        execution.payload_validation_status = status
        return PayloadValidation(True, payload_observed, status)

    if child_event_observed(root_event, process_tree):
        status = "nonzero_exit_child_observed"
        execution.payload_validation_status = status
        return PayloadValidation(True, payload_observed, status)

    status = "nonzero_exit_no_child"
    execution.payload_validation_status = status
    return PayloadValidation(False, payload_observed, status)


def kill_process_tree(pid: int) -> str:
    """Terminate a process tree and return any cleanup output or error."""
    if os.name == "nt":
        try:
            result = subprocess.run(
                ["taskkill.exe", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return "\n".join(part for part in (result.stdout, result.stderr) if part)
        except Exception as exc:
            return str(exc)
    try:
        os.kill(pid, 9)
        return ""
    except Exception as exc:
        return str(exc)


def execute_command(case: TargetCase, timeout_seconds: int) -> ExecutionResult:
    """Run a target case and capture process execution metadata."""
    invocation = build_shell_invocation(case)
    start_dt = datetime.now().astimezone()
    start_monotonic = time.monotonic()
    result = ExecutionResult(
        started=False,
        start_time=start_dt.isoformat(),
        status="NOT_RUN",
        launch_commandline=invocation.launch_commandline,
        shell_wrapped=invocation.shell_wrapped,
    )

    try:
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        proc = subprocess.Popen(
            invocation.popen_args,
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=creationflags,
            start_new_session=os.name != "nt",
        )
        result.started = True
        result.pid = proc.pid
        try:
            stdout, stderr = proc.communicate(timeout=timeout_seconds)
            result.exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            result.timed_out = True
            kill_note = kill_process_tree(proc.pid)
            try:
                proc.kill()
            except Exception as exc:
                kill_note = "\n".join(part for part in (kill_note, str(exc)) if part)
            stdout, stderr = proc.communicate()
            result.exit_code = None
            result.note = kill_note
        result.stdout = stdout or ""
        result.stderr = stderr or ""
    except Exception as exc:
        result.note = str(exc)
        result.status = "FAILED_LAUNCH"

    end_dt = datetime.now().astimezone()
    result.end_time = end_dt.isoformat()
    result.duration_ms = int((time.monotonic() - start_monotonic) * 1000)

    if result.status == "FAILED_LAUNCH":
        return result
    if result.timed_out:
        result.status = "FAILED_TIMEOUT"
    elif not result.started:
        result.status = "FAILED_LAUNCH"
    elif result.exit_code == 0:
        result.status = "EXECUTED_EXIT_0"
    else:
        result.status = "EXECUTED_EXIT_NONZERO"
    return result
