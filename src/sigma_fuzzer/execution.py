"""Execute target command lines through the configured Windows shell."""

from __future__ import annotations

import os
import subprocess
import time
from datetime import datetime

from .models import ExecutionResult, TargetCase


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
    "was not found",
    "commandnotfoundexception",
    "the syntax of the command is incorrect",
    "parsererror",
    "missing expression after",
    "unexpected token",
    "missing closing",
    "incomplete string",
)


def build_shell_command(case: TargetCase) -> list[str]:
    """Build the shell invocation used to run one target case."""
    commandline = case.target_commandline
    if case.shell == "cmd.exe":
        return ["cmd.exe", "/c", commandline]
    if case.shell == "powershell.exe":
        return ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", commandline]
    if case.shell == "pwsh.exe":
        return ["pwsh.exe", "-NoProfile", "-Command", commandline]
    raise ValueError(f"Unsupported shell: {case.shell}")


def execution_text(result: ExecutionResult) -> str:
    """Return normalized process output used for execution classification."""
    return "\n".join(part for part in (result.stdout, result.stderr, result.note) if part).lower()


def has_any_pattern(text: str, patterns: tuple[str, ...]) -> bool:
    """Return whether text contains any known classification pattern."""
    return any(pattern in text for pattern in patterns)


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
    cmd = build_shell_command(case)
    start_dt = datetime.now().astimezone()
    start_monotonic = time.monotonic()
    result = ExecutionResult(started=False, start_time=start_dt.isoformat(), status="NOT_RUN")

    try:
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        proc = subprocess.Popen(
            cmd,
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
