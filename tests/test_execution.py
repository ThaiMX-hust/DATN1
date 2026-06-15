from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sigma_rule_evaluator.execution import (
    build_shell_invocation,
    command_execution_failure_reason,
    execute_command,
    validate_payload_execution,
)
from sigma_rule_evaluator.models import ExecutionResult, SysmonProcessEvent, TargetCase


def make_case(commandline: str, shell: str = "cmd.exe") -> TargetCase:
    return TargetCase(
        index=1,
        test_id="test",
        target_commandline=commandline,
        target_rule="rule",
        technique_id="technique",
        mutation="manual",
        shell=shell,
        timeout_seconds=10,
        raw={},
    )


def process_event(
    record_id: int,
    guid: str,
    image: str,
    commandline: str,
    parent_guid: str = "",
) -> SysmonProcessEvent:
    return SysmonProcessEvent(
        event_record_id=record_id,
        process_guid=guid,
        parent_process_guid=parent_guid,
        image=image,
        commandline=commandline,
    )


class ShellInvocationTests(unittest.TestCase):
    def test_wraps_plain_cmd_payload_once(self) -> None:
        invocation = build_shell_invocation(make_case("whoami"))

        self.assertEqual(invocation.popen_args, ["cmd.exe", "/c", "whoami"])
        self.assertTrue(invocation.shell_wrapped)
        self.assertEqual(invocation.launch_commandline, "cmd.exe /c whoami")

    def test_does_not_double_wrap_existing_cmd_exe(self) -> None:
        commandline = "cmd.exe /c whoami"
        invocation = build_shell_invocation(make_case(commandline))

        self.assertEqual(invocation.popen_args, commandline)
        self.assertFalse(invocation.shell_wrapped)
        self.assertEqual(invocation.launch_commandline, commandline)

    def test_does_not_double_wrap_quoted_full_cmd_path(self) -> None:
        commandline = r'"C:\Windows\System32\cmd.exe" /c whoami'
        invocation = build_shell_invocation(make_case(commandline))

        self.assertEqual(invocation.popen_args, commandline)
        self.assertFalse(invocation.shell_wrapped)

    def test_percent_comspec_stays_wrapped(self) -> None:
        commandline = r"%COMSPEC% /c whoami"
        invocation = build_shell_invocation(make_case(commandline))

        self.assertEqual(invocation.popen_args, ["cmd.exe", "/c", commandline])
        self.assertTrue(invocation.shell_wrapped)


class PayloadValidationTests(unittest.TestCase):
    def test_exit_zero_without_payload_child_succeeds(self) -> None:
        execution = ExecutionResult(
            started=True,
            exit_code=0,
            launch_commandline=r'cmd.exe /c "cd C:\Users\Public"',
        )
        root = process_event(1, "root", r"C:\Windows\System32\cmd.exe", execution.launch_commandline)

        validation = validate_payload_execution(execution, root, [root])

        self.assertTrue(validation.can_execute)
        self.assertFalse(validation.payload_observed)
        self.assertEqual(validation.status, "exit_0")
        self.assertEqual(execution.payload_validation_status, "exit_0")

    def test_cmd_c_exit_zero_with_payload_child_succeeds(self) -> None:
        execution = ExecutionResult(
            started=True,
            exit_code=0,
            launch_commandline="cmd.exe /c whoami",
        )
        root = process_event(1, "root", r"C:\Windows\System32\cmd.exe", execution.launch_commandline)
        child = process_event(
            2,
            "child",
            r"C:\Windows\System32\whoami.exe",
            "whoami",
            parent_guid="root",
        )

        validation = validate_payload_execution(execution, root, [root, child])

        self.assertTrue(validation.can_execute)
        self.assertTrue(validation.payload_observed)
        self.assertEqual(validation.status, "exit_0")
        self.assertEqual(execution.payload_validation_status, "exit_0")

    def test_nonzero_exit_without_payload_child_fails(self) -> None:
        execution = ExecutionResult(started=True, exit_code=1, launch_commandline="cmd.exe /c missing-command")
        root = process_event(1, "root", r"C:\Windows\System32\cmd.exe", "cmd.exe /c missing-command")

        validation = validate_payload_execution(execution, root, [root])

        self.assertFalse(validation.can_execute)
        self.assertFalse(validation.payload_observed)
        self.assertEqual(validation.status, "nonzero_exit_no_child")
        self.assertEqual(execution.payload_validation_status, "nonzero_exit_no_child")

    def test_nonzero_exit_with_cmd_child_is_usable(self) -> None:
        execution = ExecutionResult(started=True, exit_code=1, launch_commandline="cmd.exe /c cmd.exe /c exit 1")
        root = process_event(1, "root", r"C:\Windows\System32\cmd.exe", execution.launch_commandline)
        child = process_event(
            2,
            "child",
            r"C:\Windows\System32\cmd.exe",
            "cmd.exe /c exit 1",
            parent_guid="root",
        )

        validation = validate_payload_execution(execution, root, [root, child])

        self.assertTrue(validation.can_execute)
        self.assertFalse(validation.payload_observed)
        self.assertEqual(validation.status, "nonzero_exit_child_observed")
        self.assertEqual(execution.payload_validation_status, "nonzero_exit_child_observed")

    def test_nonzero_exit_with_payload_child_is_usable(self) -> None:
        execution = ExecutionResult(started=True, exit_code=1, launch_commandline="cmd.exe /c ping 127.0.0.1")
        root = process_event(1, "root", r"C:\Windows\System32\cmd.exe", "cmd.exe /c ping 127.0.0.1")
        child = process_event(
            2,
            "child",
            r"C:\Windows\System32\PING.EXE",
            "ping 127.0.0.1",
            parent_guid="root",
        )

        validation = validate_payload_execution(execution, root, [root, child])

        self.assertTrue(validation.can_execute)
        self.assertTrue(validation.payload_observed)
        self.assertEqual(validation.status, "nonzero_exit_payload_observed")
        self.assertEqual(execution.payload_validation_status, "nonzero_exit_payload_observed")

    def test_command_output_error_fails_even_with_payload_child(self) -> None:
        execution = ExecutionResult(
            started=True,
            exit_code=1,
            stderr="ParserError: Unexpected token '}' in expression or statement.",
            launch_commandline="powershell.exe -Command bad",
        )
        root = process_event(1, "root", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", execution.launch_commandline)
        child = process_event(
            2,
            "child",
            r"C:\Windows\System32\whoami.exe",
            "whoami",
            parent_guid="root",
        )

        validation = validate_payload_execution(execution, root, [root, child])

        self.assertFalse(validation.can_execute)
        self.assertTrue(validation.payload_observed)
        self.assertEqual(validation.status, "command_output_error")
        self.assertEqual(execution.payload_validation_status, "command_output_error")
        self.assertIn("unexpected token", validation.note)

    def test_command_output_error_fails_even_with_exit_zero(self) -> None:
        execution = ExecutionResult(
            started=True,
            exit_code=0,
            stdout="'badcmd' is not recognized as an internal or external command",
            launch_commandline="cmd.exe /c badcmd",
        )
        root = process_event(1, "root", r"C:\Windows\System32\cmd.exe", execution.launch_commandline)

        validation = validate_payload_execution(execution, root, [root])

        self.assertFalse(validation.can_execute)
        self.assertFalse(validation.payload_observed)
        self.assertEqual(validation.status, "command_output_error")
        self.assertEqual(execution.payload_validation_status, "command_output_error")


class CommandExecutionFailureReasonTests(unittest.TestCase):
    def test_includes_matched_pattern_and_stderr_excerpt(self) -> None:
        execution = ExecutionResult(
            started=True,
            exit_code=1,
            stderr="ParserError: Unexpected token '}' in expression or statement.",
            launch_commandline="powershell.exe -Command bad",
        )

        reason = command_execution_failure_reason(execution)

        self.assertIn("matched error pattern(s): parsererror; unexpected token", reason)
        self.assertIn("stderr: ParserError: Unexpected token '}'", reason)

    def test_includes_stdout_for_cmd_missing_binary(self) -> None:
        execution = ExecutionResult(
            started=True,
            exit_code=1,
            stdout="'badcmd' is not recognized as an internal or external command",
            launch_commandline="cmd.exe /c badcmd",
        )

        reason = command_execution_failure_reason(execution)

        self.assertIn("matched error pattern(s): is not recognized as an internal or external command", reason)
        self.assertIn("stdout: 'badcmd' is not recognized", reason)


class ExecuteCommandTests(unittest.TestCase):
    def test_timeout_kills_process_tree(self) -> None:
        class FakeProcess:
            pid = 1234
            returncode = None

            def __init__(self) -> None:
                self.calls = 0
                self.killed = False

            def communicate(self, input: str | None = None, timeout: int | None = None):
                self.calls += 1
                if timeout is not None:
                    raise subprocess.TimeoutExpired(cmd="fake", timeout=timeout)
                return "", ""

            def kill(self) -> None:
                self.killed = True

        fake_process = FakeProcess()
        with patch("sigma_rule_evaluator.execution.subprocess.Popen", return_value=fake_process) as popen:
            with patch("sigma_rule_evaluator.execution.kill_process_tree", return_value="killed") as kill_tree:
                result = execute_command(make_case("whoami"), timeout_seconds=1)

        self.assertTrue(result.timed_out)
        self.assertEqual(result.status, "FAILED_TIMEOUT")
        self.assertEqual(result.note, "killed")
        self.assertTrue(fake_process.killed)
        kill_tree.assert_called_once_with(1234)
        self.assertIs(popen.call_args.kwargs["stdin"], subprocess.PIPE)
        self.assertFalse(popen.call_args.kwargs["shell"])


if __name__ == "__main__":
    unittest.main()
