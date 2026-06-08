from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sigma_rule_evaluator.utils import runner_parent_matches


class RunnerParentMatchesTests(unittest.TestCase):
    def test_matches_module_invocation(self) -> None:
        parent = r"C:\Python312\python.exe -m sigma_rule_evaluator.cli --execute"

        self.assertTrue(runner_parent_matches(parent))

    def test_matches_renamed_module_package(self) -> None:
        parent = r"C:\Python312\python.exe -m renamed_runner.cli --execute"

        with patch("sigma_rule_evaluator.utils.__package__", "renamed_runner"):
            self.assertTrue(runner_parent_matches(parent))

    def test_matches_custom_environment_marker(self) -> None:
        parent = r"C:\Tools\python.exe -m custom_entrypoint --execute"

        with patch.dict("os.environ", {"SIGMA_RULE_EVALUATOR_RUNNER_MARKERS": "custom_entrypoint"}):
            self.assertTrue(runner_parent_matches(parent))

    def test_matches_legacy_environment_marker(self) -> None:
        parent = r"C:\Tools\python.exe -m old_entrypoint --execute"

        with patch.dict("os.environ", {"SIGMA_FUZZER_RUNNER_MARKERS": "old_entrypoint"}):
            self.assertTrue(runner_parent_matches(parent))

    def test_does_not_match_plain_python_process(self) -> None:
        parent = r"C:\Python312\python.exe other_tool.py --execute"

        self.assertFalse(runner_parent_matches(parent))


if __name__ == "__main__":
    unittest.main()
