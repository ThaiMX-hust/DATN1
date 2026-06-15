from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sigma_rule_evaluator.cases import group_by_technique, technique_dir_map
from sigma_rule_evaluator.detection import collect_triggered_rules_for_case
from sigma_rule_evaluator.models import CaseResult, RunnerConfig, TargetCase
from sigma_rule_evaluator.runner import (
    effective_case_timeout_seconds,
    evtx_name_for_case,
    restored_result_for_case,
    select_cases_after_last_evtx,
)


def make_case(index: int, test_id: str, technique_id: str) -> TargetCase:
    return TargetCase(
        index=index,
        test_id=test_id,
        target_commandline=f"echo {test_id}",
        target_rule=f"rules/{technique_id}.yml",
        technique_id=technique_id,
        mutation="manual",
        shell="cmd.exe",
        timeout_seconds=None,
        raw={},
    )


def touch_evtx(path: Path, timestamp: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"")
    os.utime(path, (timestamp, timestamp))


class ResumeFromEvtxTests(unittest.TestCase):
    def test_resumes_after_newest_evtx_in_runner_execution_order(self) -> None:
        cases = [
            make_case(1, "a1", "T1000.001"),
            make_case(2, "b1", "T2000.001"),
            make_case(3, "a2", "T1000.001"),
            make_case(4, "b2", "T2000.001"),
        ]
        dir_map = technique_dir_map(list(group_by_technique(cases)))

        with tempfile.TemporaryDirectory() as temp_dir:
            batch_dir = Path(temp_dir)
            evtx_dir = batch_dir / "evtx"

            touch_evtx(evtx_dir / evtx_name_for_case(cases[0], dir_map), 100)
            touch_evtx(evtx_dir / evtx_name_for_case(cases[1], dir_map), 300)

            remaining, resume = select_cases_after_last_evtx(cases, batch_dir, dir_map)

        self.assertEqual([case.test_id for case in remaining], ["b2"])
        self.assertEqual(resume.last_case.test_id if resume.last_case else None, "b1")
        self.assertEqual(resume.skipped_count, 3)

    def test_no_matching_evtx_runs_all_cases(self) -> None:
        cases = [
            make_case(1, "a1", "T1000.001"),
            make_case(2, "b1", "T2000.001"),
        ]
        dir_map = technique_dir_map(list(group_by_technique(cases)))

        with tempfile.TemporaryDirectory() as temp_dir:
            batch_dir = Path(temp_dir)
            touch_evtx(batch_dir / "evtx" / "unrelated.evtx", 100)

            remaining, resume = select_cases_after_last_evtx(cases, batch_dir, dir_map)

        self.assertEqual(remaining, cases)
        self.assertIsNone(resume.last_case)
        self.assertEqual(resume.skipped_count, 0)
        self.assertEqual(resume.ignored_evtx_count, 1)

    def test_restored_result_uses_existing_evtx_or_marks_missing_as_failed(self) -> None:
        case = make_case(1, "a1", "T1000.001")

        with tempfile.TemporaryDirectory() as temp_dir:
            batch_dir = Path(temp_dir)
            evtx_path = batch_dir / "evtx" / "t1000.001__a1.evtx"
            touch_evtx(evtx_path, 100)

            restored = restored_result_for_case(case, evtx_path, batch_dir)
            missing = restored_result_for_case(case, None, batch_dir)

        self.assertTrue(restored.can_execute)
        self.assertEqual(restored.execution.status, "RESTORED_EVTX")
        self.assertEqual(restored.evtx_name, "t1000.001__a1.evtx")
        self.assertEqual(missing.execution.status, "MISSING_RESUME_EVTX")
        self.assertEqual(missing.final_status, "execution_failed")

    def test_detection_for_restored_case_matches_by_original_logfile(self) -> None:
        case = make_case(1, "a1", "T1000.001")
        result = CaseResult(case=case)
        result.evtx_name = "t1000.001__a1.evtx"
        detections = [
            {
                "rule": {"id": "rule-1", "title": "Example Rule"},
                "matches": [
                    {
                        "OriginalLogfile": r"C:\tmp\t1000.001__a1.evtx",
                        "CommandLine": "echo a1",
                        "ProcessGuid": "{abc}",
                    }
                ],
            }
        ]

        rules = collect_triggered_rules_for_case(detections, result)

        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].id, "rule-1")

    def test_case_timeout_is_capped_by_runner_config(self) -> None:
        case = make_case(1, "a1", "T1000.001")
        case.timeout_seconds = 10
        config = RunnerConfig(
            config_path=Path("input.json"),
            output_dir=Path("output"),
            base_dir=Path("."),
            timeout_seconds=2,
        )

        self.assertEqual(effective_case_timeout_seconds(case, config), 2)


if __name__ == "__main__":
    unittest.main()
