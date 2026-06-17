from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.list_sigma_test_case_order import build_order_plan, default_output_path, format_table, rows_for_plan


def write_cases(path: Path) -> None:
    cases = [
        {
            "test_id": "a1",
            "target_commandline": "echo a1",
            "target_rule": "rule_a",
            "technique_id": "T1000",
        },
        {
            "test_id": "b1",
            "target_commandline": "echo b1",
            "target_rule": "rule_b",
            "technique_id": "T2000",
        },
        {
            "test_id": "a2",
            "target_commandline": "echo a2",
            "target_rule": "rule_a",
            "technique_id": "T1000",
        },
        {
            "test_id": "b2",
            "target_commandline": "echo b2",
            "target_rule": "rule_b",
            "technique_id": "T2000",
        },
    ]
    path.write_text(json.dumps(cases), encoding="utf-8")


class ListSigmaTestCaseOrderTests(unittest.TestCase):
    def test_lists_runner_execution_order_grouped_by_technique(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "cases.json"
            write_cases(config_path)

            rows = rows_for_plan(build_order_plan(config_path))

        self.assertEqual([row["test_id"] for row in rows], ["a1", "a2", "b1", "b2"])
        self.assertEqual([row["input_index"] for row in rows], [1, 3, 2, 4])

    def test_table_handles_empty_resume_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config_path = root / "cases.json"
            write_cases(config_path)
            evtx_path = root / "batch" / "evtx" / "T2000__b2.evtx"
            evtx_path.parent.mkdir(parents=True)
            evtx_path.write_bytes(b"")
            os.utime(evtx_path, (100, 100))

            plan = build_order_plan(config_path, resume_from_batch=root / "batch")
            table = format_table(
                plan,
                rows_for_plan(plan),
                argparse.Namespace(max_commandline_width=140),
            )

        self.assertIn("Will execute: 0 case(s)", table)

    def test_default_output_path_uses_format_extension(self) -> None:
        base_dir = Path("project")
        config_path = Path("input") / "sample.cases.json"

        self.assertEqual(
            default_output_path(base_dir, config_path, "csv"),
            Path("project") / "output" / "test_case_order" / "sample.cases.csv",
        )
        self.assertEqual(
            default_output_path(base_dir, config_path, "table"),
            Path("project") / "output" / "test_case_order" / "sample.cases.txt",
        )


if __name__ == "__main__":
    unittest.main()
