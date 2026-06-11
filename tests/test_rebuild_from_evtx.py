from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sigma_rule_evaluator.cases import group_by_technique, technique_dir_map
from sigma_rule_evaluator.models import TargetCase
from sigma_rule_evaluator.rebuild_from_evtx import (
    latest_batch_dir,
    resolve_evtx_dir,
    restore_results_from_existing_evtx,
)
from sigma_rule_evaluator.runner import evtx_name_for_case


def make_case(index: int, test_id: str, technique_id: str = "t1000.001") -> TargetCase:
    return TargetCase(
        index=index,
        test_id=test_id,
        target_commandline=f"echo {test_id}",
        target_rule="proc_creation_win_example",
        technique_id=technique_id,
        mutation="manual",
        shell="cmd.exe",
        timeout_seconds=None,
        raw={},
    )


def touch_evtx(path: Path, timestamp: int = 100) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"")
    os.utime(path, (timestamp, timestamp))


class RebuildFromEvtxTests(unittest.TestCase):
    def test_restore_defaults_to_present_evtx_only(self) -> None:
        cases = [make_case(1, "a1"), make_case(2, "a2")]
        dir_map = technique_dir_map(list(group_by_technique(cases)))

        with tempfile.TemporaryDirectory() as temp_dir:
            batch_dir = Path(temp_dir)
            evtx_dir = batch_dir / "evtx"
            touch_evtx(evtx_dir / evtx_name_for_case(cases[0], dir_map))
            touch_evtx(evtx_dir / "unrelated.evtx")

            restore = restore_results_from_existing_evtx(cases, batch_dir, evtx_dir, dir_map)

        results = restore.results_by_technique["t1000.001"]
        self.assertEqual([result.case.test_id for result in results], ["a1"])
        self.assertEqual(restore.matched_count, 1)
        self.assertEqual(restore.missing_count, 1)
        self.assertEqual(restore.ignored_evtx_count, 1)
        self.assertTrue(results[0].can_execute)
        self.assertEqual(results[0].execution.status, "RESTORED_EVTX")

    def test_restore_can_include_missing_cases(self) -> None:
        cases = [make_case(1, "a1"), make_case(2, "a2")]
        dir_map = technique_dir_map(list(group_by_technique(cases)))

        with tempfile.TemporaryDirectory() as temp_dir:
            batch_dir = Path(temp_dir)
            evtx_dir = batch_dir / "evtx"
            touch_evtx(evtx_dir / evtx_name_for_case(cases[0], dir_map))

            restore = restore_results_from_existing_evtx(
                cases,
                batch_dir,
                evtx_dir,
                dir_map,
                include_missing=True,
            )

        results = restore.results_by_technique["t1000.001"]
        self.assertEqual([result.case.test_id for result in results], ["a1", "a2"])
        self.assertEqual(results[1].execution.status, "MISSING_RESUME_EVTX")
        self.assertEqual(results[1].final_status, "execution_failed")

    def test_resolve_evtx_dir_accepts_batch_or_direct_evtx_folder(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            batch_dir = Path(temp_dir)
            evtx_dir = batch_dir / "evtx"
            touch_evtx(evtx_dir / "a.evtx")

            self.assertEqual(resolve_evtx_dir(batch_dir), (batch_dir, evtx_dir))
            self.assertEqual(resolve_evtx_dir(evtx_dir), (batch_dir, evtx_dir))

    def test_latest_batch_dir_uses_newest_batch_with_evtx(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            older = output_dir / "older"
            newer = output_dir / "newer"
            touch_evtx(older / "evtx" / "a.evtx", timestamp=100)
            touch_evtx(newer / "evtx" / "b.evtx", timestamp=200)
            os.utime(older, (100, 100))
            os.utime(newer, (200, 200))

            self.assertEqual(latest_batch_dir(output_dir), newer)


if __name__ == "__main__":
    unittest.main()
