from __future__ import annotations

import sys
import tempfile
import unittest
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scripts.convert_gemini_outputs import build_cases, parse_model_items
from sigma_rule_evaluator.cases import load_cases


class ConvertGeminiOutputsTests(unittest.TestCase):
    def test_parse_model_items_accepts_unescaped_quotes(self) -> None:
        text = """[
{
"output": "taskkill /f /im "RaccineSettings".exe",
"explanation": "Insertion technique: Inserting double quotes inside the binary name 'RaccineSettings.exe' ('"RaccineSettings".exe')."
},
{
"output": "cmd.exe /c schtasks /D^ELETE /TN "Raccine Rules Updater" /F",
"explanation": "Insertion technique: Injected a caret (^) escape character into the command flag ('/D^ELETE')."
}
]"""

        items = parse_model_items(text)

        self.assertEqual(items[0]["output"], 'taskkill /f /im "RaccineSettings".exe')
        self.assertIn('"RaccineSettings".exe', items[0]["explanation"])
        self.assertEqual(items[1]["output"], 'cmd.exe /c schtasks /D^ELETE /TN "Raccine Rules Updater" /F')

    def test_build_cases_writes_evaluator_compatible_shape(self) -> None:
        with tempfile.TemporaryDirectory() as dirname:
            temp_dir = Path(dirname)
            gemini_dir = temp_dir / "gemini_result_add"
            rules_dir = temp_dir / "rules"
            rule_name = "proc_creation_win_demo"
            rule_output_dir = gemini_dir / rule_name
            rule_output_dir.mkdir(parents=True)
            rules_dir.mkdir()
            (rules_dir / f"{rule_name}.yml").write_text(
                "title: Demo\n"
                "tags:\n"
                "  - attack.defense-evasion\n"
                "  - attack.t1562.001\n",
                encoding="utf-8",
            )
            (rule_output_dir / "commandline_evasion.txt").write_text(
                """[
{"output": "cmd.exe /c whoami", "explanation": "No mutation; original command."},
{"output": "cmd.exe /c who^ami", "explanation": "Injected a caret ^ into the command."}
]""",
                encoding="utf-8",
            )

            cases, summary = build_cases(
                gemini_result_dir=gemini_dir,
                rules_dir=rules_dir,
                include_rules=set(),
                limit_rules=None,
                limit_outputs_per_rule=None,
                shell="cmd.exe",
                include_source_fields=True,
                skip_missing_rules=False,
                continue_on_parse_error=False,
            )
            output_path = temp_dir / "cases.json"
            output_path.write_text(json.dumps(cases), encoding="utf-8")
            loaded = load_cases(output_path)

        self.assertEqual(summary["case_count"], 2)
        self.assertEqual(cases[0]["test_id"], "t1562.001_001")
        self.assertEqual(cases[0]["target_rule"], rule_name)
        self.assertEqual(cases[0]["technique_id"], "t1562.001")
        self.assertEqual(cases[1]["mutation"], "caret_insertion")
        self.assertEqual(loaded[0].target_commandline, "cmd.exe /c whoami")


if __name__ == "__main__":
    unittest.main()
