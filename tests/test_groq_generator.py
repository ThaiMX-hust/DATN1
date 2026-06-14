from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from generator.groq_generator import (
    DEFAULT_PROMPT_TEMPLATE,
    GroqHTTPError,
    HTTPResponse,
    GenerationConfig,
    NO_TRUE_POSITIVE_COMMAND_TEXT,
    build_jobs,
    call_groq,
    format_true_positive_commands,
    infer_mutation,
    limit_model_items,
    parse_model_json,
    parse_duration_seconds,
    request_payload,
    request_headers,
    retry_after_seconds,
    render_prompt,
    run_generation,
    should_stop_after_error,
    wait_for_request_slot,
)


class GroqGeneratorParsingTests(unittest.TestCase):
    def test_default_prompt_template_is_groq_specific(self) -> None:
        self.assertEqual(DEFAULT_PROMPT_TEMPLATE.name, "groq_prompt_template.txt")

    def test_parse_json_code_fence(self) -> None:
        text = """```json
[
  {"output": "cmd.exe /c whoami", "explanation": "quote insertion"}
]
```"""

        parsed = parse_model_json(text)

        self.assertEqual(parsed, [{"output": "cmd.exe /c whoami", "explanation": "quote insertion"}])

    def test_parse_json_embedded_array(self) -> None:
        text = 'Result:\n[{"output": "whoami", "explanation": "case substitution"}]\nDone'

        parsed = parse_model_json(text)

        self.assertEqual(parsed[0]["output"], "whoami")

    def test_infer_mutation_prefers_caret(self) -> None:
        self.assertEqual(infer_mutation("Used caret ^ insertion"), "caret_insertion")

    def test_render_prompt_requires_placeholders(self) -> None:
        rendered = render_prompt("rule={{SIGMA_RULE}} command={{TRUE_POSITIVE_TEST_COMMAND}}", "r", "c")

        self.assertEqual(rendered, "rule=r command=c")

    def test_request_headers_include_user_agent(self) -> None:
        headers = request_headers(GenerationConfig(api_key="key", user_agent="test-agent"))

        self.assertEqual(headers["User-Agent"], "test-agent")
        self.assertEqual(headers["Accept"], "application/json")

    def test_should_stop_after_non_retryable_http_error(self) -> None:
        self.assertTrue(should_stop_after_error(GroqHTTPError(403, "error code: 1010")))
        self.assertFalse(should_stop_after_error(GroqHTTPError(429, "rate limit")))

    def test_request_payload_disables_qwen_reasoning_by_default(self) -> None:
        payload = request_payload("prompt", GenerationConfig())

        self.assertEqual(payload["reasoning_format"], "hidden")
        self.assertEqual(payload["reasoning_effort"], "none")
        self.assertEqual(payload["max_completion_tokens"], 768)

    def test_default_groq_request_interval_is_one_minute(self) -> None:
        self.assertEqual(GenerationConfig().min_request_interval_seconds, 60.0)

    def test_format_multiple_true_positive_commands(self) -> None:
        formatted = format_true_positive_commands(["whoami", "hostname"])

        self.assertEqual(formatted, "1. whoami\n2. hostname")

    def test_format_missing_true_positive_command(self) -> None:
        formatted = format_true_positive_commands([])

        self.assertEqual(formatted, NO_TRUE_POSITIVE_COMMAND_TEXT)

    def test_parse_duration_seconds(self) -> None:
        self.assertAlmostEqual(parse_duration_seconds("940ms") or 0, 0.94)
        self.assertAlmostEqual(parse_duration_seconds("7.66s") or 0, 7.66)
        self.assertAlmostEqual(parse_duration_seconds("2m59.56s") or 0, 179.56)

    def test_retry_after_prefers_header(self) -> None:
        response = HTTPResponse(429, "Please try again in 940ms.", {"retry-after": "2"})

        self.assertEqual(retry_after_seconds(response, fallback_seconds=10), 2)

    def test_retry_after_reads_error_message(self) -> None:
        response = HTTPResponse(429, "Please try again in 940ms.", {})

        self.assertAlmostEqual(retry_after_seconds(response, fallback_seconds=10), 0.94)

    def test_limit_model_items_caps_outputs(self) -> None:
        items = [
            {"output": "one", "explanation": "a"},
            {"output": "two", "explanation": "b"},
            {"output": "three", "explanation": "c"},
            {"output": "four", "explanation": "d"},
        ]

        limited, skipped = limit_model_items(items, 3)

        self.assertEqual([item["output"] for item in limited], ["one", "two", "three"])
        self.assertEqual(skipped, 1)

    def test_call_groq_retries_after_rate_limit(self) -> None:
        ok_body = json.dumps({"choices": [{"message": {"content": "[]"}}]})
        responses = [
            HTTPResponse(429, "Please try again in 940ms.", {}),
            HTTPResponse(200, ok_body, {}),
        ]

        with patch("generator.groq_generator.post_json", side_effect=responses) as post_json:
            with patch("generator.groq_generator.time.sleep") as sleep:
                content = call_groq(
                    "prompt",
                    GenerationConfig(api_key="key", max_retries=1, rate_limit_buffer_seconds=0.5),
                )

        self.assertEqual(content, "[]")
        self.assertEqual(post_json.call_count, 2)
        sleep.assert_called_once_with(1.44)

    def test_wait_for_request_slot_enforces_interval(self) -> None:
        with patch("generator.groq_generator.time.monotonic", side_effect=[100.0, 130.0]):
            with patch("generator.groq_generator.time.sleep") as sleep:
                started_at = wait_for_request_slot(70.0, GenerationConfig(min_request_interval_seconds=60.0))

        self.assertEqual(started_at, 130.0)
        sleep.assert_called_once_with(30.0)


class GroqGeneratorJobTests(unittest.TestCase):
    def test_build_jobs_defaults_to_one_prompt_per_rule(self) -> None:
        with tempfile.TemporaryDirectory() as dirname:
            temp_dir = Path(dirname)
            rules_dir = temp_dir / "rules"
            tp_dir = temp_dir / "data" / "true_positive_test"
            rule_dir = tp_dir / "proc_creation_win_demo"
            rules_dir.mkdir(parents=True)
            rule_dir.mkdir(parents=True)
            (rules_dir / "proc_creation_win_demo.yml").write_text(
                "title: Demo\n"
                "tags:\n"
                "  - attack.execution\n"
                "  - attack.t1059.003\n",
                encoding="utf-8",
            )
            (rule_dir / "commandlines.txt").write_text("cmd.exe /c whoami\nhostname\n", encoding="utf-8")

            jobs = build_jobs(
                GenerationConfig(
                    rules_dir=rules_dir,
                    true_positive_dir=tp_dir,
                    prompt_template=Path("unused"),
                    output_path=Path("unused"),
                    raw_output_dir=Path("unused"),
                )
            )

            self.assertEqual(len(jobs), 1)
            self.assertEqual(jobs[0].technique_id, "t1059.003")
            self.assertEqual(jobs[0].source_commands, ("cmd.exe /c whoami", "hostname"))
            self.assertIsNone(jobs[0].command_index)

    def test_build_jobs_can_use_one_prompt_per_command(self) -> None:
        with tempfile.TemporaryDirectory() as dirname:
            temp_dir = Path(dirname)
            rules_dir = temp_dir / "rules"
            tp_dir = temp_dir / "data" / "true_positive_test"
            rule_dir = tp_dir / "proc_creation_win_demo"
            rules_dir.mkdir(parents=True)
            rule_dir.mkdir(parents=True)
            (rules_dir / "proc_creation_win_demo.yml").write_text(
                "title: Demo\n"
                "tags:\n"
                "  - attack.execution\n"
                "  - attack.t1059.003\n",
                encoding="utf-8",
            )
            (rule_dir / "commandlines.txt").write_text("cmd.exe /c whoami\nhostname\n", encoding="utf-8")

            jobs = build_jobs(
                GenerationConfig(
                    rules_dir=rules_dir,
                    true_positive_dir=tp_dir,
                    prompt_template=Path("unused"),
                    output_path=Path("unused"),
                    raw_output_dir=Path("unused"),
                    prompt_scope="command",
                )
            )

            self.assertEqual(len(jobs), 2)
            self.assertEqual(jobs[0].source_commands, ("cmd.exe /c whoami",))
            self.assertEqual(jobs[0].command_index, 1)
            self.assertEqual(jobs[1].source_commands, ("hostname",))
            self.assertEqual(jobs[1].command_index, 2)

    def test_build_jobs_includes_rules_without_commandlines(self) -> None:
        with tempfile.TemporaryDirectory() as dirname:
            temp_dir = Path(dirname)
            rules_dir = temp_dir / "rules"
            tp_dir = temp_dir / "data" / "true_positive_test"
            empty_rule_dir = tp_dir / "proc_creation_win_empty"
            rules_dir.mkdir(parents=True)
            empty_rule_dir.mkdir(parents=True)
            for rule_name in ("proc_creation_win_empty", "proc_creation_win_missing"):
                (rules_dir / f"{rule_name}.yml").write_text(
                    "title: Demo\n"
                    "tags:\n"
                    "  - attack.execution\n"
                    "  - attack.t1059.003\n",
                    encoding="utf-8",
                )
            (empty_rule_dir / "commandlines.txt").write_text("# no commands yet\n\n", encoding="utf-8")

            jobs = build_jobs(
                GenerationConfig(
                    rules_dir=rules_dir,
                    true_positive_dir=tp_dir,
                    prompt_template=Path("unused"),
                    output_path=Path("unused"),
                    raw_output_dir=Path("unused"),
                )
            )

            self.assertEqual(len(jobs), 2)
            self.assertEqual({job.rule_path.stem for job in jobs}, {"proc_creation_win_empty", "proc_creation_win_missing"})
            self.assertTrue(all(job.source_commands == () for job in jobs))
            self.assertTrue(all(job.command_index is None for job in jobs))

    def test_command_scope_includes_rules_without_commandlines(self) -> None:
        with tempfile.TemporaryDirectory() as dirname:
            temp_dir = Path(dirname)
            rules_dir = temp_dir / "rules"
            tp_dir = temp_dir / "data" / "true_positive_test"
            command_rule_dir = tp_dir / "proc_creation_win_with_commands"
            rules_dir.mkdir(parents=True)
            command_rule_dir.mkdir(parents=True)
            for rule_name in ("proc_creation_win_missing", "proc_creation_win_with_commands"):
                (rules_dir / f"{rule_name}.yml").write_text(
                    "title: Demo\n"
                    "tags:\n"
                    "  - attack.execution\n"
                    "  - attack.t1059.003\n",
                    encoding="utf-8",
                )
            (command_rule_dir / "commandlines.txt").write_text("cmd.exe /c whoami\nhostname\n", encoding="utf-8")

            jobs = build_jobs(
                GenerationConfig(
                    rules_dir=rules_dir,
                    true_positive_dir=tp_dir,
                    prompt_template=Path("unused"),
                    output_path=Path("unused"),
                    raw_output_dir=Path("unused"),
                    prompt_scope="command",
                )
            )

            self.assertEqual(len(jobs), 3)
            missing_job = next(job for job in jobs if job.rule_path.stem == "proc_creation_win_missing")
            self.assertEqual(missing_job.source_commands, ())
            self.assertIsNone(missing_job.command_index)

    def test_run_generation_writes_rule_files_and_resumes_missing_rules(self) -> None:
        with tempfile.TemporaryDirectory() as dirname:
            temp_dir = Path(dirname)
            rules_dir = temp_dir / "rules"
            tp_dir = temp_dir / "data" / "true_positive_test"
            output_path = temp_dir / "input" / "cases.json"
            raw_output_dir = temp_dir / "output" / "raw"
            rule_output_dir = temp_dir / "output" / "rules"
            prompt_template = temp_dir / "prompt_template.txt"
            rules_dir.mkdir(parents=True)
            prompt_template.write_text(
                "rule={{SIGMA_RULE}}\ncommand={{TRUE_POSITIVE_TEST_COMMAND}}",
                encoding="utf-8",
            )
            for rule_name, command in (
                ("proc_creation_win_a", "cmd.exe /c whoami"),
                ("proc_creation_win_b", "hostname"),
            ):
                (rules_dir / f"{rule_name}.yml").write_text(
                    "title: Demo\n"
                    "tags:\n"
                    "  - attack.execution\n"
                    "  - attack.t1059.003\n",
                    encoding="utf-8",
                )
                rule_tp_dir = tp_dir / rule_name
                rule_tp_dir.mkdir(parents=True)
                (rule_tp_dir / "commandlines.txt").write_text(command, encoding="utf-8")

            config = GenerationConfig(
                rules_dir=rules_dir,
                true_positive_dir=tp_dir,
                prompt_template=prompt_template,
                output_path=output_path,
                raw_output_dir=raw_output_dir,
                rule_output_dir=rule_output_dir,
                api_key="key",
                max_retries=0,
                min_request_interval_seconds=0,
            )

            first_response = '[{"output": "cmd.exe /c whoami /user", "explanation": "safe variant"}]'
            second_response = '[{"output": "hostname.exe", "explanation": "path variation"}]'

            with patch("generator.groq_generator.call_groq", side_effect=[first_response, KeyboardInterrupt()]):
                with self.assertRaises(KeyboardInterrupt):
                    run_generation(config)

            self.assertTrue((rule_output_dir / "proc_creation_win_a.json").exists())
            self.assertEqual((rule_output_dir / "proc_creation_win_a.json").read_text(encoding="utf-8").strip(), first_response)
            self.assertFalse((rule_output_dir / "proc_creation_win_b.json").exists())

            with patch("generator.groq_generator.call_groq", return_value=second_response) as call:
                run_generation(config)

            output_after_resume = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(call.call_count, 1)
            self.assertEqual(output_after_resume, [])
            self.assertTrue((rule_output_dir / "proc_creation_win_b.json").exists())
            self.assertEqual((rule_output_dir / "proc_creation_win_b.json").read_text(encoding="utf-8").strip(), second_response)


if __name__ == "__main__":
    unittest.main()
