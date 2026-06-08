from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from generator.cerebras_generator import (
    DEFAULT_API_URL,
    DEFAULT_MODEL,
    DEFAULT_PROMPT_TEMPLATE,
    CerebrasConfig,
    CerebrasHTTPError,
    call_cerebras,
    request_headers,
    request_payload,
    run_generation,
    should_stop_after_error,
)
from generator.groq_generator import HTTPResponse


class CerebrasGeneratorTests(unittest.TestCase):
    def test_default_prompt_template_is_cerebras_specific(self) -> None:
        self.assertEqual(DEFAULT_PROMPT_TEMPLATE.name, "cerebras_prompt_template.txt")

    def test_request_payload_defaults_to_gpt_oss_120b(self) -> None:
        payload = request_payload("prompt", CerebrasConfig())

        self.assertEqual(payload["model"], DEFAULT_MODEL)
        self.assertEqual(payload["model"], "gpt-oss-120b")
        self.assertEqual(payload["messages"], [{"role": "user", "content": "prompt"}])
        self.assertNotIn("reasoning_format", payload)
        self.assertEqual(payload["max_completion_tokens"], 768)
        self.assertNotIn("reasoning_effort", payload)

    def test_request_payload_can_include_reasoning_format(self) -> None:
        payload = request_payload("prompt", CerebrasConfig(reasoning_format="hidden"))

        self.assertEqual(payload["reasoning_format"], "hidden")

    def test_request_headers_include_cerebras_auth(self) -> None:
        headers = request_headers(CerebrasConfig(api_key="key", user_agent="test-agent"))

        self.assertEqual(headers["Authorization"], "Bearer key")
        self.assertEqual(headers["User-Agent"], "test-agent")
        self.assertEqual(headers["Accept"], "application/json")

    def test_call_cerebras_posts_to_default_endpoint(self) -> None:
        ok_body = json.dumps({"choices": [{"message": {"content": "[]"}}]})

        with patch("generator.cerebras_generator.post_json", return_value=HTTPResponse(200, ok_body, {})) as post_json:
            content = call_cerebras("prompt", CerebrasConfig(api_key="key", max_retries=0))

        self.assertEqual(content, "[]")
        args = post_json.call_args.args
        self.assertEqual(args[0], DEFAULT_API_URL)
        self.assertEqual(args[2]["model"], "gpt-oss-120b")

    def test_call_cerebras_retries_after_rate_limit(self) -> None:
        ok_body = json.dumps({"choices": [{"message": {"content": "[]"}}]})
        responses = [
            HTTPResponse(429, "Please try again in 940ms.", {}),
            HTTPResponse(200, ok_body, {}),
        ]

        with patch("generator.cerebras_generator.post_json", side_effect=responses) as post_json:
            with patch("generator.cerebras_generator.time.sleep") as sleep:
                content = call_cerebras(
                    "prompt",
                    CerebrasConfig(api_key="key", max_retries=1, rate_limit_buffer_seconds=0.5),
                )

        self.assertEqual(content, "[]")
        self.assertEqual(post_json.call_count, 2)
        sleep.assert_called_once_with(1.44)

    def test_should_stop_after_non_retryable_http_error(self) -> None:
        self.assertTrue(should_stop_after_error(CerebrasHTTPError(401, "unauthorized")))
        self.assertFalse(should_stop_after_error(CerebrasHTTPError(429, "rate limit")))

    def test_run_generation_checkpoints_and_resumes(self) -> None:
        with tempfile.TemporaryDirectory() as dirname:
            temp_dir = Path(dirname)
            rules_dir = temp_dir / "rules"
            tp_dir = temp_dir / "data" / "true_positive_test"
            output_path = temp_dir / "input" / "cases.json"
            checkpoint_path = temp_dir / "output" / "checkpoint.json"
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

            config = CerebrasConfig(
                rules_dir=rules_dir,
                true_positive_dir=tp_dir,
                prompt_template=prompt_template,
                output_path=output_path,
                raw_output_dir=raw_output_dir,
                rule_output_dir=rule_output_dir,
                checkpoint_path=checkpoint_path,
                api_key="key",
                max_retries=0,
            )

            first_response = '[{"output": "cmd.exe /c whoami /user", "explanation": "safe variant"}]'
            second_response = '[{"output": "hostname.exe", "explanation": "path variation"}]'

            with patch(
                "generator.cerebras_generator.call_cerebras",
                side_effect=[first_response, KeyboardInterrupt()],
            ):
                with self.assertRaises(KeyboardInterrupt):
                    run_generation(config)

            output_after_interrupt = json.loads(output_path.read_text(encoding="utf-8"))
            checkpoint_after_interrupt = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            self.assertEqual(output_after_interrupt, [])
            self.assertEqual(checkpoint_after_interrupt["record_count"], 1)
            self.assertFalse(checkpoint_after_interrupt["completed"])
            self.assertTrue((rule_output_dir / "proc_creation_win_a.json").exists())
            self.assertEqual((rule_output_dir / "proc_creation_win_a.json").read_text(encoding="utf-8").strip(), first_response)
            self.assertFalse((rule_output_dir / "proc_creation_win_b.json").exists())

            with patch("generator.cerebras_generator.call_cerebras", return_value=second_response) as call:
                run_generation(config)

            output_after_resume = json.loads(output_path.read_text(encoding="utf-8"))
            checkpoint_after_resume = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            self.assertEqual(call.call_count, 1)
            self.assertEqual(output_after_resume, [])
            self.assertEqual(checkpoint_after_resume["record_count"], 2)
            self.assertTrue(checkpoint_after_resume["completed"])
            self.assertTrue((rule_output_dir / "proc_creation_win_b.json").exists())
            self.assertEqual((rule_output_dir / "proc_creation_win_b.json").read_text(encoding="utf-8").strip(), second_response)

    def test_run_generation_retries_checkpoint_errors_without_rule_file(self) -> None:
        with tempfile.TemporaryDirectory() as dirname:
            temp_dir = Path(dirname)
            rules_dir = temp_dir / "rules"
            tp_dir = temp_dir / "data" / "true_positive_test"
            output_path = temp_dir / "input" / "cases.json"
            checkpoint_path = temp_dir / "output" / "checkpoint.json"
            raw_output_dir = temp_dir / "output" / "raw"
            rule_output_dir = temp_dir / "output" / "rules"
            prompt_template = temp_dir / "prompt_template.txt"
            rules_dir.mkdir(parents=True)
            prompt_template.write_text(
                "rule={{SIGMA_RULE}}\ncommand={{TRUE_POSITIVE_TEST_COMMAND}}",
                encoding="utf-8",
            )
            rule_name = "proc_creation_win_a"
            (rules_dir / f"{rule_name}.yml").write_text(
                "title: Demo\n"
                "tags:\n"
                "  - attack.execution\n"
                "  - attack.t1059.003\n",
                encoding="utf-8",
            )
            rule_tp_dir = tp_dir / rule_name
            rule_tp_dir.mkdir(parents=True)
            (rule_tp_dir / "commandlines.txt").write_text("cmd.exe /c whoami", encoding="utf-8")

            config = CerebrasConfig(
                rules_dir=rules_dir,
                true_positive_dir=tp_dir,
                prompt_template=prompt_template,
                output_path=output_path,
                raw_output_dir=raw_output_dir,
                rule_output_dir=rule_output_dir,
                checkpoint_path=checkpoint_path,
                api_key="key",
                max_retries=0,
            )

            with patch("generator.cerebras_generator.call_cerebras", return_value=""):
                run_generation(config)

            checkpoint_after_error = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            self.assertIn("error", checkpoint_after_error["records"][0])
            self.assertFalse((rule_output_dir / f"{rule_name}.json").exists())

            fixed_response = '[{"output": "cmd.exe /c whoami /user", "explanation": "safe variant"}]'
            with patch("generator.cerebras_generator.call_cerebras", return_value=fixed_response) as call:
                run_generation(config)

            output_after_retry = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(call.call_count, 1)
            self.assertEqual(output_after_retry, [])
            self.assertTrue((rule_output_dir / f"{rule_name}.json").exists())
            self.assertEqual((rule_output_dir / f"{rule_name}.json").read_text(encoding="utf-8").strip(), fixed_response)

    def test_run_generation_saves_non_json_llm_output_raw(self) -> None:
        with tempfile.TemporaryDirectory() as dirname:
            temp_dir = Path(dirname)
            rules_dir = temp_dir / "rules"
            tp_dir = temp_dir / "data" / "true_positive_test"
            output_path = temp_dir / "input" / "cases.json"
            checkpoint_path = temp_dir / "output" / "checkpoint.json"
            raw_output_dir = temp_dir / "output" / "raw"
            rule_output_dir = temp_dir / "output" / "rules"
            prompt_template = temp_dir / "prompt_template.txt"
            rules_dir.mkdir(parents=True)
            prompt_template.write_text(
                "rule={{SIGMA_RULE}}\ncommand={{TRUE_POSITIVE_TEST_COMMAND}}",
                encoding="utf-8",
            )
            rule_name = "proc_creation_win_a"
            (rules_dir / f"{rule_name}.yml").write_text(
                "title: Demo\n"
                "tags:\n"
                "  - attack.execution\n"
                "  - attack.t1059.003\n",
                encoding="utf-8",
            )
            rule_tp_dir = tp_dir / rule_name
            rule_tp_dir.mkdir(parents=True)
            (rule_tp_dir / "commandlines.txt").write_text("cmd.exe /c whoami", encoding="utf-8")

            config = CerebrasConfig(
                rules_dir=rules_dir,
                true_positive_dir=tp_dir,
                prompt_template=prompt_template,
                output_path=output_path,
                raw_output_dir=raw_output_dir,
                rule_output_dir=rule_output_dir,
                checkpoint_path=checkpoint_path,
                api_key="key",
                max_retries=0,
            )
            raw_response = "not json, but still useful"

            with patch("generator.cerebras_generator.call_cerebras", return_value=raw_response):
                run_generation(config)

            self.assertEqual((rule_output_dir / f"{rule_name}.json").read_text(encoding="utf-8").strip(), raw_response)
            self.assertEqual(json.loads(output_path.read_text(encoding="utf-8")), [])


if __name__ == "__main__":
    unittest.main()
