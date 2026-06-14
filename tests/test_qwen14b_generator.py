from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from generator.groq_generator import GeneratorError, HTTPResponse
from generator.qwen_14b_generator import (
    DEFAULT_API_URL,
    DEFAULT_PROMPT_TEMPLATE,
    Qwen14BConfig,
    call_qwen14b,
    config_from_args,
    extract_response_text,
    request_headers,
    request_payload,
    run_generation,
)


class Qwen14BGeneratorTests(unittest.TestCase):
    def test_default_prompt_template_is_qwen14b_specific(self) -> None:
        self.assertEqual(DEFAULT_PROMPT_TEMPLATE.name, "qwen14b_prompt_template.txt")

    def test_request_payload_uses_prompt_and_max_tokens_only(self) -> None:
        payload = request_payload("prompt text", Qwen14BConfig(max_completion_tokens=512))

        self.assertEqual(payload, {"prompt": "prompt text", "max_tokens": 512})

    def test_request_headers_do_not_include_auth(self) -> None:
        headers = request_headers(Qwen14BConfig(user_agent="test-agent"))

        self.assertEqual(headers["User-Agent"], "test-agent")
        self.assertEqual(headers["Accept"], "application/json")
        self.assertNotIn("Authorization", headers)

    def test_extract_response_text_accepts_response_key(self) -> None:
        response = HTTPResponse(200, json.dumps({"response": '[{"output":"cmd","explanation":"ok"}]'}), {})

        self.assertEqual(extract_response_text(response), '[{"output":"cmd","explanation":"ok"}]')

    def test_call_qwen14b_posts_to_generate_endpoint(self) -> None:
        response = HTTPResponse(200, json.dumps({"response": "[]"}), {})

        with patch("generator.qwen_14b_generator.post_qwen_json", return_value=response) as post_json:
            content = call_qwen14b(
                "prompt",
                Qwen14BConfig(
                    api_url="http://127.0.0.1:5002/generate",
                    max_completion_tokens=256,
                    connect_timeout_seconds=10,
                    timeout_seconds=180,
                    max_retries=0,
                ),
            )

        self.assertEqual(content, "[]")
        args = post_json.call_args.args
        self.assertEqual(args[0], "http://127.0.0.1:5002/generate")
        self.assertEqual(args[2], {"prompt": "prompt", "max_tokens": 256})
        self.assertEqual(args[3], 10)
        self.assertEqual(args[4], 180)

    def test_config_from_args_prefers_llm_api_endpoint_env(self) -> None:
        parser = __import__("generator.qwen_14b_generator", fromlist=["build_parser"]).build_parser()
        args = parser.parse_args(["--dry-run", "--env-file", "missing.env"])

        with patch.dict(os.environ, {"LLM_API_ENDPOINT": "http://example.local/generate"}, clear=False):
            config = config_from_args(args)

        self.assertEqual(config.api_url, "http://example.local/generate")

    def test_config_from_args_falls_back_to_default_endpoint(self) -> None:
        parser = __import__("generator.qwen_14b_generator", fromlist=["build_parser"]).build_parser()
        args = parser.parse_args(["--dry-run", "--env-file", "missing.env"])

        with patch.dict(os.environ, {"LLM_API_ENDPOINT": ""}, clear=False):
            config = config_from_args(args)

        self.assertEqual(config.api_url, DEFAULT_API_URL)

    def test_call_qwen14b_reports_connection_refused_clearly(self) -> None:
        import requests

        with patch(
            "generator.qwen_14b_generator.post_qwen_json",
            side_effect=requests.ConnectionError("No connection could be made because the target machine actively refused it"),
        ):
            with self.assertRaises(GeneratorError) as raised:
                call_qwen14b("prompt", Qwen14BConfig(api_url="http://100.105.150.19:5002/generate", max_retries=0))

        self.assertIn("cannot connect to Qwen 14B endpoint", str(raised.exception))
        self.assertIn("check VPN, server process, and port 5002", str(raised.exception))

    def test_run_generation_writes_model_output_without_checkpoint(self) -> None:
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
            rule_name = "proc_creation_win_demo"
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

            response_text = '[{"output": "cmd.exe /c whoami /user", "explanation": "safe variant"}]'
            config = Qwen14BConfig(
                rules_dir=rules_dir,
                true_positive_dir=tp_dir,
                prompt_template=prompt_template,
                output_path=output_path,
                raw_output_dir=raw_output_dir,
                rule_output_dir=rule_output_dir,
                max_retries=0,
                min_request_interval_seconds=0,
            )

            with patch("generator.qwen_14b_generator.call_qwen14b", return_value=response_text):
                run_generation(config)

            self.assertEqual((rule_output_dir / f"{rule_name}.json").read_text(encoding="utf-8").strip(), response_text)
            self.assertFalse((raw_output_dir / "qwen14b_generation_checkpoint.json").exists())
            self.assertEqual(json.loads(output_path.read_text(encoding="utf-8")), [])
            self.assertEqual(len(list(raw_output_dir.glob("qwen14b_generation_*.json"))), 1)


if __name__ == "__main__":
    unittest.main()
