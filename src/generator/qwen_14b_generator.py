"""Generate Sigma command-line mutation cases through a Qwen 14B /generate API.

The module mirrors ``groq_generator.py`` for local/VPN-hosted Qwen 14B servers.
It renders Sigma rules and true-positive command-line examples through a prompt
template, calls an endpoint that accepts ``{"prompt": ..., "max_tokens": ...}``,
and writes per-rule LLM outputs for later conversion.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import requests
except ModuleNotFoundError:  # pragma: no cover - project requirements include requests
    requests = None

REQUEST_EXCEPTIONS: tuple[type[BaseException], ...] = ()
if requests is not None:
    REQUEST_EXCEPTIONS = (requests.RequestException,)

try:  # Support both package imports and direct script execution.
    from .groq_generator import (
        DEFAULT_MAX_OUTPUTS,
        DEFAULT_RULES_DIR,
        DEFAULT_TRUE_POSITIVE_DIR,
        GeneratorError,
        HTTPResponse,
        build_jobs,
        format_true_positive_commands,
        job_result_path,
        load_env_file,
        normalize_response_headers,
        positive_int,
        read_text,
        read_completed_job_result,
        render_prompt,
        retry_after_seconds,
        wait_for_request_slot,
        write_job_result,
        write_json_overwrite,
    )
except ImportError:  # pragma: no cover - used when run as a file
    from groq_generator import (
        DEFAULT_MAX_OUTPUTS,
        DEFAULT_RULES_DIR,
        DEFAULT_TRUE_POSITIVE_DIR,
        GeneratorError,
        HTTPResponse,
        build_jobs,
        format_true_positive_commands,
        job_result_path,
        load_env_file,
        normalize_response_headers,
        positive_int,
        read_text,
        read_completed_job_result,
        render_prompt,
        retry_after_seconds,
        wait_for_request_slot,
        write_job_result,
        write_json_overwrite,
    )


DEFAULT_MODEL = "qwen14b"
DEFAULT_API_URL = "http://100.105.150.19:5002/generate"
DEFAULT_API_URL_ENV = "LLM_API_ENDPOINT"
DEFAULT_USER_AGENT = "DATN1-Qwen14BGenerator/1.0"
DEFAULT_PROMPT_TEMPLATE = Path(__file__).with_name("qwen14b_prompt_template.txt")
DEFAULT_OUTPUT_PATH = Path("input/cmdline_bypass_with_Qwen14B.generated.json")
DEFAULT_RAW_OUTPUT_DIR = Path("output/qwen14b_generator")
DEFAULT_RULE_OUTPUT_DIR = DEFAULT_RAW_OUTPUT_DIR / "rules"
DEFAULT_MAX_COMPLETION_TOKENS = 1536
DEFAULT_CONNECT_TIMEOUT_SECONDS = 10
DEFAULT_TIMEOUT_SECONDS = 180
DEFAULT_MAX_RETRIES = 1
DEFAULT_RETRY_DELAY_SECONDS = 20.0
DEFAULT_MIN_REQUEST_INTERVAL_SECONDS = 60.0
RETRYABLE_HTTP_CODES = {408, 409, 429, 500, 502, 503, 504}
NON_RETRYABLE_HTTP_CODES = {400, 401, 403, 404, 422}


class Qwen14BHTTPError(GeneratorError):
    """Raised when the Qwen 14B endpoint returns an HTTP error response."""

    def __init__(self, status_code: int, body: str) -> None:
        self.status_code = status_code
        self.body = body
        message = f"Qwen 14B API HTTP {status_code}: {body}"
        super().__init__(message)


@dataclass(frozen=True)
class Qwen14BConfig:
    """Runtime settings for one Qwen 14B generation run."""

    rules_dir: Path = DEFAULT_RULES_DIR
    true_positive_dir: Path = DEFAULT_TRUE_POSITIVE_DIR
    prompt_template: Path = DEFAULT_PROMPT_TEMPLATE
    output_path: Path = DEFAULT_OUTPUT_PATH
    raw_output_dir: Path = DEFAULT_RAW_OUTPUT_DIR
    rule_output_dir: Path = DEFAULT_RULE_OUTPUT_DIR
    model: str = DEFAULT_MODEL
    api_url: str = DEFAULT_API_URL
    user_agent: str = DEFAULT_USER_AGENT
    prompt_scope: str = "rule"
    include_rules: tuple[str, ...] = ()
    limit_rules: int | None = None
    limit_commands_per_rule: int | None = None
    max_outputs: int = DEFAULT_MAX_OUTPUTS
    shell: str = "cmd.exe"
    max_completion_tokens: int = DEFAULT_MAX_COMPLETION_TOKENS
    connect_timeout_seconds: int = DEFAULT_CONNECT_TIMEOUT_SECONDS
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    max_retries: int = DEFAULT_MAX_RETRIES
    retry_delay_seconds: float = DEFAULT_RETRY_DELAY_SECONDS
    rate_limit_buffer_seconds: float = 0.5
    max_rate_limit_sleep_seconds: float = 120.0
    min_request_interval_seconds: float = DEFAULT_MIN_REQUEST_INTERVAL_SECONDS
    overwrite: bool = False
    resume: bool = True
    dry_run: bool = False
    save_prompts: bool = False
    continue_on_error: bool = False


def request_payload(prompt: str, config: Qwen14BConfig) -> dict[str, Any]:
    """Build the local /generate payload expected by the Qwen 14B server."""
    return {
        "prompt": prompt,
        "max_tokens": config.max_completion_tokens,
    }


def request_headers(config: Qwen14BConfig) -> dict[str, str]:
    """Build HTTP headers for Qwen 14B requests."""
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": config.user_agent,
    }


def post_qwen_json(
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    connect_timeout_seconds: int,
    read_timeout_seconds: int,
) -> HTTPResponse:
    """Post JSON to the local Qwen 14B endpoint."""
    if requests is None:
        raise RuntimeError("requests is not installed")
    response = requests.post(
        url=url,
        headers=headers,
        json=payload,
        timeout=(connect_timeout_seconds, read_timeout_seconds),
    )
    return HTTPResponse(response.status_code, response.text, normalize_response_headers(response.headers))


def qwen14b_error_text(status_code: int, body: str) -> str:
    """Return a compact, useful Qwen 14B error body for logs."""
    text = body.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return text[:500]

    if isinstance(data, dict):
        for key in ("error", "detail", "message"):
            value = data.get(key)
            if isinstance(value, str):
                return value[:500]
            if isinstance(value, dict):
                message = value.get("message") or value.get("code") or text
                return str(message)[:500]
    return text[:500]


def extract_text_from_json(data: Any) -> str:
    """Extract generated text from common local /generate response shapes."""
    if isinstance(data, str):
        return data
    if isinstance(data, list):
        return json.dumps(data, ensure_ascii=False)
    if not isinstance(data, dict):
        return str(data)

    choices = data.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            message = first.get("message")
            if isinstance(message, dict) and isinstance(message.get("content"), str):
                return message["content"]
            if isinstance(first.get("text"), str):
                return first["text"]

    for key in ("response", "generated_text", "text", "output", "content", "result"):
        value = data.get(key)
        if isinstance(value, str):
            return value
        if isinstance(value, (list, dict)):
            return json.dumps(value, ensure_ascii=False)

    return json.dumps(data, ensure_ascii=False)


def extract_response_text(response: HTTPResponse) -> str:
    """Return generated text from an HTTP response."""
    text = response.text.strip()
    if not text:
        raise GeneratorError("empty response from Qwen 14B endpoint")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return text
    return extract_text_from_json(data)


def format_request_exception(exc: BaseException, endpoint: str) -> str:
    """Return a clear network error for local/VPN endpoint failures."""
    message = str(exc)
    if "actively refused" in message or "connection refused" in message.lower():
        return f"cannot connect to Qwen 14B endpoint {endpoint}; check VPN, server process, and port 5002. Original error: {message}"
    return f"request to Qwen 14B endpoint {endpoint} failed: {message}"


def should_stop_after_error(exc: Exception) -> bool:
    """Return whether the generator should stop instead of trying every prompt."""
    return isinstance(exc, Qwen14BHTTPError) and exc.status_code in NON_RETRYABLE_HTTP_CODES


def call_qwen14b(prompt: str, config: Qwen14BConfig) -> str:
    """Call Qwen 14B and return generated text."""
    headers = request_headers(config)
    payload = request_payload(prompt, config)
    last_error = ""

    for attempt in range(config.max_retries + 1):
        try:
            response = post_qwen_json(
                config.api_url,
                headers,
                payload,
                config.connect_timeout_seconds,
                config.timeout_seconds,
            )
            if response.status_code >= 400:
                error_text = qwen14b_error_text(response.status_code, response.text)
                if response.status_code in RETRYABLE_HTTP_CODES and attempt < config.max_retries:
                    fallback = config.retry_delay_seconds * (attempt + 1)
                    sleep_seconds = retry_after_seconds(response, fallback) + config.rate_limit_buffer_seconds
                    if sleep_seconds > config.max_rate_limit_sleep_seconds:
                        raise Qwen14BHTTPError(
                            response.status_code,
                            f"{error_text}; retry wait {sleep_seconds:.2f}s exceeds "
                            f"--max-rate-limit-sleep-seconds={config.max_rate_limit_sleep_seconds:g}",
                        )
                    last_error = f"Qwen 14B API HTTP {response.status_code}: {error_text}"
                    print(
                        f"    [rate-limit] waiting {sleep_seconds:.2f}s before retry "
                        f"{attempt + 1}/{config.max_retries}",
                        file=sys.stderr,
                    )
                    time.sleep(sleep_seconds)
                    continue
                raise Qwen14BHTTPError(response.status_code, error_text)
            return extract_response_text(response)
        except Qwen14BHTTPError:
            raise
        except REQUEST_EXCEPTIONS + (TimeoutError, OSError, RuntimeError, ValueError) as exc:
            last_error = format_request_exception(exc, config.api_url)
            if attempt < config.max_retries:
                time.sleep(config.retry_delay_seconds * (attempt + 1))
                continue
            break

    raise GeneratorError(f"Qwen 14B API request failed: {last_error}")


def run_generation(config: Qwen14BConfig) -> int:
    """Run generation and write both runner cases and raw audit output."""
    template = read_text(config.prompt_template)
    jobs = build_jobs(config)
    if config.dry_run:
        rule_count = len({job.rule_path for job in jobs})
        print(f"[+] Dry run: {len(jobs)} prompt(s) across {rule_count} rule(s)")
        return 0
    if not jobs:
        raise GeneratorError("no jobs found; check --rules-dir and --true-positive-dir")

    raw_records: list[dict[str, Any]] = []
    generated_cases: list[dict[str, Any]] = []
    last_request_started_at: float | None = None

    print(f"[+] Generating with model {config.model}: {len(jobs)} prompt(s)")
    for index, job in enumerate(jobs, start=1):
        command_label = (
            f"command #{job.command_index}"
            if job.command_index is not None
            else f"{len(job.source_commands)} command(s)"
        )
        result_path = job_result_path(job, config.rule_output_dir)

        if config.resume:
            completed_result = read_completed_job_result(result_path)
            if completed_result is not None:
                print(f"[{index}/{len(jobs)}] {job.rule_path.stem} {command_label} [skip file]")
                raw_records.append(dict(completed_result["record"]))
                continue

        prompt = render_prompt(template, job.rule_text, format_true_positive_commands(job.source_commands))
        print(f"[{index}/{len(jobs)}] {job.rule_path.stem} {command_label}")
        raw_record: dict[str, Any] = {
            "rule": job.rule_path.stem,
            "rule_path": str(job.rule_path),
            "technique_id": job.technique_id,
            "source_true_positive_command": "\n".join(job.source_commands),
            "source_true_positive_commands": list(job.source_commands),
            "source_true_positive_index": job.command_index,
            "source_true_positive_count": len(job.source_commands),
            "model": config.model,
        }
        if config.save_prompts:
            raw_record["prompt"] = prompt

        error: Exception | None = None
        try:
            last_request_started_at = wait_for_request_slot(last_request_started_at, config)
            response_text = call_qwen14b(prompt, config)
            raw_record["response_text"] = response_text
            write_job_result(
                job=job,
                config=config,
                raw_record=raw_record,
                generated_cases=[],
            )
        except Exception as exc:
            error = exc
            raw_record["error"] = str(exc)
            print(f"    [!] {exc}", file=sys.stderr)

        raw_records.append(raw_record)
        if error is not None and should_stop_after_error(error) and not config.continue_on_error:
            print(
                "    [!] Stopping after non-retryable Qwen 14B API error. "
                "Fix the endpoint/network issue, or pass --continue-on-error to keep scanning.",
                file=sys.stderr,
            )
            break

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    raw_path = config.raw_output_dir / f"qwen14b_generation_{timestamp}.json"
    raw_payload = {
        "created_at": timestamp,
        "model": config.model,
        "api_url": config.api_url,
        "prompt_template": str(config.prompt_template),
        "rules_dir": str(config.rules_dir),
        "true_positive_dir": str(config.true_positive_dir),
        "rule_output_dir": str(config.rule_output_dir),
        "max_outputs": config.max_outputs,
        "generated_case_count": len(generated_cases),
        "record_count": len(raw_records),
        "generated_cases": generated_cases,
        "records": raw_records,
    }

    write_json_overwrite(config.output_path, generated_cases)
    write_json_overwrite(raw_path, raw_payload)
    print(f"[+] Wrote legacy converted cases: {config.output_path} ({len(generated_cases)} case(s))")
    print(f"[+] Wrote per-rule LLM outputs: {config.rule_output_dir}")
    print(f"[+] Wrote raw audit: {raw_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser for the Qwen 14B generator."""
    parser = argparse.ArgumentParser(description="Generate Sigma rule evaluator cases with local Qwen 14B.")
    parser.add_argument("--rules-dir", default=str(DEFAULT_RULES_DIR))
    parser.add_argument("--true-positive-dir", default=str(DEFAULT_TRUE_POSITIVE_DIR))
    parser.add_argument("--prompt-template", default=str(DEFAULT_PROMPT_TEMPLATE))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_PATH))
    parser.add_argument("--raw-output-dir", default=str(DEFAULT_RAW_OUTPUT_DIR))
    parser.add_argument("--rule-output-dir", help="Per-rule result directory. Defaults to <raw-output-dir>/rules.")
    parser.add_argument("--rule", action="append", default=[], help="Rule stem to generate. Can be repeated.")
    parser.add_argument("--limit-rules", type=positive_int)
    parser.add_argument("--limit-commands-per-rule", type=positive_int)
    parser.add_argument("--max-outputs", type=positive_int, default=DEFAULT_MAX_OUTPUTS)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--api-url", help=f"Qwen 14B /generate endpoint. Defaults to {DEFAULT_API_URL_ENV}.")
    parser.add_argument("--api-url-env", default=DEFAULT_API_URL_ENV)
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    parser.add_argument(
        "--prompt-scope",
        choices=["rule", "command"],
        default="rule",
        help="Use one prompt per rule by default, or one prompt per true-positive command.",
    )
    parser.add_argument("--shell", default="cmd.exe")
    parser.add_argument(
        "--max-completion-tokens",
        "--max-tokens",
        dest="max_completion_tokens",
        type=positive_int,
        default=DEFAULT_MAX_COMPLETION_TOKENS,
        help=f"Max tokens sent as request body max_tokens. Default: {DEFAULT_MAX_COMPLETION_TOKENS}.",
    )
    parser.add_argument("--connect-timeout-seconds", type=positive_int, default=DEFAULT_CONNECT_TIMEOUT_SECONDS)
    parser.add_argument("--timeout-seconds", type=positive_int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES)
    parser.add_argument("--retry-delay-seconds", type=float, default=DEFAULT_RETRY_DELAY_SECONDS)
    parser.add_argument(
        "--rate-limit-buffer-seconds",
        type=float,
        default=0.5,
        help="Extra seconds added to retry-after/reset waits.",
    )
    parser.add_argument(
        "--max-rate-limit-sleep-seconds",
        type=float,
        default=120.0,
        help="Abort instead of sleeping longer than this for one retry.",
    )
    parser.add_argument(
        "--min-request-interval-seconds",
        type=float,
        default=DEFAULT_MIN_REQUEST_INTERVAL_SECONDS,
        help="Minimum time between request starts. Default 60s to avoid overloading the local model.",
    )
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--no-resume", action="store_true", help="Ignore per-rule result files and start a new run.")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--save-prompts", action="store_true")
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Keep processing prompts after non-retryable API errors.",
    )
    return parser


def resolve_api_url(cli_value: str | None, env_name: str) -> str:
    """Return CLI endpoint, environment endpoint, or the built-in VPN endpoint."""
    return (cli_value or "").strip() or os.environ.get(env_name, "").strip() or DEFAULT_API_URL


def config_from_args(args: argparse.Namespace) -> Qwen14BConfig:
    """Create Qwen14BConfig from parsed CLI args."""
    load_env_file(Path(args.env_file))
    if args.max_retries < 0:
        raise GeneratorError("--max-retries must be >= 0")
    if args.retry_delay_seconds < 0:
        raise GeneratorError("--retry-delay-seconds must be >= 0")
    if args.rate_limit_buffer_seconds < 0:
        raise GeneratorError("--rate-limit-buffer-seconds must be >= 0")
    if args.max_rate_limit_sleep_seconds < 0:
        raise GeneratorError("--max-rate-limit-sleep-seconds must be >= 0")
    if args.min_request_interval_seconds < 0:
        raise GeneratorError("--min-request-interval-seconds must be >= 0")

    raw_output_dir = Path(args.raw_output_dir)
    return Qwen14BConfig(
        rules_dir=Path(args.rules_dir),
        true_positive_dir=Path(args.true_positive_dir),
        prompt_template=Path(args.prompt_template),
        output_path=Path(args.output),
        raw_output_dir=raw_output_dir,
        rule_output_dir=Path(args.rule_output_dir) if args.rule_output_dir else raw_output_dir / "rules",
        model=args.model,
        api_url=resolve_api_url(args.api_url, args.api_url_env),
        user_agent=args.user_agent,
        prompt_scope=args.prompt_scope,
        include_rules=tuple(args.rule),
        limit_rules=args.limit_rules,
        limit_commands_per_rule=args.limit_commands_per_rule,
        max_outputs=args.max_outputs,
        shell=args.shell,
        max_completion_tokens=args.max_completion_tokens,
        connect_timeout_seconds=args.connect_timeout_seconds,
        timeout_seconds=args.timeout_seconds,
        max_retries=args.max_retries,
        retry_delay_seconds=args.retry_delay_seconds,
        rate_limit_buffer_seconds=args.rate_limit_buffer_seconds,
        max_rate_limit_sleep_seconds=args.max_rate_limit_sleep_seconds,
        min_request_interval_seconds=args.min_request_interval_seconds,
        overwrite=args.overwrite,
        resume=not args.no_resume,
        dry_run=args.dry_run,
        save_prompts=args.save_prompts,
        continue_on_error=args.continue_on_error,
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run_generation(config_from_args(args))
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
