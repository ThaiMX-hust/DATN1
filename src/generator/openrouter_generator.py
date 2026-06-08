"""Generate Sigma command-line mutation cases through the OpenRouter chat API.

The module mirrors ``cerebras_generator.py`` but targets OpenRouter's
OpenAI-compatible chat completions endpoint.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:  # Support both package imports and direct script execution.
    from .cerebras_generator import (
        checkpoint_payload,
        checkpoint_records_by_key,
        flush_progress,
        job_resume_key,
        read_json_if_exists,
        template_fingerprint,
        write_json_overwrite,
    )
    from .groq_generator import (
        DEFAULT_MAX_OUTPUTS,
        DEFAULT_RULES_DIR,
        DEFAULT_TRUE_POSITIVE_DIR,
        GeneratorError,
        build_jobs,
        format_true_positive_commands,
        job_result_path,
        load_env_file,
        positive_int,
        post_json,
        read_text,
        read_completed_job_result,
        render_prompt,
        retry_after_seconds,
        write_job_result,
    )
except ImportError:  # pragma: no cover - used when run as a file
    from cerebras_generator import (
        checkpoint_payload,
        checkpoint_records_by_key,
        flush_progress,
        job_resume_key,
        read_json_if_exists,
        template_fingerprint,
        write_json_overwrite,
    )
    from groq_generator import (
        DEFAULT_MAX_OUTPUTS,
        DEFAULT_RULES_DIR,
        DEFAULT_TRUE_POSITIVE_DIR,
        GeneratorError,
        build_jobs,
        format_true_positive_commands,
        job_result_path,
        load_env_file,
        positive_int,
        post_json,
        read_text,
        read_completed_job_result,
        render_prompt,
        retry_after_seconds,
        write_job_result,
    )


DEFAULT_MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free"
DEFAULT_API_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_USER_AGENT = "DATN1-OpenRouterGenerator/1.0"
DEFAULT_PROMPT_TEMPLATE = Path(__file__).with_name("openrouter_prompt_template.txt")
DEFAULT_OUTPUT_PATH = Path("input/cmdline_bypass_with_OpenRouter.generated.json")
DEFAULT_RAW_OUTPUT_DIR = Path("output/openrouter_generator")
DEFAULT_RULE_OUTPUT_DIR = DEFAULT_RAW_OUTPUT_DIR / "rules"
DEFAULT_CHECKPOINT_FILENAME = "openrouter_generation_checkpoint.json"
DEFAULT_MAX_COMPLETION_TOKENS = 768
RETRYABLE_HTTP_CODES = {429, 500, 502, 503, 504}
NON_RETRYABLE_HTTP_CODES = {400, 401, 402, 403, 404, 422}


class OpenRouterHTTPError(GeneratorError):
    """Raised when OpenRouter returns an HTTP error response."""

    def __init__(self, status_code: int, body: str) -> None:
        self.status_code = status_code
        self.body = body
        hint = openrouter_error_hint(status_code, body)
        message = f"OpenRouter API HTTP {status_code}: {body}"
        if hint:
            message = f"{message} ({hint})"
        super().__init__(message)


@dataclass(frozen=True)
class OpenRouterConfig:
    """Runtime settings for one OpenRouter generation run."""

    rules_dir: Path = DEFAULT_RULES_DIR
    true_positive_dir: Path = DEFAULT_TRUE_POSITIVE_DIR
    prompt_template: Path = DEFAULT_PROMPT_TEMPLATE
    output_path: Path = DEFAULT_OUTPUT_PATH
    raw_output_dir: Path = DEFAULT_RAW_OUTPUT_DIR
    rule_output_dir: Path = DEFAULT_RULE_OUTPUT_DIR
    checkpoint_path: Path = DEFAULT_RAW_OUTPUT_DIR / DEFAULT_CHECKPOINT_FILENAME
    model: str = DEFAULT_MODEL
    api_url: str = DEFAULT_API_URL
    api_key: str = ""
    user_agent: str = DEFAULT_USER_AGENT
    prompt_scope: str = "rule"
    include_rules: tuple[str, ...] = ()
    limit_rules: int | None = None
    limit_commands_per_rule: int | None = None
    max_outputs: int = DEFAULT_MAX_OUTPUTS
    shell: str = "cmd.exe"
    temperature: float = 0.2
    max_completion_tokens: int = DEFAULT_MAX_COMPLETION_TOKENS
    timeout_seconds: int = 90
    max_retries: int = 8
    retry_delay_seconds: float = 3.0
    rate_limit_buffer_seconds: float = 0.5
    max_rate_limit_sleep_seconds: float = 120.0
    overwrite: bool = False
    resume: bool = True
    retry_errors: bool = False
    dry_run: bool = False
    save_prompts: bool = False
    continue_on_error: bool = False


def openrouter_error_hint(status_code: int, body: str) -> str:
    """Return a concise remediation hint for common OpenRouter HTTP errors."""
    body_lower = body.lower()
    if status_code == 401:
        return "check OPENROUTER_API_KEY"
    if status_code == 402:
        return "check OpenRouter account credits/limits"
    if status_code == 403:
        return "check OpenRouter key permissions or model access"
    if status_code in {400, 404, 422} and "model" in body_lower:
        return "model may be unavailable/deprecated; check access or pass --model with a listed model"
    return ""


def request_payload(prompt: str, config: OpenRouterConfig) -> dict[str, Any]:
    """Build an OpenRouter chat completions payload."""
    return {
        "model": config.model,
        "messages": [
            {"role": "system", "content": "You output only valid JSON. No analysis. No markdown."},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "temperature": config.temperature,
        "max_tokens": config.max_completion_tokens,
    }


def request_headers(config: OpenRouterConfig) -> dict[str, str]:
    """Build HTTP headers for OpenRouter requests."""
    return {
        "Authorization": f"Bearer {config.api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": config.user_agent,
    }


def openrouter_error_text(status_code: int, body: str) -> str:
    """Return a compact, useful OpenRouter error body for logs."""
    text = body.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return text[:500]

    error = data.get("error") if isinstance(data, dict) else None
    if isinstance(error, dict):
        message = error.get("message") or error.get("code") or text
        return str(message)[:500]
    return text[:500]


def should_stop_after_error(exc: Exception) -> bool:
    """Return whether the generator should stop instead of trying every prompt."""
    return isinstance(exc, OpenRouterHTTPError) and exc.status_code in NON_RETRYABLE_HTTP_CODES


def call_openrouter(prompt: str, config: OpenRouterConfig) -> str:
    """Call OpenRouter and return the assistant message content."""
    if not config.api_key:
        raise GeneratorError("missing OPENROUTER_API_KEY; set it in the environment or pass --api-key-env")

    headers = request_headers(config)
    payload = request_payload(prompt, config)
    last_error = ""

    for attempt in range(config.max_retries + 1):
        try:
            response = post_json(config.api_url, headers, payload, config.timeout_seconds)
            if response.status_code >= 400:
                error_text = openrouter_error_text(response.status_code, response.text)
                if response.status_code in RETRYABLE_HTTP_CODES and attempt < config.max_retries:
                    fallback = config.retry_delay_seconds * (attempt + 1)
                    sleep_seconds = retry_after_seconds(response, fallback) + config.rate_limit_buffer_seconds
                    if sleep_seconds > config.max_rate_limit_sleep_seconds:
                        raise OpenRouterHTTPError(
                            response.status_code,
                            f"{error_text}; retry wait {sleep_seconds:.2f}s exceeds "
                            f"--max-rate-limit-sleep-seconds={config.max_rate_limit_sleep_seconds:g}",
                        )
                    last_error = f"OpenRouter API HTTP {response.status_code}: {error_text}"
                    print(
                        f"    [rate-limit] waiting {sleep_seconds:.2f}s before retry "
                        f"{attempt + 1}/{config.max_retries}",
                        file=sys.stderr,
                    )
                    time.sleep(sleep_seconds)
                    continue
                raise OpenRouterHTTPError(response.status_code, error_text)
            data = json.loads(response.text)
            return str(data["choices"][0]["message"].get("content") or "")
        except OpenRouterHTTPError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError, KeyError, IndexError, TypeError, ValueError) as exc:
            last_error = str(exc)
            if attempt < config.max_retries:
                time.sleep(config.retry_delay_seconds * (attempt + 1))
                continue
            break

    raise GeneratorError(f"OpenRouter API request failed: {last_error}")


def run_generation(config: OpenRouterConfig) -> int:
    """Run generation and write both runner cases and raw audit output."""
    template = read_text(config.prompt_template)
    template_hash = template_fingerprint(template)
    jobs = build_jobs(config)
    if config.dry_run:
        rule_count = len({job.rule_path for job in jobs})
        print(f"[+] Dry run: {len(jobs)} prompt(s) across {rule_count} rule(s)")
        return 0
    if not jobs:
        raise GeneratorError("no jobs found; check --rules-dir and --true-positive-dir")

    checkpoint = read_json_if_exists(config.checkpoint_path) if config.resume else {}
    completed_records = checkpoint_records_by_key(checkpoint, retry_errors=config.retry_errors)
    created_at = str(checkpoint.get("created_at") or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))

    raw_records: list[dict[str, Any]] = []
    generated_cases: list[dict[str, Any]] = []
    counters: dict[str, int] = {}
    seen_outputs: set[tuple[str, str]] = set()

    if config.resume and completed_records:
        print(f"[+] Resuming from {config.checkpoint_path}: {len(completed_records)} successful checkpoint job(s)")
    print(f"[+] Generating with model {config.model}: {len(jobs)} prompt(s)")
    for index, job in enumerate(jobs, start=1):
        command_label = (
            f"command #{job.command_index}"
            if job.command_index is not None
            else f"{len(job.source_commands)} command(s)"
        )
        key = job_resume_key(job, config, template_hash)
        result_path = job_result_path(job, config.rule_output_dir)

        if config.resume:
            completed_result = read_completed_job_result(result_path)
            if completed_result is not None:
                print(f"[{index}/{len(jobs)}] {job.rule_path.stem} {command_label} [skip file]")
                raw_records.append(dict(completed_result["record"]))
                continue

        if key in completed_records:
            print(f"[{index}/{len(jobs)}] {job.rule_path.stem} {command_label} [skip checkpoint]")
            raw_record = dict(completed_records[key])
            raw_records.append(raw_record)
            write_job_result(
                job=job,
                config=config,
                raw_record=raw_record,
                generated_cases=[],
                template_hash=template_hash,
            )
            continue

        prompt = render_prompt(template, job.rule_text, format_true_positive_commands(job.source_commands))
        print(f"[{index}/{len(jobs)}] {job.rule_path.stem} {command_label}")
        raw_record: dict[str, Any] = {
            "job_key": key,
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
            response_text = call_openrouter(prompt, config)
            raw_record["response_text"] = response_text
            write_job_result(
                job=job,
                config=config,
                raw_record=raw_record,
                generated_cases=[],
                template_hash=template_hash,
            )
        except Exception as exc:
            error = exc
            raw_record["error"] = str(exc)
            print(f"    [!] {exc}", file=sys.stderr)

        raw_records.append(raw_record)
        flush_progress(
            created_at=created_at,
            config=config,
            template_hash=template_hash,
            raw_records=raw_records,
            generated_cases=generated_cases,
            completed=False,
        )
        if error is not None and should_stop_after_error(error) and not config.continue_on_error:
            print(
                "    [!] Stopping after non-retryable OpenRouter API error. "
                "Fix the API key/model/network issue, or pass --continue-on-error to keep scanning.",
                file=sys.stderr,
            )
            break

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    raw_path = config.raw_output_dir / f"openrouter_generation_{timestamp}.json"
    raw_payload = checkpoint_payload(
        created_at=created_at,
        updated_at=timestamp,
        config=config,
        template_hash=template_hash,
        raw_records=raw_records,
        generated_cases=generated_cases,
        completed=True,
    )

    write_json_overwrite(config.output_path, generated_cases)
    write_json_overwrite(config.checkpoint_path, raw_payload)
    write_json_overwrite(raw_path, raw_payload)
    print(f"[+] Wrote legacy converted cases: {config.output_path} ({len(generated_cases)} case(s))")
    print(f"[+] Wrote per-rule LLM outputs: {config.rule_output_dir}")
    print(f"[+] Wrote checkpoint: {config.checkpoint_path}")
    print(f"[+] Wrote raw audit: {raw_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser for the OpenRouter generator."""
    parser = argparse.ArgumentParser(description="Generate Sigma rule evaluator cases with OpenRouter Nemotron.")
    parser.add_argument("--rules-dir", default=str(DEFAULT_RULES_DIR))
    parser.add_argument("--true-positive-dir", default=str(DEFAULT_TRUE_POSITIVE_DIR))
    parser.add_argument("--prompt-template", default=str(DEFAULT_PROMPT_TEMPLATE))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_PATH))
    parser.add_argument("--raw-output-dir", default=str(DEFAULT_RAW_OUTPUT_DIR))
    parser.add_argument("--rule-output-dir", help="Per-rule result directory. Defaults to <raw-output-dir>/rules.")
    parser.add_argument(
        "--checkpoint",
        help=f"Resume checkpoint path. Defaults to <raw-output-dir>/{DEFAULT_CHECKPOINT_FILENAME}.",
    )
    parser.add_argument("--rule", action="append", default=[], help="Rule stem to generate. Can be repeated.")
    parser.add_argument("--limit-rules", type=positive_int)
    parser.add_argument("--limit-commands-per-rule", type=positive_int)
    parser.add_argument("--max-outputs", type=positive_int, default=DEFAULT_MAX_OUTPUTS)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--api-url", default=DEFAULT_API_URL)
    parser.add_argument("--api-key-env", default="OPENROUTER_API_KEY")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    parser.add_argument(
        "--prompt-scope",
        choices=["rule", "command"],
        default="rule",
        help="Use one prompt per rule by default, or one prompt per true-positive command.",
    )
    parser.add_argument("--shell", default="cmd.exe")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--max-completion-tokens", type=positive_int, default=DEFAULT_MAX_COMPLETION_TOKENS)
    parser.add_argument("--timeout-seconds", type=positive_int, default=90)
    parser.add_argument("--max-retries", type=int, default=8)
    parser.add_argument("--retry-delay-seconds", type=float, default=3.0)
    parser.add_argument(
        "--rate-limit-buffer-seconds",
        type=float,
        default=0.5,
        help="Extra seconds added to OpenRouter retry-after/reset waits.",
    )
    parser.add_argument(
        "--max-rate-limit-sleep-seconds",
        type=float,
        default=120.0,
        help="Abort instead of sleeping longer than this for one retry.",
    )
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--no-resume", action="store_true", help="Ignore the checkpoint and start a new run.")
    parser.add_argument(
        "--retry-errors",
        action="store_true",
        help="Deprecated compatibility flag. Checkpointed error jobs are retried when no per-rule result file exists.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--save-prompts", action="store_true")
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Keep processing prompts after non-retryable API errors such as 401/403.",
    )
    return parser


def config_from_args(args: argparse.Namespace) -> OpenRouterConfig:
    """Create OpenRouterConfig from parsed CLI args."""
    load_env_file(Path(args.env_file))
    api_key = os.environ.get(args.api_key_env, "")
    if args.max_retries < 0:
        raise GeneratorError("--max-retries must be >= 0")
    if args.retry_delay_seconds < 0:
        raise GeneratorError("--retry-delay-seconds must be >= 0")
    if args.rate_limit_buffer_seconds < 0:
        raise GeneratorError("--rate-limit-buffer-seconds must be >= 0")
    if args.max_rate_limit_sleep_seconds < 0:
        raise GeneratorError("--max-rate-limit-sleep-seconds must be >= 0")

    return OpenRouterConfig(
        rules_dir=Path(args.rules_dir),
        true_positive_dir=Path(args.true_positive_dir),
        prompt_template=Path(args.prompt_template),
        output_path=Path(args.output),
        raw_output_dir=Path(args.raw_output_dir),
        rule_output_dir=Path(args.rule_output_dir) if args.rule_output_dir else Path(args.raw_output_dir) / "rules",
        checkpoint_path=Path(args.checkpoint) if args.checkpoint else Path(args.raw_output_dir) / DEFAULT_CHECKPOINT_FILENAME,
        model=args.model,
        api_url=args.api_url,
        api_key=api_key,
        user_agent=args.user_agent,
        prompt_scope=args.prompt_scope,
        include_rules=tuple(args.rule),
        limit_rules=args.limit_rules,
        limit_commands_per_rule=args.limit_commands_per_rule,
        max_outputs=args.max_outputs,
        shell=args.shell,
        temperature=args.temperature,
        max_completion_tokens=args.max_completion_tokens,
        timeout_seconds=args.timeout_seconds,
        max_retries=args.max_retries,
        retry_delay_seconds=args.retry_delay_seconds,
        rate_limit_buffer_seconds=args.rate_limit_buffer_seconds,
        max_rate_limit_sleep_seconds=args.max_rate_limit_sleep_seconds,
        overwrite=args.overwrite,
        resume=not args.no_resume,
        retry_errors=args.retry_errors,
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
