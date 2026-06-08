"""Generate Sigma command-line mutation cases through the Cerebras chat API.

The module mirrors ``groq_generator.py`` but targets Cerebras' chat
completions endpoint and defaults to Cerebras' recommended GPT OSS model.
"""

from __future__ import annotations

import argparse
import hashlib
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


DEFAULT_MODEL = "gpt-oss-120b"
DEFAULT_API_URL = "https://api.cerebras.ai/v1/chat/completions"
DEFAULT_USER_AGENT = "DATN1-CerebrasGenerator/1.0"
DEFAULT_PROMPT_TEMPLATE = Path(__file__).with_name("cerebras_prompt_template.txt")
DEFAULT_OUTPUT_PATH = Path("input/cmdline_bypass_with_Cerebras.generated.json")
DEFAULT_RAW_OUTPUT_DIR = Path("output/cerebras_generator")
DEFAULT_RULE_OUTPUT_DIR = DEFAULT_RAW_OUTPUT_DIR / "rules"
DEFAULT_CHECKPOINT_FILENAME = "cerebras_generation_checkpoint.json"
DEFAULT_MAX_COMPLETION_TOKENS = 768
RETRYABLE_HTTP_CODES = {429, 500, 502, 503, 504}
NON_RETRYABLE_HTTP_CODES = {400, 401, 403, 404, 422}


class CerebrasHTTPError(GeneratorError):
    """Raised when Cerebras returns an HTTP error response."""

    def __init__(self, status_code: int, body: str) -> None:
        self.status_code = status_code
        self.body = body
        hint = cerebras_error_hint(status_code, body)
        message = f"Cerebras API HTTP {status_code}: {body}"
        if hint:
            message = f"{message} ({hint})"
        super().__init__(message)


@dataclass(frozen=True)
class CerebrasConfig:
    """Runtime settings for one Cerebras generation run."""

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
    reasoning_format: str = "none"
    overwrite: bool = False
    resume: bool = True
    retry_errors: bool = False
    dry_run: bool = False
    save_prompts: bool = False
    continue_on_error: bool = False


def cerebras_error_hint(status_code: int, body: str) -> str:
    """Return a concise remediation hint for common Cerebras HTTP errors."""
    body_lower = body.lower()
    if status_code == 401:
        return "check CEREBRAS_API_KEY"
    if status_code == 403:
        return "check project/model permissions for this API key"
    if status_code in {400, 404, 422} and "model" in body_lower:
        return "model may be unavailable/deprecated; check access or pass --model with a listed model"
    return ""


def request_payload(prompt: str, config: CerebrasConfig) -> dict[str, Any]:
    """Build a Cerebras chat completions payload."""
    payload: dict[str, Any] = {
        "model": config.model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "temperature": config.temperature,
        "max_completion_tokens": config.max_completion_tokens,
    }
    if config.reasoning_format and config.reasoning_format != "none":
        payload["reasoning_format"] = config.reasoning_format
    return payload


def request_headers(config: CerebrasConfig) -> dict[str, str]:
    """Build HTTP headers for Cerebras requests."""
    return {
        "Authorization": f"Bearer {config.api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": config.user_agent,
    }


def cerebras_error_text(status_code: int, body: str) -> str:
    """Return a compact, useful Cerebras error body for logs."""
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
    return isinstance(exc, CerebrasHTTPError) and exc.status_code in NON_RETRYABLE_HTTP_CODES


def template_fingerprint(template: str) -> str:
    """Return a stable fingerprint for prompt-template-sensitive resume keys."""
    return hashlib.sha256(template.encode("utf-8")).hexdigest()


def job_resume_key(job: Any, config: CerebrasConfig, template_hash: str) -> str:
    """Return a stable key for deciding whether a job was already processed."""
    key_payload = {
        "model": config.model,
        "api_url": config.api_url,
        "prompt_scope": config.prompt_scope,
        "template_sha256": template_hash,
        "rule": job.rule_path.stem,
        "source_true_positive_index": job.command_index,
        "source_true_positive_commands": list(job.source_commands),
    }
    return json.dumps(key_payload, ensure_ascii=False, sort_keys=True)


def read_json_if_exists(path: Path) -> dict[str, Any]:
    """Read a JSON object when it exists; return an empty object otherwise."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise GeneratorError(f"invalid checkpoint JSON: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise GeneratorError(f"checkpoint must be a JSON object: {path}")
    return data


def checkpoint_records_by_key(
    checkpoint: dict[str, Any],
    *,
    retry_errors: bool,
) -> dict[str, dict[str, Any]]:
    """Return successful checkpoint records keyed by resume key."""
    records_by_key: dict[str, dict[str, Any]] = {}
    records = checkpoint.get("records", [])
    if not isinstance(records, list):
        return records_by_key
    for record in records:
        if not isinstance(record, dict):
            continue
        key = record.get("job_key")
        if not isinstance(key, str) or not key:
            continue
        if record.get("error"):
            continue
        if not str(record.get("response_text") or "").strip():
            continue
        records_by_key[key] = record
    return records_by_key


def write_json_overwrite(path: Path, data: Any) -> None:
    """Write pretty JSON atomically, overwriting the generated artifact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f"{path.name}.tmp")
    temp_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp_path.replace(path)


def checkpoint_payload(
    *,
    created_at: str,
    updated_at: str,
    config: CerebrasConfig,
    template_hash: str,
    raw_records: list[dict[str, Any]],
    generated_cases: list[dict[str, Any]],
    completed: bool,
) -> dict[str, Any]:
    """Build the checkpoint/audit payload shape."""
    return {
        "created_at": created_at,
        "updated_at": updated_at,
        "completed": completed,
        "model": config.model,
        "api_url": config.api_url,
        "prompt_template": str(config.prompt_template),
        "prompt_template_sha256": template_hash,
        "rules_dir": str(config.rules_dir),
        "true_positive_dir": str(config.true_positive_dir),
        "rule_output_dir": str(config.rule_output_dir),
        "max_outputs": config.max_outputs,
        "generated_case_count": len(generated_cases),
        "record_count": len(raw_records),
        "generated_cases": generated_cases,
        "records": raw_records,
    }


def flush_progress(
    *,
    created_at: str,
    config: CerebrasConfig,
    template_hash: str,
    raw_records: list[dict[str, Any]],
    generated_cases: list[dict[str, Any]],
    completed: bool,
) -> None:
    """Persist generated cases and checkpoint state immediately."""
    updated_at = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    write_json_overwrite(config.output_path, generated_cases)
    write_json_overwrite(
        config.checkpoint_path,
        checkpoint_payload(
            created_at=created_at,
            updated_at=updated_at,
            config=config,
            template_hash=template_hash,
            raw_records=raw_records,
            generated_cases=generated_cases,
            completed=completed,
        ),
    )


def call_cerebras(prompt: str, config: CerebrasConfig) -> str:
    """Call Cerebras and return the assistant message content."""
    if not config.api_key:
        raise GeneratorError("missing CEREBRAS_API_KEY; set it in the environment or pass --api-key-env")

    headers = request_headers(config)
    payload = request_payload(prompt, config)
    last_error = ""

    for attempt in range(config.max_retries + 1):
        try:
            response = post_json(config.api_url, headers, payload, config.timeout_seconds)
            if response.status_code >= 400:
                error_text = cerebras_error_text(response.status_code, response.text)
                if response.status_code in RETRYABLE_HTTP_CODES and attempt < config.max_retries:
                    fallback = config.retry_delay_seconds * (attempt + 1)
                    sleep_seconds = retry_after_seconds(response, fallback) + config.rate_limit_buffer_seconds
                    if sleep_seconds > config.max_rate_limit_sleep_seconds:
                        raise CerebrasHTTPError(
                            response.status_code,
                            f"{error_text}; retry wait {sleep_seconds:.2f}s exceeds "
                            f"--max-rate-limit-sleep-seconds={config.max_rate_limit_sleep_seconds:g}",
                        )
                    last_error = f"Cerebras API HTTP {response.status_code}: {error_text}"
                    print(
                        f"    [rate-limit] waiting {sleep_seconds:.2f}s before retry "
                        f"{attempt + 1}/{config.max_retries}",
                        file=sys.stderr,
                    )
                    time.sleep(sleep_seconds)
                    continue
                raise CerebrasHTTPError(response.status_code, error_text)
            data = json.loads(response.text)
            return str(data["choices"][0]["message"].get("content") or "")
        except CerebrasHTTPError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError, KeyError, IndexError, TypeError, ValueError) as exc:
            last_error = str(exc)
            if attempt < config.max_retries:
                time.sleep(config.retry_delay_seconds * (attempt + 1))
                continue
            break

    raise GeneratorError(f"Cerebras API request failed: {last_error}")


def run_generation(config: CerebrasConfig) -> int:
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
            response_text = call_cerebras(prompt, config)
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
                "    [!] Stopping after non-retryable Cerebras API error. "
                "Fix the API key/model/network issue, or pass --continue-on-error to keep scanning.",
                file=sys.stderr,
            )
            break

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    raw_path = config.raw_output_dir / f"cerebras_generation_{timestamp}.json"
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
    """Build CLI parser for the Cerebras generator."""
    parser = argparse.ArgumentParser(description="Generate Sigma rule evaluator cases with Cerebras GPT OSS 120B.")
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
    parser.add_argument("--api-key-env", default="CEREBRAS_API_KEY")
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
        help="Extra seconds added to Cerebras retry-after/reset waits.",
    )
    parser.add_argument(
        "--max-rate-limit-sleep-seconds",
        type=float,
        default=120.0,
        help="Abort instead of sleeping longer than this for one retry.",
    )
    parser.add_argument(
        "--reasoning-format",
        choices=["hidden", "raw", "parsed", "none"],
        default="none",
        help="Cerebras reasoning format. Default omits the parameter.",
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


def config_from_args(args: argparse.Namespace) -> CerebrasConfig:
    """Create CerebrasConfig from parsed CLI args."""
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

    return CerebrasConfig(
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
        reasoning_format=args.reasoning_format,
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
