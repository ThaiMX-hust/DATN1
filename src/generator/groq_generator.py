"""Generate Sigma command-line mutation cases through the Groq chat API.

The module renders local Sigma rules, with true-positive command-line examples
when available, through ``prompt_template.txt``, calls Groq's OpenAI-compatible
chat endpoint, and writes cases that can be consumed by
``sigma_rule_evaluator.cli``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from dotenv import load_dotenv

try:
    import requests
except ModuleNotFoundError:  # pragma: no cover - optional dependency fallback
    requests = None


DEFAULT_MODEL = "qwen/qwen3-32b"
DEFAULT_API_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_USER_AGENT = "DATN1-GroqGenerator/1.0"
DEFAULT_PROMPT_TEMPLATE = Path(__file__).with_name("groq_prompt_template.txt")
DEFAULT_RULES_DIR = Path("rules")
DEFAULT_TRUE_POSITIVE_DIR = Path("data/true_positive_test")
DEFAULT_OUTPUT_PATH = Path("input/qwen32b.generated.json")
DEFAULT_RAW_OUTPUT_DIR = Path("output/groq_generator_test")
DEFAULT_RULE_OUTPUT_DIR = DEFAULT_RAW_OUTPUT_DIR / "rules"
DEFAULT_MAX_OUTPUTS = 3
DEFAULT_MAX_COMPLETION_TOKENS = 768
DEFAULT_MIN_REQUEST_INTERVAL_SECONDS = 60.0
RETRYABLE_HTTP_CODES = {429, 500, 502, 503, 504}
NON_RETRYABLE_HTTP_CODES = {400, 401, 403, 404, 422}

SIGMA_PLACEHOLDER = "{{SIGMA_RULE}}"
COMMAND_PLACEHOLDER = "{{TRUE_POSITIVE_TEST_COMMAND}}"
NO_TRUE_POSITIVE_COMMAND_TEXT = "No true-positive test command was provided. Use the Sigma rule only."
ATTACK_TECHNIQUE_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
TRY_AGAIN_RE = re.compile(r"try again in\s+([0-9.]+\s*(?:ms|s|m|h))", re.IGNORECASE)
DURATION_PART_RE = re.compile(r"([0-9]+(?:\.[0-9]+)?)\s*(ms|s|m|h)", re.IGNORECASE)


class GeneratorError(RuntimeError):
    """Raised when generation cannot continue."""


class GroqHTTPError(GeneratorError):
    """Raised when Groq returns an HTTP error response."""

    def __init__(self, status_code: int, body: str) -> None:
        self.status_code = status_code
        self.body = body
        hint = groq_error_hint(status_code, body)
        message = f"Groq API HTTP {status_code}: {body}"
        if hint:
            message = f"{message} ({hint})"
        super().__init__(message)


@dataclass(frozen=True)
class HTTPResponse:
    """Small transport-neutral HTTP response shape."""

    status_code: int
    text: str
    headers: dict[str, str]


def groq_error_hint(status_code: int, body: str) -> str:
    """Return a concise remediation hint for common Groq HTTP errors."""
    body_lower = body.lower()
    if status_code == 401:
        return "check GROQ_API_KEY"
    if status_code == 403 and "1010" in body_lower:
        return "Cloudflare 1010: client/browser signature or network was blocked; install requests or try another network"
    if status_code == 403:
        return "check project/model permissions for this API key"
    return ""


@dataclass(frozen=True)
class GenerationConfig:
    """Runtime settings for one generation run."""

    rules_dir: Path = DEFAULT_RULES_DIR
    true_positive_dir: Path = DEFAULT_TRUE_POSITIVE_DIR
    prompt_template: Path = DEFAULT_PROMPT_TEMPLATE
    output_path: Path = DEFAULT_OUTPUT_PATH
    raw_output_dir: Path = DEFAULT_RAW_OUTPUT_DIR
    rule_output_dir: Path = DEFAULT_RULE_OUTPUT_DIR
    # config groq api
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
    # config rate limit
    max_retries: int = 8
    retry_delay_seconds: float = 3.0
    rate_limit_buffer_seconds: float = 0.5
    max_rate_limit_sleep_seconds: float = 120.0
    min_request_interval_seconds: float = DEFAULT_MIN_REQUEST_INTERVAL_SECONDS
    reasoning_format: str = "hidden"
    reasoning_effort: str = "none"
    overwrite: bool = False
    resume: bool = True
    dry_run: bool = False
    save_prompts: bool = False
    continue_on_error: bool = False


@dataclass(frozen=True)
class GenerationJob:
    """One Sigma rule and its true-positive command context to send to the model."""

    rule_path: Path
    rule_text: str
    source_commands: tuple[str, ...]
    command_index: int | None
    technique_id: str


def read_text(path: Path) -> str:
    """Read UTF-8 text and raise a clear error when the file is absent."""
    if not path.exists():
        raise GeneratorError(f"file not found: {path}")
    return path.read_text(encoding="utf-8-sig")


def render_prompt(template: str, sigma_rule: str, command: str) -> str:
    """Fill the prompt template with one rule and one true-positive command."""
    if SIGMA_PLACEHOLDER not in template:
        raise GeneratorError(f"prompt template missing {SIGMA_PLACEHOLDER}")
    if COMMAND_PLACEHOLDER not in template:
        raise GeneratorError(f"prompt template missing {COMMAND_PLACEHOLDER}")
    return template.replace(SIGMA_PLACEHOLDER, sigma_rule).replace(COMMAND_PLACEHOLDER, command)


def normalize_rule_name(value: str) -> str:
    """Return a rule stem from either a path or a bare rule name."""
    text = str(value).strip().strip("\"'")
    if not text:
        raise GeneratorError("empty rule name")
    return Path(text).stem


def selected_rule_paths(rules_dir: Path, include_rules: Iterable[str]) -> list[Path]:
    """Return sorted Sigma rule paths, optionally restricted by rule names."""
    if not rules_dir.exists():
        raise GeneratorError(f"rules directory not found: {rules_dir}")

    requested = {normalize_rule_name(rule) for rule in include_rules}
    if requested:
        paths: list[Path] = []
        missing: list[str] = []
        for rule_name in sorted(requested):
            path = rules_dir / f"{rule_name}.yml"
            if path.exists():
                paths.append(path)
            else:
                missing.append(rule_name)
        if missing:
            raise GeneratorError(f"rule file(s) not found: {', '.join(missing)}")
        return paths

    return sorted(rules_dir.glob("*.yml"))


def true_positive_path(rule_path: Path, true_positive_dir: Path) -> Path:
    """Return the commandlines.txt path expected for a Sigma rule."""
    return true_positive_dir / rule_path.stem / "commandlines.txt"


def load_true_positive_commands(path: Path) -> list[str]:
    """Read non-empty true-positive commands from commandlines.txt."""
    if not path.exists():
        return []
    commands: list[str] = []
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        command = raw_line.strip()
        if command and not command.startswith("#"):
            commands.append(command)
    return commands


def rule_technique_id(rule_text: str) -> str:
    """Extract the first ATT&CK technique tag from a Sigma rule."""
    techniques = sorted({match.group(1).lower() for match in ATTACK_TECHNIQUE_RE.finditer(rule_text)})
    return techniques[0] if techniques else "unknown"


def format_true_positive_commands(commands: Iterable[str]) -> str:
    """Format one or more true-positive commands for the prompt template."""
    command_list = [command.strip() for command in commands if command.strip()]
    if not command_list:
        return NO_TRUE_POSITIVE_COMMAND_TEXT
    if len(command_list) == 1:
        return command_list[0]
    return "\n".join(f"{index}. {command}" for index, command in enumerate(command_list, start=1))


def build_jobs(config: GenerationConfig) -> list[GenerationJob]:
    """Create generation jobs from local rules, using true-positive commands when available."""
    jobs: list[GenerationJob] = []
    rule_paths = selected_rule_paths(config.rules_dir, config.include_rules)
    if config.limit_rules is not None:
        rule_paths = rule_paths[: config.limit_rules]

    for rule_path in rule_paths:
        rule_text = read_text(rule_path)
        commands = load_true_positive_commands(true_positive_path(rule_path, config.true_positive_dir))
        if config.limit_commands_per_rule is not None:
            commands = commands[: config.limit_commands_per_rule]
        technique_id = rule_technique_id(rule_text)
        if not commands:
            jobs.append(
                GenerationJob(
                    rule_path=rule_path,
                    rule_text=rule_text,
                    source_commands=(),
                    command_index=None,
                    technique_id=technique_id,
                )
            )
            continue
        if config.prompt_scope == "command":
            for index, command in enumerate(commands, start=1):
                jobs.append(
                    GenerationJob(
                        rule_path=rule_path,
                        rule_text=rule_text,
                        source_commands=(command,),
                        command_index=index,
                        technique_id=technique_id,
                    )
                )
        elif config.prompt_scope == "rule":
            jobs.append(
                GenerationJob(
                    rule_path=rule_path,
                    rule_text=rule_text,
                    source_commands=tuple(commands),
                    command_index=None,
                    technique_id=technique_id,
                )
            )
        else:
            raise GeneratorError(f"unsupported prompt scope: {config.prompt_scope}")
    return jobs


def request_payload(prompt: str, config: GenerationConfig) -> dict[str, Any]:
    """Build an OpenAI-compatible chat completions payload for Groq."""
    payload: dict[str, Any] = {
        "model": config.model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "temperature": config.temperature,
        "max_completion_tokens": config.max_completion_tokens,
    }
    if config.reasoning_format and config.reasoning_format != "none":
        payload["reasoning_format"] = config.reasoning_format
    if config.reasoning_effort and config.reasoning_effort != "omit":
        payload["reasoning_effort"] = config.reasoning_effort
    return payload


def request_headers(config: GenerationConfig) -> dict[str, str]:
    """Build HTTP headers for Groq requests."""
    return {
        "Authorization": f"Bearer {config.api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": config.user_agent,
    }


def normalize_response_headers(headers: Any) -> dict[str, str]:
    """Normalize HTTP headers to lower-case keys."""
    return {str(key).lower(): str(value) for key, value in dict(headers).items()}


def post_json_with_requests(
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    timeout_seconds: int,
) -> HTTPResponse:
    """Post JSON with requests when it is installed."""
    if requests is None:
        raise RuntimeError("requests is not installed")
    response = requests.post(url, headers=headers, json=payload, timeout=timeout_seconds)
    return HTTPResponse(response.status_code, response.text, normalize_response_headers(response.headers))


def post_json_with_urllib(
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    timeout_seconds: int,
) -> HTTPResponse:
    """Post JSON with the Python standard library."""
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return HTTPResponse(
                response.status,
                response.read().decode("utf-8"),
                normalize_response_headers(response.headers),
            )
    except urllib.error.HTTPError as exc:
        return HTTPResponse(
            exc.code,
            exc.read().decode("utf-8", errors="replace"),
            normalize_response_headers(exc.headers),
        )


def post_json(
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    timeout_seconds: int,
) -> HTTPResponse:
    """Post JSON, preferring requests because it is already a project dependency."""
    if requests is not None:
        return post_json_with_requests(url, headers, payload, timeout_seconds)
    return post_json_with_urllib(url, headers, payload, timeout_seconds)


def groq_error_text(status_code: int, body: str) -> str:
    """Return a compact, useful error body for logs."""
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
    return isinstance(exc, GroqHTTPError) and exc.status_code in NON_RETRYABLE_HTTP_CODES


def parse_duration_seconds(value: str) -> float | None:
    """Parse Groq-style duration strings such as 940ms, 7.66s, or 2m59.56s."""
    text = str(value or "").strip().lower()
    if not text:
        return None
    try:
        return max(0.0, float(text))
    except ValueError:
        pass

    total = 0.0
    matched = False
    for amount_text, unit in DURATION_PART_RE.findall(text):
        matched = True
        amount = float(amount_text)
        if unit == "ms":
            total += amount / 1000.0
        elif unit == "s":
            total += amount
        elif unit == "m":
            total += amount * 60.0
        elif unit == "h":
            total += amount * 3600.0
    return total if matched else None


def retry_after_seconds(response: HTTPResponse, fallback_seconds: float) -> float:
    """Return the best wait time for a retryable response."""
    for header_name in ("retry-after", "x-ratelimit-reset-tokens", "x-ratelimit-reset-requests"):
        wait = parse_duration_seconds(response.headers.get(header_name, ""))
        if wait is not None:
            return wait

    match = TRY_AGAIN_RE.search(response.text)
    if match:
        wait = parse_duration_seconds(match.group(1))
        if wait is not None:
            return wait
    return fallback_seconds


def wait_for_request_slot(last_request_started_at: float | None, config: GenerationConfig) -> float:
    """Throttle proactive Groq requests to avoid the model's per-minute limits."""
    now = time.monotonic()
    if last_request_started_at is None or config.min_request_interval_seconds <= 0:
        return now

    elapsed = now - last_request_started_at
    sleep_seconds = config.min_request_interval_seconds - elapsed
    if sleep_seconds > 0:
        print(f"    [rate-limit] waiting {sleep_seconds:.2f}s before next Groq request", file=sys.stderr)
        time.sleep(sleep_seconds)
        now = time.monotonic()
    return now


def call_groq(prompt: str, config: GenerationConfig) -> str:
    """Call Groq and return the assistant message content."""
    if not config.api_key:
        raise GeneratorError("missing GROQ_API_KEY; set it in the environment")

    headers = request_headers(config)
    payload = request_payload(prompt, config)
    last_error = ""

    for attempt in range(config.max_retries + 1):
        try:
            response = post_json(config.api_url, headers, payload, config.timeout_seconds)
            if response.status_code >= 400:
                error_text = groq_error_text(response.status_code, response.text)
                if response.status_code in RETRYABLE_HTTP_CODES and attempt < config.max_retries:
                    fallback = config.retry_delay_seconds * (attempt + 1)
                    sleep_seconds = retry_after_seconds(response, fallback) + config.rate_limit_buffer_seconds
                    if sleep_seconds > config.max_rate_limit_sleep_seconds:
                        raise GroqHTTPError(
                            response.status_code,
                            f"{error_text}; retry wait {sleep_seconds:.2f}s exceeds "
                            f"--max-rate-limit-sleep-seconds={config.max_rate_limit_sleep_seconds:g}",
                        )
                    last_error = f"Groq API HTTP {response.status_code}: {error_text}"
                    print(
                        f"    [rate-limit] waiting {sleep_seconds:.2f}s before retry "
                        f"{attempt + 1}/{config.max_retries}",
                        file=sys.stderr,
                    )
                    time.sleep(sleep_seconds)
                    continue
                raise GroqHTTPError(response.status_code, error_text)
            data = json.loads(response.text)
            return str(data["choices"][0]["message"].get("content") or "")
        except GroqHTTPError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError, KeyError, IndexError, TypeError, ValueError) as exc:
            last_error = str(exc)
            if attempt < config.max_retries:
                time.sleep(config.retry_delay_seconds * (attempt + 1))
                continue
            break

    raise GeneratorError(f"Groq API request failed: {last_error}")


def write_json_overwrite(path: Path, data: Any) -> None:
    """Write pretty JSON atomically, overwriting the generated artifact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f"{path.name}.tmp")
    temp_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp_path.replace(path)


def write_text_overwrite(path: Path, text: str) -> None:
    """Write text atomically, overwriting the generated artifact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f"{path.name}.tmp")
    temp_path.write_text(text.rstrip() + "\n", encoding="utf-8")
    temp_path.replace(path)


def job_result_filename(job: GenerationJob) -> str:
    """Return the per-job output filename."""
    if job.command_index is None:
        return f"{job.rule_path.stem}.json"
    return f"{job.rule_path.stem}__command_{job.command_index:03d}.json"


def job_result_path(job: GenerationJob, rule_output_dir: Path) -> Path:
    """Return where a successful result for this job should be saved."""
    return rule_output_dir / job_result_filename(job)


def read_completed_job_result(path: Path) -> dict[str, Any] | None:
    """Read a completed per-rule LLM output file, or None if it needs rerun."""
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8-sig").strip()
    if not text:
        return None

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict) and data.get("completed") is True and isinstance(data.get("record"), dict):
        return data

    return {
        "completed": True,
        "llm_output": text,
        "generated_cases": [],
        "record": {"response_text": text},
    }


def write_job_result(
    *,
    job: GenerationJob,
    config: Any,
    raw_record: dict[str, Any],
    generated_cases: list[dict[str, Any]],
    template_hash: str | None = None,
) -> Path:
    """Persist the raw LLM output for one rule/job."""
    response_text = str(raw_record.get("response_text") or "").strip()
    if not response_text:
        raise GeneratorError(f"empty LLM response for {job.rule_path.stem}")
    path = job_result_path(job, config.rule_output_dir)
    write_text_overwrite(path, response_text)
    return path


def run_generation(config: GenerationConfig) -> int:
    """Run generation and write both runner cases and raw audit output."""
    template = read_text(config.prompt_template)
    jobs = build_jobs(config)
    if config.dry_run:
        rule_count = len({job.rule_path for job in jobs})
        print(f"[+] Dry run: {len(jobs)} prompt(s) across {rule_count} rule(s)")
        return 0
    if not jobs:
        raise GeneratorError("no jobs found; check --rules-dir and --true-positive-dir")

    generated_cases: list[dict[str, Any]] = []
    raw_records: list[dict[str, Any]] = []
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
            response_text = call_groq(prompt, config)
            raw_record["response_text"] = response_text
            write_job_result(job=job, config=config, raw_record=raw_record, generated_cases=[])
        except Exception as exc:
            error = exc
            raw_record["error"] = str(exc)
            print(f"    [!] {exc}", file=sys.stderr)

        raw_records.append(raw_record)
        if error is not None and should_stop_after_error(error) and not config.continue_on_error:
            print(
                "    [!] Stopping after non-retryable Groq API error. "
                "Fix the API key/model/network issue, or pass --continue-on-error to keep scanning.",
                file=sys.stderr,
            )
            break

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    raw_path = config.raw_output_dir / f"groq_generation_{timestamp}.json"
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


def positive_int(value: str) -> int:
    """Argparse type for positive integers."""
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser for the Groq generator."""
    parser = argparse.ArgumentParser(description="Generate Sigma rule evaluator cases with Groq qwen/qwen3-32b.")
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
    parser.add_argument("--api-url", default=DEFAULT_API_URL)
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    parser.add_argument(
        "--prompt-scope",
        choices=["rule", "command"],
        default="rule",
        help="Use one prompt per rule by default, or one prompt per true-positive command; rules without commands still get one prompt.",
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
        help="Extra seconds added to Groq retry-after/reset waits.",
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
        help="Minimum time between Groq request starts. Default 60s for qwen/qwen3-32b limits.",
    )
    parser.add_argument(
        "--reasoning-format",
        choices=["hidden", "raw", "parsed", "none"],
        default="hidden",
        help="Groq Qwen reasoning format. Use 'none' to omit the parameter.",
    )
    parser.add_argument(
        "--reasoning-effort",
        choices=["none", "default", "omit"],
        default="none",
        help="Qwen 3 32B reasoning effort. Default disables reasoning for stricter JSON output.",
    )
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--no-resume", action="store_true", help="Ignore per-rule result files and start a new run.")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--save-prompts", action="store_true")
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Keep processing prompts after non-retryable API errors such as 401/403.",
    )
    return parser


def config_from_args(args: argparse.Namespace) -> GenerationConfig:
    """Create GenerationConfig from parsed CLI args."""
    load_dotenv()
    api_key = os.getenv("GROQ_API_KEY", "")
    print(f"[+] Using GROQ_API_KEY from environment: {'set' if api_key else 'not set'}", file=sys.stderr)
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

    return GenerationConfig(
        rules_dir=Path(args.rules_dir),
        true_positive_dir=Path(args.true_positive_dir),
        prompt_template=Path(args.prompt_template),
        output_path=Path(args.output),
        raw_output_dir=Path(args.raw_output_dir),
        rule_output_dir=Path(args.rule_output_dir) if args.rule_output_dir else Path(args.raw_output_dir) / "rules",
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
        min_request_interval_seconds=args.min_request_interval_seconds,
        reasoning_format=args.reasoning_format,
        reasoning_effort=args.reasoning_effort,
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
