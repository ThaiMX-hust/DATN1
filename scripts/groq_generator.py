"""Generate command-line evasion JSON files from prompt.txt using Groq.

The script scans prompt folders, sends each prompt to Groq's OpenAI-compatible
chat completions API, validates that the response is a JSON array, and writes it
to commandline_evasion.txt in the same folder.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from pathlib import Path
from typing import Any

import requests


DEFAULT_MODEL = "qwen/qwen3-32b"
DEFAULT_REQUESTS_PER_MINUTE = 3.0
DEFAULT_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_OUTPUT_CANDIDATES = (Path("gemini_result_add"), Path("gemini_results_add"))


class GenerationError(RuntimeError):
    """Raised when a prompt cannot be generated or validated."""


def load_dotenv(path: Path) -> None:
    """Load simple KEY=VALUE lines into the environment if not already set."""
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def resolve_prompt_root(value: str | None) -> Path:
    """Choose the prompt root, accepting both singular and plural folder names."""
    if value:
        return Path(value)

    for candidate in DEFAULT_OUTPUT_CANDIDATES:
        if candidate.exists():
            return candidate

    return DEFAULT_OUTPUT_CANDIDATES[0]


def strip_json_fences(text: str) -> str:
    """Return the JSON-looking portion of a model response."""
    content = text.strip()

    fenced = re.search(r"```(?:json)?\s*(.*?)\s*```", content, flags=re.IGNORECASE | re.DOTALL)
    if fenced:
        content = fenced.group(1).strip()

    if content.startswith("[") and content.endswith("]"):
        return content

    start = content.find("[")
    end = content.rfind("]")
    if start != -1 and end != -1 and end > start:
        return content[start : end + 1].strip()

    return content


def validate_generation(raw_text: str) -> str:
    """Validate and pretty-print the model response as the expected JSON array."""
    json_text = strip_json_fences(raw_text)
    try:
        parsed = json.loads(json_text)
    except json.JSONDecodeError as exc:
        raise GenerationError(f"response is not valid JSON: {exc}") from exc

    if not isinstance(parsed, list):
        raise GenerationError("response JSON must be a list")

    for index, item in enumerate(parsed, start=1):
        if not isinstance(item, dict):
            raise GenerationError(f"item {index} must be an object")
        if "output" not in item or "explanation" not in item:
            raise GenerationError(f"item {index} must contain output and explanation")
        if not isinstance(item["output"], str) or not isinstance(item["explanation"], str):
            raise GenerationError(f"item {index} output and explanation must be strings")

    return json.dumps(parsed, ensure_ascii=False, indent=2) + "\n"


def groq_chat_completion(
    *,
    prompt: str,
    api_key: str,
    endpoint: str,
    model: str,
    temperature: float,
    max_tokens: int,
    timeout: int,
    retries: int,
) -> str:
    """Call Groq's chat completions API and return the assistant text."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload: dict[str, Any] = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "Return valid JSON only. Do not wrap the JSON in Markdown.",
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    last_error = ""
    for attempt in range(1, retries + 2):
        try:
            response = requests.post(endpoint, headers=headers, json=payload, timeout=timeout)
        except requests.RequestException as exc:
            last_error = str(exc)
        else:
            if response.status_code < 400:
                data = response.json()
                return data["choices"][0]["message"]["content"]

            last_error = f"HTTP {response.status_code}: {response.text[:500]}"
            if response.status_code not in {408, 409, 429, 500, 502, 503, 504}:
                break

        if attempt <= retries:
            time.sleep(min(30, 2**attempt))

    raise GenerationError(last_error or "unknown Groq API error")


class RateLimiter:
    """Simple process-local request pacing."""

    def __init__(self, requests_per_minute: float) -> None:
        self.minimum_interval = 0.0
        if requests_per_minute > 0:
            self.minimum_interval = 60.0 / requests_per_minute
        self.next_request_time = 0.0

    def wait(self) -> None:
        """Sleep until the next request is allowed."""
        if self.minimum_interval <= 0:
            return

        now = time.monotonic()
        if now < self.next_request_time:
            time.sleep(self.next_request_time - now)
        self.next_request_time = time.monotonic() + self.minimum_interval


def iter_prompt_dirs(root: Path, only: str | None) -> list[Path]:
    """Return prompt directories sorted by folder name."""
    if not root.exists():
        raise FileNotFoundError(f"prompt root not found: {root}")

    prompt_dirs = sorted(path.parent for path in root.glob("*/prompt.txt"))
    if only:
        needle = only.lower()
        prompt_dirs = [path for path in prompt_dirs if needle in path.name.lower()]
    return prompt_dirs


def should_process(output_path: Path, overwrite: bool) -> bool:
    """Return whether this commandline_evasion.txt should be generated."""
    if overwrite:
        return True
    return not output_path.exists() or output_path.stat().st_size == 0


def write_error_files(output_path: Path, raw_text: str, error: str) -> None:
    """Preserve failed model output without corrupting the target JSON file."""
    output_path.with_suffix(".raw.txt").write_text(raw_text, encoding="utf-8")
    output_path.with_suffix(".error.txt").write_text(error.rstrip() + "\n", encoding="utf-8")


def generate_for_directory(
    config: argparse.Namespace,
    prompt_dir: Path,
    api_key: str,
    rate_limiter: RateLimiter,
) -> str:
    """Generate one commandline_evasion.txt and return a status label."""
    prompt_path = prompt_dir / "prompt.txt"
    output_path = prompt_dir / "commandline_evasion.txt"

    if not should_process(output_path, config.overwrite):
        return "skip"

    if config.dry_run:
        return "dry-run"

    prompt = prompt_path.read_text(encoding="utf-8-sig", errors="replace")
    rate_limiter.wait()
    raw_text = groq_chat_completion(
        prompt=prompt,
        api_key=api_key,
        endpoint=config.endpoint,
        model=config.model,
        temperature=config.temperature,
        max_tokens=config.max_tokens,
        timeout=config.timeout,
        retries=config.retries,
    )

    try:
        validated = validate_generation(raw_text)
    except GenerationError as exc:
        write_error_files(output_path, raw_text, str(exc))
        raise

    output_path.write_text(validated, encoding="utf-8")
    output_path.with_suffix(".raw.txt").unlink(missing_ok=True)
    output_path.with_suffix(".error.txt").unlink(missing_ok=True)
    return "write"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Groq over gemini_result_add prompt.txt files and write commandline_evasion.txt."
    )
    parser.add_argument("--root", help="Prompt root folder. Defaults to gemini_result_add if present.")
    parser.add_argument("--env-file", default=".env", help="Path to .env containing GROQ_API_KEY.")
    parser.add_argument("--api-key-env", default="GROQ_API_KEY", help="Environment variable for the Groq API key.")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT, help="Groq OpenAI-compatible endpoint.")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Groq model name.")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument(
        "--requests-per-minute",
        type=float,
        default=DEFAULT_REQUESTS_PER_MINUTE,
        help="Maximum request rate. Default: 3 requests/minute. Use 0 to disable pacing.",
    )
    parser.add_argument("--limit", type=int, help="Maximum number of prompt folders to process.")
    parser.add_argument("--only", help="Only process folders whose name contains this text.")
    parser.add_argument("--overwrite", action="store_true", help="Regenerate files that already have content.")
    parser.add_argument("--dry-run", action="store_true", help="List what would be processed without calling Groq.")
    return parser.parse_args()


def main() -> int:
    config = parse_args()
    load_dotenv(Path(config.env_file))

    api_key = os.environ.get(config.api_key_env, "")
    if not api_key and not config.dry_run:
        raise SystemExit(f"Missing API key. Set {config.api_key_env} or add it to {config.env_file}.")

    root = resolve_prompt_root(config.root)
    prompt_dirs = iter_prompt_dirs(root, config.only)
    if config.limit is not None:
        prompt_dirs = prompt_dirs[: config.limit]

    rate_limiter = RateLimiter(config.requests_per_minute)
    counts = {"write": 0, "skip": 0, "dry-run": 0, "error": 0}
    for index, prompt_dir in enumerate(prompt_dirs, start=1):
        output_path = prompt_dir / "commandline_evasion.txt"
        try:
            status = generate_for_directory(config, prompt_dir, api_key, rate_limiter)
        except GenerationError as exc:
            counts["error"] += 1
            print(f"[{index}/{len(prompt_dirs)}] ERROR {prompt_dir.name}: {exc}")
            continue

        counts[status] += 1
        if status == "dry-run":
            action = "would write" if should_process(output_path, config.overwrite) else "would skip"
        else:
            action = status
        print(f"[{index}/{len(prompt_dirs)}] {action}: {prompt_dir.name}")

    print(
        "Done: "
        f"written={counts['write']} skipped={counts['skip']} "
        f"dry_run={counts['dry-run']} errors={counts['error']}"
    )
    return 1 if counts["error"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
