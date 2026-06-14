"""Convert Gemini commandline_evasion.txt outputs into sigma_rule_evaluator cases."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


DEFAULT_GEMINI_RESULT_DIR = Path("gemini_result_add")
DEFAULT_RULES_DIR = Path("rules")
DEFAULT_OUTPUT_PATH = Path("input/gemini_cases.generated.json")

ATTACK_TECHNIQUE_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
ATTACK_TACTIC_RE = re.compile(r"attack\.([a-z][a-z0-9_-]*)", re.IGNORECASE)
CODE_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)
LOOSE_ITEM_RE = re.compile(
    r'"output"\s*:\s*"(?P<output>.*?)"\s*,\s*"explanation"\s*:\s*"(?P<explanation>.*?)"'
    r"\s*(?=,?\s*\}\s*(?:,|\]|\Z))",
    re.IGNORECASE | re.DOTALL,
)


def strip_code_fence(text: str) -> str:
    """Remove a surrounding Markdown JSON fence when the model returned one."""
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = CODE_FENCE_RE.sub("", stripped).strip()
    return stripped


def loose_unescape(value: str) -> str:
    """Decode common JSON escapes while preserving invalid Windows backslashes."""
    result: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char != "\\" or index + 1 >= len(value):
            result.append(char)
            index += 1
            continue

        next_char = value[index + 1]
        if next_char in {'"', "\\", "/"}:
            result.append(next_char)
            index += 2
        elif next_char == "u" and index + 5 < len(value):
            hex_value = value[index + 2 : index + 6]
            try:
                result.append(chr(int(hex_value, 16)))
                index += 6
            except ValueError:
                result.append(char)
                index += 1
        else:
            result.append(char)
            index += 1
    return "".join(result)


def normalize_model_items(data: Any) -> list[dict[str, str]]:
    """Normalize parsed model data into output/explanation items."""
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        data = data["results"]
    if not isinstance(data, list):
        raise ValueError("LLM output must be a JSON array or an object with a 'results' array")

    parsed: list[dict[str, str]] = []
    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"LLM output item #{index} is not an object")
        parsed.append(
            {
                "output": str(item.get("output") or "").strip(),
                "explanation": str(item.get("explanation") or "").strip(),
            }
        )
    return parsed


def parse_loose_model_items(text: str) -> list[dict[str, str]]:
    """Parse JSON-like output/explanation pairs that contain unescaped quotes."""
    items: list[dict[str, str]] = []
    for match in LOOSE_ITEM_RE.finditer(text):
        items.append(
            {
                "output": loose_unescape(match.group("output")).strip(),
                "explanation": loose_unescape(match.group("explanation")).strip(),
            }
        )
    if not items:
        raise ValueError("No output/explanation pairs found in LLM output")
    return items


def parse_model_items(text: str) -> list[dict[str, str]]:
    """Parse a Gemini output file, accepting strict JSON and common JSON-like text."""
    cleaned = strip_code_fence(text)
    try:
        return normalize_model_items(json.loads(cleaned))
    except json.JSONDecodeError as strict_error:
        start = cleaned.find("[")
        end = cleaned.rfind("]")
        if start >= 0 and end > start:
            try:
                return normalize_model_items(json.loads(cleaned[start : end + 1]))
            except json.JSONDecodeError:
                pass
        try:
            return parse_loose_model_items(cleaned)
        except ValueError as loose_error:
            raise ValueError(f"{strict_error}; {loose_error}") from loose_error


def infer_mutation(explanation: str) -> str:
    """Best-effort mutation label from the model explanation."""
    text = explanation.lower()
    if "omit" in text or "omission" in text or "remove" in text:
        return "omission"
    if "caret" in text or "^" in explanation:
        return "caret_insertion"
    if "whitespace" in text or "extra spaces" in text or "space" in text or "tab" in text:
        return "whitespace_insertion"
    if "quote" in text or "quotation" in text:
        return "quote_insertion"
    if "case" in text:
        return "case_substitution"
    if "reorder" in text or "order" in text:
        return "argument_reordering"
    if "substitution" in text or "alias" in text or "equivalent flag" in text:
        return "option_alias_substitution"
    if "base64" in text or "encoding" in text or "encoded" in text or "recoding" in text:
        return "encoding"
    if "path" in text or "environment variable" in text or "normalization" in text:
        return "path_variation"
    if "no mutation" in text or "original command" in text:
        return "llm_generated"
    return "llm_generated"


def rule_path_for_name(rules_dir: Path, rule_name: str) -> Path | None:
    """Return the Sigma rule path for a rule stem when it exists."""
    for suffix in (".yml", ".yaml"):
        candidate = rules_dir / f"{rule_name}{suffix}"
        if candidate.exists():
            return candidate
    return None


def first_unique(matches: list[str]) -> str:
    """Return the first non-empty value from a list after lower-casing it."""
    seen: set[str] = set()
    for value in matches:
        normalized = value.strip().lower()
        if normalized and normalized not in seen:
            return normalized
        seen.add(normalized)
    return ""


def technique_or_tactic_from_rule(rule_path: Path | None) -> str:
    """Extract the first ATT&CK technique tag, falling back to tactic tags."""
    if rule_path is None:
        return "unknown"
    rule_text = rule_path.read_text(encoding="utf-8-sig", errors="replace")
    technique = first_unique([match.group(1) for match in ATTACK_TECHNIQUE_RE.finditer(rule_text)])
    if technique:
        return technique

    tactic = first_unique([match.group(1) for match in ATTACK_TACTIC_RE.finditer(rule_text)])
    return tactic or "unknown"


def safe_test_id_prefix(value: str) -> str:
    """Return a stable test_id prefix."""
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip().lower())
    return cleaned.strip("_") or "unknown"


def iter_evasion_files(gemini_result_dir: Path, include_rules: set[str]) -> list[Path]:
    """Return sorted Gemini commandline_evasion.txt files."""
    if not gemini_result_dir.exists():
        raise FileNotFoundError(f"Gemini result directory not found: {gemini_result_dir}")

    files = sorted(path for path in gemini_result_dir.glob("*/commandline_evasion.txt") if path.is_file())
    if include_rules:
        files = [path for path in files if path.parent.name in include_rules]
    return files


def build_cases(
    *,
    gemini_result_dir: Path,
    rules_dir: Path,
    include_rules: set[str],
    limit_rules: int | None,
    limit_outputs_per_rule: int | None,
    shell: str,
    include_source_fields: bool,
    skip_missing_rules: bool,
    continue_on_parse_error: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build evaluator cases from Gemini commandline_evasion.txt files."""
    cases: list[dict[str, Any]] = []
    counters: dict[str, int] = defaultdict(int)
    missing_rules: list[str] = []
    parse_errors: dict[str, str] = {}
    empty_files: list[str] = []
    processed_files = 0

    evasion_files = iter_evasion_files(gemini_result_dir, include_rules)
    if limit_rules is not None:
        evasion_files = evasion_files[:limit_rules]

    for evasion_file in evasion_files:
        rule_name = evasion_file.parent.name
        rule_path = rule_path_for_name(rules_dir, rule_name)
        if rule_path is None:
            missing_rules.append(rule_name)
            if skip_missing_rules:
                continue

        try:
            raw_text = evasion_file.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            if not continue_on_parse_error:
                raise ValueError(f"failed to read {evasion_file}: {exc}") from exc
            parse_errors[str(evasion_file)] = f"read error: {exc}"
            continue

        if not raw_text.strip():
            empty_files.append(str(evasion_file))
            continue

        try:
            items = parse_model_items(raw_text)
        except Exception as exc:
            if not continue_on_parse_error:
                raise ValueError(f"failed to parse {evasion_file}: {exc}") from exc
            parse_errors[str(evasion_file)] = str(exc)
            continue

        if limit_outputs_per_rule is not None:
            items = items[:limit_outputs_per_rule]
        items = [item for item in items if item["output"]]
        if not items:
            empty_files.append(str(evasion_file))
            continue

        processed_files += 1
        technique_id = technique_or_tactic_from_rule(rule_path)
        prefix = safe_test_id_prefix(technique_id)
        for output_index, item in enumerate(items, start=1):
            counters[prefix] += 1
            case: dict[str, Any] = {
                "test_id": f"{prefix}_{counters[prefix]:03d}",
                "target_commandline": item["output"],
                "target_rule": rule_name,
                "technique_id": technique_id,
                "shell": shell,
                "mutation": infer_mutation(item["explanation"]),
            }
            if include_source_fields:
                case.update(
                    {
                        "llm_explanation": item["explanation"],
                        "source_model": "gemini",
                        "source_output_index": output_index,
                        "source_evasion_file": str(evasion_file),
                        "source_rule_path": str(rule_path) if rule_path else "",
                    }
                )
            cases.append(case)

    summary = {
        "case_count": len(cases),
        "processed_file_count": processed_files,
        "empty_file_count": len(empty_files),
        "empty_files": empty_files,
        "missing_rule_count": len(missing_rules),
        "missing_rules": missing_rules,
        "parse_error_count": len(parse_errors),
        "parse_errors": parse_errors,
    }
    return cases, summary


def write_json(path: Path, data: Any, overwrite: bool) -> None:
    """Write JSON output for sigma_rule_evaluator."""
    if path.exists() and not overwrite:
        raise FileExistsError(f"output already exists: {path}; pass --overwrite to replace it")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f"{path.name}.tmp")
    temp_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp_path.replace(path)


def positive_int(value: str) -> int:
    """Argparse type for positive integers."""
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    parser = argparse.ArgumentParser(
        description="Convert gemini_result_add commandline_evasion.txt files into sigma_rule_evaluator cases."
    )
    parser.add_argument("--gemini-result-dir", default=str(DEFAULT_GEMINI_RESULT_DIR))
    parser.add_argument("--rules-dir", default=str(DEFAULT_RULES_DIR))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_PATH))
    parser.add_argument("--rule", action="append", default=[], help="Rule stem to include. Can be repeated.")
    parser.add_argument("--limit-rules", type=positive_int)
    parser.add_argument("--limit-outputs-per-rule", type=positive_int)
    parser.add_argument("--shell", default="cmd.exe", choices=["cmd.exe", "powershell.exe", "pwsh.exe"])
    parser.add_argument("--wrap-tests", action="store_true", help="Write {'tests': [...]} instead of a JSON array.")
    parser.add_argument("--include-source-fields", action="store_true")
    parser.add_argument("--skip-missing-rules", action="store_true", help="Ignore outputs without a matching rule file.")
    parser.add_argument("--strict-rules", action="store_true", help="Fail when any output has no matching rule file.")
    parser.add_argument("--continue-on-parse-error", action="store_true")
    parser.add_argument("--overwrite", action="store_true", help="Replace an existing output file.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        cases, summary = build_cases(
            gemini_result_dir=Path(args.gemini_result_dir),
            rules_dir=Path(args.rules_dir),
            include_rules={str(rule).strip() for rule in args.rule if str(rule).strip()},
            limit_rules=args.limit_rules,
            limit_outputs_per_rule=args.limit_outputs_per_rule,
            shell=args.shell,
            include_source_fields=args.include_source_fields,
            skip_missing_rules=args.skip_missing_rules,
            continue_on_parse_error=args.continue_on_parse_error,
        )
        if args.strict_rules and summary["missing_rules"]:
            preview = ", ".join(summary["missing_rules"][:10])
            suffix = "..." if len(summary["missing_rules"]) > 10 else ""
            raise ValueError(f"missing Sigma rule file(s): {preview}{suffix}")
        if not cases:
            raise ValueError("no cases were generated; check --gemini-result-dir, --rules-dir, or --rule")

        payload: Any = {"tests": cases} if args.wrap_tests else cases
        write_json(Path(args.output), payload, overwrite=args.overwrite)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    print(f"[+] Converted {summary['case_count']} Gemini output(s) from {summary['processed_file_count']} file(s)")
    print(f"[+] Output: {args.output}")
    if summary["empty_file_count"]:
        print(f"[-] Empty/no-output file(s): {summary['empty_file_count']}", file=sys.stderr)
    if summary["missing_rule_count"]:
        print(f"[!] Missing Sigma rule file(s): {summary['missing_rule_count']}", file=sys.stderr)
        for rule_name in summary["missing_rules"][:10]:
            print(f"    - {rule_name}", file=sys.stderr)
        if summary["missing_rule_count"] > 10:
            print("    ...", file=sys.stderr)
    if summary["parse_error_count"]:
        print(f"[!] Parse error(s): {summary['parse_error_count']}", file=sys.stderr)
        for path, error in list(summary["parse_errors"].items())[:10]:
            print(f"    - {path}: {error}", file=sys.stderr)
        if summary["parse_error_count"] > 10:
            print("    ...", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
