"""Convert Groq per-rule outputs into sigma_rule_evaluator input cases."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


DEFAULT_GROQ_RULE_OUTPUT_DIR = Path("output/qwen14b_generator/rules")
DEFAULT_RULES_DIR = Path("rules")
DEFAULT_OUTPUT_PATH = Path("input/qwen14b_local_cases.generated.json")
ATTACK_TECHNIQUE_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
ATTACK_TACTIC_RE = re.compile(r"attack\.([a-z][a-z0-9_-]*)", re.IGNORECASE)
CODE_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)
COMMAND_INDEX_SUFFIX_RE = re.compile(r"__command_\d+$", re.IGNORECASE)


def strip_code_fence(text: str) -> str:
    """Remove a surrounding Markdown JSON fence when the model returned one."""
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = CODE_FENCE_RE.sub("", stripped).strip()
    return stripped


def parse_model_json(text: str) -> list[dict[str, str]]:
    """Parse a Groq output file into output/explanation items."""
    cleaned = strip_code_fence(text)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("[")
        end = cleaned.rfind("]")
        if start < 0 or end <= start:
            raise
        data = json.loads(cleaned[start : end + 1])

    if isinstance(data, dict) and isinstance(data.get("results"), list):
        data = data["results"]
    if not isinstance(data, list):
        raise ValueError("Groq output must be a JSON array or an object with a 'results' array")

    parsed: list[dict[str, str]] = []
    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Groq output item #{index} is not an object")
        parsed.append(
            {
                "output": str(item.get("output") or "").strip(),
                "explanation": str(item.get("explanation") or "").strip(),
            }
        )
    return parsed


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


def rule_name_from_output_path(path: Path) -> str:
    """Return the target rule stem from a Groq per-rule output filename."""
    return COMMAND_INDEX_SUFFIX_RE.sub("", path.stem)


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


def iter_groq_output_files(groq_output_dir: Path, include_rules: set[str]) -> list[Path]:
    """Return sorted Groq output JSON files, optionally restricted by rule names."""
    if not groq_output_dir.exists():
        raise FileNotFoundError(f"Groq output directory not found: {groq_output_dir}")

    files = sorted(path for path in groq_output_dir.glob("*.json") if path.is_file())
    if include_rules:
        files = [path for path in files if rule_name_from_output_path(path) in include_rules]
    return files


def build_cases(
    *,
    groq_output_dir: Path,
    rules_dir: Path,
    include_rules: set[str],
    limit_files: int | None,
    limit_outputs_per_file: int | None,
    shell: str,
    include_source_fields: bool,
    skip_missing_rules: bool,
    continue_on_parse_error: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build evaluator cases from Groq per-rule output files."""
    cases: list[dict[str, Any]] = []
    counters: dict[str, int] = defaultdict(int)
    missing_rules: list[str] = []
    parse_errors: dict[str, str] = {}
    processed_files = 0

    output_files = iter_groq_output_files(groq_output_dir, include_rules)
    if limit_files is not None:
        output_files = output_files[:limit_files]

    for output_file in output_files:
        rule_name = rule_name_from_output_path(output_file)
        rule_path = rule_path_for_name(rules_dir, rule_name)
        if rule_path is None:
            missing_rules.append(rule_name)
            if skip_missing_rules:
                continue

        try:
            items = parse_model_json(output_file.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            if not continue_on_parse_error:
                raise ValueError(f"failed to parse {output_file}: {exc}") from exc
            parse_errors[str(output_file)] = str(exc)
            continue

        if limit_outputs_per_file is not None:
            items = items[:limit_outputs_per_file]
        items = [item for item in items if item["output"]]
        if not items:
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
                        "source_model": "groq",
                        "source_output_index": output_index,
                        "source_groq_output_file": str(output_file),
                        "source_rule_path": str(rule_path) if rule_path else "",
                    }
                )
            cases.append(case)

    summary = {
        "case_count": len(cases),
        "processed_file_count": processed_files,
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
        description="Convert output/groq_generator/rules JSON files into sigma_rule_evaluator cases."
    )
    parser.add_argument("--groq-output-dir", default=str(DEFAULT_GROQ_RULE_OUTPUT_DIR))
    parser.add_argument("--rules-dir", default=str(DEFAULT_RULES_DIR))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_PATH))
    parser.add_argument("--rule", action="append", default=[], help="Rule stem to include. Can be repeated.")
    parser.add_argument("--limit-files", type=positive_int)
    parser.add_argument("--limit-outputs-per-file", type=positive_int)
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
            groq_output_dir=Path(args.groq_output_dir),
            rules_dir=Path(args.rules_dir),
            include_rules={str(rule).strip() for rule in args.rule if str(rule).strip()},
            limit_files=args.limit_files,
            limit_outputs_per_file=args.limit_outputs_per_file,
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
            raise ValueError("no cases were generated; check --groq-output-dir, --rules-dir, or --rule")

        payload: Any = {"tests": cases} if args.wrap_tests else cases
        write_json(Path(args.output), payload, overwrite=args.overwrite)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    print(f"[+] Converted {summary['case_count']} Groq output(s) from {summary['processed_file_count']} file(s)")
    print(f"[+] Output: {args.output}")
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
