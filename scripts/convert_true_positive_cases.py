"""Convert true-positive command lines into sigma_rule_evaluator input cases."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


DEFAULT_TRUE_POSITIVE_DIR = Path("data/true_positive_test")
DEFAULT_RULES_DIR = Path("rules")
DEFAULT_OUTPUT_PATH = Path("input/true_positive_cases.generated.json")
ATTACK_TECHNIQUE_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
ATTACK_TACTIC_RE = re.compile(r"attack\.([a-z][a-z0-9_-]*)", re.IGNORECASE)


def read_commandlines(path: Path) -> list[str]:
    """Read non-empty, non-comment command lines from a commandlines.txt file."""
    commands: list[str] = []
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        command = raw_line.strip()
        if command and not command.startswith("#"):
            commands.append(command)
    return commands


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


def iter_commandline_files(true_positive_dir: Path, include_rules: set[str]) -> list[Path]:
    """Return sorted commandline files, optionally restricted by rule names."""
    if not true_positive_dir.exists():
        raise FileNotFoundError(f"true-positive directory not found: {true_positive_dir}")

    files = sorted(true_positive_dir.glob("*/commandlines.txt"))
    if include_rules:
        files = [path for path in files if path.parent.name in include_rules]
    return files


def build_cases(
    *,
    true_positive_dir: Path,
    rules_dir: Path,
    include_rules: set[str],
    limit_rules: int | None,
    limit_commands_per_rule: int | None,
    shell: str,
    mutation: str,
    include_source_fields: bool,
    skip_missing_rules: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build evaluator cases from true-positive commandline files."""
    cases: list[dict[str, Any]] = []
    counters: dict[str, int] = defaultdict(int)
    missing_rules: list[str] = []
    processed_rules = 0

    commandline_files = iter_commandline_files(true_positive_dir, include_rules)
    if limit_rules is not None:
        commandline_files = commandline_files[:limit_rules]

    for commandline_file in commandline_files:
        rule_name = commandline_file.parent.name
        rule_path = rule_path_for_name(rules_dir, rule_name)
        if rule_path is None:
            missing_rules.append(rule_name)
            if skip_missing_rules:
                continue
        technique_id = technique_or_tactic_from_rule(rule_path)
        commands = read_commandlines(commandline_file)
        if limit_commands_per_rule is not None:
            commands = commands[:limit_commands_per_rule]
        if not commands:
            continue

        processed_rules += 1
        prefix = safe_test_id_prefix(technique_id)
        for command_index, command in enumerate(commands, start=1):
            counters[prefix] += 1
            case: dict[str, Any] = {
                "test_id": f"{prefix}_{counters[prefix]:03d}",
                "target_commandline": command,
                "target_rule": rule_name,
                "technique_id": technique_id,
                "shell": shell,
                "mutation": mutation,
            }
            if include_source_fields:
                case.update(
                    {
                        "source_command_index": command_index,
                        "source_commandlines_file": str(commandline_file),
                        "source_rule_path": str(rule_path) if rule_path else "",
                    }
                )
            cases.append(case)

    summary = {
        "case_count": len(cases),
        "processed_rule_count": processed_rules,
        "missing_rule_count": len(missing_rules),
        "missing_rules": missing_rules,
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
        description="Convert data/true_positive_test commandlines.txt files into sigma_rule_evaluator JSON cases."
    )
    parser.add_argument("--true-positive-dir", default=str(DEFAULT_TRUE_POSITIVE_DIR))
    parser.add_argument("--rules-dir", default=str(DEFAULT_RULES_DIR))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_PATH))
    parser.add_argument("--rule", action="append", default=[], help="Rule stem to include. Can be repeated.")
    parser.add_argument("--limit-rules", type=positive_int)
    parser.add_argument("--limit-commands-per-rule", type=positive_int)
    parser.add_argument("--shell", default="cmd.exe", choices=["cmd.exe", "powershell.exe", "pwsh.exe"])
    parser.add_argument("--mutation", default="true_positive")
    parser.add_argument("--wrap-tests", action="store_true", help="Write {'tests': [...]} instead of a JSON array.")
    parser.add_argument("--include-source-fields", action="store_true")
    parser.add_argument("--skip-missing-rules", action="store_true", help="Ignore folders without a matching rule file.")
    parser.add_argument("--strict-rules", action="store_true", help="Fail when any folder has no matching rule file.")
    parser.add_argument("--overwrite", action="store_true", help="Replace an existing output file.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        cases, summary = build_cases(
            true_positive_dir=Path(args.true_positive_dir),
            rules_dir=Path(args.rules_dir),
            include_rules={str(rule).strip() for rule in args.rule if str(rule).strip()},
            limit_rules=args.limit_rules,
            limit_commands_per_rule=args.limit_commands_per_rule,
            shell=args.shell,
            mutation=args.mutation,
            include_source_fields=args.include_source_fields,
            skip_missing_rules=args.skip_missing_rules,
        )
        if args.strict_rules and summary["missing_rules"]:
            preview = ", ".join(summary["missing_rules"][:10])
            suffix = "..." if len(summary["missing_rules"]) > 10 else ""
            raise ValueError(f"missing Sigma rule file(s): {preview}{suffix}")
        if not cases:
            raise ValueError("no cases were generated; check --true-positive-dir, --rules-dir, or --rule")

        payload: Any = {"tests": cases} if args.wrap_tests else cases
        write_json(Path(args.output), payload, overwrite=args.overwrite)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    print(f"[+] Converted {summary['case_count']} command line(s) from {summary['processed_rule_count']} rule folder(s)")
    print(f"[+] Output: {args.output}")
    if summary["missing_rule_count"]:
        print(f"[!] Missing Sigma rule file(s): {summary['missing_rule_count']}", file=sys.stderr)
        for rule_name in summary["missing_rules"][:10]:
            print(f"    - {rule_name}", file=sys.stderr)
        if summary["missing_rule_count"] > 10:
            print("    ...", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
