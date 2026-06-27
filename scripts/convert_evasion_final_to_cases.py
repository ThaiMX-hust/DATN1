"""Convert results/results_final/evasion_final.csv into evaluator JSON cases."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVASION_CSV = PROJECT_ROOT / "results" / "results_final" / "evasion_final.csv"
DEFAULT_INPUT_DIR = PROJECT_ROOT / "input"
DEFAULT_RULES_DIR = PROJECT_ROOT / "rules"
DEFAULT_OUTPUT = PROJECT_ROOT / "input" / "evasion_final.generated.json"
DEFAULT_SUMMARY_OUTPUT = PROJECT_ROOT / "input" / "evasion_final.generated.summary.json"

ATTACK_TECHNIQUE_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
ATTACK_TACTIC_RE = re.compile(r"attack\.([a-z][a-z0-9_-]*)", re.IGNORECASE)
BACKSLASH_RUN_RE = re.compile(r"\\+")
UNC_HOST_RE = re.compile(r"(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9_.-]+)\\")


def cell_text(value: Any) -> str:
    """Return a stable text value."""
    if value is None:
        return ""
    return str(value).strip().replace("\r\n", "\n").replace("\r", "\n")


def normalize_backslash_runs(command: str) -> str:
    """Collapse JSON-style escaped backslashes while preserving UNC prefixes."""

    def replace_run(match: re.Match[str]) -> str:
        run = match.group(0)
        start, end = match.span()
        previous = command[start - 1] if start > 0 else ""
        after = command[end:]
        at_unc_prefix = (
            previous in {"", " ", "\t", "'", '"', "(", ",", "=", ">", "<", "|"}
            and UNC_HOST_RE.match(after) is not None
        )
        if at_unc_prefix and len(run) >= 2:
            return r"\\"
        if len(run) >= 2:
            return "\\" * max(1, len(run) // 2)
        return run

    return BACKSLASH_RUN_RE.sub(replace_run, command)


def normalize_command(command: str) -> str:
    """Normalize command text without changing shell syntax."""
    normalized = cell_text(command)
    normalized = normalized.replace(r"\"", '"').replace(r"\/", "/")
    return normalize_backslash_runs(normalized)


def command_key(command: str) -> str:
    """Return normalized command key used for metadata lookup."""
    return normalize_command(command)


def safe_test_id_prefix(value: str) -> str:
    """Return a stable evaluator test id prefix."""
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip().lower())
    return cleaned.strip("_") or "unknown"


def first_unique(values: list[str]) -> str:
    """Return the first non-empty unique value after lower-casing."""
    seen: set[str] = set()
    for value in values:
        normalized = value.strip().lower()
        if normalized and normalized not in seen:
            return normalized
        seen.add(normalized)
    return ""


def rule_path_for_name(rules_dir: Path, rule_name: str) -> Path | None:
    """Return the Sigma rule path for a rule stem when it exists."""
    for suffix in (".yml", ".yaml"):
        candidate = rules_dir / f"{rule_name}{suffix}"
        if candidate.exists():
            return candidate
    return None


def technique_or_tactic_from_rule(rules_dir: Path, rule_name: str) -> str:
    """Extract the first ATT&CK technique tag, falling back to tactic tags."""
    rule_path = rule_path_for_name(rules_dir, rule_name)
    if rule_path is None:
        return "unknown"

    rule_text = rule_path.read_text(encoding="utf-8-sig", errors="replace")
    technique = first_unique([match.group(1) for match in ATTACK_TECHNIQUE_RE.finditer(rule_text)])
    if technique:
        return technique

    tactic = first_unique([match.group(1) for match in ATTACK_TACTIC_RE.finditer(rule_text)])
    return tactic or "unknown"


def load_json_cases(path: Path) -> list[dict[str, Any]]:
    """Load evaluator cases from a JSON file."""
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(data, dict) and isinstance(data.get("tests"), list):
        data = data["tests"]
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def build_case_lookup(input_dir: Path) -> tuple[dict[tuple[str, str], dict[str, str]], dict[str, dict[str, str]], dict[str, Any]]:
    """Build exact and rule-level metadata lookup from existing input JSON files."""
    exact: dict[tuple[str, str], dict[str, str]] = {}
    by_rule: dict[str, dict[str, str]] = {}
    source_counts: Counter[str] = Counter()
    duplicate_exact_keys = 0

    for path in sorted(input_dir.glob("*.json")):
        if path.name == DEFAULT_OUTPUT.name:
            continue
        try:
            cases = load_json_cases(path)
        except Exception:
            continue

        for case in cases:
            rule_name = cell_text(case.get("target_rule"))
            commandline = command_key(cell_text(case.get("target_commandline")))
            technique_id = cell_text(case.get("technique_id")) or "unknown"
            shell = cell_text(case.get("shell")) or "cmd.exe"
            mutation = cell_text(case.get("mutation")) or "validated_evasion"
            if not rule_name:
                continue

            metadata = {
                "technique_id": technique_id,
                "shell": shell,
                "mutation": mutation,
                "source_input": str(path),
            }
            by_rule.setdefault(rule_name, metadata)
            if not commandline:
                continue

            key = (rule_name, commandline)
            if key in exact:
                duplicate_exact_keys += 1
                continue
            exact[key] = metadata
            source_counts[path.name] += 1

    summary = {
        "exact_lookup_count": len(exact),
        "rule_lookup_count": len(by_rule),
        "duplicate_exact_keys": duplicate_exact_keys,
        "source_counts": dict(source_counts),
    }
    return exact, by_rule, summary


def read_evasion_rows(evasion_csv: Path, dedupe: bool) -> tuple[list[dict[str, str]], dict[str, int]]:
    """Read unique evasion_final rows."""
    raw_row_count = 0
    duplicate_after_normalization = 0
    with evasion_csv.open("r", encoding="utf-8-sig", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        if not reader.fieldnames:
            raise ValueError(f"empty CSV: {evasion_csv}")
        missing = sorted({"rule_name", "commandline_evasion"} - set(reader.fieldnames))
        if missing:
            raise ValueError(f"{evasion_csv} missing column(s): {', '.join(missing)}")

        rows: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for row in reader:
            raw_row_count += 1
            rule_name = cell_text(row.get("rule_name"))
            commandline = normalize_command(cell_text(row.get("commandline_evasion")))
            if not rule_name or not commandline:
                continue
            key = (rule_name, commandline)
            if dedupe and key in seen:
                duplicate_after_normalization += 1
                continue
            seen.add(key)
            rows.append(
                {
                    "rule_name": rule_name,
                    "commandline_evasion": commandline,
                    "row_count": cell_text(row.get("row_count")),
                    "sources": cell_text(row.get("sources")),
                }
            )
    summary = {
        "raw_row_count": raw_row_count,
        "case_rows_after_dedupe": len(rows),
        "duplicate_after_normalization": duplicate_after_normalization,
    }
    return rows, summary


def build_cases(
    *,
    evasion_csv: Path,
    input_dir: Path,
    rules_dir: Path,
    default_shell: str,
    default_mutation: str,
    dedupe: bool,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """Build evaluator cases from evasion_final.csv."""
    exact_lookup, rule_lookup, lookup_summary = build_case_lookup(input_dir)
    evasion_rows, evasion_summary = read_evasion_rows(evasion_csv, dedupe=dedupe)

    cases: list[dict[str, str]] = []
    counters: dict[str, int] = defaultdict(int)
    metadata_sources: Counter[str] = Counter()
    unknown_technique_rules: set[str] = set()

    for row in evasion_rows:
        rule_name = row["rule_name"]
        commandline = row["commandline_evasion"]
        metadata = exact_lookup.get((rule_name, command_key(commandline)))
        metadata_source = "exact_input_lookup"

        if metadata is None:
            metadata = rule_lookup.get(rule_name)
            metadata_source = "rule_input_lookup"

        if metadata is None:
            metadata = {
                "technique_id": technique_or_tactic_from_rule(rules_dir, rule_name),
                "shell": default_shell,
                "mutation": default_mutation,
                "source_input": "",
            }
            metadata_source = "rule_file_fallback"

        technique_id = cell_text(metadata.get("technique_id")) or technique_or_tactic_from_rule(rules_dir, rule_name)
        if not technique_id or technique_id == "unknown":
            unknown_technique_rules.add(rule_name)
            technique_id = "unknown"

        prefix = safe_test_id_prefix(technique_id)
        counters[prefix] += 1
        metadata_sources[metadata_source] += 1
        cases.append(
            {
                "test_id": f"{prefix}_{counters[prefix]:03d}",
                "target_commandline": commandline,
                "target_rule": rule_name,
                "technique_id": technique_id,
                "shell": cell_text(metadata.get("shell")) or default_shell,
                "mutation": cell_text(metadata.get("mutation")) or default_mutation,
            }
        )

    summary = {
        "evasion_csv": str(evasion_csv),
        "case_count": len(cases),
        "dedupe": dedupe,
        "evasion_rows": evasion_summary,
        "metadata_sources": dict(metadata_sources),
        "lookup": lookup_summary,
        "unknown_technique_rule_count": len(unknown_technique_rules),
        "unknown_technique_rules": sorted(unknown_technique_rules),
        "test_id_prefix_counts": dict(sorted(counters.items())),
    }
    return cases, summary


def write_json(path: Path, data: Any, overwrite: bool) -> None:
    """Write JSON atomically."""
    if path.exists() and not overwrite:
        raise FileExistsError(f"output already exists: {path}; pass --overwrite to replace it")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f"{path.name}.tmp")
    temp_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp_path.replace(path)


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Convert evasion_final.csv to evaluator input JSON.")
    parser.add_argument("--evasion-csv", type=Path, default=DEFAULT_EVASION_CSV)
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR)
    parser.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--summary-output", type=Path, default=DEFAULT_SUMMARY_OUTPUT)
    parser.add_argument("--shell", default="cmd.exe", choices=["cmd.exe", "powershell.exe", "pwsh.exe"])
    parser.add_argument("--mutation", default="validated_evasion")
    parser.add_argument("--keep-duplicates", action="store_true", help="Keep duplicate rule/command pairs after normalization.")
    parser.add_argument("--wrap-tests", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def main() -> int:
    """CLI entrypoint."""
    args = parse_args()
    try:
        cases, summary = build_cases(
            evasion_csv=args.evasion_csv.resolve(),
            input_dir=args.input_dir.resolve(),
            rules_dir=args.rules_dir.resolve(),
            default_shell=args.shell,
            default_mutation=args.mutation,
            dedupe=not args.keep_duplicates,
        )
        payload: Any = {"tests": cases} if args.wrap_tests else cases
        write_json(args.output.resolve(), payload, overwrite=args.overwrite)
        if args.summary_output:
            write_json(args.summary_output.resolve(), summary, overwrite=True)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    print(f"[+] Exported {summary['case_count']} evasion case(s)")
    print(f"[+] Output: {args.output.resolve()}")
    if args.summary_output:
        print(f"[+] Summary: {args.summary_output.resolve()}")
    print(f"[+] Metadata sources: {summary['metadata_sources']}")
    if summary["unknown_technique_rule_count"]:
        print(f"[!] Unknown technique rules: {summary['unknown_technique_rule_count']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
