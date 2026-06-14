"""Export sigma_rule_evaluator cases from tactic workbook rows."""

from __future__ import annotations

import argparse
import json
import posixpath
import re
import sys
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET


DEFAULT_EXCEL_PATH = Path(r"C:\Users\thaim\Downloads\Result_Pharse1_14xlsx")
DEFAULT_OUTPUT_PATH = Path("input/executable_false_rerun_cases.json")
DEFAULT_RULES_DIR = Path("rules")

MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
NS = {"a": MAIN_NS, "r": REL_NS, "rel": PKG_REL_NS}

TRUE_VALUES = {"1", "1.0", "true", "yes", "y"}
FALSE_VALUES = {"0", "0.0", "false", "no", "n"}
ATTACK_TECHNIQUE_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
ATTACK_TACTIC_RE = re.compile(r"attack\.([a-z][a-z0-9_-]*)", re.IGNORECASE)


def column_index(cell_ref: str) -> int:
    """Return zero-based column index for an Excel cell reference."""
    letters = "".join(ch for ch in cell_ref if ch.isalpha()).upper()
    index = 0
    for letter in letters:
        index = index * 26 + ord(letter) - ord("A") + 1
    return index - 1


def read_shared_strings(workbook: zipfile.ZipFile) -> list[str]:
    """Read workbook shared strings."""
    try:
        root = ET.fromstring(workbook.read("xl/sharedStrings.xml"))
    except KeyError:
        return []

    return [
        "".join(node.text or "" for node in item.findall(".//a:t", NS))
        for item in root.findall("a:si", NS)
    ]


def cell_value(cell: ET.Element, shared_strings: list[str]) -> str:
    """Return a string value for one worksheet cell."""
    cell_type = cell.attrib.get("t")
    if cell_type == "inlineStr":
        return "".join(node.text or "" for node in cell.findall(".//a:t", NS))

    value_node = cell.find("a:v", NS)
    value = "" if value_node is None else value_node.text or ""
    if cell_type == "s" and value:
        return shared_strings[int(value)]
    return value


def workbook_sheet_paths(workbook: zipfile.ZipFile) -> list[tuple[str, str]]:
    """Return sheet names and internal XML paths in workbook order."""
    workbook_root = ET.fromstring(workbook.read("xl/workbook.xml"))
    rels_root = ET.fromstring(workbook.read("xl/_rels/workbook.xml.rels"))
    rel_targets = {
        rel.attrib["Id"]: rel.attrib["Target"]
        for rel in rels_root.findall("rel:Relationship", NS)
    }

    sheets: list[tuple[str, str]] = []
    for sheet in workbook_root.findall("a:sheets/a:sheet", NS):
        target = rel_targets[sheet.attrib[f"{{{REL_NS}}}id"]].lstrip("/")
        if not target.startswith("xl/"):
            target = posixpath.normpath(posixpath.join("xl", target))
        sheets.append((sheet.attrib["name"], target))
    return sheets


def read_sheet_rows(
    workbook: zipfile.ZipFile,
    sheet_path: str,
    shared_strings: list[str],
) -> list[dict[int, str]]:
    """Read worksheet rows as sparse column-index dictionaries."""
    sheet_root = ET.fromstring(workbook.read(sheet_path))
    rows: list[dict[int, str]] = []
    for row in sheet_root.findall("a:sheetData/a:row", NS):
        rows.append(
            {
                column_index(cell.attrib.get("r", "A1")): cell_value(cell, shared_strings)
                for cell in row.findall("a:c", NS)
            }
        )
    return rows


def normalize_bool_text(value: Any) -> str:
    """Normalize spreadsheet boolean-ish values to true/false/blank text."""
    text = str(value or "").strip().lower()
    if text in TRUE_VALUES:
        return "true"
    if text in FALSE_VALUES:
        return "false"
    return text


def row_matches(value: Any, wanted: str) -> bool:
    """Return whether a row value matches the requested filter value."""
    return normalize_bool_text(value) == normalize_bool_text(wanted)


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
        return ""
    rule_text = rule_path.read_text(encoding="utf-8-sig", errors="replace")
    technique = first_unique([match.group(1) for match in ATTACK_TECHNIQUE_RE.finditer(rule_text)])
    if technique:
        return technique

    tactic = first_unique([match.group(1) for match in ATTACK_TACTIC_RE.finditer(rule_text)])
    return tactic


def normalize_command(command: str) -> str:
    """Normalize worksheet command text without changing shell syntax."""
    return command.replace("\r\n", "\n").replace("\r", "\n").strip()


def build_cases(
    *,
    excel_path: Path,
    filter_column: str,
    filter_value: str,
    command_column: str,
    fallback_command_column: str,
    rules_dir: Path,
    shell: str,
    mutation: str,
    dedupe: bool,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """Build evaluator case dictionaries from matching workbook rows."""
    cases: list[dict[str, str]] = []
    counters: dict[str, int] = defaultdict(int)
    seen: set[tuple[str, str, str]] = set()
    skipped: list[dict[str, Any]] = []
    sheet_counts: dict[str, int] = defaultdict(int)
    raw_match_count = 0

    with zipfile.ZipFile(excel_path) as workbook:
        shared_strings = read_shared_strings(workbook)
        for sheet_name, sheet_path in workbook_sheet_paths(workbook):
            if sheet_name == "Fill_Summary":
                continue

            rows = read_sheet_rows(workbook, sheet_path, shared_strings)
            if not rows:
                continue
            headers = {str(value).strip(): index for index, value in rows[0].items()}
            required_headers = {"Technical", "Rule_name", filter_column}
            missing_headers = sorted(required_headers - set(headers))
            if missing_headers:
                skipped.append(
                    {
                        "sheet": sheet_name,
                        "reason": f"missing header(s): {', '.join(missing_headers)}",
                    }
                )
                continue

            last_technique = ""
            for row_number, row in enumerate(rows[1:], start=2):
                if not any(str(value or "").strip() for value in row.values()):
                    continue

                technique = str(row.get(headers["Technical"], "") or "").strip().lower()
                if technique:
                    last_technique = technique
                else:
                    technique = last_technique

                if not row_matches(row.get(headers[filter_column], ""), filter_value):
                    continue
                raw_match_count += 1

                rule_name = str(row.get(headers["Rule_name"], "") or "").strip()
                if not technique and rule_name:
                    technique = technique_or_tactic_from_rule(rules_dir, rule_name)
                command = normalize_command(
                    str(row.get(headers.get(command_column, -1), "") or "")
                )
                if not command and fallback_command_column in headers:
                    command = normalize_command(
                        str(row.get(headers[fallback_command_column], "") or "")
                    )

                missing = [
                    field
                    for field, value in {
                        "Technical": technique,
                        "Rule_name": rule_name,
                        command_column: command,
                    }.items()
                    if not value
                ]
                if missing:
                    skipped.append(
                        {
                            "sheet": sheet_name,
                            "row": row_number,
                            "reason": f"missing value(s): {', '.join(missing)}",
                        }
                    )
                    continue

                key = (technique, rule_name, command)
                if dedupe and key in seen:
                    skipped.append(
                        {
                            "sheet": sheet_name,
                            "row": row_number,
                            "reason": "duplicate technique/rule/command",
                        }
                    )
                    continue
                seen.add(key)

                prefix = safe_test_id_prefix(technique)
                counters[prefix] += 1
                cases.append(
                    {
                        "test_id": f"{prefix}_{counters[prefix]:03d}",
                        "target_commandline": command,
                        "target_rule": rule_name,
                        "technique_id": technique,
                        "shell": shell,
                        "mutation": mutation,
                    }
                )
                sheet_counts[sheet_name] += 1

    summary = {
        "excel_path": str(excel_path),
        "filter_column": filter_column,
        "filter_value": filter_value,
        "raw_match_count": raw_match_count,
        "case_count": len(cases),
        "dedupe": dedupe,
        "skipped_count": len(skipped),
        "skipped": skipped,
        "sheet_counts": dict(sheet_counts),
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


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser."""
    parser = argparse.ArgumentParser(description="Export evaluator JSON cases from a tactic workbook.")
    parser.add_argument("--excel", type=Path, default=DEFAULT_EXCEL_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument("--filter-column", default="Excutable")
    parser.add_argument("--filter-value", default="0")
    parser.add_argument("--command-column", default="Commandline_evasion")
    parser.add_argument("--fallback-command-column", default="Command_match_rule")
    parser.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES_DIR)
    parser.add_argument("--shell", default="cmd.exe", choices=["cmd.exe", "powershell.exe", "pwsh.exe"])
    parser.add_argument("--mutation", default="rerun_executable_false")
    parser.add_argument("--dedupe", action="store_true")
    parser.add_argument("--wrap-tests", action="store_true")
    parser.add_argument("--summary-output", type=Path)
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if not args.excel.exists():
            raise FileNotFoundError(f"Excel file not found: {args.excel}")
        cases, summary = build_cases(
            excel_path=args.excel,
            filter_column=args.filter_column,
            filter_value=args.filter_value,
            command_column=args.command_column,
            fallback_command_column=args.fallback_command_column,
            rules_dir=args.rules_dir,
            shell=args.shell,
            mutation=args.mutation,
            dedupe=args.dedupe,
        )
        payload: Any = {"tests": cases} if args.wrap_tests else cases
        write_json(args.output, payload, overwrite=args.overwrite)
        if args.summary_output:
            write_json(args.summary_output, summary, overwrite=True)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    print(
        f"[+] Exported {summary['case_count']} case(s) from "
        f"{summary['raw_match_count']} matching row(s)"
    )
    print(f"[+] Output: {args.output}")
    if args.summary_output:
        print(f"[+] Summary: {args.summary_output}")
    if summary["skipped_count"]:
        print(f"[!] Skipped {summary['skipped_count']} row(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
