"""Import command-line test cases from the commandline match rule workbook."""

from __future__ import annotations

import argparse
import posixpath
import re
import zipfile
from collections import defaultdict
from pathlib import Path
from xml.etree import ElementTree as ET


DEFAULT_EXCEL_PATH = Path(r"C:\Users\thaim\Downloads\commandline match rule.xlsx")
DEFAULT_OUTPUT_DIR = Path("data/true_positive_test")
DEFAULT_SHEET = "rules_atomic_commandlines"
DEFAULT_OUTPUT_FILE = "commandlines.txt"

MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
NS = {"a": MAIN_NS, "r": REL_NS, "rel": PKG_REL_NS}


def column_index(cell_ref: str) -> int:
    letters = "".join(ch for ch in cell_ref if ch.isalpha()).upper()
    index = 0
    for letter in letters:
        index = index * 26 + ord(letter) - ord("A") + 1
    return index - 1


def read_shared_strings(workbook: zipfile.ZipFile) -> list[str]:
    try:
        root = ET.fromstring(workbook.read("xl/sharedStrings.xml"))
    except KeyError:
        return []

    strings: list[str] = []
    for item in root.findall("a:si", NS):
        strings.append("".join(node.text or "" for node in item.findall(".//a:t", NS)))
    return strings


def cell_value(cell: ET.Element, shared_strings: list[str]) -> str:
    cell_type = cell.attrib.get("t")
    if cell_type == "inlineStr":
        return "".join(node.text or "" for node in cell.findall(".//a:t", NS))

    value_node = cell.find("a:v", NS)
    value = "" if value_node is None else value_node.text or ""
    if cell_type == "s" and value:
        return shared_strings[int(value)]
    return value


def read_sheet_rows(workbook: zipfile.ZipFile, sheet_name: str) -> list[dict[int, str]]:
    workbook_root = ET.fromstring(workbook.read("xl/workbook.xml"))
    rels_root = ET.fromstring(workbook.read("xl/_rels/workbook.xml.rels"))
    rel_targets = {
        rel.attrib["Id"]: rel.attrib["Target"]
        for rel in rels_root.findall("rel:Relationship", NS)
    }

    sheet = None
    for candidate in workbook_root.findall("a:sheets/a:sheet", NS):
        if candidate.attrib["name"] == sheet_name:
            sheet = candidate
            break
    if sheet is None:
        raise ValueError(f"Sheet not found: {sheet_name}")

    rel_id = sheet.attrib[f"{{{REL_NS}}}id"]
    target = rel_targets[rel_id]
    sheet_path = target.lstrip("/")
    if not sheet_path.startswith("xl/"):
        sheet_path = posixpath.normpath(posixpath.join("xl", sheet_path))

    shared_strings = read_shared_strings(workbook)
    sheet_root = ET.fromstring(workbook.read(sheet_path))
    rows: list[dict[int, str]] = []
    for row in sheet_root.findall("a:sheetData/a:row", NS):
        values: dict[int, str] = {}
        for cell in row.findall("a:c", NS):
            values[column_index(cell.attrib.get("r", "A1"))] = cell_value(
                cell,
                shared_strings,
            )
        rows.append(values)
    return rows


def normalize_command(command: str) -> str:
    return re.sub(r"\s+", " ", command).strip()


def build_rule_commands(rows: list[dict[int, str]]) -> dict[str, list[str]]:
    if not rows:
        raise ValueError("Sheet is empty")

    headers = {value: index for index, value in rows[0].items()}
    try:
        rule_column = headers["rule_name"]
        command_column = headers["commandline match rule"]
    except KeyError as exc:
        raise ValueError("Required columns not found") from exc

    rule_commands: dict[str, list[str]] = defaultdict(list)
    for row in rows[1:]:
        rule_name = (row.get(rule_column) or "").strip()
        if not rule_name:
            continue
        rule_commands.setdefault(rule_name, [])

        command = normalize_command(row.get(command_column) or "")
        if command:
            rule_commands[rule_name].append(command)

    return dict(rule_commands)


def write_rule_commands(
    rule_commands: dict[str, list[str]],
    output_dir: Path,
    output_file: str,
) -> tuple[int, int]:
    output_dir.mkdir(parents=True, exist_ok=True)
    command_count = 0

    for rule_name in sorted(rule_commands):
        rule_dir = output_dir / rule_name
        rule_dir.mkdir(parents=True, exist_ok=True)
        commands = rule_commands[rule_name]
        command_count += len(commands)
        content = "\n".join(commands)
        if content:
            content += "\n"
        (rule_dir / output_file).write_text(content, encoding="utf-8")

    return len(rule_commands), command_count


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create true_positive_test commandlines.txt files from an xlsx workbook."
    )
    parser.add_argument("--excel", type=Path, default=DEFAULT_EXCEL_PATH)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--sheet", default=DEFAULT_SHEET)
    parser.add_argument("--output-file", default=DEFAULT_OUTPUT_FILE)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.excel.exists():
        raise FileNotFoundError(f"Excel file not found: {args.excel}")

    with zipfile.ZipFile(args.excel) as workbook:
        rows = read_sheet_rows(workbook, args.sheet)

    rule_commands = build_rule_commands(rows)
    rule_count, command_count = write_rule_commands(
        rule_commands,
        args.output_dir,
        args.output_file,
    )
    print(
        f"Wrote {rule_count} rule folders and {command_count} command lines "
        f"to {args.output_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
