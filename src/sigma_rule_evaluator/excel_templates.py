"""Build lightweight Excel workbook templates from rule index data."""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape, quoteattr


TEMPLATE_HEADERS = [
    "Technical",
    "Rule_name",
    "Title",
    "Rule_id",
    "Command_match_rule",
    "Commandline_evasion",
    "Excutable",
    "Bypass target rule",
    "Bypass all rule",
    "Trigger rule",
]

ATTACK_TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

SHEET_NAME_RE = re.compile(r"[\[\]:*?/\\]")


def column_name(index: int) -> str:
    """Convert a one-based column index to an Excel column name."""
    name = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        name = chr(65 + remainder) + name
    return name


def safe_sheet_name(name: str, used_names: set[str]) -> str:
    """Return a unique Excel-safe sheet name."""
    cleaned = SHEET_NAME_RE.sub(" ", name).strip() or "Sheet"
    cleaned = cleaned[:31]
    candidate = cleaned
    suffix = 2
    while candidate.lower() in used_names:
        suffix_text = f" {suffix}"
        candidate = f"{cleaned[:31 - len(suffix_text)]}{suffix_text}"
        suffix += 1
    used_names.add(candidate.lower())
    return candidate


def technique_label(technique: str) -> str:
    """Return the display label for an ATT&CK technique tag."""
    return technique.lower().removeprefix("attack.")


def technique_sort_key(technique: str) -> tuple[int, int, str]:
    """Return a numeric sort key for ATT&CK technique tags."""
    suffix = technique.lower().removeprefix("attack.t")
    main_text, _, sub_text = suffix.partition(".")
    main = int(main_text) if main_text.isdigit() else 0
    sub = int(sub_text) if sub_text.isdigit() else -1
    return main, sub, technique


def tactic_sort_key(tactic: str) -> tuple[int, str]:
    """Return the preferred workbook order for an ATT&CK tactic."""
    try:
        return ATTACK_TACTIC_ORDER.index(tactic), tactic
    except ValueError:
        return len(ATTACK_TACTIC_ORDER), tactic


def rows_for_tactic(tactic_data: dict[str, Any], blank_rows_between_techniques: int = 1) -> list[list[str]]:
    """Build worksheet rows for one tactic entry from the rule index."""
    rows = [TEMPLATE_HEADERS]
    techniques = tactic_data.get("techniques", {})
    for technique_index, technique in enumerate(sorted(techniques, key=technique_sort_key)):
        if technique_index:
            rows.extend([[] for _ in range(blank_rows_between_techniques)])
        rules = techniques[technique].get("rules", [])
        for rule_index, rule in enumerate(rules):
            rows.append(
                [
                    technique_label(technique) if rule_index == 0 else "",
                    str(rule.get("name", "")),
                    str(rule.get("title", "")),
                    str(rule.get("id", "")),
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                ]
            )
    return rows


def cell_xml(row_number: int, column_number: int, value: Any, style: int | None = None) -> str:
    """Render one worksheet cell as inline-string XML."""
    text = "" if value is None else str(value)
    attrs = [f'r="{column_name(column_number)}{row_number}"']
    if style is not None:
        attrs.append(f's="{style}"')
    if text == "":
        return f"<c {' '.join(attrs)}/>"
    return f"<c {' '.join(attrs)} t=\"inlineStr\"><is><t>{escape(text)}</t></is></c>"


def sheet_xml(rows: list[list[str]]) -> str:
    """Render worksheet XML for the provided row data."""
    column_widths = [14, 48, 72, 38, 22, 28, 18, 22, 18, 42]
    cols = "".join(
        f'<col min="{index}" max="{index}" width="{width}" customWidth="1"/>'
        for index, width in enumerate(column_widths, start=1)
    )
    row_xml_parts: list[str] = []
    for row_number, row in enumerate(rows, start=1):
        if not row:
            row_xml_parts.append(f'<row r="{row_number}"/>')
            continue
        cells = "".join(
            cell_xml(row_number, column_number, value, style=1 if row_number == 1 else None)
            for column_number, value in enumerate(row, start=1)
        )
        row_xml_parts.append(f'<row r="{row_number}">{cells}</row>')

    last_row = max(1, len(rows))
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<dimension ref="A1:J{last_row}"/>'
        '<sheetViews><sheetView workbookViewId="0">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
        '</sheetView></sheetViews>'
        f"<cols>{cols}</cols>"
        f"<sheetData>{''.join(row_xml_parts)}</sheetData>"
        f'<autoFilter ref="A1:J{last_row}"/>'
        '</worksheet>'
    )


def workbook_xml(sheets: list[tuple[str, list[list[str]]]]) -> str:
    """Render the workbook XML that lists worksheet entries."""
    sheet_entries = "".join(
        f'<sheet name={quoteattr(name)} sheetId="{index}" r:id="rId{index}"/>'
        for index, (name, _) in enumerate(sheets, start=1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets>'
        f"{sheet_entries}"
        '</sheets>'
        '</workbook>'
    )


def workbook_rels_xml(sheet_count: int) -> str:
    """Render workbook relationship XML for sheets and styles."""
    relationships = [
        f'<Relationship Id="rId{index}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        f'Target="worksheets/sheet{index}.xml"/>'
        for index in range(1, sheet_count + 1)
    ]
    relationships.append(
        f'<Relationship Id="rId{sheet_count + 1}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f"{''.join(relationships)}"
        '</Relationships>'
    )


def root_rels_xml() -> str:
    """Render the root package relationship XML."""
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        '</Relationships>'
    )


def content_types_xml(sheet_count: int) -> str:
    """Render package content-type XML for workbook parts."""
    sheet_overrides = "".join(
        '<Override '
        f'PartName="/xl/worksheets/sheet{index}.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        for index in range(1, sheet_count + 1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        f"{sheet_overrides}"
        '</Types>'
    )


def styles_xml() -> str:
    """Render the minimal styles XML used by generated templates."""
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="2">'
        '<font><sz val="11"/><name val="Calibri"/></font>'
        '<font><b/><sz val="11"/><name val="Calibri"/></font>'
        '</fonts>'
        '<fills count="2">'
        '<fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill>'
        '</fills>'
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="2">'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
        '</cellXfs>'
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        '</styleSheet>'
    )


def build_template_workbook(index_data: dict[str, Any], output_path: Path) -> None:
    """Create an XLSX template workbook from parsed index data."""
    tactics = index_data.get("tactics", {})
    used_sheet_names: set[str] = set()
    sheets: list[tuple[str, list[list[str]]]] = []
    for tactic in sorted(tactics, key=tactic_sort_key):
        tactic_data = tactics[tactic]
        sheet_name = safe_sheet_name(str(tactic_data.get("name") or tactic), used_sheet_names)
        sheets.append((sheet_name, rows_for_tactic(tactic_data)))

    if not sheets:
        sheets.append(("Rules", [TEMPLATE_HEADERS]))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as workbook:
        workbook.writestr("[Content_Types].xml", content_types_xml(len(sheets)))
        workbook.writestr("_rels/.rels", root_rels_xml())
        workbook.writestr("xl/workbook.xml", workbook_xml(sheets))
        workbook.writestr("xl/_rels/workbook.xml.rels", workbook_rels_xml(len(sheets)))
        workbook.writestr("xl/styles.xml", styles_xml())
        for index, (_, rows) in enumerate(sheets, start=1):
            workbook.writestr(f"xl/worksheets/sheet{index}.xml", sheet_xml(rows))


def export_template_from_index(index_path: Path, output_path: Path) -> None:
    """Load rule index JSON and export an XLSX template workbook."""
    with index_path.open("r", encoding="ascii") as f:
        index_data = json.load(f)
    build_template_workbook(index_data, output_path)
