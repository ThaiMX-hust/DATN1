"""Summarize Sigma rules by MITRE ATT&CK tactic tags."""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES_DIR = PROJECT_ROOT / "rules"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "output" / "rules_by_tactic"

TOP_LEVEL_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$")
ATTACK_TACTIC_RE = re.compile(r"^attack\.([a-z]+(?:-[a-z]+)*)$")
TECHNIQUE_TAG_RE = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$", re.IGNORECASE)

DETAIL_FIELDNAMES = [
    "tactic",
    "rule_name",
    "title",
    "rule_id",
    "status",
    "level",
    "path",
    "tags",
    "techniques",
]
SUMMARY_FIELDNAMES = ["tactic", "rule_count"]


@dataclass(frozen=True)
class RuleMetadata:
    """Metadata needed to group one Sigma rule by ATT&CK tactic."""

    rule_name: str
    title: str
    rule_id: str
    status: str
    level: str
    path: Path
    tags: list[str]

    @property
    def tactics(self) -> list[str]:
        """Return tactic names such as discovery or defense-evasion."""
        tactics: list[str] = []
        for tag in self.tags:
            match = ATTACK_TACTIC_RE.match(tag.lower())
            if match:
                tactics.append(match.group(1))
        return unique_sorted(tactics)

    @property
    def techniques(self) -> list[str]:
        """Return ATT&CK technique tags such as attack.t1059.001."""
        return unique_sorted(tag.lower() for tag in self.tags if TECHNIQUE_TAG_RE.match(tag))


def unique_sorted(values: Any) -> list[str]:
    """Return unique strings sorted alphabetically."""
    return sorted(dict.fromkeys(str(value) for value in values if str(value)))


def strip_yaml_comment(value: str) -> str:
    """Strip a YAML-style inline comment while respecting simple quotes."""
    quote: str | None = None
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char in {"'", '"'}:
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
            continue
        if char == "#" and quote is None:
            return value[:index]
    return value


def clean_yaml_scalar(value: str) -> str:
    """Return a simple scalar value without surrounding quotes."""
    value = strip_yaml_comment(value).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def parse_inline_tags(value: str) -> list[str]:
    """Parse tags written as either a scalar or a simple inline list."""
    value = clean_yaml_scalar(value)
    if not value:
        return []
    if not (value.startswith("[") and value.endswith("]")):
        return [value]
    tags: list[str] = []
    for raw_tag in value[1:-1].split(","):
        tag = clean_yaml_scalar(raw_tag)
        if tag:
            tags.append(tag)
    return tags


def read_rule_metadata(rule_path: Path) -> RuleMetadata:
    """Read only the top-level metadata needed from a Sigma YAML rule."""
    values = {
        "title": "",
        "id": "",
        "status": "",
        "level": "",
    }
    tags: list[str] = []
    in_tags_block = False

    for raw_line in rule_path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        top_level_match = TOP_LEVEL_RE.match(raw_line)
        if top_level_match:
            key, raw_value = top_level_match.groups()
            in_tags_block = key == "tags"
            if key in values:
                values[key] = clean_yaml_scalar(raw_value)
            elif key == "tags":
                tags.extend(parse_inline_tags(raw_value))
            continue

        if in_tags_block and stripped.startswith("-"):
            tag = clean_yaml_scalar(stripped[1:])
            if tag:
                tags.append(tag)

    return RuleMetadata(
        rule_name=rule_path.stem,
        title=values["title"],
        rule_id=values["id"],
        status=values["status"],
        level=values["level"],
        path=rule_path,
        tags=unique_sorted(tags),
    )


def iter_rule_files(rules_dir: Path) -> list[Path]:
    """Return all YAML rule files in stable order."""
    return sorted(
        path
        for path in rules_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}
    )


def display_path(path: Path, base_dir: Path) -> str:
    """Return a compact path when possible."""
    try:
        return str(path.resolve().relative_to(base_dir.resolve())).replace("\\", "/")
    except ValueError:
        return str(path)


def rule_to_json(rule: RuleMetadata, base_dir: Path) -> dict[str, Any]:
    """Convert a rule metadata object to JSON-friendly data."""
    return {
        "rule_name": rule.rule_name,
        "title": rule.title,
        "id": rule.rule_id,
        "status": rule.status,
        "level": rule.level,
        "path": display_path(rule.path, base_dir),
        "tags": rule.tags,
        "techniques": rule.techniques,
    }


def build_tactic_map(rules: list[RuleMetadata], include_untagged: bool) -> dict[str, list[RuleMetadata]]:
    """Group rules by tactic. Rules with multiple tactics appear in each tactic."""
    tactic_map: dict[str, list[RuleMetadata]] = defaultdict(list)
    for rule in rules:
        tactics = rule.tactics
        if not tactics and include_untagged:
            tactics = ["__no_tactic__"]
        for tactic in tactics:
            tactic_map[tactic].append(rule)
    return dict(sorted(tactic_map.items()))


def build_json_payload(
    rules: list[RuleMetadata],
    tactic_map: dict[str, list[RuleMetadata]],
    rules_dir: Path,
    base_dir: Path,
) -> dict[str, Any]:
    """Build the main JSON report."""
    rules_without_tactics = [rule for rule in rules if not rule.tactics]
    return {
        "rules_dir": display_path(rules_dir, base_dir),
        "total_rules": len(rules),
        "tactic_count": len([tactic for tactic in tactic_map if tactic != "__no_tactic__"]),
        "rules_with_tactics": len(rules) - len(rules_without_tactics),
        "rules_without_tactics": len(rules_without_tactics),
        "tactics": {
            tactic: {
                "count": len(tactic_rules),
                "rules": [rule_to_json(rule, base_dir) for rule in sorted(tactic_rules, key=lambda item: item.rule_name)],
            }
            for tactic, tactic_rules in tactic_map.items()
        },
    }


def detail_rows(tactic_map: dict[str, list[RuleMetadata]], base_dir: Path) -> list[dict[str, str]]:
    """Return one CSV row per tactic/rule pair."""
    rows: list[dict[str, str]] = []
    for tactic, tactic_rules in tactic_map.items():
        for rule in sorted(tactic_rules, key=lambda item: item.rule_name):
            rows.append(
                {
                    "tactic": tactic,
                    "rule_name": rule.rule_name,
                    "title": rule.title,
                    "rule_id": rule.rule_id,
                    "status": rule.status,
                    "level": rule.level,
                    "path": display_path(rule.path, base_dir),
                    "tags": "; ".join(rule.tags),
                    "techniques": "; ".join(rule.techniques),
                }
            )
    return rows


def summary_rows(tactic_map: dict[str, list[RuleMetadata]]) -> list[dict[str, str | int]]:
    """Return one CSV summary row per tactic."""
    return [{"tactic": tactic, "rule_count": len(tactic_rules)} for tactic, tactic_rules in tactic_map.items()]


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    """Write rows to a UTF-8 CSV file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(description="Group Sigma rules by MITRE ATT&CK tactic tags.")
    parser.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES_DIR, help="Folder containing Sigma rule YAML files.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR, help="Folder where reports are written.")
    parser.add_argument(
        "--include-untagged",
        action="store_true",
        help='Include rules without ATT&CK tactic tags under "__no_tactic__".',
    )
    return parser


def main() -> int:
    """Run the rule tactic summarizer."""
    args = build_parser().parse_args()
    rules_dir = args.rules_dir.resolve()
    output_dir = args.output_dir.resolve()
    base_dir = PROJECT_ROOT.resolve()

    if not rules_dir.exists():
        raise FileNotFoundError(f"rules directory not found: {rules_dir}")

    rules = [read_rule_metadata(path) for path in iter_rule_files(rules_dir)]
    tactic_map = build_tactic_map(rules, include_untagged=args.include_untagged)
    payload = build_json_payload(rules, tactic_map, rules_dir, base_dir)

    json_path = output_dir / "rules_by_tactic.json"
    summary_csv_path = output_dir / "tactic_summary.csv"
    detail_csv_path = output_dir / "tactic_rules.csv"

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_csv(summary_csv_path, SUMMARY_FIELDNAMES, summary_rows(tactic_map))
    write_csv(detail_csv_path, DETAIL_FIELDNAMES, detail_rows(tactic_map, base_dir))

    print(f"Scanned {payload['total_rules']} rules across {payload['tactic_count']} tactics.")
    print(f"Rules without tactic tags: {payload['rules_without_tactics']}")
    print(f"Wrote JSON: {display_path(json_path, base_dir)}")
    print(f"Wrote summary CSV: {display_path(summary_csv_path, base_dir)}")
    print(f"Wrote detail CSV: {display_path(detail_csv_path, base_dir)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
