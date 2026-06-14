"""Build Gemini prompt folders for rules listed in rule_add.txt."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


DEFAULT_RULE_ADD = Path("rule_add.txt")
DEFAULT_TEMPLATE = Path("prompt_cmdl_evasion.txt")
DEFAULT_RULES_DIR = Path("rules")
DEFAULT_TRUE_POSITIVE_DIR = Path("data/true_positive_test")
DEFAULT_OUTPUT_DIR = Path("gemini_result_add")

SIGMA_PLACEHOLDER = "{{SIGMA_RULE}}"
COMMAND_PLACEHOLDER = "{{TRUE_POSITIVE_TEST_COMMAND}}"
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def read_text(path: Path) -> str:
    """Read UTF-8 text with a useful missing-file error."""
    if not path.exists():
        raise FileNotFoundError(f"file not found: {path}")
    return path.read_text(encoding="utf-8-sig", errors="replace")


def render_prompt(template: str, sigma_rule: str, command: str) -> str:
    """Fill the configured prompt template."""
    if SIGMA_PLACEHOLDER not in template:
        raise ValueError(f"prompt template missing {SIGMA_PLACEHOLDER}")
    if COMMAND_PLACEHOLDER not in template:
        raise ValueError(f"prompt template missing {COMMAND_PLACEHOLDER}")
    return template.replace(SIGMA_PLACEHOLDER, sigma_rule).replace(COMMAND_PLACEHOLDER, command)


def rule_path_for_name(rules_dir: Path, rule_name: str) -> Path | None:
    """Return the Sigma rule path for a rule stem."""
    for suffix in (".yml", ".yaml"):
        candidate = rules_dir / f"{rule_name}{suffix}"
        if candidate.exists():
            return candidate
    return None


def first_yaml_id(rule_text: str) -> str:
    """Extract the top-level id value from a Sigma rule."""
    for raw_line in rule_text.splitlines():
        line = raw_line.strip()
        if line.startswith("id:"):
            return line.split(":", 1)[1].strip().strip("\"'").lower()
    return ""


def build_rule_id_index(rules_dir: Path) -> dict[str, str]:
    """Map Sigma rule IDs to rule stems."""
    if not rules_dir.exists():
        raise FileNotFoundError(f"rules directory not found: {rules_dir}")

    index: dict[str, str] = {}
    for rule_path in sorted(list(rules_dir.glob("*.yml")) + list(rules_dir.glob("*.yaml"))):
        rule_id = first_yaml_id(read_text(rule_path))
        if rule_id:
            index[rule_id] = rule_path.stem
    return index


def resolve_rule_from_fields(
    fields: list[str],
    rules_dir: Path,
    id_to_rule: dict[str, str],
) -> tuple[str, str] | None:
    """Resolve a rule_add row to a rule stem and source type."""
    first_field = fields[0].strip() if fields else ""
    if first_field and rule_path_for_name(rules_dir, first_field):
        return first_field, "rule_name"

    for field in fields[:4]:
        value = field.strip()
        if UUID_RE.match(value):
            rule_name = id_to_rule.get(value.lower())
            if rule_name:
                return rule_name, "rule_id"
    return None


def collect_rules(
    rule_add_path: Path,
    rules_dir: Path,
    id_to_rule: dict[str, str],
) -> tuple[list[str], dict[str, Any]]:
    """Collect unique rule names from rule_add.txt, preserving first-seen order."""
    seen: set[str] = set()
    rules: list[str] = []
    unresolved: list[dict[str, Any]] = []
    duplicate_count = 0
    source_counts = {"rule_name": 0, "rule_id": 0}

    for line_number, raw_line in enumerate(read_text(rule_add_path).splitlines(), start=1):
        fields = [field.strip() for field in raw_line.split("\t")]
        if line_number == 1 and fields and fields[0].lower() == "rule_name":
            continue
        if not any(fields):
            continue

        resolved = resolve_rule_from_fields(fields, rules_dir, id_to_rule)
        if resolved is None:
            unresolved.append({"line": line_number, "fields": fields[:4]})
            continue

        rule_name, source = resolved
        source_counts[source] += 1
        if rule_name in seen:
            duplicate_count += 1
            continue
        seen.add(rule_name)
        rules.append(rule_name)

    summary = {
        "raw_resolved_row_count": sum(source_counts.values()),
        "source_counts": source_counts,
        "duplicate_resolved_rows": duplicate_count,
        "unresolved_count": len(unresolved),
        "unresolved": unresolved,
    }
    return rules, summary


def true_positive_text(true_positive_dir: Path, rule_name: str) -> str:
    """Return true-positive commands for a rule, or an empty string when absent."""
    path = true_positive_dir / rule_name / "commandlines.txt"
    if not path.exists():
        return ""
    return read_text(path).strip()


def write_rule_folder(
    *,
    output_dir: Path,
    rule_name: str,
    prompt: str,
    overwrite_prompt: bool,
    overwrite_evasion_file: bool,
) -> None:
    """Write prompt.txt and commandline_evasion.txt for one rule."""
    rule_dir = output_dir / rule_name
    rule_dir.mkdir(parents=True, exist_ok=True)

    prompt_path = rule_dir / "prompt.txt"
    if overwrite_prompt or not prompt_path.exists():
        prompt_path.write_text(prompt.rstrip() + "\n", encoding="utf-8")

    evasion_path = rule_dir / "commandline_evasion.txt"
    if overwrite_evasion_file or not evasion_path.exists():
        evasion_path.write_text("", encoding="utf-8")


def build_gemini_result(config: argparse.Namespace) -> dict[str, Any]:
    """Build the full gemini_result_add folder."""
    template = read_text(config.template)
    id_to_rule = build_rule_id_index(config.rules_dir)
    rules, summary = collect_rules(config.rule_add, config.rules_dir, id_to_rule)
    config.output_dir.mkdir(parents=True, exist_ok=True)

    empty_true_positive: list[str] = []
    for rule_name in rules:
        rule_path = rule_path_for_name(config.rules_dir, rule_name)
        if rule_path is None:
            continue
        sigma_rule = read_text(rule_path).strip()
        command_text = true_positive_text(config.true_positive_dir, rule_name)
        if not command_text:
            empty_true_positive.append(rule_name)
        prompt = render_prompt(template, sigma_rule, command_text)
        write_rule_folder(
            output_dir=config.output_dir,
            rule_name=rule_name,
            prompt=prompt,
            overwrite_prompt=config.overwrite_prompts,
            overwrite_evasion_file=config.overwrite_evasion_files,
        )

    manifest = {
        "rule_add": str(config.rule_add),
        "template": str(config.template),
        "rules_dir": str(config.rules_dir),
        "true_positive_dir": str(config.true_positive_dir),
        "output_dir": str(config.output_dir),
        "rule_count": len(rules),
        "empty_true_positive_count": len(empty_true_positive),
        "empty_true_positive_rules": empty_true_positive,
        **summary,
    }
    (config.output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create Gemini prompt folders from rule_add.txt.")
    parser.add_argument("--rule-add", type=Path, default=DEFAULT_RULE_ADD)
    parser.add_argument("--template", type=Path, default=DEFAULT_TEMPLATE)
    parser.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES_DIR)
    parser.add_argument("--true-positive-dir", type=Path, default=DEFAULT_TRUE_POSITIVE_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--overwrite-prompts", action="store_true")
    parser.add_argument("--overwrite-evasion-files", action="store_true")
    return parser.parse_args()


def main() -> int:
    manifest = build_gemini_result(parse_args())
    print(
        f"Wrote {manifest['rule_count']} rule folder(s) to {manifest['output_dir']} "
        f"({manifest['empty_true_positive_count']} with empty true-positive input)"
    )
    if manifest["unresolved_count"]:
        print(f"Unresolved row(s): {manifest['unresolved_count']}; see manifest.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
