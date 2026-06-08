"""Index Sigma rules by ATT&CK tactic and technique metadata."""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any


ATTACK_TACTICS = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

TECHNIQUE_RE = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$", re.IGNORECASE)
TOP_LEVEL_FIELD_RE = re.compile(r"^([A-Za-z0-9_]+):(?:\s*(.*))?$")
LIST_ITEM_RE = re.compile(r"^\s*-\s*(.+?)\s*$")
DETECTION_FIELD_RE = re.compile(r"^\s*-?\s*([A-Za-z0-9_]+)(?:\|[^:]+)?\s*:")
DANGEROUS_SYSTEM_ACTION_RE = re.compile(
    r"(?:\\|\b)(?:shutdown|psshutdown|bcdedit|bcdboot|bootcfg|bootrec|bootsect)\.exe\b"
    r"|\b(?:shutdown|psshutdown|bcdedit|bcdboot|bootcfg|bootrec|bootsect)\b"
    r"|\b(?:stop-computer|restart-computer|reboot)\b"
    r"|\b(?:safeboot|recoveryenabled|bootstatuspolicy|bootmenupolicy)\b",
    re.IGNORECASE,
)


def strip_inline_comment(value: str) -> str:
    """Remove a simple YAML inline comment from a scalar value."""
    text = value.strip()
    if not text:
        return ""
    if text[0] in ("'", '"'):
        return text
    return text.split(" #", 1)[0].rstrip()


def clean_scalar(value: str) -> str:
    """Normalize a simple YAML scalar into plain text."""
    text = strip_inline_comment(value)
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        return text[1:-1]
    if text in ("~", "null", "Null", "NULL"):
        return ""
    return text


def parse_inline_list(value: str) -> list[str]:
    """Parse a simple inline YAML list or scalar into strings."""
    text = clean_scalar(value)
    if not text:
        return []
    if text.startswith("[") and text.endswith("]"):
        return [clean_scalar(part) for part in text[1:-1].split(",") if clean_scalar(part)]
    return [text]


def parse_sigma_metadata(path: Path) -> dict[str, Any]:
    """Extract top-level Sigma metadata used by the rule index."""
    metadata: dict[str, Any] = {
        "title": "",
        "id": "",
        "status": "",
        "level": "",
        "tags": [],
    }
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = TOP_LEVEL_FIELD_RE.match(line)
        if not match:
            index += 1
            continue

        key = match.group(1)
        value = match.group(2) or ""
        if key == "tags":
            tags = parse_inline_list(value)
            index += 1
            while index < len(lines):
                next_line = lines[index]
                if TOP_LEVEL_FIELD_RE.match(next_line):
                    break
                item_match = LIST_ITEM_RE.match(next_line)
                if item_match:
                    tags.append(clean_scalar(item_match.group(1)))
                index += 1
            metadata["tags"] = [tag for tag in tags if tag]
            continue

        if key in metadata:
            metadata[key] = clean_scalar(value)
        index += 1

    return metadata


def top_level_block(lines: list[str], field_name: str) -> list[str]:
    """Return the body lines for a top-level YAML block."""
    block: list[str] = []
    in_block = False
    for line in lines:
        top_level = TOP_LEVEL_FIELD_RE.match(line)
        if top_level:
            if in_block:
                break
            in_block = top_level.group(1) == field_name
            continue
        if in_block:
            block.append(line)
    return block


def detection_field_names(lines: list[str]) -> set[str]:
    """Collect field names referenced in a Sigma detection block."""
    fields: set[str] = set()
    for line in top_level_block(lines, "detection"):
        match = DETECTION_FIELD_RE.match(line)
        if match:
            fields.add(match.group(1))
    return fields


def dangerous_system_action_reason(lines: list[str]) -> str:
    """Return why a rule references dangerous system actions, if any."""
    detection_text = "\n".join(top_level_block(lines, "detection"))
    match = DANGEROUS_SYSTEM_ACTION_RE.search(detection_text)
    if not match:
        return ""
    return f"detection references boot/shutdown action: {match.group(0)}"


def normalize_tag(tag: str) -> str:
    """Normalize a Sigma tag for index comparisons."""
    return tag.strip().lower()


def technique_sort_key(technique: str) -> tuple[int, int, str]:
    """Return a numeric sort key for ATT&CK technique tags."""
    suffix = technique.lower().removeprefix("attack.t")
    main_text, _, sub_text = suffix.partition(".")
    main = int(main_text) if main_text.isdigit() else 0
    sub = int(sub_text) if sub_text.isdigit() else -1
    return main, sub, technique


def rule_path(path: Path, base_dir: Path) -> str:
    """Return a portable rule path relative to the repository base."""
    try:
        return str(path.relative_to(base_dir)).replace("\\", "/")
    except ValueError:
        return str(path)


def normalize_tactic_filter(value: str) -> str:
    """Normalize a user-provided tactic filter."""
    tactic = value.strip().lower()
    if tactic.startswith("attack."):
        tactic = tactic.removeprefix("attack.")
    return tactic


def normalize_technique_filter(value: str) -> str:
    """Normalize a user-provided technique filter to an ATT&CK tag."""
    technique = value.strip().lower().replace("_", ".")
    if technique.startswith("attack."):
        technique = technique.removeprefix("attack.")
    if technique.startswith("t"):
        return f"attack.{technique}"
    return f"attack.t{technique}"


def technique_label(technique: str) -> str:
    """Return the display label for an ATT&CK technique tag."""
    return technique.removeprefix("attack.").upper()


def rule_record(path: Path, rules_dir: Path) -> dict[str, Any]:
    """Build one indexed rule record from a Sigma YAML file."""
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    metadata = parse_sigma_metadata(path)
    tags = [normalize_tag(tag) for tag in metadata["tags"]]
    fields = detection_field_names(lines)
    tactics = sorted(
        {
            tag.removeprefix("attack.")
            for tag in tags
            if tag.startswith("attack.") and tag.removeprefix("attack.") in ATTACK_TACTICS
        }
    )
    techniques = sorted(
        {tag for tag in tags if TECHNIQUE_RE.match(tag)},
        key=technique_sort_key,
    )
    return {
        "name": path.stem,
        "title": metadata["title"],
        "id": metadata["id"],
        "status": metadata["status"],
        "level": metadata["level"],
        "path": rule_path(path, rules_dir.parent),
        "tags": tags,
        "tactics": tactics,
        "techniques": techniques,
        "has_detection_commandline": "CommandLine" in fields,
        "dangerous_system_action": dangerous_system_action_reason(lines),
    }


def minimal_rule(rule: dict[str, Any]) -> dict[str, Any]:
    """Return the compact rule shape stored under index groups."""
    return {
        "name": rule["name"],
        "title": rule["title"],
        "id": rule["id"],
        "status": rule["status"],
        "level": rule["level"],
        "path": rule["path"],
        "tags": rule["tags"],
    }


def excluded_rule(rule: dict[str, Any], reason: str) -> dict[str, Any]:
    """Return a compact rule record with an exclusion reason."""
    record = minimal_rule(rule)
    record["exclusion_reason"] = reason
    return record


def build_rules_attack_index(
    rules_dir: Path,
    tactic_filters: list[str] | None = None,
    technique_filters: list[str] | None = None,
    require_detection_commandline: bool = False,
    exclude_dangerous_system_actions: bool = False,
) -> dict[str, Any]:
    """Build the complete rules-to-ATT&CK index data structure."""
    tactic_set = {normalize_tactic_filter(value) for value in tactic_filters or []}
    technique_set = {normalize_technique_filter(value) for value in technique_filters or []}

    all_rules = [rule_record(path, rules_dir) for path in sorted(rules_dir.rglob("*.yml"))]
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    missing_tactic: list[dict[str, Any]] = []
    missing_technique: list[dict[str, Any]] = []
    missing_attack_tags: list[dict[str, Any]] = []
    excluded_missing_commandline: list[dict[str, Any]] = []
    excluded_dangerous: list[dict[str, Any]] = []

    def matches_filters(rule: dict[str, Any]) -> bool:
        """Return whether a rule passes the active tactic and technique filters."""
        if tactic_set and not any(tactic in tactic_set for tactic in rule["tactics"]):
            return False
        if technique_set and not any(technique in technique_set for technique in rule["techniques"]):
            return False
        return True

    for rule in all_rules:
        if require_detection_commandline and not rule["has_detection_commandline"]:
            excluded_missing_commandline.append(
                excluded_rule(rule, "missing CommandLine field under detection")
            )
            continue
        if exclude_dangerous_system_actions and rule["dangerous_system_action"]:
            excluded_dangerous.append(excluded_rule(rule, rule["dangerous_system_action"]))
            continue

        tactics = rule["tactics"]
        techniques = rule["techniques"]
        if not tactics and not techniques:
            if matches_filters(rule):
                missing_attack_tags.append(minimal_rule(rule))
            continue
        if not tactics:
            if matches_filters(rule):
                missing_tactic.append(minimal_rule(rule))
            continue
        if not techniques:
            if matches_filters(rule):
                missing_technique.append(minimal_rule(rule))
            continue

        for tactic in tactics:
            if tactic_set and tactic not in tactic_set:
                continue
            for technique in techniques:
                if technique_set and technique not in technique_set:
                    continue
                grouped[tactic][technique].append(minimal_rule(rule))

    tactics_output: dict[str, Any] = {}
    indexed_rule_names: set[str] = set()
    indexed_rule_ref_count = 0
    for tactic in sorted(grouped):
        techniques_output: dict[str, Any] = {}
        for technique in sorted(grouped[tactic], key=technique_sort_key):
            rules = sorted(grouped[tactic][technique], key=lambda item: item["name"])
            indexed_rule_ref_count += len(rules)
            indexed_rule_names.update(rule["name"] for rule in rules)
            techniques_output[technique] = {
                "technique": technique_label(technique),
                "rule_count": len(rules),
                "rules": rules,
            }
        tactics_output[tactic] = {
            "name": ATTACK_TACTICS.get(tactic, tactic),
            "technique_count": len(techniques_output),
            "rule_ref_count": sum(item["rule_count"] for item in techniques_output.values()),
            "techniques": techniques_output,
        }

    return {
        "metadata": {
            "rules_dir": str(rules_dir),
            "rule_file_count": len(all_rules),
            "included_rule_file_count": len(
                {
                    rule_name
                    for techniques in grouped.values()
                    for rules in techniques.values()
                    for rule_name in [rule["name"] for rule in rules]
                }
            )
            + len(missing_tactic)
            + len(missing_technique)
            + len(missing_attack_tags),
            "indexed_unique_rule_count": len(indexed_rule_names),
            "indexed_rule_ref_count": indexed_rule_ref_count,
            "tactic_count": len(tactics_output),
            "technique_count": len({technique for techniques in grouped.values() for technique in techniques}),
            "association_mode": "Each technique tag is associated with each tactic tag found in the same Sigma rule.",
            "filters": {
                "tactics": sorted(tactic_set),
                "techniques": sorted(technique_set, key=technique_sort_key),
                "require_detection_commandline": require_detection_commandline,
                "exclude_dangerous_system_actions": exclude_dangerous_system_actions,
            },
        },
        "tactics": tactics_output,
        "excluded_rules": {
            "missing_detection_commandline": excluded_missing_commandline,
            "dangerous_system_action": excluded_dangerous,
        },
        "rules_without_attack_mapping": {
            "missing_tactic": missing_tactic,
            "missing_technique": missing_technique,
            "missing_attack_tags": missing_attack_tags,
        },
    }
