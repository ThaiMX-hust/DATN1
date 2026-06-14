"""Create commandlines.txt inputs from rule_add.txt."""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


DEFAULT_INPUT = Path("rule_add.txt")
DEFAULT_OUTPUT_DIR = Path("data/rule_add_true_positive")


def read_rule_add(path: Path, dedupe: bool) -> tuple[dict[str, list[str]], list[dict[str, Any]]]:
    """Read rule_add.txt as tab-separated Rule_name/Command_match_rule rows."""
    if not path.exists():
        raise FileNotFoundError(f"input file not found: {path}")

    rule_commands: dict[str, list[str]] = defaultdict(list)
    seen: set[tuple[str, str]] = set()
    skipped: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8-sig", newline="") as input_file:
        reader = csv.DictReader(input_file, delimiter="\t")
        for row_number, row in enumerate(reader, start=2):
            rule_name = (row.get("Rule_name") or "").strip()
            command = (row.get("Command_match_rule") or "").strip()

            if not rule_name:
                skipped.append({"row": row_number, "reason": "blank rule_name"})
                continue
            if not command:
                skipped.append({"row": row_number, "rule_name": rule_name, "reason": "blank command"})
                continue

            key = (rule_name, command)
            if dedupe and key in seen:
                skipped.append({"row": row_number, "rule_name": rule_name, "reason": "duplicate command"})
                continue
            seen.add(key)
            rule_commands[rule_name].append(command)

    return dict(rule_commands), skipped


def write_commandlines(rule_commands: dict[str, list[str]], output_dir: Path) -> None:
    """Write one commandlines.txt file per rule."""
    output_dir.mkdir(parents=True, exist_ok=True)
    for rule_name, commands in sorted(rule_commands.items()):
        rule_dir = output_dir / rule_name
        rule_dir.mkdir(parents=True, exist_ok=True)
        (rule_dir / "commandlines.txt").write_text(
            "\n".join(commands) + "\n",
            encoding="utf-8",
        )


def write_manifest(
    output_dir: Path,
    input_path: Path,
    rule_commands: dict[str, list[str]],
    skipped: list[dict[str, Any]],
    dedupe: bool,
) -> None:
    """Write a small import manifest for auditability."""
    payload = {
        "input": str(input_path),
        "dedupe": dedupe,
        "rule_count": len(rule_commands),
        "command_count": sum(len(commands) for commands in rule_commands.values()),
        "skipped_count": len(skipped),
        "skipped": skipped,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Import rule_add.txt command lines into rule folders.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--keep-duplicates", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    dedupe = not args.keep_duplicates
    rule_commands, skipped = read_rule_add(args.input, dedupe=dedupe)
    write_commandlines(rule_commands, args.output_dir)
    write_manifest(args.output_dir, args.input, rule_commands, skipped, dedupe=dedupe)
    print(
        f"Wrote {len(rule_commands)} rule folder(s), "
        f"{sum(len(commands) for commands in rule_commands.values())} command line(s) "
        f"to {args.output_dir}"
    )
    print(f"Skipped {len(skipped)} row(s); see {args.output_dir / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
