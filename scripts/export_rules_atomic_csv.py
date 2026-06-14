"""Export Sigma rule metadata and Atomic Red Team command lines to CSV."""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path


DEFAULT_RULES_DIR = Path("rules")
DEFAULT_ATOMIC_DIR = Path("data/atomic_redteam")
DEFAULT_OUTPUT_PATH = Path("output/rules_atomic_commandlines.csv")


def clean_yaml_scalar(value: str) -> str:
    value = value.strip()
    if "#" in value:
        value = value.split("#", 1)[0].rstrip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def parse_inline_tags(value: str) -> list[str]:
    value = clean_yaml_scalar(value)
    if not (value.startswith("[") and value.endswith("]")):
        return [value] if value else []
    raw_tags = value[1:-1].split(",")
    return [clean_yaml_scalar(tag) for tag in raw_tags if clean_yaml_scalar(tag)]


def read_rule_metadata(rule_path: Path) -> tuple[str, list[str]]:
    title = ""
    tags: list[str] = []
    in_tags_block = False

    for raw_line in rule_path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if not raw_line.startswith((" ", "\t")):
            in_tags_block = False

        if raw_line.startswith("title:"):
            title = clean_yaml_scalar(raw_line.split(":", 1)[1])
            continue

        if raw_line.startswith("tags:"):
            in_tags_block = True
            tags.extend(parse_inline_tags(raw_line.split(":", 1)[1]))
            continue

        if in_tags_block and stripped.startswith("-"):
            tags.append(clean_yaml_scalar(stripped[1:]))

    return title, tags


def iter_rule_files(rules_dir: Path) -> list[Path]:
    return sorted(
        path
        for path in rules_dir.iterdir()
        if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}
    )


def read_commandlines(commandline_path: Path) -> list[str]:
    commands: list[str] = []
    for raw_line in commandline_path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        command = raw_line.strip()
        if command and not command.startswith("#"):
            commands.append(command)
    return commands


def build_rows(rules_dir: Path, atomic_dir: Path, only_with_commandlines: bool) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    for rule_path in iter_rule_files(rules_dir):
        rule_name = rule_path.stem
        title, tags = read_rule_metadata(rule_path)
        tag_text = "; ".join(dict.fromkeys(tags))
        commandline_path = atomic_dir / rule_name / "commandlines.txt"
        commands = read_commandlines(commandline_path) if commandline_path.exists() else []

        if not commands and not only_with_commandlines:
            commands = [""]

        for command in commands:
            rows.append(
                {
                    "tag": tag_text,
                    "rule_name": rule_name,
                    "title": title,
                    "commandline match rule": re.sub(r"\s+", " ", command).strip(),
                }
            )

    return rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a CSV with tag, rule_name, title, and Atomic Red Team command lines."
    )
    parser.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES_DIR)
    parser.add_argument("--atomic-dir", type=Path, default=DEFAULT_ATOMIC_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument(
        "--only-with-commandlines",
        action="store_true",
        help="Only include rules that have an Atomic commandline.txt with at least one command line.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.rules_dir.exists():
        raise FileNotFoundError(f"rules directory not found: {args.rules_dir}")
    if not args.atomic_dir.exists():
        raise FileNotFoundError(f"atomic directory not found: {args.atomic_dir}")

    rows = build_rows(args.rules_dir, args.atomic_dir, args.only_with_commandlines)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8-sig", newline="") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=["tag", "rule_name", "title", "commandline match rule"],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
