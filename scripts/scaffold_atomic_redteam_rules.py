"""Create LLM true-positive data folders for Sigma rules that do not have one."""

from __future__ import annotations

import argparse
from pathlib import Path


DEFAULT_RULES_DIR = Path("rules")
DEFAULT_REFERENCE_DIR = Path("data/atomic_redteam")
DEFAULT_TARGET_DIR = Path("data/LLM_true_positive")
DEFAULT_PROMPT_TEMPLATE = Path("data/LLM_true_positive/prompt_trigger_rule_template.txt")


def iter_rule_files(rules_dir: Path) -> list[Path]:
    """Return sorted Sigma rule files from a flat rules directory."""
    if not rules_dir.exists():
        raise FileNotFoundError(f"rules directory not found: {rules_dir}")
    if not rules_dir.is_dir():
        raise NotADirectoryError(f"rules path is not a directory: {rules_dir}")

    return sorted(
        path
        for path in rules_dir.iterdir()
        if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}
    )


def render_prompt(template_text: str, rule_text: str) -> str:
    """Fill the rule placeholder when the template contains one."""
    if "{{rule}}" in template_text:
        return template_text.replace("{{rule}}", rule_text.rstrip())
    return template_text


def missing_rule_files(rules_dir: Path, reference_dir: Path) -> list[Path]:
    """Return rules whose stem is not already a folder in the reference directory."""
    return [
        rule_path
        for rule_path in iter_rule_files(rules_dir)
        if not (reference_dir / rule_path.stem).is_dir()
    ]


def scaffold_rule_folder(rule_path: Path, target_dir: Path, template_text: str) -> Path:
    """Create one per-rule folder with prompt.txt and an empty commandlines.txt."""
    rule_dir = target_dir / rule_path.stem
    rule_dir.mkdir(parents=True, exist_ok=False)

    rule_text = rule_path.read_text(encoding="utf-8-sig", errors="replace")
    prompt_text = render_prompt(template_text, rule_text)

    (rule_dir / "prompt.txt").write_text(prompt_text, encoding="utf-8")
    (rule_dir / "commandlines.txt").write_text("", encoding="utf-8")
    return rule_dir


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create data/LLM_true_positive/<rule_name> folders for Sigma rules "
            "that do not already have a matching folder in data/atomic_redteam."
        )
    )
    parser.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES_DIR)
    parser.add_argument(
        "--reference-dir",
        type=Path,
        default=DEFAULT_REFERENCE_DIR,
        help="Directory used to decide which rule folders are missing.",
    )
    parser.add_argument("--target-dir", type=Path, default=DEFAULT_TARGET_DIR)
    parser.add_argument("--template", type=Path, default=DEFAULT_PROMPT_TEMPLATE)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only print missing rule folders; do not create files.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.template.exists():
        raise FileNotFoundError(f"prompt template not found: {args.template}")
    if not args.reference_dir.exists():
        raise FileNotFoundError(f"reference directory not found: {args.reference_dir}")

    target_dir = args.target_dir
    target_dir.mkdir(parents=True, exist_ok=True)

    missing_reference_rules = missing_rule_files(args.rules_dir, args.reference_dir)
    rules_to_create = [
        rule_path
        for rule_path in missing_reference_rules
        if not (target_dir / rule_path.stem).exists()
    ]
    if args.dry_run:
        for rule_path in rules_to_create:
            print(rule_path.stem)
        print(f"Rules missing in reference: {len(missing_reference_rules)}")
        print(f"Folders to create: {len(rules_to_create)}")
        return 0

    template_text = args.template.read_text(encoding="utf-8-sig", errors="replace")
    created_dirs = [
        scaffold_rule_folder(rule_path, target_dir, template_text)
        for rule_path in rules_to_create
    ]

    for created_dir in created_dirs:
        print(created_dir)
    print(f"Created folders: {len(created_dirs)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
