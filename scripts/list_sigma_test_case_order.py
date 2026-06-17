"""Write the test-case execution order used by sigma_rule_evaluator."""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from sigma_rule_evaluator.cases import group_by_technique, load_cases, select_cases, technique_dir_map
from sigma_rule_evaluator.models import TargetCase
from sigma_rule_evaluator.path_config import load_path_config
from sigma_rule_evaluator.runner import (
    ResumeFromEvtx,
    evtx_name_for_case,
    execution_order,
    select_cases_after_last_evtx,
)
from sigma_rule_evaluator.utils import resolve_path, safe_name


FIELDNAMES = [
    "run_order",
    "input_index",
    "test_id",
    "technique_id",
    "mutation",
    "shell",
    "timeout_seconds",
    "target_rule",
    "evtx_name",
    "target_commandline",
]


@dataclass(frozen=True)
class CaseOrderPlan:
    """Resolved dry-run plan for the test cases that would be executed."""

    config_path: Path
    selected_count: int
    technique_count: int
    cases: list[TargetCase]
    dir_map: dict[str, str]
    resume: ResumeFromEvtx | None = None


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        description="List the exact test_case order that sigma_rule_evaluator will execute for an input JSON file."
    )
    parser.add_argument("--path-config", help="Project path JSON file. Defaults to config/paths.json when it exists.")
    parser.add_argument("--config", help="Input JSON file. Overrides input_config in the path config.")
    parser.add_argument("--base-dir", default=None, help="Base folder for CLI relative paths.")
    parser.add_argument("--offset", type=int, default=0, help="Same meaning as sigma_rule_evaluator --offset.")
    parser.add_argument("--limit", type=int, help="Same meaning as sigma_rule_evaluator --limit.")
    parser.add_argument(
        "--resume-from-batch",
        help="Existing batch folder; list only cases after the newest matching EVTX, matching evaluator resume logic.",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format. Defaults to table.",
    )
    parser.add_argument(
        "--output",
        help="Output file. Defaults to output/test_case_order/<input-name>.<format-extension>.",
    )
    parser.add_argument("--stdout", action="store_true", help="Print to stdout instead of writing an output file.")
    parser.add_argument(
        "--max-commandline-width",
        type=int,
        default=140,
        help="Truncate command lines in table output. Use 0 for no truncation. JSON/CSV are never truncated.",
    )
    return parser


def _configured_value(cli_value: str | None, config_value: str | Path | None) -> str | Path | None:
    """Return a CLI value when supplied, otherwise return the config value."""
    return cli_value if cli_value not in (None, "") else config_value


def _required_path(value: str | Path | None, base_dir: Path, option_name: str) -> Path:
    """Resolve a required path option relative to the configured base directory."""
    path = resolve_path(value, base_dir)
    if path is None:
        raise ValueError(f"{option_name} is required")
    return path


def resolve_cli_paths(args: argparse.Namespace) -> tuple[Path, Path, Path | None]:
    """Resolve base, config, and resume paths using the evaluator path config rules."""
    cwd = Path.cwd()
    path_config = load_path_config(args.path_config, cwd)
    base_dir = Path(args.base_dir).resolve() if args.base_dir else path_config.base_dir or cwd
    config_path = _required_path(
        _configured_value(args.config, path_config.input_config),
        base_dir,
        "--config or input_config in path config",
    )
    resume_from_batch = resolve_path(args.resume_from_batch, base_dir)
    return base_dir, config_path, resume_from_batch


def build_order_plan(
    config_path: Path,
    offset: int = 0,
    limit: int | None = None,
    resume_from_batch: Path | None = None,
) -> CaseOrderPlan:
    """Return the same test-case order used by the evaluator runner."""
    selected_cases = select_cases(load_cases(config_path), offset, limit)
    full_grouped = group_by_technique(selected_cases)
    dir_map = technique_dir_map(list(full_grouped))

    cases_to_run = selected_cases
    resume: ResumeFromEvtx | None = None
    if resume_from_batch is not None:
        cases_to_run, resume = select_cases_after_last_evtx(selected_cases, resume_from_batch, dir_map)

    return CaseOrderPlan(
        config_path=config_path,
        selected_count=len(selected_cases),
        technique_count=len(full_grouped),
        cases=execution_order(cases_to_run),
        dir_map=dir_map,
        resume=resume,
    )


def case_to_row(run_order: int, case: TargetCase, dir_map: dict[str, str]) -> dict[str, object]:
    """Convert a TargetCase into one output row."""
    return {
        "run_order": run_order,
        "input_index": case.index,
        "test_id": case.test_id,
        "technique_id": case.technique_id,
        "mutation": case.mutation,
        "shell": case.shell,
        "timeout_seconds": case.timeout_seconds,
        "target_rule": case.target_rule,
        "evtx_name": evtx_name_for_case(case, dir_map),
        "target_commandline": case.target_commandline,
    }


def rows_for_plan(plan: CaseOrderPlan) -> list[dict[str, object]]:
    """Return serializable rows for an order plan."""
    return [case_to_row(position, case, plan.dir_map) for position, case in enumerate(plan.cases, start=1)]


def json_payload(plan: CaseOrderPlan, rows: list[dict[str, object]], args: argparse.Namespace) -> dict[str, Any]:
    """Return the JSON payload for an order plan."""
    resume = plan.resume
    return {
        "config": str(plan.config_path),
        "offset": args.offset,
        "limit": args.limit,
        "selected_count": plan.selected_count,
        "technique_count": plan.technique_count,
        "run_count": len(rows),
        "resume_from_batch": str(resume.batch_dir) if resume else None,
        "resume_after_evtx": str(resume.last_evtx_path) if resume and resume.last_evtx_path else None,
        "resume_after_test_id": resume.last_case.test_id if resume and resume.last_case else None,
        "resume_skipped_count": resume.skipped_count if resume else 0,
        "resume_ignored_evtx_count": resume.ignored_evtx_count if resume else 0,
        "cases": rows,
    }


def format_csv(rows: list[dict[str, object]]) -> str:
    """Format rows as CSV text."""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=FIELDNAMES, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def truncate_text(value: object, max_width: int) -> str:
    """Convert a value to text and truncate it for table display."""
    text = "" if value is None else str(value)
    if max_width <= 0 or len(text) <= max_width:
        return text
    if max_width <= 3:
        return text[:max_width]
    return text[: max_width - 3] + "..."


def format_table(plan: CaseOrderPlan, rows: list[dict[str, object]], args: argparse.Namespace) -> str:
    """Format rows as a readable table."""
    display_rows: list[dict[str, str]] = []
    for row in rows:
        display_row = {field: str(row[field] or "") for field in FIELDNAMES}
        display_row["target_commandline"] = truncate_text(
            row["target_commandline"],
            args.max_commandline_width,
        )
        display_rows.append(display_row)

    columns = [
        ("run_order", "run"),
        ("input_index", "input"),
        ("technique_id", "technique"),
        ("test_id", "test_id"),
        ("mutation", "mutation"),
        ("shell", "shell"),
        ("timeout_seconds", "timeout"),
        ("target_rule", "target_rule"),
        ("evtx_name", "evtx_name"),
        ("target_commandline", "target_commandline"),
    ]

    widths = {
        field: max([len(header), *(len(row[field]) for row in display_rows)])
        for field, header in columns
    }
    lines = [
        f"Config: {plan.config_path}",
        f"Selected: {plan.selected_count} case(s) in {plan.technique_count} technique group(s)",
        f"Will execute: {len(rows)} case(s)",
    ]
    if plan.resume:
        resume = plan.resume
        lines.extend(
            [
                f"Resume batch: {resume.batch_dir}",
                f"Resume after EVTX: {resume.last_evtx_path or '<none>'}",
                f"Resume after test_id: {resume.last_case.test_id if resume.last_case else '<none>'}",
                f"Resume skipped: {resume.skipped_count} case(s)",
                f"Resume ignored EVTX: {resume.ignored_evtx_count} file(s)",
            ]
        )
    lines.append("")
    lines.append("  ".join(header.ljust(widths[field]) for field, header in columns))
    lines.append("  ".join("-" * widths[field] for field, _header in columns))
    for row in display_rows:
        lines.append("  ".join(row[field].ljust(widths[field]) for field, _header in columns))
    return "\n".join(lines) + "\n"


def render_output(plan: CaseOrderPlan, rows: list[dict[str, object]], args: argparse.Namespace) -> str:
    """Render the selected output format."""
    if args.format == "json":
        return json.dumps(json_payload(plan, rows, args), indent=2, ensure_ascii=False) + "\n"
    if args.format == "csv":
        return format_csv(rows)
    return format_table(plan, rows, args)


def default_output_path(base_dir: Path, config_path: Path, output_format: str) -> Path:
    """Return the default file path used for case-order output."""
    extensions = {
        "table": "txt",
        "json": "json",
        "csv": "csv",
    }
    extension = extensions.get(output_format, "txt")
    return base_dir / "output" / "test_case_order" / f"{safe_name(config_path.stem)}.{extension}"


def run(args: argparse.Namespace) -> int:
    """Write or print the execution order."""
    base_dir, config_path, resume_from_batch = resolve_cli_paths(args)
    plan = build_order_plan(config_path, args.offset, args.limit, resume_from_batch)
    rows = rows_for_plan(plan)
    output_text = render_output(plan, rows, args)

    if args.stdout:
        print(output_text, end="")
        return 0

    output_path = _required_path(args.output, base_dir, "--output") if args.output else default_output_path(
        base_dir,
        config_path,
        args.format,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(output_text, encoding="utf-8")
    print(f"[+] Wrote case order: {output_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse CLI args and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
