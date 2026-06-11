"""Rebuild result.csv/results.csv from existing exported EVTX files."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from sigma_rule_evaluator.models import RunnerConfig
from sigma_rule_evaluator.path_config import DEFAULT_OUTPUT_DIR, DEFAULT_RULES_DIR, load_path_config
from sigma_rule_evaluator.rebuild_from_evtx import latest_batch_dir, rebuild_results_from_evtx
from sigma_rule_evaluator.utils import resolve_path


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser for EVTX report rebuilding."""
    parser = argparse.ArgumentParser(
        description="Run Zircolite against already exported EVTX files and rebuild result CSV/JSON reports."
    )
    parser.add_argument(
        "--batch-dir",
        help=(
            "Existing batch folder that contains an evtx subfolder, or an EVTX folder directly. "
            "Defaults to the newest batch under output-dir."
        ),
    )
    parser.add_argument("--path-config", help="Project path JSON file. Defaults to config/paths.json when it exists.")
    parser.add_argument("--config", help="Input JSON file. Overrides input_config in the path config.")
    parser.add_argument("--output-dir", help="Output folder used to auto-detect latest batch.")
    parser.add_argument("--base-dir", default=None, help="Base folder for CLI relative paths.")
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--include-missing",
        action="store_true",
        help="Also include configured cases that do not have a matching EVTX file.",
    )
    parser.add_argument(
        "--csv-name",
        default="results.csv",
        help="Extra CSV filename copied from result.csv. Defaults to results.csv.",
    )
    parser.add_argument("--no-zircolite", action="store_true")
    parser.add_argument("--zircolite-path", help="Path to zircolite.py or Zircolite executable.")
    parser.add_argument("--python-exe", help="Python executable for zircolite.py.")
    parser.add_argument("--ruleset", help="Path to the Zircolite ruleset JSON.")
    parser.add_argument("--rules-dir", help="Local Sigma rules folder used to resolve target rule metadata.")
    parser.add_argument("--zircolite-config", help="Optional Zircolite config file.")
    parser.add_argument("--zircolite-jsononly", action="store_true")
    parser.add_argument("--zircolite-timeout-seconds", type=int, default=180)
    parser.add_argument("--save-debug-artifacts", action="store_true")
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


def config_from_args(args: argparse.Namespace) -> RunnerConfig:
    """Create a RunnerConfig for EVTX-only detection."""
    cwd = Path.cwd()
    path_config = load_path_config(args.path_config, cwd)
    base_dir = Path(args.base_dir).resolve() if args.base_dir else path_config.base_dir or cwd
    return RunnerConfig(
        config_path=_required_path(
            _configured_value(args.config, path_config.input_config),
            base_dir,
            "--config or input_config in path config",
        ),
        output_dir=_required_path(
            _configured_value(args.output_dir, path_config.output_dir) or DEFAULT_OUTPUT_DIR,
            base_dir,
            "--output-dir",
        ),
        base_dir=base_dir,
        path_config_path=path_config.source_path,
        rules_dir=_required_path(
            _configured_value(args.rules_dir, path_config.rules_dir) or DEFAULT_RULES_DIR,
            base_dir,
            "--rules-dir",
        ),
        offset=args.offset,
        limit=args.limit,
        execute=False,
        no_zircolite=args.no_zircolite,
        zircolite_path=resolve_path(_configured_value(args.zircolite_path, path_config.zircolite_path), base_dir),
        python_exe=args.python_exe or path_config.python_exe,
        ruleset=resolve_path(_configured_value(args.ruleset, path_config.ruleset), base_dir),
        zircolite_config=resolve_path(
            _configured_value(args.zircolite_config, path_config.zircolite_config),
            base_dir,
        ),
        zircolite_jsononly=args.zircolite_jsononly,
        zircolite_timeout_seconds=args.zircolite_timeout_seconds,
        save_debug_artifacts=args.save_debug_artifacts,
    )


def run(args: argparse.Namespace) -> int:
    """Run one EVTX-only rebuild."""
    config = config_from_args(args)
    batch_dir = resolve_path(args.batch_dir, config.base_dir) if args.batch_dir else latest_batch_dir(config.output_dir)
    if batch_dir is None:
        raise ValueError("--batch-dir could not be resolved")

    output = rebuild_results_from_evtx(
        config,
        batch_dir,
        include_missing=args.include_missing,
        csv_name=args.csv_name,
    )
    print(f"[+] Batch       : {output.batch_dir}")
    print(f"[+] EVTX        : {output.evtx_dir}")
    print(f"[+] Selected    : {output.selected_count}")
    print(f"[+] Matched EVTX: {output.matched_count}")
    print(f"[+] Missing EVTX: {output.missing_count}")
    print(f"[+] Ignored EVTX: {output.ignored_evtx_count}")
    print(f"[+] Result CSV  : {output.result_csv}")
    if output.requested_csv != output.result_csv:
        print(f"[+] Extra CSV   : {output.requested_csv}")
    print(f"[+] Result JSON : {output.result_json}")
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
