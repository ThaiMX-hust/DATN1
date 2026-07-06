"""Command-line interface for running Sigma rule evaluation batches."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .models import RunnerConfig
from .path_config import DEFAULT_OUTPUT_DIR, DEFAULT_RULES_DIR, load_path_config
from .runner import run_target_batch
from .utils import resolve_path


def positive_int(value: str) -> int:
    """Parse a positive integer CLI argument."""
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(description="Run target command lines, export Sysmon EVTX, and scan with Zircolite.")
    parser.add_argument("--path-config", help="Project path JSON file. Defaults to config/paths.json when it exists.")
    parser.add_argument("--config", help="Input JSON file. Overrides input_config in the path config.")
    parser.add_argument("--output-dir", help="Output folder. Overrides output_dir in the path config.")
    parser.add_argument("--base-dir", default=None, help="Base folder for CLI relative paths.")
    parser.add_argument(
        "--resume-from-batch",
        help="Existing target_commandline_tests batch folder; run cases after the newest matching EVTX.",
    )
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--execute", action="store_true", help="Run command lines. Without this, only dry-run.")
    parser.add_argument("--timeout-seconds", type=positive_int, default=2)
    parser.add_argument("--flush-wait-seconds", type=float, default=1.0)
    parser.add_argument("--record-read-timeout-seconds", type=int, default=15)
    parser.add_argument("--export-timeout-seconds", type=int, default=60)
    parser.add_argument("--process-tree-quiescence-seconds", type=float, default=5.0)
    parser.add_argument("--process-tree-max-wait-seconds", type=float, default=60.0)
    parser.add_argument("--no-zircolite", action="store_true")
    parser.add_argument("--zircolite-path", help="Path to zircolite.py or Zircolite executable.")
    parser.add_argument("--python-exe", help="Python executable for zircolite.py.")
    parser.add_argument("--ruleset", help="Path to the Zircolite ruleset JSON.")
    parser.add_argument("--rules-dir", help="Local Sigma rules folder used to resolve target rule metadata.")
    parser.add_argument("--zircolite-config", help="Optional Zircolite config file.")
    parser.add_argument("--zircolite-timeout-seconds", type=int, default=180)
    parser.add_argument("--save-debug-artifacts", action="store_true")
    return parser


def _required_path(value: str | Path | None, base_dir: Path, option_name: str) -> Path:
    """Resolve a required path option relative to the configured base directory."""
    path = resolve_path(value, base_dir)
    if path is None:
        raise ValueError(f"{option_name} is required")
    return path


def _configured_value(cli_value: str | None, config_value: str | Path | None) -> str | Path | None:
    """Return a CLI value when supplied, otherwise return the config value."""
    return cli_value if cli_value not in (None, "") else config_value


def config_from_args(args: argparse.Namespace) -> RunnerConfig:
    """Create a RunnerConfig from parsed CLI arguments."""
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
        resume_from_batch=resolve_path(args.resume_from_batch, base_dir),
        offset=args.offset,
        limit=args.limit,
        execute=args.execute,
        timeout_seconds=args.timeout_seconds,
        flush_wait_seconds=args.flush_wait_seconds,
        record_read_timeout_seconds=args.record_read_timeout_seconds,
        export_timeout_seconds=args.export_timeout_seconds,
        process_tree_quiescence_seconds=args.process_tree_quiescence_seconds,
        process_tree_max_wait_seconds=args.process_tree_max_wait_seconds,
        no_zircolite=args.no_zircolite,
        zircolite_path=resolve_path(_configured_value(args.zircolite_path, path_config.zircolite_path), base_dir),
        python_exe=args.python_exe or path_config.python_exe,
        ruleset=resolve_path(_configured_value(args.ruleset, path_config.ruleset), base_dir),
        zircolite_config=resolve_path(
            _configured_value(args.zircolite_config, path_config.zircolite_config),
            base_dir,
        ),
        zircolite_timeout_seconds=args.zircolite_timeout_seconds,
        save_debug_artifacts=args.save_debug_artifacts,
    )


def run(args: argparse.Namespace) -> int:
    """Run one batch using parsed CLI arguments."""
    return run_target_batch(config_from_args(args))


def main(argv: list[str] | None = None) -> int:
    """Parse command-line arguments and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
