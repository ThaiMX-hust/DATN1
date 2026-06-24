"""Create workbook copies containing only rules shared by all three models.

This is the alignment step after ``filter_rules_without_commandlines.py``.
It preserves the exact common rule universe across Qwen32B, Qwen14B and
Gemini, so the total rule count and the rule identities are identical.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from filter_rules_without_commandlines import collect_evidence, write_filtered_workbook


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODEL_WORKBOOKS = {
    "qwen32b": PROJECT_ROOT / "results" / "filtered" / "qwen32b" / "qwen32b_res_filtered.xlsx",
    "qwen14b": PROJECT_ROOT
    / "results"
    / "filtered"
    / "qwen14b"
    / "qwen14b_res_by_tactic_filtered.xlsx",
    "gemini": PROJECT_ROOT / "results" / "filtered" / "gemini" / "gemini_res_filtered.xlsx",
}


def write_audit(destination: Path, evidence_by_model: dict, removed_by_model: dict[str, set[str]]) -> None:
    """Write the non-common rules removed during the alignment step."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8-sig", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "model_removed_from",
                "rule_id",
                "rule_name",
                "tactics_removed_from",
                "source_rows_removed",
            ],
            lineterminator="\n",
        )
        writer.writeheader()
        for model in MODEL_WORKBOOKS:
            for key in sorted(removed_by_model[model]):
                item = evidence_by_model[model][key]
                writer.writerow(
                    {
                        "model_removed_from": model,
                        "rule_id": item.rule_id,
                        "rule_name": item.rule_name,
                        "tactics_removed_from": "; ".join(sorted(item.tactics)),
                        "source_rows_removed": item.source_rows,
                    }
                )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=PROJECT_ROOT / "results" / "filtered_common",
        help="Directory for the aligned workbook copies (default: results/filtered_common).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    sources = {model: path.resolve() for model, path in MODEL_WORKBOOKS.items()}
    missing = [str(path) for path in sources.values() if not path.is_file()]
    if missing:
        raise FileNotFoundError("Missing filtered source workbooks:\n" + "\n".join(missing))

    evidence_by_model = {model: collect_evidence(path) for model, path in sources.items()}
    common_keys = set.intersection(*(set(evidence) for evidence in evidence_by_model.values()))
    removed_by_model = {
        model: set(evidence) - common_keys for model, evidence in evidence_by_model.items()
    }
    write_audit(args.output_root / "removed_non_common_rules_audit.csv", evidence_by_model, removed_by_model)

    for model, source in sources.items():
        destination = args.output_root / model / f"{source.stem}_common.xlsx"
        deleted_rows = write_filtered_workbook(source, destination, removed_by_model[model])
        print(
            f"{model}: kept {len(common_keys)} common rules; removed "
            f"{len(removed_by_model[model])} rules / {sum(deleted_rows.values())} rows -> {destination}"
        )
    print(f"Common rule set: {len(common_keys)} rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
