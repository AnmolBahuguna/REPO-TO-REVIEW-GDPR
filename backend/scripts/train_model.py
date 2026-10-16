from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.datasets import load_dataset
from app.ml_pipeline import train_and_save


def main() -> int:
    parser = argparse.ArgumentParser(description="Train the code triage model with group-safe validation and test splits.")
    parser.add_argument("dataset", type=Path, help="Labeled .jsonl or .csv dataset")
    parser.add_argument("--model", type=Path, default=ROOT / "artifacts" / "privacy_triage.joblib")
    args = parser.parse_args()
    try:
        examples = load_dataset(args.dataset)
        metadata = train_and_save(examples, args.dataset, args.model)
    except (FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))
        return 2
    print(json.dumps({"model_path": str(args.model), **metadata}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
