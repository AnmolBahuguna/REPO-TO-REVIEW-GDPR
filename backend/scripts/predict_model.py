from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.ml_pipeline import load_model, predict_text


def main() -> int:
    parser = argparse.ArgumentParser(description="Classify a code sample with a trained triage model.")
    parser.add_argument("source", type=Path, help="UTF-8 source file or snippet")
    parser.add_argument("--model", type=Path, default=ROOT / "artifacts" / "privacy_triage.joblib")
    args = parser.parse_args()
    try:
        bundle = load_model(args.model)
        if bundle is None:
            parser.error(f"Trained model not found: {args.model}. Run train_model.py first.")
            return 2
        code = args.source.read_text(encoding="utf-8")
        print(json.dumps(predict_text(bundle, code), indent=2, sort_keys=True))
    except (OSError, UnicodeError, KeyError, ValueError) as exc:
        parser.error(str(exc))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
