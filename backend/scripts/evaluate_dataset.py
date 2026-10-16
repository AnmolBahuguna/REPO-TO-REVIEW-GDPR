from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.analyzers import analyze_source_file
from app.datasets import DatasetExample, load_dataset, validate_dataset

SEED = "privacy-lens-evaluation-v1"


def _split(examples: list[DatasetExample]) -> tuple[list[DatasetExample], list[DatasetExample]]:
    groups = sorted(
        {example.group_id for example in examples},
        key=lambda group: hashlib.sha256(f"{SEED}:{group}".encode()).hexdigest(),
    )
    if len(groups) < 2:
        raise ValueError("At least two distinct variant groups are required for a held-out evaluation.")
    test_count = max(1, round(len(groups) * 0.2))
    test_count = min(test_count, len(groups) - 1)
    test_groups = set(groups[:test_count])
    train = [example for example in examples if example.group_id not in test_groups]
    test = [example for example in examples if example.group_id in test_groups]
    return train, test


def _prediction(example: DatasetExample) -> tuple[str, set[str]]:
