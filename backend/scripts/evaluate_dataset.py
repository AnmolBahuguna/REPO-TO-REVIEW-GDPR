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
    extension = {
        "python": "py",
        "javascript": "js",
        "js": "js",
        "typescript": "ts",
        "ts": "ts",
        "tsx": "tsx",
        "sql": "sql",
        "json": "json",
        "yaml": "yaml",
        "yml": "yml",
    }.get(example.language)
    if not extension:
        return "unsupported", set()
    findings, _, parse_status = analyze_source_file(
        f"eval.{extension}",
        example.code,
        ["UK GDPR", "India DPDP"],
    )
    if parse_status != "parsed":
        return parse_status, set()
    if not findings:
        return "negative", set()
    if any(
        finding["status"] == "potential_issue"
        or finding["rule_id"] in {"PRIVACY.PERSONAL_DATA_FIELD", "PRIVACY.SENSITIVE_DATA_FIELD"}
        for finding in findings
    ):
        return "positive", {finding["category"] for finding in findings}
    return "requires_context", {finding["category"] for finding in findings}


def _binary_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(row["actual"] == "positive" and row["predicted"] == "positive" for row in rows)
    fp = sum(row["actual"] == "negative" and row["predicted"] != "negative" for row in rows)
    tn = sum(row["actual"] == "negative" and row["predicted"] == "negative" for row in rows)
    fn = sum(row["actual"] == "positive" and row["predicted"] == "negative" for row in rows)
    return {
        "examples": len(rows),
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "false_negative_rate": fn / (fn + tp) if fn + tp else None,
    }


def evaluate(path: Path) -> dict[str, Any]:
    examples = load_dataset(path)
    train, held_out = _split(examples)
    rows: list[dict[str, Any]] = []
    excluded_context = 0
    context_correct = 0
    unsupported = 0
    for example in held_out:
        predicted, detected_categories = _prediction(example)
        if predicted == "unsupported":
            unsupported += 1
            continue
        if predicted == "parse_error":
            unsupported += 1
            continue
        if example.label == "requires_context":
