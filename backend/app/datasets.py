from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

VALID_LABELS = {"positive", "negative", "requires_context"}
CODE_KEYS = ("code", "code_snippet", "snippet", "source", "text")
LABEL_KEYS = ("label", "expected_label", "classification")


@dataclass(frozen=True)
class DatasetExample:
    index: int
    code: str
    language: str
    label: str
    category: str
    group_id: str
    sample_id: str = ""
    framework: str = "unknown"
    data_category: str = "unspecified"
    pattern_type: str = "unspecified"
    evidence_lines: tuple[int, ...] = ()
    rule_id: str = ""
    jurisdiction: str = "not_applicable"
    severity: str = "unassigned"
    review_notes: str = ""


def _get_value(row: dict[str, Any], names: Iterable[str], default: Any = None) -> Any:
    normalized = {str(key).strip().lower(): value for key, value in row.items()}
    return next((normalized[name] for name in names if normalized.get(name) not in (None, "")), default)


def load_dataset(path: str | Path) -> list[DatasetExample]:
    dataset_path = Path(path)
    if not dataset_path.is_file():
        raise FileNotFoundError(f"Dataset file not found: {dataset_path}")

    if dataset_path.suffix.lower() == ".jsonl":
        rows = []
        with dataset_path.open(encoding="utf-8") as dataset_file:
            for line_number, raw_line in enumerate(dataset_file, start=1):
                if not raw_line.strip():
                    continue
                try:
                    value = json.loads(raw_line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSONL at line {line_number}: {exc.msg}") from exc
                if not isinstance(value, dict):
