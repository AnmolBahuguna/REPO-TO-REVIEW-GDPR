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
                    raise ValueError(f"Dataset line {line_number} must contain a JSON object.")
                rows.append(value)
    elif dataset_path.suffix.lower() == ".csv":
        with dataset_path.open(encoding="utf-8-sig", newline="") as dataset_file:
            rows = list(csv.DictReader(dataset_file))
    else:
        raise ValueError("Dataset must be a .jsonl or .csv file.")

    examples: list[DatasetExample] = []
    for index, row in enumerate(rows, start=1):
        code = _get_value(row, CODE_KEYS)
        label = str(_get_value(row, LABEL_KEYS, "")).strip().lower()
        label = {"uncertain": "requires_context", "context": "requires_context"}.get(label, label)
        if not isinstance(code, str) or not code.strip():
            raise ValueError(f"Dataset record {index} is missing non-empty code/snippet text.")
        if label not in VALID_LABELS:
            raise ValueError(f"Dataset record {index} has invalid label {label!r}; expected one of {sorted(VALID_LABELS)}.")
        language = str(_get_value(row, ("language", "lang"), "unknown")).strip().lower()
        category = str(_get_value(row, ("category", "rule", "issue_category"), "unspecified")).strip().lower()
        group_id = str(_get_value(row, ("group_id", "variant_group", "family_id", "source_id"), "")).strip()
        if not group_id:
            # Exact duplicates stay in one split; semantic variants should supply a shared group_id.
            normalized = re.sub(r"\s+", " ", code).strip().lower()
            group_id = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        evidence_value = _get_value(row, ("evidence_lines",), "")
        if isinstance(evidence_value, list):
            evidence_lines = tuple(int(value) for value in evidence_value)
        else:
            evidence_lines = tuple(int(value) for value in re.findall(r"\d+", str(evidence_value)))
        examples.append(DatasetExample(
            index=index, code=code, language=language, label=label, category=category, group_id=group_id,
            sample_id=str(_get_value(row, ("sample_id", "id"), f"sample-{index}")).strip(),
            framework=str(_get_value(row, ("framework",), "unknown")).strip().lower(),
            data_category=str(_get_value(row, ("data_category",), "unspecified")).strip().lower(),
            pattern_type=str(_get_value(row, ("pattern_type",), "unspecified")).strip().lower(),
            evidence_lines=evidence_lines,
            rule_id=str(_get_value(row, ("rule_id",), "")).strip(),
            jurisdiction=str(_get_value(row, ("jurisdiction",), "not_applicable")).strip(),
            severity=str(_get_value(row, ("severity",), "unassigned")).strip().lower(),
            review_notes=str(_get_value(row, ("review_notes",), "")).strip(),
        ))
    return examples


def validate_dataset(path: str | Path) -> dict[str, Any]:
    examples = load_dataset(path)
    return {
        "valid": True,
        "records": len(examples),
        "labels": {label: sum(example.label == label for example in examples) for label in sorted(VALID_LABELS)},
        "languages": sorted({example.language for example in examples}),
        "categories": sorted({example.category for example in examples}),
        "group_ids": len({example.group_id for example in examples}),
        "limitations": [
            "Dataset labels and examples are not legal or production ground truth.",
            "Supply a shared group_id/variant_group for semantically related variants to prevent split leakage.",
            "Review labels with code and product context; uncertain cases belong in requires_context.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a labeled JSONL or CSV scanner dataset.")
    parser.add_argument("dataset", type=Path, help="Path to the dataset file")
    args = parser.parse_args()
    try:
        result = validate_dataset(args.dataset)
    except (FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
