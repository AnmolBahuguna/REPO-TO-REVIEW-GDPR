"""Train and load a grouped, text-based triage model for labeled code examples."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupShuffleSplit

from .datasets import DatasetExample

SEED = 42
LABELS = ("negative", "positive", "requires_context")


def _partition(examples: list[DatasetExample], test_size: float, seed: int) -> tuple[list[int], list[int]]:
    groups = [item.group_id for item in examples]
    labels = {item.label for item in examples}
    splitter = GroupShuffleSplit(n_splits=100, test_size=test_size, random_state=seed)
    for train_idx, held_idx in splitter.split(examples, groups=groups):
        if ({examples[i].label for i in train_idx} == labels
                and {examples[i].label for i in held_idx} == labels):
            return list(train_idx), list(held_idx)
    raise ValueError(
        "Cannot make a group-safe split containing every label on both sides. "
        "Add more distinct group_id values for each label (at least 3 per label is recommended)."
    )


def grouped_split(examples: list[DatasetExample]) -> tuple[list[int], list[int], list[int]]:
    groups_by_label = {
        label: {item.group_id for item in examples if item.label == label}
        for label in LABELS
    }
    missing = [label for label, groups in groups_by_label.items() if not groups]
    scarce = [label for label, groups in groups_by_label.items() if 0 < len(groups) < 3]
    if missing or scarce:
        raise ValueError(
            "Training requires positive, negative, and requires_context labels with at least 3 distinct "
            f"groups per label. Missing: {missing}; too few groups: {scarce}."
        )
    if len({item.group_id for item in examples}) < 15:
        raise ValueError("At least 15 distinct groups are required for group-safe train/validation/test splits.")
    remaining_idx, test_idx = _partition(examples, 0.2, SEED)
    remaining = [examples[i] for i in remaining_idx]
    train_local, validation_local = _partition(remaining, 0.25, SEED + 1)
    train_idx = [remaining_idx[i] for i in train_local]
    validation_idx = [remaining_idx[i] for i in validation_local]
    return train_idx, validation_idx, test_idx


def make_model() -> Pipeline:
    features = FeatureUnion([
        ("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=1, max_features=100_000)),
        ("char", TfidfVectorizer(analyzer="char", ngram_range=(2, 5), min_df=1, max_features=150_000)),
    ])
    return Pipeline([
        ("features", features),
        ("classifier", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=SEED)),
    ])


def _metrics(actual: list[str], predicted: list[str]) -> dict[str, Any]:
    confusion = {label: {guess: 0 for guess in LABELS} for label in LABELS}
    for expected, guess in zip(actual, predicted):
        confusion[expected][guess] += 1
    per_label = {}
    for label in LABELS:
        tp = confusion[label][label]
        fp = sum(confusion[other][label] for other in LABELS if other != label)
        fn = sum(confusion[label][other] for other in LABELS if other != label)
        per_label[label] = {
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
            "support": sum(confusion[label].values()),
        }
    total = sum(sum(row.values()) for row in confusion.values())
    accuracy = sum(confusion[label][label] for label in LABELS) / total if total else None
    macro_f1 = sum(value["f1"] or 0 for value in per_label.values()) / len(LABELS)
    return {"accuracy": accuracy, "macro_f1": macro_f1, "per_label": per_label, "confusion_matrix": confusion}


def train_and_save(examples: list[DatasetExample], dataset_path: Path, model_path: Path) -> dict[str, Any]:
    train_idx, validation_idx, test_idx = grouped_split(examples)
    train = [examples[i] for i in train_idx]
    validation = [examples[i] for i in validation_idx]
    held_out = [examples[i] for i in test_idx]
    model = make_model()
    model.fit([item.code for item in train], [item.label for item in train])

