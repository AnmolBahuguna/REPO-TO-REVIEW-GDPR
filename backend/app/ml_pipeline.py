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

    # Validation is reported for iteration; final test is reported once and never used to fit.
    validation_metrics = _metrics([item.label for item in validation], model.predict([item.code for item in validation]).tolist())
    test_metrics = _metrics([item.label for item in held_out], model.predict([item.code for item in held_out]).tolist())
    # Refit the deployable model on all development data after the test score is fixed.
    development = train + validation
    model.fit([item.code for item in development], [item.label for item in development])
    model_path.parent.mkdir(parents=True, exist_ok=True)
    dataset_hash = hashlib.sha256(dataset_path.read_bytes()).hexdigest()
    bundle = {
        "model": model,
        "metadata": {
            "model_version": "1.0.0",
            "dataset_sha256": dataset_hash,
            "dataset_records": len(examples),
            "train_records": len(train),
            "validation_records": len(validation),
            "test_records": len(held_out),
            "development_groups": len({item.group_id for item in development}),
            "test_groups": len({item.group_id for item in held_out}),
            "labels": list(LABELS),
            "features": "word and character TF-IDF n-grams; balanced logistic regression",
            "split": "grouped 60/20/20; group IDs never cross splits",
            "seed": SEED,
            "metrics": {"validation": validation_metrics, "test": test_metrics},
            "caveat": "Metrics reflect only this supplied dataset; they are not legal validation or production accuracy.",
        },
    }
    joblib.dump(bundle, model_path)
    return bundle["metadata"]


def load_model(model_path: str | Path) -> dict[str, Any] | None:
    path = Path(model_path)
    if not path.is_file():
        return None
    return joblib.load(path)


def predict_text(bundle: dict[str, Any], code: str) -> dict[str, Any]:
    model: Pipeline = bundle["model"]
    probabilities = model.predict_proba([code])[0]
    classes = model.named_steps["classifier"].classes_
    ranked = sorted(zip(classes, probabilities), key=lambda item: float(item[1]), reverse=True)
    return {
        "label": str(ranked[0][0]),
        "top_class_score": float(ranked[0][1]),
        "probabilities": {str(label): float(probability) for label, probability in zip(classes, probabilities)},
        "model_version": bundle["metadata"]["model_version"],
        "caveat": "Model probabilities are uncalibrated triage scores; review code and rule-based findings. This is not a legal determination.",
    }


def predict_many(bundle: dict[str, Any], texts: list[str]) -> list[dict[str, Any]]:
    if not texts:
        return []
    model: Pipeline = bundle["model"]
    probabilities = model.predict_proba(texts)
    classes = model.named_steps["classifier"].classes_
    predictions = []
    for row in probabilities:
        ranked = sorted(zip(classes, row), key=lambda item: float(item[1]), reverse=True)
        predictions.append({
            "label": str(ranked[0][0]),
            "top_class_score": float(ranked[0][1]),
            "probabilities": {str(label): float(probability) for label, probability in zip(classes, row)},
            "model_version": bundle["metadata"]["model_version"],
