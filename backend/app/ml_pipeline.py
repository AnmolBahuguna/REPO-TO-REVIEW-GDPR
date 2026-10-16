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
