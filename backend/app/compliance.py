from __future__ import annotations

from typing import Any

from .catalog import legacy_finding


def build_finding(
    title: str,
    severity: str,
    category: str,
    evidence: list[str],
    jurisdiction: str,
    recommendation: str | None = None,
) -> dict[str, Any]:
    return legacy_finding(title, severity, category, evidence, jurisdiction, recommendation)
