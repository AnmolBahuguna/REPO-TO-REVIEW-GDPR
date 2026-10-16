from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CATALOG_PATH = Path(__file__).resolve().parent.parent / "rules" / "catalog.v1.json"

with CATALOG_PATH.open(encoding="utf-8") as catalog_file:
    CATALOG: dict[str, Any] = json.load(catalog_file)

RULES_BY_ID = {rule["id"]: rule for rule in CATALOG["rules"]}


def build_finding(
    rule_id: str,
    *,
    file_path: str,
    line_start: int,
    line_end: int,
    evidence: str,
    jurisdiction: str,
    confidence: float | None = None,
    status: str | None = None,
    reasoning: str | None = None,
    recommended_fix: str | None = None,
    false_positive_notes: str | None = None,
    evidence_kind: str | None = None,
) -> dict[str, Any]:
    rule = RULES_BY_ID[rule_id]
    jurisdiction_config = CATALOG["jurisdictions"].get(jurisdiction, {})
    legal_reference = None
    references = jurisdiction_config.get("references", {})
    legal_category = {
        "personal_data_indicator": "personal_data_indicator",
        "sensitive_data_indicator": "sensitive_data_indicator",
        "technical_vulnerability": "technical_vulnerability",
    }.get(rule["category"])
    if jurisdiction_config.get("status") == "verified" and legal_category:
        legal_reference = references.get(legal_category)

    return {
        "rule_id": rule_id,
