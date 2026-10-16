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
        "title": rule["title"],
        "category": rule["category"],
        "severity": rule["severity"],
        "confidence": round(confidence if confidence is not None else rule["confidence"], 2),
        "status": status or rule["status"],
        "file_path": file_path,
        "line_start": line_start,
        "line_end": line_end,
        "evidence": evidence,
        "reasoning": reasoning or rule["reasoning"],
        "jurisdiction": jurisdiction,
        "relevant_legal_reference": legal_reference,
        "recommended_fix": recommended_fix or rule["recommended_fix"],
        "false_positive_notes": false_positive_notes or rule["false_positive_notes"],
        "evidence_kind": evidence_kind or "code",
        "explanation": None,
    }


def legacy_finding(title: str, severity: str, category: str, evidence: list[str], jurisdiction: str, recommendation: str | None = None) -> dict[str, Any]:
    category_id = {
        "Personal data": "PRIVACY.PERSONAL_DATA_FIELD",
        "Sensitive data": "PRIVACY.SENSITIVE_DATA_FIELD",
        "Logging risk": "PRIVACY.SENSITIVE_LOGGING",
        "Access control": "API.UNGUARDED_PERSONAL_ROUTE",
        "Processing risk": "SECURITY.SQL_INJECTION",
    }.get(category, "PRIVACY.PERSONAL_DATA_FIELD")
    location, _, message = evidence[0].partition(" - ") if evidence else ("", "", title)
    file_path, _, line_value = location.rpartition(":")
    try:
        line = max(1, int(line_value))
    except ValueError:
        file_path, line = "", 1
    legacy = build_finding(
        category_id,
        file_path=file_path,
        line_start=line,
        line_end=line,
        evidence=message or title,
        jurisdiction=jurisdiction,
        confidence=None,
        status="requires_manual_review" if category_id.startswith("PRIVACY") else None,
        recommended_fix=recommendation,
        evidence_kind="legacy",
    )
    legal_basis = {
        ("Personal data", "UK GDPR"): "UK GDPR Articles 5 and 25 (potential relevance; human review required)",
        ("Sensitive data", "UK GDPR"): "UK GDPR Article 9 (potential relevance; human review required)",
        ("Logging risk", "UK GDPR"): "UK GDPR Article 32 (potential relevance; human review required)",
    }.get((category, jurisdiction), "Potentially relevant requirements require current human review.")
    legacy.update(
        title=title,
        severity=severity,
        category=category,
        evidence=evidence,
        legal_basis=legal_basis,
        recommendation=recommendation or legacy["recommended_fix"],
    )
    return legacy
