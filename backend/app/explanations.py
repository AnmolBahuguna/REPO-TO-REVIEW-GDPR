from __future__ import annotations

import json
import os
import re
from typing import Any

import httpx

from .catalog import RULES_BY_ID

MAX_EXPLANATIONS = 8
MAX_SNIPPET_LENGTH = 350
MAX_OUTPUT_LENGTH = 600
UNSUPPORTED_CLAIM_RE = re.compile(
    r"(?i)\b(?:article\s+\d+|section\s+\d+|compliant|compliance certified|illegal|unlawful|"
    r"violates? (?:the )?(?:gdpr|dpdp)|breach of (?:the )?(?:gdpr|dpdp))\b"
)


def _parse_explanation(content: str, rule_ids: set[str]) -> dict[str, dict[str, str]]:
    parsed = json.loads(content)
    if not isinstance(parsed, dict) or set(parsed) != {"findings"} or not isinstance(parsed["findings"], list):
        raise ValueError("The explanation response did not match the required JSON schema.")
    result: dict[str, dict[str, str]] = {}
    for item in parsed["findings"]:
        if not isinstance(item, dict) or set(item) != {"rule_id", "explanation", "recommended_fix"}:
            raise ValueError("The explanation response included an invalid finding object.")
        rule_id = item["rule_id"]
        explanation = item["explanation"]
        recommended_fix = item["recommended_fix"]
        if (
            rule_id not in rule_ids
            or not isinstance(explanation, str)
            or not isinstance(recommended_fix, str)
            or not explanation.strip()
            or not recommended_fix.strip()
            or len(explanation) > MAX_OUTPUT_LENGTH
            or len(recommended_fix) > MAX_OUTPUT_LENGTH
            or UNSUPPORTED_CLAIM_RE.search(explanation)
            or UNSUPPORTED_CLAIM_RE.search(recommended_fix)
        ):
            raise ValueError("The explanation response contained an unsupported claim or invalid value.")
        result[rule_id] = {
            "explanation": explanation.strip(),
            "recommended_fix": recommended_fix.strip(),
        }
    return result


async def enrich_findings(findings: list[dict[str, Any]]) -> tuple[int, str | None]:
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        return 0, "OpenRouter explanations were requested but OPENROUTER_API_KEY is not configured; deterministic scanner guidance is shown."
    if not findings:
