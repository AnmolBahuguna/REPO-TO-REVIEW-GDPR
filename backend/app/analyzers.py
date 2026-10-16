from __future__ import annotations

import ast
import re
from typing import Any

from tree_sitter import Parser
from tree_sitter_language_pack import get_parser

from .catalog import build_finding

PERSONAL_RE = re.compile(
    r"(?i)(?:e[-_]?mail|phone|mobile|first[-_]?name|last[-_]?name|full[-_]?name|"
    r"home[-_]?address|address|postcode|postal[-_]?code|date[-_]?of[-_]?birth|"
    r"\bdob\b|aadhaar|aadhar|\bpan\b|national[-_]?insurance|\bni[-_]?number\b|"
    r"passport|ssn|social[-_]?security|ip[-_]?address|user[-_]?id|customer[-_]?id|"
    r"account[-_]?id|device[-_]?id|emailaddress)"
)
PERSONAL_VALUE_PATTERNS = {
    "email": re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
    "phone": re.compile(r"(?<!\w)(?:\+?\d[\d ()-]{7,}\d)(?!\w)"),
    "PAN": re.compile(r"(?i)\b[A-Z]{5}\d{4}[A-Z]\b"),
    "Aadhaar-like identifier": re.compile(r"(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\d)"),
    "UK National Insurance-like identifier": re.compile(r"(?i)\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b"),
}
SENSITIVE_RE = re.compile(
    r"(?i)(?:health|medical|diagnos|medication|biometric|fingerprint|faceprint|"
    r"religion|ethnicity|disability|pregnancy|genetic|sexual[-_]?orientation)"
)
SECRET_NAME_RE = re.compile(r"(?i)(?:password|passwd|secret|api[-_]?key|access[-_]?token|private[-_]?key)")
PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:|x+|none|null|placeholder|changeme|change[-_ ]?me|example|sample|"
    r"your[-_ ].*|test(?:ing)?|dummy|fake|redacted|<.*>|\$\{.*\}|process\.env\..*|os\.getenv\(.*\))$"
)
SQL_RE = re.compile(r"(?i)\b(?:select\b.+\bfrom\b|insert\s+into|update\b.+\bset\b|delete\s+from)\b")
LOG_CALL_RE = re.compile(
    r"(?i)(?:logger|logging|console)\s*\.\s*(?:log|info|warning|warn|error|debug|exception)\s*\(|"
    r"(?<![A-Za-z0-9_])(?:print|pprint)\s*\("
)
OUTBOUND_RE = re.compile(
    r"(?i)(?:requests|httpx|axios)\s*\.\s*(?:post|put|patch|request)\s*\(|"
    r"(?<![A-Za-z0-9_])fetch\s*\("
)
AUTH_RE = re.compile(
    r"(?i)(?:login[-_]?required|auth[-_]?required|requires?[-_]?auth|authmiddleware|"
    r"verifytoken|checkauth|authenticated|authorization|"
    r"Depends\s*\(\s*(?:get_current_user|current_user|require_user)|"
    r"jwt_required|permission_classes|isAuthenticated|authorize)"
