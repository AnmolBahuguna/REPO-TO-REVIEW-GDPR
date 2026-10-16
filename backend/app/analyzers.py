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
)
ROUTE_RE = re.compile(
    r"(?i)(?:@(?:app|router|bp|api)\.(?:get|post|put|patch|delete|route)|"
    r"\.(?:get|post|put|patch|delete)\s*\(\s*['\"`/]|@(Get|Post|Put|Patch|Delete)Mapping|"
    r"@RequestMapping)"
)
SQL_INTERPOLATION_RE = re.compile(
    r"(?i)(?:execute|executemany|query)\s*\([^)]*(?:f['\"]|%s?['\"]\s*%|\.format\s*\(|\+\s*\w+|`[^`]*\$\{)"
)
BROAD_QUERY_RE = re.compile(
    r"(?i)(?:\.query\s*\([^)]*\)\s*\.all\s*\(|\.all\s*\(\s*\)|\.find\s*\(\s*\{\s*\}\s*\)|"
    r"fetchall\s*\(\s*\)|SELECT\s+\*\s+FROM)"
)

PRIVACY_RULE_IDS = ("PRIVACY.PERSONAL_DATA_FIELD", "PRIVACY.SENSITIVE_DATA_FIELD")


def redact_evidence(source: str) -> str:
    value = source.strip()
    value = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*", "Bearer [REDACTED]", value)
    value = re.sub(r"(?i)(password|passwd|secret|api[-_]?key|access[-_]?token|private[-_]?key)\s*([=:])\s*(['\"`])[^'\"`]*\3", r"\1\2[REDACTED]", value)
    value = re.sub(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", "[PAN REDACTED]", value, flags=re.IGNORECASE)
    value = re.sub(r"\b\d{4}\s?\d{4}\s?\d{4}\b", "[IDENTIFIER REDACTED]", value)
    value = re.sub(r"\b[A-Z]{2}\s?\d{6}[A-Z]\b", "[IDENTIFIER REDACTED]", value, flags=re.IGNORECASE)
    value = re.sub(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[EMAIL REDACTED]", value, flags=re.IGNORECASE)
    value = re.sub(r"(?<!\w)(?:\+?\d[\d ()-]{7,}\d)(?!\w)", "[PHONE REDACTED]", value)
    return value[:500]


def _line_for_offset(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _finding(
    rule_id: str,
    file_path: str,
    source: str,
    start: int,
    end: int,
    jurisdiction: str,
    **overrides: Any,
) -> dict[str, Any]:
    line_start = _line_for_offset(source, start)
    line_end = max(line_start, _line_for_offset(source, max(start, end - 1)))
    lines = source.splitlines()
    snippet = "\n".join(lines[max(0, line_start - 2): min(len(lines), line_end + 1)])
    return build_finding(
        rule_id,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        evidence=redact_evidence(snippet),
        jurisdiction=jurisdiction,
        **overrides,
    )


def _matching_identifiers(source: str) -> list[tuple[int, int, str, str]]:
    matches: list[tuple[int, int, str, str]] = []
    for match in re.finditer(r"[A-Za-z_$][A-Za-z0-9_$-]*", source):
        token = match.group()
        normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", token).lower()
        if PERSONAL_RE.search(normalized):
            matches.append((match.start(), match.end(), normalized, "personal_data_indicator"))
        if SENSITIVE_RE.search(normalized):
            matches.append((match.start(), match.end(), normalized, "sensitive_data_indicator"))
    return matches


def _is_model_field(node: ast.AST) -> bool:
    if isinstance(node, (ast.Name, ast.arg, ast.Attribute)):
        return bool(PERSONAL_RE.search(ast.unparse(node)))
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return bool(PERSONAL_RE.search(node.value))
    return False


def _is_sensitive_field(node: ast.AST) -> bool:
    if isinstance(node, (ast.Name, ast.arg, ast.Attribute)):
        return bool(SENSITIVE_RE.search(ast.unparse(node)))
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return bool(SENSITIVE_RE.search(node.value))
    return False


def _python_analysis(file_path: str, source: str, jurisdictions: list[str]) -> tuple[list[dict[str, Any]], str]:
    try:
        root = ast.parse(source)
    except SyntaxError:
        return [], "parse_error"

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    dynamic_sql_sources: dict[str, str] = {}
    for assignment in ast.walk(root):
        if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
            continue
        value = assignment.value
        if value is None:
            continue
        rendered_value = ast.unparse(value)
        interpolated = isinstance(value, (ast.JoinedStr, ast.BinOp)) or (
            isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) and value.func.attr == "format"
        )
        if not SQL_RE.search(rendered_value) or not interpolated:
            continue
        targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
        dynamic_sql_sources.update(
            {target.id: rendered_value for target in targets if isinstance(target, ast.Name)}
        )

    def add(rule_id: str, node: ast.AST, jurisdiction: str, **kwargs: Any) -> None:
        line = getattr(node, "lineno", 1)
        key = (rule_id, line, jurisdiction)
        if key in seen:
            return
        seen.add(key)
        start = max(0, getattr(node, "col_offset", 0))
        lines = source.splitlines(keepends=True)
        prefix = sum(len(value) for value in lines[:line - 1])
        findings.append(_finding(
            rule_id,
            file_path,
            source,
            prefix + start,
            prefix + len(lines[line - 1]) if line <= len(lines) else prefix + start + 1,
            jurisdiction,
            **kwargs,
        ))

    personal_nodes: list[ast.AST] = []
    sensitive_nodes: list[ast.AST] = []
