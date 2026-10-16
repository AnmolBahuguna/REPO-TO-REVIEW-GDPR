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
    personal_model_classes: set[str] = set()
    sensitive_model_classes: set[str] = set()
    routes: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in ast.walk(root):
        if isinstance(node, (ast.ClassDef,)):
            bases = " ".join(ast.unparse(base) for base in node.bases).lower()
            decorators = " ".join(ast.unparse(item) for item in node.decorator_list).lower()
            is_model = any(name in bases for name in ("basemodel", "model", "declarativebase", "mappedas")) or "dataclass" in decorators
            if not is_model and re.search(r"\bbase\b", bases):
                is_model = any(
                    isinstance(child, (ast.AnnAssign, ast.Assign))
                    and re.search(r"\b(?:column|mapped|relationship)\b", ast.unparse(child), re.I)
                    for child in node.body
                )
            if is_model:
                for child in node.body:
                    if isinstance(child, (ast.AnnAssign, ast.Assign)):
                        targets = [child.target] if isinstance(child, ast.AnnAssign) else child.targets
                        for target in targets:
                            for subnode in ast.walk(target):
                                if _is_model_field(subnode):
                                    personal_nodes.append(subnode)
                                    personal_model_classes.add(node.name)
                                if _is_sensitive_field(subnode):
                                    sensitive_nodes.append(subnode)
                                    sensitive_model_classes.add(node.name)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            decorator_text = " ".join(ast.unparse(decorator) for decorator in node.decorator_list)
            if ROUTE_RE.search(decorator_text):
                routes.append(node)
            for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
                if _is_model_field(argument):
                    personal_nodes.append(argument)
                if _is_sensitive_field(argument):
                    sensitive_nodes.append(argument)
        if isinstance(node, ast.Dict):
            for key in node.keys:
                if key and _is_model_field(key):
                    personal_nodes.append(key)
                if key and _is_sensitive_field(key):
                    sensitive_nodes.append(key)
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for subnode in ast.walk(target):
                    if isinstance(subnode, (ast.Name, ast.Attribute)):
                        if _is_model_field(subnode):
                            personal_nodes.append(subnode)
                        if _is_sensitive_field(subnode):
                            sensitive_nodes.append(subnode)

    for node in personal_nodes:
        for jurisdiction in jurisdictions:
            add("PRIVACY.PERSONAL_DATA_FIELD", node, jurisdiction)
    for node in sensitive_nodes:
        for jurisdiction in jurisdictions:
            add("PRIVACY.SENSITIVE_DATA_FIELD", node, jurisdiction)

    for node in ast.walk(root):
        if isinstance(node, ast.Call):
            call_name = ast.unparse(node.func).lower()
            rendered = ast.unparse(node)
            safely_transformed = bool(re.search(r"\b(?:redact|mask|sanitize|hash|hmac)\s*\(", rendered, re.I))
            # Flag secret literals, but never include their value in report evidence.
            for keyword in node.keywords:
                if SECRET_NAME_RE.search(keyword.arg or "") and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                    if len(keyword.value.value) >= 8 and not PLACEHOLDER_RE.fullmatch(keyword.value.value):
                        add("SECURITY.HARDCODED_SECRET", node, "General security review")
            if isinstance(node.func, ast.Attribute) and node.func.attr.lower() in {"execute", "executemany", "query"} and node.args:
                query = node.args[0]
                query_text = ast.unparse(query)
                effective_query_text = (
                    dynamic_sql_sources.get(query.id, query_text)
                    if isinstance(query, ast.Name)
                    else query_text
                )
                dynamic_sql = isinstance(query, (ast.JoinedStr, ast.BinOp)) or (
                    isinstance(query, ast.Call) and isinstance(query.func, ast.Attribute) and query.func.attr == "format"
                ) or (isinstance(query, ast.Name) and query.id in dynamic_sql_sources)
                # Bound execute(sql, params) is safe unless SQL itself is dynamically composed.
                if SQL_RE.search(effective_query_text) and dynamic_sql:
                    add("SECURITY.SQL_INJECTION", node, "General security review")
            if not safely_transformed and re.search(r"(?i)(?:logger|logging|console)\.(?:log|info|warning|warn|error|debug|exception)$|^(?:print|pprint)$", call_name) and any(
                PERSONAL_RE.search(ast.unparse(arg)) or SENSITIVE_RE.search(ast.unparse(arg))
                or SECRET_NAME_RE.search(ast.unparse(arg)) or re.search(r"\b(?:request|body|payload|user)\b", ast.unparse(arg), re.I)
                for arg in node.args
            ):
                add("PRIVACY.SENSITIVE_LOGGING", node, "General security review")
            if OUTBOUND_RE.search(call_name) and any(
                PERSONAL_RE.search(ast.unparse(arg)) or SENSITIVE_RE.search(ast.unparse(arg))
                for arg in [*node.args, *(keyword.value for keyword in node.keywords)]
            ):
                for jurisdiction in jurisdictions:
                    add("PRIVACY.PERSONAL_DATA_EGRESS", node, jurisdiction)
            if call_name.endswith("httpexception") and any(
                keyword.arg == "detail" and re.search(r"\b(?:exc|exception|request|body|payload)\b", ast.unparse(keyword.value), re.I)
                for keyword in node.keywords
            ):
                add("PRIVACY.UNSAFE_EXCEPTION", node, "General security review")

        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and SECRET_NAME_RE.search(target.id) for target in node.targets
        ):
            value = node.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                if len(value.value) >= 8 and not PLACEHOLDER_RE.fullmatch(value.value):
                    add("SECURITY.HARDCODED_SECRET", node, "General security review")

    for function in routes:
        body = ast.unparse(function)
        references_personal_model = any(
            re.search(rf"\b{re.escape(name)}\b", body) for name in personal_model_classes
        )
        references_sensitive_model = any(
            re.search(rf"\b{re.escape(name)}\b", body) for name in sensitive_model_classes
        )
        personal_access = (
            PERSONAL_RE.search(body)
            or SENSITIVE_RE.search(body)
            or references_personal_model
            or references_sensitive_model
        )
        if not personal_access:
            continue
        decorated = " ".join(ast.unparse(item) for item in function.decorator_list)
        if AUTH_RE.search(decorated) or AUTH_RE.search(body):
            continue
        for jurisdiction in jurisdictions:
            add("API.UNGUARDED_PERSONAL_ROUTE", function, jurisdiction)
        if BROAD_QUERY_RE.search(body) or re.search(r"\breturn\b.+\.(?:all|find|fetchall)\s*\(", body, re.I | re.S):
            add("API.BROAD_DATA_RESPONSE", function, "General security review")
        if re.search(r"(?i)\b(?:export|download|dump|bulk)\b", body) and (
            BROAD_QUERY_RE.search(body) or re.search(r"\.(?:all|findAll|fetchall)\s*\(", body, re.I)
        ):
            add("PRIVACY.BULK_EXPORT", function, "General security review")
        if re.search(r"tenant|organization|workspace", body, re.I) and not re.search(r"tenant_id|organization_id|workspace_id", body, re.I):
            add("PRIVACY.CROSS_TENANT_QUERY", function, "General security review")

    for node in ast.walk(root):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            for label, pattern in PERSONAL_VALUE_PATTERNS.items():
                match = pattern.search(node.value)
                if match:
                    for jurisdiction in jurisdictions:
                        add(
                            "PRIVACY.PERSONAL_DATA_FIELD",
                            node,
                            jurisdiction,
                            confidence=0.86,
                            reasoning=f"A source string contains a value shaped like a {label}. The value is redacted in the report; confirm whether it is real, synthetic, or a test fixture.",
                            evidence_kind="literal_data_indicator",
                        )

    return findings, "parsed"


def _tree_sitter_analysis(
    language: str,
    file_path: str,
    source: str,
    jurisdictions: list[str],
) -> tuple[list[dict[str, Any]], str]:
    parser: Parser = get_parser(language)
    tree = parser.parse(source.encode("utf-8", errors="replace"))
    if tree.root_node.has_error:
        return [], "parse_error"

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    source_bytes = source.encode("utf-8")
    source_lines = source.splitlines()
    line_starts: list[int] = []
    offset = 0
    for line in source_lines:
        line_starts.append(offset)
        offset += len(line) + 1

    def add(rule_id: str, line: int, jurisdiction: str, **kwargs: Any) -> None:
        key = (rule_id, line, jurisdiction)
        if key in seen:
            return
        seen.add(key)
        if not 1 <= line <= len(source_lines):
            return
        start = line_starts[line - 1]
        findings.append(_finding(
            rule_id, file_path, source, start, start + len(source_lines[line - 1]), jurisdiction, **kwargs
        ))

    named_nodes: list[Any] = []
    string_nodes: list[Any] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.child_count == 0 and node.type in {
            "identifier", "property_identifier", "shorthand_property_identifier",
            "shorthand_property_identifier_pattern", "type_identifier",
        }:
            named_nodes.append(node)
        if node.child_count == 0 and node.type in {"string", "string_literal", "template_string"}:
            string_nodes.append(node)
        stack.extend(reversed(node.children))

    for node in named_nodes:
        token = node.text.decode("utf-8", errors="replace")
        normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", token).lower()
        line = node.start_point.row + 1
        line_text = source_lines[line - 1] if line <= len(source_lines) else ""
        # Only treat an identifier as data evidence in field-like or data-flow contexts.
        field_context = node.type in {
            "property_identifier", "shorthand_property_identifier",
            "shorthand_property_identifier_pattern", "type_identifier",
        } or re.search(r"(?i)(?:schema|model|payload|request|body|customer|user|profile|column|field)", line_text)
        if field_context and PERSONAL_RE.search(normalized):
            for jurisdiction in jurisdictions:
                add("PRIVACY.PERSONAL_DATA_FIELD", line, jurisdiction)
        if field_context and SENSITIVE_RE.search(normalized):
            for jurisdiction in jurisdictions:
                add("PRIVACY.SENSITIVE_DATA_FIELD", line, jurisdiction)

    for node in string_nodes:
        token = node.text.decode("utf-8", errors="replace")
        for label, pattern in PERSONAL_VALUE_PATTERNS.items():
            if pattern.search(token):
                for jurisdiction in jurisdictions:
                    add(
                        "PRIVACY.PERSONAL_DATA_FIELD",
                        node.start_point.row + 1,
                        jurisdiction,
                        confidence=0.86,
                        reasoning=f"A source string contains a value shaped like a {label}. The value is redacted in the report; confirm whether it is real, synthetic, or a test fixture.",
                        evidence_kind="literal_data_indicator",
                    )

    # Parse-aware route and flow checks. Tree-sitter ensures the file is syntactically
    # represented; these bounded checks are review signals, not complete taint proofs.
    if language in {"javascript", "typescript", "tsx"}:
        for line_index, line_text in enumerate(source_lines, start=1):
            if SECRET_NAME_RE.search(line_text):
                match = re.search(r"(?i)(?:password|passwd|secret|api[-_]?key|access[-_]?token|private[-_]?key)\s*[:=]\s*(['\"`])([^'\"`]+)\1", line_text)
                if match and len(match.group(2)) >= 8 and not PLACEHOLDER_RE.fullmatch(match.group(2)):
                    add("SECURITY.HARDCODED_SECRET", line_index, "General security review")
            if SQL_RE.search(line_text) and SQL_INTERPOLATION_RE.search(line_text):
                add("SECURITY.SQL_INJECTION", line_index, "General security review")
            if OUTBOUND_RE.search(line_text) and (PERSONAL_RE.search(line_text) or SENSITIVE_RE.search(line_text)):
                for jurisdiction in jurisdictions:
                    add("PRIVACY.PERSONAL_DATA_EGRESS", line_index, jurisdiction)
            if re.search(r"\b(?:throw\s+new\s+Error|res\.status|HttpException)\b", line_text) and re.search(
                r"(?i)(?:request|req\.body|payload|user|customer|exception|error)", line_text
            ):
                add("PRIVACY.UNSAFE_EXCEPTION", line_index, "General security review")

        nodes = _walk_tree(tree.root_node)
        for call_node in nodes:
            if call_node.type != "call_expression":
                continue
            call_source = source_bytes[call_node.start_byte:call_node.end_byte].decode("utf-8", errors="replace")
            line = call_node.start_point.row + 1
            safely_transformed = bool(re.search(r"\b(?:redact|mask|sanitize|hash|hmac)\s*\(", call_source, re.I))
            argument_identifiers = " ".join(
                descendant.text.decode("utf-8", errors="replace")
                for descendant in _walk_tree(call_node)
                if descendant.child_count == 0 and descendant.type in {
                    "identifier", "property_identifier", "shorthand_property_identifier",
                    "shorthand_property_identifier_pattern", "type_identifier",
                }
            )
            logs_data = re.search(
                r"(?i)\b(?:request|payload|user|customer|email|phone|token|password|secret)\b",
                argument_identifiers,
            ) or re.search(r"(?i)\breq\b.*\bbody\b", argument_identifiers)
            if not safely_transformed and LOG_CALL_RE.match(call_source) and logs_data:
                add("PRIVACY.SENSITIVE_LOGGING", line, "General security review")
            if SQL_RE.search(call_source) and SQL_INTERPOLATION_RE.search(call_source):
                add("SECURITY.SQL_INJECTION", line, "General security review")
            if OUTBOUND_RE.search(call_source) and (PERSONAL_RE.search(call_source) or SENSITIVE_RE.search(call_source)):
                for jurisdiction in jurisdictions:
                    add("PRIVACY.PERSONAL_DATA_EGRESS", line, jurisdiction)

        for node in nodes:
            if node.type in {"function_declaration", "method_definition", "arrow_function", "function"}:
                start_line = node.start_point.row + 1
                end_line = node.end_point.row + 1
                body = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
                parent = node.parent
                route_context = body
                for _ in range(5):
                    if parent is None:
                        break
                    route_context = source_bytes[parent.start_byte:parent.end_byte].decode("utf-8", errors="replace")
                    if ROUTE_RE.search(route_context) or re.search(
                        r"(?i)(?:app|router|api)\.(?:get|post|put|patch|delete)\s*\(", route_context
                    ):
                        break
                    if parent.type in {"program", "statement_block"}:
                        break
                    parent = parent.parent
                if not ROUTE_RE.search(route_context) and not re.search(
                    r"(?i)(?:app|router|api)\.(?:get|post|put|patch|delete)\s*\(", route_context
                ):
                    continue
                if not (PERSONAL_RE.search(body) or SENSITIVE_RE.search(body)):
                    continue
                if AUTH_RE.search(body) or AUTH_RE.search(route_context):
                    continue
                add("API.UNGUARDED_PERSONAL_ROUTE", start_line, jurisdictions[0])
                if BROAD_QUERY_RE.search(body) or re.search(r"\.(?:find|all|findAll)\s*\(", body):
                    add("API.BROAD_DATA_RESPONSE", start_line, "General security review")
                if re.search(r"(?i)\b(?:export|download|dump|bulk)\b", body) and re.search(
                    r"\.(?:find|all|findAll)\s*\(", body
                ):
                    add("PRIVACY.BULK_EXPORT", start_line, "General security review")
                if re.search(r"tenant|workspace|organization", body, re.I) and not re.search(
                    r"tenantId|workspaceId|organizationId", body, re.I
                ):
                    add("PRIVACY.CROSS_TENANT_QUERY", start_line, "General security review")
                if end_line > start_line:
                    for jurisdiction in jurisdictions[1:]:
                        add("API.UNGUARDED_PERSONAL_ROUTE", start_line, jurisdiction)

    if language == "sql":
        for line_index, line_text in enumerate(source_lines, start=1):
            if re.search(r"(?i)\bEXEC(?:UTE)?\s*\(\s*['\"].*(?:\+|%|concat\s*\()", line_text):
                add("SECURITY.SQL_INJECTION", line_index, "General security review")
            if re.search(r"(?i)\bSELECT\s+\*\s+FROM\b", line_text):
                add("API.BROAD_DATA_RESPONSE", line_index, "General security review")

    return findings, "parsed"


def _walk_tree(root: Any) -> list[Any]:
    nodes: list[Any] = []
    stack = [root]
    while stack:
        node = stack.pop()
        nodes.append(node)
        stack.extend(reversed(node.children))
    return nodes


def _schema_analysis(
    file_path: str, source: str, jurisdictions: list[str]
) -> tuple[list[dict[str, Any]], str]:
    findings: list[dict[str, Any]] = []
    if file_path.lower().endswith(".json"):
        import json
        try:
            schema = json.loads(source)
        except (json.JSONDecodeError, TypeError):
            return findings, "parse_error"
    else:
        import yaml
        try:
            schema = yaml.safe_load(source)
        except (yaml.YAMLError, TypeError):
            return findings, "parse_error"

    def visit(value: Any, parent_key: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = str(key)
                line = _key_line(source, normalized)
                if PERSONAL_RE.search(normalized):
                    for jurisdiction in jurisdictions:
                        findings.append(_finding("PRIVACY.PERSONAL_DATA_FIELD", file_path, source, _offset_for_line(source, line), _offset_for_line(source, line) + 1, jurisdiction))
                if SENSITIVE_RE.search(normalized):
                    for jurisdiction in jurisdictions:
                        findings.append(_finding("PRIVACY.SENSITIVE_DATA_FIELD", file_path, source, _offset_for_line(source, line), _offset_for_line(source, line) + 1, jurisdiction))
                visit(child, normalized)
        elif isinstance(value, list):
            for child in value:
                visit(child, parent_key)

    visit(schema)
    return findings, "parsed"


def _key_line(source: str, key: str) -> int:
    escaped = re.escape(key)
    match = re.search(rf"(?m)^\s*(?:['\"]?{escaped}['\"]?)\s*:", source)
    if not match:
        match = re.search(rf"['\"]{escaped}['\"]\s*:", source)
    return _line_for_offset(source, match.start()) if match else 1


def _offset_for_line(source: str, line: int) -> int:
    if line <= 1:
        return 0
    return sum(len(row) + 1 for row in source.splitlines()[:line - 1])


def analyze_source_file(
    file_path: str,
    source: str,
    jurisdictions: list[str],
) -> tuple[list[dict[str, Any]], str, str]:
    extension = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
    if extension == "py":
        findings, status = _python_analysis(file_path, source, jurisdictions)
        return findings, "python-ast", status
    if extension in {"js", "jsx", "mjs", "cjs"}:
        findings, status = _tree_sitter_analysis("javascript", file_path, source, jurisdictions)
        return findings, "tree-sitter-javascript", status
    if extension in {"ts", "mts", "cts"}:
        findings, status = _tree_sitter_analysis("typescript", file_path, source, jurisdictions)
        return findings, "tree-sitter-typescript", status
    if extension == "tsx":
        findings, status = _tree_sitter_analysis("tsx", file_path, source, jurisdictions)
        return findings, "tree-sitter-tsx", status
    if extension == "sql":
        findings, status = _tree_sitter_analysis("sql", file_path, source, jurisdictions)
        return findings, "tree-sitter-sql", status
    if extension in {"json", "yaml", "yml"}:
        findings, status = _schema_analysis(file_path, source, jurisdictions)
        return findings, "json-schema" if extension == "json" else "yaml-schema", status
    return [], "unsupported", "unsupported"
