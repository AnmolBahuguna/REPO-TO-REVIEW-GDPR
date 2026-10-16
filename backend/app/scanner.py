from __future__ import annotations

import json
import os
import posixpath
import re
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from .analyzers import analyze_source_file, redact_evidence
from .catalog import CATALOG
from .ml_pipeline import load_model, predict_many

IGNORED_PATH_PARTS = {
    "node_modules", ".git", "dist", "build", "coverage", "venv", ".venv",
    "vendor", "__pycache__", ".next", ".nuxt", "target", ".idea", ".vscode",
}
SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
    ".sql", ".json", ".yaml", ".yml",
}
SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".sql",
}
MAX_SUPPORTED_FILES = 250
MAX_FILE_SIZE_BYTES = 1_000_000
MAX_WARNINGS = 20
MAX_CONCURRENT_DOWNLOADS = 8
MAX_SCAN_SECONDS = 180
MAX_SEMGREP_SECONDS = 25


def extract_repo_details(repo_url: str) -> tuple[str, str]:
    value = repo_url.strip()
    if not value:
        raise ValueError("A GitHub repository URL is required.")

    candidate = value if "://" in value else f"https://{value}"
    parsed = urlparse(candidate)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Enter a public GitHub repository URL, such as https://github.com/owner/repository.")

    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) != 2:
        raise ValueError("Repository URL must contain only an owner and repository name.")

    owner, repo_name = parts
    repo_name = repo_name.removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", owner):
        raise ValueError("The GitHub repository owner is invalid.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", repo_name) or repo_name in {".", ".."}:
        raise ValueError("The GitHub repository name is invalid.")
    return owner, repo_name


def normalize_jurisdictions(jurisdictions: list[str] | None) -> list[str]:
    items = ["UK GDPR", "India DPDP"] if jurisdictions is None else jurisdictions
    aliases = {
        "uk gdpr": "UK GDPR",
        "uk_gdpr": "UK GDPR",
        "india dpdp": "India DPDP",
        "india_dpdp": "India DPDP",
    }
    names: list[str] = []
    for item in items:
        normalized = str(item).strip().lower()
        if normalized not in aliases:
            raise ValueError(f"Unsupported jurisdiction: {item}")
        name = aliases[normalized]
        if name not in names:
            names.append(name)
    if not names:
        raise ValueError("Select at least one jurisdiction.")
    return names


def _github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "code-to-gdpr-generator",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_json(client: httpx.Client, url: str) -> dict[str, Any]:
    response = client.get(url)
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("GitHub API returned an unexpected response.")
    return payload


def fetch_text(client: httpx.Client, url: str) -> str:
    response = client.get(url, headers={"Accept": "text/plain"})
    response.raise_for_status()
    if len(response.content) > MAX_FILE_SIZE_BYTES:
        raise ValueError("Downloaded file exceeds the configured file-size limit.")
    return response.text


def _safe_repo_path(path: str) -> bool:
    normalized = posixpath.normpath(path)
    return (
        bool(path)
        and not path.startswith("/")
        and normalized not in {".", ".."}
        and not normalized.startswith("../")
        and "\\" not in path
        and "\x00" not in path
    )


def _rule_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {level: 0 for level in ("critical", "high", "medium", "low")}
    for finding in findings:
        severity = finding["severity"]
        if severity in counts:
            counts[severity] += 1
    return counts


def _semgrep_findings(
    files: dict[str, str],
    jurisdictions: list[str],
    warnings: list[str],
) -> list[dict[str, Any]]:
    executable = shutil.which("semgrep")
    if not executable:
        warnings.append("Semgrep is not installed; built-in AST/tree-sitter checks completed without Semgrep rules.")
        return []

    config_path = Path(__file__).resolve().parent.parent / "rules" / "semgrep.yml"
    findings: list[dict[str, Any]] = []
    try:
        with tempfile.TemporaryDirectory(prefix="privacy-lens-") as temp_dir:
            root = Path(temp_dir)
            for relative_path, source in files.items():
                target = root.joinpath(*relative_path.split("/"))
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source, encoding="utf-8")
            command = [
                executable,
                "--config", str(config_path),
                "--json",
                "--no-git-ignore",
                "--metrics=off",
                str(root),
            ]
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=MAX_SEMGREP_SECONDS,
                check=False,
                shell=False,
            )
            if result.returncode not in (0, 1):
                warnings.append("Semgrep exited with an error; built-in analyzers' results were retained.")
                return []
            output = json.loads(result.stdout or "{}")
            for match in output.get("results", []):
                check_id = match.get("check_id", "")
                line = int(match.get("start", {}).get("line", 1))
                rule_id = (
                    "SECURITY.SQL_INJECTION"
                    if "sql-interpolation" in check_id
                    else "SECURITY.HARDCODED_SECRET"
                )
                relative_path = Path(match.get("path", "")).relative_to(root).as_posix()
                code = match.get("extra", {}).get("lines", "")
                # A Semgrep result is retained only when the corresponding evidence line exists.
                if not code:
                    continue
                findings.append({
                    "rule_id": rule_id,
                    "title": "Semgrep: " + match.get("extra", {}).get("message", rule_id),
                    "category": "technical_vulnerability",
                    "severity": "high",
                    "confidence": 0.8,
                    "status": "potential_issue",
                    "file_path": relative_path,
                    "line_start": line,
                    "line_end": int(match.get("end", {}).get("line", line)),
                    "evidence": redact_evidence(code),
                    "reasoning": "An enabled Semgrep rule matched this source. Validate the data flow and remediation context.",
                    "jurisdiction": "General security review",
                    "relevant_legal_reference": None,
                    "recommended_fix": "Review the matching rule and use a safe parameterized query or external secret store.",
                    "false_positive_notes": "Semgrep pattern matches can be false positives; confirm source and data flow.",
                    "evidence_kind": "semgrep",
                    "explanation": None,
                })
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, ValueError):
        warnings.append("Semgrep could not complete; built-in analyzers' results were retained.")
        return []
    return findings


def analyze_repository(repo_url: str, jurisdictions: list[str] | None = None) -> dict[str, Any]:
    owner, repo_name = extract_repo_details(repo_url)
    selected_jurisdictions = normalize_jurisdictions(jurisdictions)
    api_repo = f"https://api.github.com/repos/{quote(owner, safe='')}/{quote(repo_name, safe='')}"
    deadline = time.monotonic() + MAX_SCAN_SECONDS

    # Fixed HTTPS origins, validated repository components, and disabled redirects
    # prevent user-controlled URLs from reaching arbitrary network destinations.
    with httpx.Client(headers=_github_headers(), timeout=20, follow_redirects=False) as client:
        repo_meta = fetch_json(client, api_repo)
        default_branch = repo_meta.get("default_branch")
        if not isinstance(default_branch, str) or not default_branch:
            raise ValueError("GitHub did not provide a default branch for this repository.")

        tree_url = f"{api_repo}/git/trees/{quote(default_branch, safe='')}?recursive=1"
        tree = fetch_json(client, tree_url)
        warnings: list[str] = []

        def add_warning(message: str) -> None:
            if message in warnings:
                return
            if len(warnings) < MAX_WARNINGS:
                warnings.append(message)
            elif warnings[-1] != "Additional scan warnings were omitted.":
                warnings[-1] = "Additional scan warnings were omitted."

        if tree.get("truncated"):
            add_warning("GitHub truncated the repository tree; some files were not available to the scanner.")

        supported_files: list[dict[str, Any]] = []
        unsupported_samples: list[str] = []
        skipped = 0
        unsupported = 0
        for item in tree.get("tree", []):
            if item.get("type") != "blob":
                continue
            path = item.get("path", "")
            if not _safe_repo_path(path):
                skipped += 1
                continue
