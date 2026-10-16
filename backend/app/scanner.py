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
