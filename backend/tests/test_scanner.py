import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from app.analyzers import analyze_source_file, redact_evidence
from app.catalog import CATALOG, build_finding
from app.datasets import load_dataset, validate_dataset
from app.explanations import _parse_explanation, enrich_findings
from app.main import app
from app.scanner import _github_headers, analyze_repository, extract_repo_details, normalize_jurisdictions
from scripts.evaluate_dataset import _split, evaluate


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health_and_versioned_rule_catalog_endpoints(self):
        self.assertEqual(self.client.get("/health").json()["status"], "ok")
        rules = self.client.get("/api/rules").json()
        self.assertEqual(rules["catalog_version"], "1.0.0")
        self.assertEqual([item["id"] for item in rules["jurisdictions"]], ["uk_gdpr", "india_dpdp"])
        self.assertEqual(rules["jurisdiction_mappings"]["India DPDP"]["status"], "current_status_unverified")

    def test_scan_rejects_invalid_repo_and_empty_jurisdictions(self):
        invalid_repo = self.client.post(
            "/api/scan",
            json={"repo_url": "https://example.com/owner/repo", "jurisdictions": ["UK GDPR"]},
        )
        self.assertEqual(invalid_repo.status_code, 400)

        no_jurisdiction = self.client.post(
            "/api/scan",
            json={"repo_url": "https://github.com/owner/repo", "jurisdictions": []},
        )
        self.assertEqual(no_jurisdiction.status_code, 422)

    def test_scan_returns_structured_scanner_result(self):
        expected = {
            "repo": {"owner": "owner", "name": "repo", "default_branch": "main", "url": "https://github.com/owner/repo"},
            "summary": {
                "files_scanned": 1,
                "files_skipped": 0,
                "total_findings": 0,
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "jurisdictions": ["UK GDPR"],
                "generated_at": "2026-01-01T00:00:00+00:00",
            },
            "findings": [],
            "warnings": [],
        }
        with patch("app.main.analyze_repository", return_value=expected):
            response = self.client.post(
                "/api/scan",
                json={"repo_url": "https://github.com/owner/repo", "jurisdictions": ["UK GDPR"]},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), expected)


class RepoValidationTests(unittest.TestCase):
    def test_github_token_is_sent_as_bearer_auth(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test-github-token"}):
            headers = _github_headers()
        self.assertEqual(headers["Authorization"], "Bearer test-github-token")

