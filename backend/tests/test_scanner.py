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

    def test_extracts_repository_from_supported_url_forms(self):
        self.assertEqual(
            extract_repo_details("https://github.com/example/project"),
            ("example", "project"),
        )
        self.assertEqual(
            extract_repo_details("github.com/example/project.git"),
            ("example", "project"),
        )

    def test_rejects_non_github_and_non_repository_urls(self):
        invalid_urls = [
            "https://example.com/example/project",
            "http://github.com/example/project",
            "https://github.com/example/project/tree/main",
            "https://github.com/",
            "https://github.com/example/project?tab=readme",
            "https://user:password@github.com/example/project",
        ]
        for repo_url in invalid_urls:
            with self.subTest(repo_url=repo_url):
                with self.assertRaises(ValueError):
                    extract_repo_details(repo_url)

    def test_normalizes_supported_jurisdictions_and_rejects_others(self):
        self.assertEqual(
            normalize_jurisdictions(["uk_gdpr", "India DPDP", "UK GDPR"]),
            ["UK GDPR", "India DPDP"],
        )
        with self.assertRaisesRegex(ValueError, "Unsupported jurisdiction"):
            normalize_jurisdictions(["California"])
        with self.assertRaisesRegex(ValueError, "Select at least one"):
            normalize_jurisdictions([])


class AnalyzerTests(unittest.TestCase):
    def _rule_ids(self, filename: str, source: str) -> set[str]:
        findings, _, status = analyze_source_file(filename, source, ["UK GDPR", "India DPDP"])
        self.assertEqual(status, "parsed")
        return {finding["rule_id"] for finding in findings}

    def test_python_personal_and_sensitive_schema_and_routes_are_review_not_legal_conclusions(self):
        source = """
from pydantic import BaseModel
from fastapi import APIRouter

class Customer(BaseModel):
    email_address: str
    diagnosis_code: str

router = APIRouter()
@router.get("/customers/{customer_id}")
def fetch_customer(customer_id: int):
    return db.query(Customer).all()
"""
        findings, method, status = analyze_source_file("src/customers.py", source, ["UK GDPR", "India DPDP"])
        self.assertEqual(method, "python-ast")
        self.assertEqual(status, "parsed")
        self.assertIn("PRIVACY.PERSONAL_DATA_FIELD", {finding["rule_id"] for finding in findings})
        self.assertIn("PRIVACY.SENSITIVE_DATA_FIELD", {finding["rule_id"] for finding in findings})
        self.assertIn("API.UNGUARDED_PERSONAL_ROUTE", {finding["rule_id"] for finding in findings})
        self.assertTrue(all(finding["status"] == "requires_manual_review" for finding in findings))
        self.assertTrue(all(finding["line_start"] > 0 and finding["evidence"] for finding in findings))
        india_findings = [finding for finding in findings if finding["jurisdiction"] == "India DPDP"]
        self.assertTrue(india_findings)
