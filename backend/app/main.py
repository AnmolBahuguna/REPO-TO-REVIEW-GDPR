from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

# Load local credentials from backend/.env regardless of the process working directory.
load_dotenv(Path(__file__).resolve().parents[1] / ".env")

from .catalog import CATALOG
from .explanations import enrich_findings
from .scanner import analyze_repository

app = FastAPI(
    title="Code-to-GDPR Generator",
    description="Evidence-based static privacy signals for public GitHub repositories.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    repo_url: str = Field(min_length=1, max_length=2048)
    jurisdictions: list[str] = Field(default_factory=lambda: ["UK GDPR", "India DPDP"], max_length=2)
    include_explanations: bool = False


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "service": "code-to-gdpr-generator"}


@app.get("/api/rules")
def list_rules() -> dict[str, Any]:
    return {
        "catalog_version": CATALOG["catalog_version"],
        "schema_version": CATALOG["schema_version"],
        "rules": CATALOG["rules"],
        "jurisdiction_mappings": CATALOG["jurisdictions"],
        "jurisdictions": [
            {"id": "uk_gdpr", "name": "UK GDPR"},
            {"id": "india_dpdp", "name": "India DPDP"},
        ],
        "notes": [
            "Findings are technical signals and manual-review prompts, not legal determinations.",
            "India DPDP commencement and rules status are not currently verified in this release.",
            "Unsupported source files are counted and reported; they are not represented as analyzed.",
        ],
    }


@app.post("/api/scan")
async def scan_repository(payload: ScanRequest):
    repo_url = (payload.repo_url or "").strip()
