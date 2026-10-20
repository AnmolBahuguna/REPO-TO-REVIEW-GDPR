from __future__ import annotations

import asyncio
import json
import os
from queue import Empty, Queue
from threading import Thread
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

# Load local credentials from backend/.env regardless of the process working directory.
load_dotenv(Path(__file__).resolve().parents[1] / ".env")

from .catalog import CATALOG
from .explanations import enrich_findings
from .legal_assistant import answer_question, annotate_findings, source_status
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


class LegalQuestion(BaseModel):
    question: str = Field(min_length=3, max_length=2000)


def _github_http_error_detail(exc: httpx.HTTPStatusError) -> str:
    response = exc.response
    if response.status_code == 404:
        return "Repository not found or is not publicly accessible."
    if response.status_code == 403 and response.headers.get("X-RateLimit-Remaining") == "0":
        reset_at = response.headers.get("X-RateLimit-Reset")
        reset_note = ""
        if reset_at:
            try:
                reset_time = datetime.fromtimestamp(int(reset_at), tz=timezone.utc)
                reset_note = f" The quota resets at {reset_time:%Y-%m-%d %H:%M:%S} UTC."
            except (OverflowError, OSError, TypeError, ValueError):
                pass
        if os.getenv("GITHUB_TOKEN", "").strip():
            return f"GitHub API quota for the configured token is exhausted.{reset_note}"
        return (
            "GitHub's unauthenticated API quota is exhausted. Add GITHUB_TOKEN=your_token "
            f"to backend/.env and restart the backend.{reset_note}"
        )
    return "GitHub rejected a repository scan request. Check repository access and try again."


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


@app.get("/api/legal/sources")
def list_legal_sources() -> dict[str, Any]:
    return {"sources": source_status()}


@app.post("/api/legal/ask")
async def ask_legal_question(payload: LegalQuestion) -> dict[str, Any]:
    question = payload.question.strip()
    if len(question) < 3:
        raise HTTPException(status_code=422, detail="Enter a question of at least 3 characters.")
    try:
        return await answer_question(question)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/scan")
async def scan_repository(payload: ScanRequest):
    repo_url = (payload.repo_url or "").strip()
    if not repo_url:
        raise HTTPException(status_code=400, detail="A GitHub repository URL is required.")
    if not payload.jurisdictions:
        raise HTTPException(status_code=422, detail="Select at least one jurisdiction.")

    try:
        result = await run_in_threadpool(analyze_repository, repo_url, payload.jurisdictions)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except httpx.HTTPStatusError as exc:
        status_code = 429 if exc.response.status_code == 403 and exc.response.headers.get("X-RateLimit-Remaining") == "0" else (
            404 if exc.response.status_code == 404 else 502
        )
        raise HTTPException(status_code=status_code, detail=_github_http_error_detail(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="GitHub API request failed; retry later or check repository access.") from exc

    legal_counts = annotate_findings(result["findings"])
    result["summary"]["legal_source_review"] = {
        **legal_counts,
        "source_documents": [source["document"] for source in source_status() if source["available"]],
    }

    if payload.include_explanations:
        result["summary"]["ai_explanations_requested"] = True
        enriched, warning = await enrich_findings(result["findings"])
        result["summary"]["ai_findings_enriched"] = enriched
        result["summary"]["ai_provider"] = "OpenRouter" if enriched else None
        if warning:
            result["warnings"].append(warning)

    return result


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
