# AI Accelerator — Code-to-GDPR Generator

Privacy Lens scans GitHub repositories for **evidence-backed technical signals** involving personal and sensitive data, API exposure, authentication, logging, secrets, SQL construction, database schemas, external data transfers, and account data lifecycle. It fetches repository files through GitHub's API and analyzes them in memory; it does not use a database or save scan results on the server. It returns source locations, redacted evidence, confidence, risk status, reasoning, false-positive notes, and remediation guidance.

It is a static-analysis aid, not a legal determination, audit, or compliance certification. A field name is not proof of unlawful processing. A clean scan does not prove that an application is compliant.

## What is implemented

- Python source analysis with Python AST, including route functions, model/schema fields, dynamic SQL variables, logging, credentials, and outbound calls.
- JavaScript, TypeScript, TSX, and SQL parsing with Tree-sitter; JSON/YAML schema inspection.
- Versioned, extensible finding metadata in `backend/rules/catalog.v1.json`.
- Optional Semgrep integration and starter rules in `backend/rules/semgrep.yml`; built-in analysis continues if Semgrep is not installed.
- Optional OpenRouter explanations and engineering recommendations for up to eight findings. This is off by default; when enabled, only redacted finding snippets and rule metadata are sent, never a repository or full file.
- JSON export and browser print-to-PDF; interactive filtering by severity and search term.
- Explicit counts and sample paths for unsupported files. Java, Go, Rust, C#, Ruby, PHP, Kotlin, Swift, and other files are **not analyzed** by the built-in parsers.
- JSONL/CSV dataset loader/validator, group-safe train/validation/test pipeline, optional ML triage on rule findings, and standalone code triage inference command.

## Seed dataset availability

These files were checked for and were **not present**:

- `code_to_gdpr_seed_dataset.jsonl`
- `code_to_gdpr_seed_dataset.csv`
- `starter_rule_catalog.json`

Put user-provided labeled dataset files under `backend/data/` using the first two filenames. The required minimum fields are `code` (or `code_snippet`, `snippet`, `source`, `text`) and `label` (or `expected_label`, `classification`); labels are `positive`, `negative`, or `requires_context` (`uncertain` is accepted as an alias). Add `language`, `category`, and a stable `group_id` for semantically related code variants. See [backend/data/README.md](./backend/data/README.md).

`backend/rules/catalog.v1.json` is the scanner's versioned rule catalog; it is not a recovered or fabricated copy of the missing starter catalog. No labeled seed dataset is included, so **no trained model or model accuracy is claimed**. Train a model with reviewed examples to turn on supplemental ML triage; rule findings remain primary. The AI recommendation checkbox uses OpenRouter inference; it does not train a model. These are separate stages.

## Compliance mapping limits

The rule catalog versions UK GDPR and India DPDP review metadata separately. UK legal references are emitted on findings only after a mapping is marked verified; this release keeps them unset pending authoritative review. India DPDP Act/rules commencement and applicability were not verified for this release, so the mapping explicitly says `current_status_unverified` and emits no legal citation. Consult current official sources and qualified counsel before relying on a legal mapping.

## Run locally

### Backend

From the repository root in PowerShell:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
