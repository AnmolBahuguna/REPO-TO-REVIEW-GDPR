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

Optional API keys can be placed in `backend/.env` (copy `backend/.env.example`) or set in the backend process environment:

```powershell
GITHUB_TOKEN=github-token-with-repository-read-access
OPENROUTER_API_KEY=openrouter-api-key
OPENROUTER_MODEL=openai/gpt-4o-mini
```

`GITHUB_TOKEN` is optional for public repositories (it raises GitHub API rate limits) and is sent only to GitHub. It may allow access to repositories the token can read, so keep it in the backend `.env`; never put it in frontend code. `OPENROUTER_API_KEY` is optional and used only when AI explanations are enabled. The scanner validates GitHub URLs, uses fixed GitHub HTTPS hosts, disables redirects, caps files at 1 MB and scans at 250 files, and never executes repository code. GitHub's recursive tree endpoint may truncate very large repositories; that condition appears as a scan warning. The API also reports unparsed and unsupported files instead of claiming they were analyzed.

Optional Semgrep installation:

```powershell
pip install semgrep
```

Semgrep runs against temporary copies of selected source files, with a time limit; temporary files are cleaned when the scan finishes. It is not required for the built-in AST/tree-sitter engine.

The backend endpoints are `/health`, `/api/rules`, and `POST /api/scan`. Interactive docs: `http://localhost:8000/docs`. Set `include_explanations: true` in a scan request to explicitly opt in to OpenRouter enrichment.

### Frontend

In another terminal:

```powershell
cd frontend
npm install
npm run dev
```

The Vite development server proxies `/api` and `/health` to `http://localhost:8000`. For a separately hosted API, set `VITE_API_BASE_URL` at frontend build time. The optional AI checkbox sends at most eight redacted finding excerpts to OpenRouter for explanations and engineering recommendations; it does not send the repository or full files.

## Tests and evaluation

Run backend tests:

```powershell
cd backend
python -m unittest discover -s tests
```

Build the frontend:

```powershell
cd frontend
npm run build
```

Install the ML dependencies and validate a dataset:

```powershell
cd backend
pip install -r requirements.txt
python -m app.datasets data/code_to_gdpr_seed_dataset.jsonl
```

Train a model and report validation and held-out test metrics. Keep semantically related examples under one `group_id`; group IDs are kept out of one another's splits:

```powershell
cd backend
python scripts/train_model.py data/code_to_gdpr_seed_dataset.jsonl
```

The trained artifact is written to `backend/artifacts/privacy_triage.joblib` (ignored by git). Classify a source file with it:

```powershell
python scripts/predict_model.py path\to\sample.py
```

The existing rule-engine evaluation remains available separately:

```powershell
python scripts/evaluate_dataset.py data/code_to_gdpr_seed_dataset.jsonl --output evaluation.json
```

Training reports per-label precision/recall/F1, macro F1, accuracy, and a confusion matrix for validation and held-out test records. All examples in a group stay together. The older evaluation script measures the existing rule engine; it is not the ML model evaluation. Small or synthetic datasets do not establish production performance.
