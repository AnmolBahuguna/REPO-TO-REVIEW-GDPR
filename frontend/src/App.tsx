import { useEffect, useMemo, useState } from 'react';

type JurisdictionOption = 'UK GDPR' | 'India DPDP';
type Severity = 'critical' | 'high' | 'medium' | 'low';

type Finding = {
  rule_id: string;
  title: string;
  severity: Severity;
  category: string;
  jurisdiction: string;
  confidence: number;
  status: 'potential_issue' | 'requires_manual_review' | 'no_issue_detected_by_rule';
  file_path: string;
  line_start: number;
  line_end: number;
  evidence: string;
  reasoning: string;
  relevant_legal_reference: { reference: string; url: string } | null;
  recommended_fix: string;
  false_positive_notes: string;
  evidence_kind: string;
  explanation: string | null;
  ml_triage?: { label: string; top_class_score: number; model_version: string };
  legal_context?: {
    status: string;
    message: string;
    sources: { document: string; page: number; reference: string; excerpt: string }[];
  };
};

type ScanResponse = {
  repo: {
    owner: string;
    name: string;
    default_branch: string;
    url: string;
  };
  summary: {
    files_scanned: number;
    files_skipped: number;
    files_unsupported: number;
    unsupported_file_samples: string[];
    files_parse_failed: number;
    analysis_methods: Record<string, number>;
    total_findings: number;
    severity_counts: Record<Severity, number>;
    status_counts: Record<Finding['status'], number>;
    jurisdictions: string[];
    compliance_mapping_versions: Record<string, string>;
    compliance_notices: Record<string, string>;
    legal_source_review?: { annotated: number; without_relevant_source: number; unsupported_jurisdiction: number; source_documents: string[] };
    semgrep_available: boolean;
    ai_explanations_requested?: boolean;
    ai_findings_enriched?: number;
    ai_provider?: string | null;
    generated_at: string;
    ml_triage?: {
      available: boolean;
      model_version: string | null;
      findings_classified: number;
      label_counts: Record<string, number>;
    };
  };
  findings: Finding[];
  warnings: string[];
};

type ScanStreamEvent = {
  type: 'progress' | 'file_result' | 'finding_batch' | 'complete' | 'error' | 'keepalive';
  phase?: string;
  completed?: number;
  total?: number;
  file_path?: string;
  message?: string;
  findings?: Finding[];
  result?: ScanResponse;
  detail?: string;
};

type ScanProgress = {
  phase: string;
  message: string;
  completed?: number;
  total?: number;
  file_path?: string;
};

type LegalResponse = {
  answer: string;
  grounded: boolean;
  citations: { document: string; page: number; reference: string }[];
  passages?: { document: string; page: number; reference: string; text: string }[];
};

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '';
const JURISDICTIONS: JurisdictionOption[] = ['UK GDPR', 'India DPDP'];
const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];
const EXAMPLE_REPOSITORY = 'https://github.com/psf/requests';

function isScanResponse(value: unknown): value is ScanResponse {
  if (!value || typeof value !== 'object') return false;
  const response = value as Partial<ScanResponse>;
  return Boolean(
    response.repo
    && typeof response.repo.owner === 'string'
    && typeof response.repo.name === 'string'
    && response.summary
    && typeof response.summary.files_scanned === 'number'
    && Array.isArray(response.findings)
    && Array.isArray(response.warnings)
    && response.findings.every((finding) => (
      typeof finding.rule_id === 'string'
      && typeof finding.file_path === 'string'
      && typeof finding.evidence === 'string'
    )),
  );
}

function mergeFindings(current: Finding[], incoming: Finding[]) {
  const merged = new Map<string, Finding>();
  for (const finding of current) {
    merged.set(`${finding.rule_id}:${finding.file_path}:${finding.line_start}:${finding.jurisdiction}`, finding);
  }
  for (const finding of incoming) {
    merged.set(`${finding.rule_id}:${finding.file_path}:${finding.line_start}:${finding.jurisdiction}`, finding);
  }
  return [...merged.values()];
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function csvCell(value: unknown) {
  let text = typeof value === 'string' ? value : value == null ? '' : JSON.stringify(value) ?? '';
  if (/^[\t\r ]*[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

function pdfSafeText(value: unknown) {
  return String(value ?? '')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/[^\x20-\x7E]/g, '?')
    .trim();
}

function wrapPdfText(value: unknown, limit = 92) {
  const words = pdfSafeText(value).split(/\s+/).filter(Boolean);
  if (!words.length) return [''];
  const wrapped: string[] = [];
  let line = '';
  for (const word of words) {
    let remaining = word;
    while (remaining.length > limit) {
      if (line) {
        wrapped.push(line);
        line = '';
      }
      wrapped.push(remaining.slice(0, limit));
      remaining = remaining.slice(limit);
    }
    if (!remaining) continue;
    if (!line) line = remaining;
    else if (line.length + remaining.length + 1 <= limit) line += ` ${remaining}`;
    else {
      wrapped.push(line);
      line = remaining;
    }
  }
  if (line) wrapped.push(line);
  return wrapped;
}

function createPdfBlob(lines: string[]) {
  const pageLines = Array.from({ length: Math.ceil(lines.length / 56) || 1 }, (_, index) => (
    lines.slice(index * 56, (index + 1) * 56)
  ));
  const pageObjectIds = pageLines.map((_, index) => 4 + index * 2);
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    `<< /Type /Pages /Kids [${pageObjectIds.map((id) => `${id} 0 R`).join(' ')}] /Count ${pageLines.length} >>`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];

  pageLines.forEach((page, index) => {
    const pageId = pageObjectIds[index];
    const contentId = pageId + 1;
    const textCommands = page.map((line, lineIndex) => (
      `${lineIndex ? 'T* ' : ''}(${line.replace(/[\\()]/g, (character) => `\\${character}`)}) Tj`
    )).join('\n');
    const stream = `BT\n/F1 9 Tf\n50 748 Td\n12 TL\n${textCommands}\nET`;
    objects.push(
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents ${contentId} 0 R >>`,
      `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`,
    );
  });

  let documentText = '%PDF-1.4\n%Privacy Lens Report\n';
  const offsets = [0];
  objects.forEach((object, index) => {
    offsets.push(documentText.length);
    documentText += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });
  const xrefOffset = documentText.length;
  documentText += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  offsets.slice(1).forEach((offset) => {
    documentText += `${String(offset).padStart(10, '0')} 00000 n \n`;
  });
  documentText += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
  return new Blob([documentText], { type: 'application/pdf' });
}

function App() {
  const [theme, setTheme] = useState<'light' | 'dark'>(() => (
    window.localStorage.getItem('privacy-lens-theme') === 'dark' ? 'dark' : 'light'
  ));
  const [repoUrl, setRepoUrl] = useState('');
  const [selectedJurisdictions, setSelectedJurisdictions] = useState<JurisdictionOption[]>(JURISDICTIONS);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [scanProgress, setScanProgress] = useState<ScanProgress | null>(null);
  const [liveFindings, setLiveFindings] = useState<Finding[]>([]);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all');
  const [includeExplanations, setIncludeExplanations] = useState(false);
  const [legalQuestion, setLegalQuestion] = useState('');
  const [legalResponse, setLegalResponse] = useState<LegalResponse | null>(null);
  const [legalLoading, setLegalLoading] = useState(false);
  const [legalError, setLegalError] = useState('');

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    window.localStorage.setItem('privacy-lens-theme', theme);
  }, [theme]);

  const toggleJurisdiction = (value: JurisdictionOption) => {
    setSelectedJurisdictions((current) => (
      current.includes(value) ? current.filter((item) => item !== value) : [...current, value]
    ));
  };

  async function askLegalQuestion(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLegalLoading(true);
    setLegalError('');
    setLegalResponse(null);
    try {
      const response = await fetch(`${API_BASE_URL}/api/legal/ask`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: legalQuestion.trim() }),
      });
      const data = await response.json().catch(() => null);
      if (!response.ok) throw new Error(data?.detail ?? `Question failed with status ${response.status}.`);
      setLegalResponse(data as LegalResponse);
    } catch (caught) {
      setLegalError(caught instanceof Error ? caught.message : 'The legal assistant could not answer right now.');
    } finally {
      setLegalLoading(false);
    }
  }

  const filteredFindings = useMemo(() => {
    if (!result) return [];
    const search = query.trim().toLowerCase();
    return result.findings
      .filter((finding) => severityFilter === 'all' || finding.severity === severityFilter)
      .filter((finding) => {
        if (!search) return true;
        const haystack = [
          finding.title,
          finding.category,
          finding.jurisdiction,
          finding.reasoning,
          finding.recommended_fix,
          finding.explanation ?? '',
          finding.evidence,
          finding.rule_id,
          finding.file_path,
        ].join(' ').toLowerCase();
        return haystack.includes(search);
      })
      .sort((first, second) => SEVERITY_ORDER.indexOf(first.severity) - SEVERITY_ORDER.indexOf(second.severity));
  }, [query, result, severityFilter]);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError('');
    setResult(null);
    setLiveFindings([]);
    setScanProgress({ phase: 'repository', message: 'Connecting to GitHub and loading the file list.' });
    setQuery('');
    setSeverityFilter('all');

    const finalResult: { value: ScanResponse | null } = { value: null };
    let streamedFindingCount = 0;

    try {
      const response = await fetch(`${API_BASE_URL}/api/scan/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repo_url: repoUrl.trim(),
          jurisdictions: selectedJurisdictions,
          include_explanations: includeExplanations,
        }),
      });

      if (!response.ok) {
        const data: unknown = await response.json().catch(() => null);
        const detail = data && typeof data === 'object' && 'detail' in data && typeof data.detail === 'string'
          ? data.detail
          : `Scan failed with status ${response.status}.`;
        throw new Error(detail);
      }
      if (!response.body) {
        throw new Error('The scan service did not return a readable progress stream.');
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let bufferedText = '';
      const handleEventLine = (line: string) => {
        if (!line.trim()) return;
        const event = JSON.parse(line) as ScanStreamEvent;
        if (event.type === 'keepalive') return;
        if (event.type === 'progress') {
          setScanProgress({
            phase: event.phase ?? 'scan',
            message: event.message ?? 'Scanning repository files.',
            completed: event.completed,
            total: event.total,
            file_path: event.file_path,
          });
          return;
        }
        if (event.type === 'file_result' || event.type === 'finding_batch') {
          const findings = event.findings ?? [];
          if (findings.length) {
            streamedFindingCount += findings.length;
            setLiveFindings((current) => mergeFindings(current, findings));
          }
          if (event.type === 'file_result') {
            setScanProgress({
              phase: 'analyze',
              message: `Analyzed ${event.completed ?? 0} of ${event.total ?? 0} files.`,
              completed: event.completed,
              total: event.total,
              file_path: event.file_path,
            });
          }
          return;
        }
        if (event.type === 'error') {
          throw new Error(event.detail ?? 'The scan could not be completed.');
        }
        if (event.type === 'complete') {
          if (!isScanResponse(event.result)) {
            throw new Error('The scan service returned an invalid final result.');
          }
          finalResult.value = event.result;
        }
      };

      while (true) {
        const { done, value } = await reader.read();
        bufferedText += decoder.decode(value, { stream: !done });
        const lines = bufferedText.split(/\r?\n/);
        bufferedText = lines.pop() ?? '';
        lines.forEach(handleEventLine);
        if (done) break;
      }
      if (bufferedText.trim()) handleEventLine(bufferedText);
      if (!finalResult.value) {
        throw new Error('The scan stream ended before a complete result arrived.');
      }
      setResult(finalResult.value);
      setLiveFindings(finalResult.value.findings);
      setScanProgress(null);
    } catch (scanError) {
      const message = scanError instanceof Error ? scanError.message : 'Could not complete the scan.';
      setError(streamedFindingCount
        ? `${message} Showing ${streamedFindingCount} findings received before the scan stopped.`
        : message);
      setScanProgress((current) => current ? { ...current, phase: 'stopped' } : null);
    } finally {
      setLoading(false);
    }
  }

  function exportJson() {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    downloadBlob(blob, `${result.repo.owner}-${result.repo.name}-privacy-report.json`);
  }

  function exportCsv() {
    if (!result) return;
    const repository = `${result.repo.owner}/${result.repo.name}`;
    const shared = {
      repository,
      branch: result.repo.default_branch,
      generated_at: result.summary.generated_at,
      summary: JSON.stringify(result.summary),
      warnings: result.warnings.join(' | '),
    };
    const columns = [
      'record_type', 'repository', 'branch', 'generated_at', 'summary', 'warnings',
      'rule_id', 'title', 'severity', 'category', 'jurisdiction', 'confidence', 'status',
      'file_path', 'line_start', 'line_end', 'evidence', 'reasoning', 'recommended_fix',
      'false_positive_notes', 'relevant_legal_reference', 'evidence_kind', 'explanation', 'ml_triage',
    ];
    const rows: Record<string, unknown>[] = [
      { record_type: 'summary', ...shared },
      ...result.findings.map((finding) => ({
        record_type: 'finding',
        ...shared,
        ...finding,
        relevant_legal_reference: finding.relevant_legal_reference,
        ml_triage: finding.ml_triage ?? null,
      })),
    ];
    const csv = [
      columns.map(csvCell).join(','),
      ...rows.map((row) => columns.map((column) => csvCell(row[column])).join(',')),
    ].join('\r\n');
    downloadBlob(
      new Blob(['\uFEFF', csv], { type: 'text/csv;charset=utf-8' }),
      `${result.repo.owner}-${result.repo.name}-privacy-report.csv`,
    );
  }

  function exportPdf() {
    if (!result) return;
    const lines: string[] = [];
    const add = (value = '') => lines.push(...wrapPdfText(value));
    const repository = `${result.repo.owner}/${result.repo.name}`;

    add('PRIVACY LENS - SCAN REPORT');
    add(`Repository: ${repository}`);
    add(`URL: ${result.repo.url}`);
    add(`Branch: ${result.repo.default_branch}`);
    add(`Generated: ${new Date(result.summary.generated_at).toLocaleString()}`);
    add(`Files scanned: ${result.summary.files_scanned} | Skipped: ${result.summary.files_skipped} | Unsupported: ${result.summary.files_unsupported} | Parse failed: ${result.summary.files_parse_failed}`);
    add(`Total findings: ${result.summary.total_findings}`);
    add(`Jurisdictions: ${result.summary.jurisdictions.join(', ')}`);
    add(`Severity counts: ${JSON.stringify(result.summary.severity_counts)}`);
    add(`Status counts: ${JSON.stringify(result.summary.status_counts)}`);
    add(`Legal assessment: potential source context for ${result.summary.legal_source_review?.annotated ?? 0} findings. These are review prompts, not confirmed legal violations.`);
    if (result.summary.legal_source_review?.source_documents.length) add(`Legal source documents: ${result.summary.legal_source_review.source_documents.join('; ')}`);
    add('');
    add('FINDINGS');
    add('');

    if (!result.findings.length) add('No findings were returned by the scan.');
    result.findings.forEach((finding, index) => {
      add(`${index + 1}. [${finding.severity.toUpperCase()}] ${finding.title}`);
      add(`Rule: ${finding.rule_id} | Jurisdiction: ${finding.jurisdiction} | Status: ${finding.status} | Confidence: ${Math.round(finding.confidence * 100)}%`);
      add(`File: ${finding.file_path}:${finding.line_start}-${finding.line_end}`);
      add(`Evidence: ${finding.evidence}`);
      add(`Reasoning: ${finding.reasoning}`);
      add(`Recommended fix: ${finding.recommended_fix}`);
      add(`False-positive notes: ${finding.false_positive_notes}`);
      if (finding.legal_context) {
        add(`Legal review note: ${finding.legal_context.message}`);
        finding.legal_context.sources.forEach((source) => {
          add(`Potentially relevant source: ${source.document}, ${source.reference}`);
          add(`Source excerpt: ${source.excerpt}`);
        });
      }
      if (finding.relevant_legal_reference) {
        add(`Legal reference: ${finding.relevant_legal_reference.reference} (${finding.relevant_legal_reference.url})`);
      }
      if (finding.explanation) add(`Explanation: ${finding.explanation}`);
      if (finding.ml_triage) {
        add(`ML triage: ${finding.ml_triage.label} (${Math.round(finding.ml_triage.top_class_score * 100)}%)`);
      }
      add('');
    });

    if (result.warnings.length) {
      add('SCAN WARNINGS');
      result.warnings.forEach((warning) => add(`- ${warning}`));
    }
    downloadBlob(
      createPdfBlob(lines),
      `${result.repo.owner}-${result.repo.name}-privacy-report.pdf`,
    );
  }

  function resetFindingFilters() {
    setQuery('');
    setSeverityFilter('all');
  }

  function sourceUrl(finding: Finding) {
    const branch = encodeURI(result?.repo.default_branch ?? 'main');
    const path = finding.file_path.split('/').map(encodeURIComponent).join('/');
    return `${result?.repo.url}/blob/${branch}/${path}#L${finding.line_start}`;
  }

  return (
    <div className="page-shell" data-theme={theme}>
      <div className="container">
        <header className="topbar">
          <a className="brand" href="/" aria-label="Code-to-GDPR home">
            <span className="brand-mark" aria-hidden="true">P</span>
            <span>Privacy Lens</span>
          </a>
          <span className="topbar-note">Open-source repository review</span>
          <button
            className="theme-toggle"
            type="button"
            onClick={() => setTheme((current) => current === 'light' ? 'dark' : 'light')}
            aria-label={`Switch to ${theme === 'light' ? 'dark' : 'light'} theme`}
            aria-pressed={theme === 'dark'}
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              {theme === 'light'
                ? <path d="M20.1 15.5A8.5 8.5 0 0 1 8.5 3.9 8.5 8.5 0 1 0 20.1 15.5Z" />
                : <><circle cx="12" cy="12" r="4" /><path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42" /></>}
            </svg>
            <span>{theme === 'light' ? 'Dark mode' : 'Light mode'}</span>
          </button>
        </header>

        <main>
          <section className="hero">
            <div className="hero-copy">
              <p className="eyebrow"><span className="eyebrow-dot" /> STATIC PRIVACY ANALYSIS</p>
              <h1>Find privacy signals<br /><span>before they become risks.</span></h1>
              <p className="hero-description">
                Review a public GitHub repository for potential personal-data handling,
                sensitive data, logging, and access-control patterns.
              </p>
              <div className="jurisdiction-tags" aria-label="Supported jurisdictions">
                <span>UK GDPR</span><span>India DPDP</span>
              </div>
            </div>
            <div className="hero-art" aria-hidden="true">
              <div className="art-orbit orbit-one" />
              <div className="art-orbit orbit-two" />
              <div className="art-shield">
                <svg viewBox="0 0 64 72" role="presentation">
                  <path d="M32 4 55 13v18c0 16-9.8 28.8-23 36C18.8 59.8 9 47 9 31V13L32 4Z" />
                  <path d="m22 35 7 7 14-15" />
                </svg>
              </div>
              <span className="art-label label-code">CODE</span>
              <span className="art-label label-privacy">PRIVACY</span>
            </div>
          </section>

          <section className="legal-chat" aria-labelledby="legal-chat-title">
            <div>
              <p className="eyebrow">LEGAL Q&amp;A AND GENERAL CHAT</p>
              <h2 id="legal-chat-title">Ask about the supplied laws or anything else</h2>
              <p>Legal answers use retrieved passages from the UK GDPR, Data Protection Act 2018, and Data (Use and Access) Act 2025. Other questions are answered by the OpenRouter chatbot.</p>
            </div>
            <form onSubmit={askLegalQuestion} className="legal-chat-form">
              <label className="sr-only" htmlFor="legal-question">Your question</label>
              <textarea id="legal-question" value={legalQuestion} onChange={(event) => setLegalQuestion(event.target.value)} maxLength={2000} required minLength={3} placeholder="Ask about data protection law or anything else…" />
              <button type="submit" disabled={legalLoading || legalQuestion.trim().length < 3}>{legalLoading ? 'Searching the laws…' : 'Ask from these laws'}</button>
            </form>
            {legalError ? <div className="error-box" role="alert">{legalError}</div> : null}
            {legalResponse ? (
              <div className="legal-answer" aria-live="polite">
                <h3>Answer</h3>
                <p>{legalResponse.answer}</p>
                {legalResponse.citations.length ? <p className="legal-citations"><strong>Sources:</strong> {legalResponse.citations.map((citation) => `${citation.document}, ${citation.reference}`).join(' · ')}</p> : null}
                {legalResponse.passages?.map((passage) => <details key={`${passage.document}-${passage.page}`}><summary>{passage.document} · {passage.reference}</summary><p>{passage.text}</p></details>)}
                <small>Informational only. This does not determine compliance, and the supplied PDFs may not include later legal changes.</small>
              </div>
            ) : null}
          </section>

          <form className="scan-panel" onSubmit={handleSubmit}>
            <div className="panel-heading">
              <div>
                <span className="step-number">01</span>
                <h2>Choose a repository</h2>
              </div>
              <span className="panel-meta">Public GitHub repositories</span>
            </div>
            <label className="field-label" htmlFor="repo-url">Repository URL</label>
            <div className="url-input-wrap">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M10 13a5 5 0 0 0 7.07 0l3-3A5 5 0 0 0 13 2.93l-1.72 1.72" />
                <path d="M14 11a5 5 0 0 0-7.07 0l-3 3A5 5 0 0 0 11 21.07l1.72-1.72" />
              </svg>
              <input
                id="repo-url"
                type="url"
                value={repoUrl}
                onChange={(event) => setRepoUrl(event.target.value)}
                placeholder="https://github.com/owner/repository"
                title="Enter a public GitHub repository URL."
                required
                disabled={loading}
              />
              <span className="input-hint">URL</span>
            </div>
            <p className="input-helper">Paste a public GitHub repository link, such as <code>github.com/owner/repository</code>.</p>
            <button className="example-repo" type="button" onClick={() => setRepoUrl(EXAMPLE_REPOSITORY)} disabled={loading}>
              Try an example <span aria-hidden="true">↗</span>
            </button>
            <div className="jurisdiction-select">
              <div>
                <span className="field-label">Regulatory lens</span>
                <span className="field-help">Select at least one jurisdiction</span>
              </div>
              <div className="checkbox-row">
                {JURISDICTIONS.map((jurisdiction) => (
                  <label key={jurisdiction} className={`check-pill ${selectedJurisdictions.includes(jurisdiction) ? 'selected' : ''}`}>
                    <input
                      type="checkbox"
                      checked={selectedJurisdictions.includes(jurisdiction)}
                      onChange={() => toggleJurisdiction(jurisdiction)}
                      disabled={loading}
                    />
                    <span className="check-indicator" aria-hidden="true">{selectedJurisdictions.includes(jurisdiction) ? '✓' : ''}</span>
                    {jurisdiction}
                  </label>
                ))}
              </div>
            </div>
            <div className="ai-option">
              <label className="check-pill" htmlFor="include-explanations">
                <input
                  id="include-explanations"
                  type="checkbox"
                  checked={includeExplanations}
                  onChange={(event) => setIncludeExplanations(event.target.checked)}
                  disabled={loading}
                />
                <span className={`check-indicator ${includeExplanations ? 'checked' : ''}`} aria-hidden="true">
                  {includeExplanations ? '✓' : ''}
                </span>
                Optional AI explanations and law-aware fix suggestions
              </label>
                <p>When enabled, up to 8 redacted finding excerpts and their retrieved legal passages are sent to OpenRouter for explanations and engineering suggestions. Repository source code is never sent in bulk.</p>
            </div>
            <div className="form-footer">
              <p><span className="info-icon" aria-hidden="true">i</span> Analysis uses public source files only.</p>
              <button type="submit" disabled={loading || selectedJurisdictions.length === 0}>
                {loading ? (
                  <><span className="spinner" aria-hidden="true" /> Scanning repository</>
                ) : (
                  <>Run privacy scan <span aria-hidden="true">→</span></>
                )}
              </button>
            </div>
          </form>

          <div className="disclaimer">
            <span aria-hidden="true">ⓘ</span>
            <p><strong>Signals, not legal advice.</strong> This static analysis may produce false positives or miss issues; review findings with engineering and legal teams.</p>
          </div>

          {error ? <div className="error-box" role="alert">{error}</div> : null}
          {loading ? (
            <div className="loading-state" role="status" aria-live="polite">
              <span className="spinner" aria-hidden="true" />
              <span>{scanProgress?.message ?? 'Reviewing repository files.'}</span>
            </div>
          ) : null}

          {(loading || (scanProgress !== null && !result)) ? (
            <section className="live-scan-panel" aria-live="polite">
              <div className="live-scan-heading">
                <strong>{loading ? 'Live scan output' : 'Partial scan output'}</strong>
                <span>{liveFindings.length} finding{liveFindings.length === 1 ? '' : 's'} so far</span>
              </div>
              {scanProgress ? (
                <p className="live-scan-status">
                  {scanProgress.message}
                  {scanProgress.total !== undefined ? ` (${scanProgress.completed ?? 0}/${scanProgress.total})` : ''}
                </p>
              ) : null}
              {scanProgress?.file_path ? (
                <code className="live-scan-file">{scanProgress.file_path}</code>
              ) : null}
              {liveFindings.length ? (
                <ul className="live-findings-list">
                  {liveFindings.slice(0, 8).map((finding) => (
                    <li key={`${finding.rule_id}:${finding.file_path}:${finding.line_start}:${finding.jurisdiction}`}>
                      <span className={`badge ${finding.severity}`}>{finding.severity}</span>
                      <span className="live-finding-details">
                        <strong>{finding.title}</strong>
                        <code>{finding.file_path}:{finding.line_start}</code>
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="live-scan-empty">
                  {loading ? 'No findings yet. Files are still being checked.' : 'No findings arrived before the scan stopped.'}
                </p>
              )}
              {liveFindings.length > 8 ? (
                <p className="live-scan-more">Showing the first 8 findings as they arrive.</p>
              ) : null}
            </section>
          ) : null}

          {result ? (
            <section className="results" aria-labelledby="results-title">
              <div className="results-heading">
                <div>
                  <p className="eyebrow">SCAN COMPLETE</p>
                  <h2 id="results-title">Privacy review</h2>
                  <a className="repo-link" href={result.repo.url} target="_blank" rel="noreferrer">
                    {result.repo.owner}/{result.repo.name}<span aria-hidden="true">↗</span>
                  </a>
                </div>
                <div className="result-actions">
                  <button type="button" className="button-secondary" onClick={exportJson}>Export JSON</button>
                  <button type="button" className="button-secondary" onClick={exportCsv}>Export CSV</button>
                  <button type="button" className="button-secondary" onClick={exportPdf}>Download PDF</button>
                </div>
              </div>

              <div className="summary-grid">
                <div className="summary-card">
                  <span className="summary-label">Files reviewed</span>
                  <strong>{result.summary.files_scanned}</strong>
                  <small>{result.summary.files_skipped} skipped · {result.summary.files_unsupported} unsupported</small>
                </div>
                <div className="summary-card">
                  <span className="summary-label">Privacy signals</span>
                  <strong>{result.summary.total_findings}</strong>
                  <small>Across {result.summary.jurisdictions.join(' + ')}</small>
                </div>
                <div className="summary-card generated-card">
                  <span className="summary-label">Generated</span>
                  <strong>{new Date(result.summary.generated_at).toLocaleString()}</strong>
                  <small>Branch: {result.repo.default_branch}</small>
                </div>
              </div>
              <div className="scan-metadata">
                <div className="status-summary" aria-label="Finding status counts">
                  <span>{result.summary.status_counts.potential_issue} potential issue</span>
                  <span>{result.summary.status_counts.requires_manual_review} manual review</span>
                  <span>{result.summary.legal_source_review?.annotated ?? 0} findings with UK legal source context</span>
                  <span>Rule catalog {Object.values(result.summary.compliance_mapping_versions)[0] ?? 'unknown'}</span>
                  <span>{result.summary.semgrep_available ? 'Semgrep enabled' : 'Semgrep unavailable'}</span>
                  {result.summary.ai_explanations_requested ? (
                    <span>{result.summary.ai_findings_enriched ?? 0} AI-enriched findings</span>
                  ) : null}
                  {result.summary.ml_triage?.available ? (
                    <span>ML triage v{result.summary.ml_triage.model_version}: {result.summary.ml_triage.findings_classified} findings</span>
                  ) : <span>ML triage model not trained yet</span>}
                </div>
                {Object.entries(result.summary.compliance_notices).map(([jurisdiction, notice]) => (
                  <p className="compliance-notice" key={jurisdiction}><strong>{jurisdiction}:</strong> {notice}</p>
                ))}
                {result.summary.unsupported_file_samples.length > 0 ? (
                  <details className="unsupported-files">
                    <summary>Unsupported files were not analyzed ({result.summary.files_unsupported})</summary>
                    <ul>{result.summary.unsupported_file_samples.map((path) => <li key={path}><code>{path}</code></li>)}</ul>
                  </details>
                ) : null}
                {Object.keys(result.summary.analysis_methods).length > 0 ? (
                  <p className="analysis-methods">
                    Analyzers: {Object.entries(result.summary.analysis_methods).map(([method, count]) => `${method} (${count})`).join(' · ')}
                  </p>
                ) : null}
              </div>

              <div className="severity-grid" aria-label="Finding severity counts">
                {SEVERITY_ORDER.map((level) => (
                  <button
                    type="button"
                    key={level}
                    className={`severity-card ${level} ${severityFilter === level ? 'active' : ''}`}
                    onClick={() => setSeverityFilter((current) => current === level ? 'all' : level)}
                    aria-pressed={severityFilter === level}
                  >
                    <span className={`severity-dot ${level}`} />
                    <span>{level}</span>
                    <strong>{result.summary.severity_counts[level] ?? 0}</strong>
                  </button>
                ))}
              </div>

              {result.warnings.length > 0 ? (
                <div className="warning-box">
                  <strong>Scan notes</strong>
                  <ul>{result.warnings.map((warning, index) => <li key={`${warning}-${index}`}>{warning}</li>)}</ul>
                </div>
              ) : null}

              <div className="findings-heading">
                <div>
                  <h3>Findings <span>{filteredFindings.length}</span></h3>
                  <p>{severityFilter !== 'all' || query.trim()
                    ? `Showing ${filteredFindings.length} of ${result.findings.length} findings. `
                    : ''}Review the evidence and recommended next steps.</p>
                </div>
                <div className="finding-filters">
                  <label htmlFor="finding-search" className="sr-only">Search findings</label>
                  <input
                    id="finding-search"
                    type="search"
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    placeholder="Search findings"
                  />
                  {severityFilter !== 'all' || query ? (
                    <button type="button" className="clear-filter" onClick={resetFindingFilters}>
                      Clear filters
                    </button>
                  ) : null}
                </div>
              </div>

              <div className="findings-list">
                {filteredFindings.length === 0 ? (
                  <div className="empty-state">
                    <span aria-hidden="true">✓</span>
                    <strong>{result.findings.length === 0 ? 'No privacy signals detected' : 'No matching findings'}</strong>
                    <p>{result.findings.length === 0
                      ? 'No configured rules matched the files reviewed. This is not a compliance certification.'
                      : 'Try a different search or clear the severity filter.'}</p>
                  </div>
                ) : filteredFindings.map((finding, index) => (
                  <article key={`${finding.title}-${finding.jurisdiction}-${index}`} className={`finding-card ${finding.severity}`}>
                    <div className="finding-marker" aria-hidden="true" />
                    <div className="finding-content">
                      <div className="finding-topline">
                        <span className={`badge ${finding.severity}`}>{finding.severity}</span>
                        <span className="category">{finding.category}</span>
                        <span className="jurisdiction">{finding.jurisdiction}</span>
                        {finding.ml_triage ? (
                          <span className="category">ML: {finding.ml_triage.label.replace(/_/g, ' ')} ({Math.round(finding.ml_triage.top_class_score * 100)}% model score)</span>
                        ) : null}
                      </div>
                      <h4>{finding.title}</h4>
                      <p className="finding-location">
                        <a className="source-link" href={sourceUrl(finding)} target="_blank" rel="noreferrer" title="Open this location on GitHub">
                          <code>{finding.file_path}:{finding.line_start}{finding.line_end !== finding.line_start ? `-${finding.line_end}` : ''}</code>
                          <span aria-hidden="true">↗</span>
                        </a>
                        <span>{finding.rule_id}</span>
                        <span>{Math.round(finding.confidence * 100)}% confidence</span>
                        <span className={`status-tag ${finding.status}`}>{finding.status.replace(/_/g, ' ')}</span>
                      </p>
                      <p className="legal-basis">{finding.reasoning}</p>
                      {finding.legal_context ? (
                        <details className="legal-context-details">
                          <summary>Legal source context · {finding.legal_context.sources.length} passage{finding.legal_context.sources.length === 1 ? '' : 's'}</summary>
                          <p>{finding.legal_context.message}</p>
                          {finding.legal_context.sources.map((source) => (
                            <div className="legal-source" key={`${source.document}-${source.page}`}>
                              <strong>{source.document} · {source.reference}</strong>
                              <p>{source.excerpt}</p>
                            </div>
                          ))}
                        </details>
                      ) : null}
                      {finding.relevant_legal_reference ? (
                        <p className="legal-reference">
                          Potentially relevant: <a href={finding.relevant_legal_reference.url} target="_blank" rel="noreferrer">
                            {finding.relevant_legal_reference.reference}
                          </a>
                        </p>
                      ) : null}
                      {finding.evidence ? (
                        <details className="evidence-details">
                          <summary>View redacted evidence</summary>
                          <div className="evidence-box">
                            <code>{finding.evidence}</code>
                          </div>
                        </details>
                      ) : null}
                      {finding.explanation ? <p className="ai-explanation"><strong>AI explanation</strong>{finding.explanation}</p> : null}
                      <p className="recommendation"><strong>Recommended next step</strong>{finding.recommended_fix}</p>
                      <p className="false-positive-notes"><strong>What may change this assessment:</strong> {finding.false_positive_notes}</p>
                    </div>
                  </article>
                ))}
              </div>
            </section>
          ) : null}
        </main>

        <footer className="footer">
          <span>Privacy Lens</span>
          <span>Evidence-based static analysis · Not a legal determination</span>
        </footer>
      </div>
    </div>
  );
}

export default App;
