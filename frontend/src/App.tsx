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

function App() {
  const [theme, setTheme] = useState<'light' | 'dark'>(() => (
    window.localStorage.getItem('privacy-lens-theme') === 'dark' ? 'dark' : 'light'
  ));
  const [repoUrl, setRepoUrl] = useState('');
  const [selectedJurisdictions, setSelectedJurisdictions] = useState<JurisdictionOption[]>(JURISDICTIONS);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all');
  const [includeExplanations, setIncludeExplanations] = useState(false);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    window.localStorage.setItem('privacy-lens-theme', theme);
  }, [theme]);

  const toggleJurisdiction = (value: JurisdictionOption) => {
    setSelectedJurisdictions((current) => (
      current.includes(value) ? current.filter((item) => item !== value) : [...current, value]
    ));
  };

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
    setQuery('');
    setSeverityFilter('all');

    try {
      const response = await fetch(`${API_BASE_URL}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repo_url: repoUrl.trim(),
          jurisdictions: selectedJurisdictions,
          include_explanations: includeExplanations,
        }),
      });

      const data: unknown = await response.json().catch(() => null);
      if (!response.ok) {
        const detail = data && typeof data === 'object' && 'detail' in data && typeof data.detail === 'string'
          ? data.detail
          : `Scan failed with status ${response.status}.`;
        throw new Error(detail);
      }
      if (!isScanResponse(data)) {
        throw new Error('The scan service returned an invalid response.');
      }
      setResult(data);
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : 'Could not complete the scan.');
    } finally {
      setLoading(false);
    }
  }

  function exportJson() {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${result.repo.owner}-${result.repo.name}-privacy-report.json`;
    anchor.click();
    URL.revokeObjectURL(url);
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
