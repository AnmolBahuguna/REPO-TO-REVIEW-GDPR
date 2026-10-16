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
