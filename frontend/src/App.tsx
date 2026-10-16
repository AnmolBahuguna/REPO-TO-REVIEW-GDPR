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
