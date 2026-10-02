export interface GitHubScanRequest {
  repository_url: string;
  ref?: string;
  ai?: boolean;
  ai_mode?: string;
  ai_provider?: string;
}

export interface Project {
  path: string;
  languages: string[];
  file_count: number;
  scanned_files: string[];
  source_type: string;
  repository_url?: string;
  ref?: string;
}

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface FindingIdentity {
  id: string;
  rule_id: string;
  title: string;
}

export interface FindingLocation {
  file: string;
  line_start: number;
  line_end: number;
}

export interface FindingClassification {
  category: string;
  severity: Severity;
  confidence: number;
}

export interface FindingContext {
  function_name?: string;
  class_name?: string;
  snippet: string;
  surrounding_code?: string;
  is_test_fixture?: boolean;
}

export interface DataFlowInfo {
  sources: string[];
  sinks: string[];
  sanitizers: string[];
  propagation_path: any[]; // Using any for propagation for simplicity
}

export interface FindingRemediation {
  explanation: string;
  recommended_fix: string;
}

export interface AIAssessment {
  is_likely_vulnerable: boolean;
  confidence_adjustment: number;
  explanation: string;
  false_positive_reason?: string;
}

export interface Finding {
  identity: FindingIdentity;
  location: FindingLocation;
  classification: FindingClassification;
  context: FindingContext;
  data_flow: DataFlowInfo;
  remediation: FindingRemediation;
  ai_assessment?: AIAssessment;
  analysis_source: string[];
  relationship?: string;
}

export interface ScanSession {
  id: string;
  project: Project;
  start_time: string;
  end_time?: string;
  duration_seconds?: number;
  findings: Finding[];
  status: string;
  analysis_version?: string;
  static_rule_count?: number;
  ai_enabled?: boolean;
  ai_mode?: string;
  ai_provider?: string;
  ai_findings_count?: number;
  static_findings_count?: number;
  verified_findings_count?: number;
  ai_candidate_findings?: number;
  ai_valid_findings?: number;
  ai_rejected_findings?: number;
  ai_added_findings?: number;
  correlated_findings?: number;
  ai_correlated_findings?: number;
  duplicate_ai_findings?: number;
  ai_duplicate_findings?: number;
  invalid_ai_locations?: number;
  provider_errors?: number;
  ai_provider_errors?: number;
}
