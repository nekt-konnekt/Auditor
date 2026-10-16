export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'passed';

export type ReadinessVerdict = 'Ready' | 'Risky' | 'Not ready';

export type Category = 'security' | 'seo' | 'accessibility' | 'performance' | 'quality';

export interface AuditIssue {
  id: string;
  category: Category;
  severity: Severity;
  /** Explicitly marks findings allowed to influence the launch-readiness verdict. */
  readinessRelevant?: boolean;
  /** True only when this finding independently blocks launch readiness. */
  readinessBlocker?: boolean;
  title: string;
  description: string;
  impact?: string;
  remediation: string;
  evidence?: string;
  lineNumber?: number;
  domSelector?: string;
  codeSnippet?: {
    original?: string;
    proposed?: string;
  };
  references?: { title: string; url: string }[];
}

export interface CategoryScore {
  category: Category;
  score: number; // 0 to 100
  passedCount: number;
  totalChecks: number;
}

export interface AuditTargetMeta {
  type: 'url' | 'code';
  target: string;
  language?: string;
  filename?: string;
  statusCode?: number;
  contentType?: string;
  responseTimeMs?: number;
  resourceSizeKb?: number;
}

export interface AuditReport {
  id: string;
  createdAt: string;
  target: AuditTargetMeta;
  overallScore: number;
  verdict: ReadinessVerdict;
  categories: Record<Category, CategoryScore>;
  summary: string;
  issues: AuditIssue[];
  /** AI-generated observations are informational and excluded from scores and diffs. */
  aiObservations?: AuditIssue[];
  metrics?: Record<string, string | number | boolean>;
}

export interface AuditRequestPayload {
  type: 'url' | 'code';
  target: string;
  code?: string;
  language?: string;
  filename?: string;
}
