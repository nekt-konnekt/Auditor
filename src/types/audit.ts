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

/**
 * Keep the readiness explanation consistent across the workspace and exports.
 * Severity affects diagnostic scores; only explicit blocker policy affects readiness.
 */
export function getReadinessExplanation(issues: AuditIssue[], verdict: ReadinessVerdict): string {
  const criticalHighCount = issues.filter((issue) => issue.severity === 'critical' || issue.severity === 'high').length;
  const blockerCount = issues.filter((issue) => issue.readinessBlocker === true).length;

  if (verdict === 'Not ready') {
    return `${blockerCount || 'One or more'} finding(s) are explicitly classified as launch blockers. Resolve those blockers before launch.`;
  }
  if (verdict === 'Risky') {
    return 'The readiness rules flagged a condition requiring review. Review the related findings before launch; the numeric score does not override this verdict.';
  }
  if (criticalHighCount > 0) {
    return `No finding is explicitly classified as a launch blocker by the current readiness rules. ${criticalHighCount} critical/high-severity finding(s) remain and should be reviewed; severity and readiness are separate signals.`;
  }
  return 'No finding is explicitly classified as a launch blocker by the current readiness rules. This verdict reflects only the checks performed and is not a guarantee of overall security or quality.';
}
