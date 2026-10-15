import { neon } from '@neondatabase/serverless';
import type { AuditReport } from '../types/audit.ts';

const databaseUrl = process.env.DATABASE_URL;
const sql = databaseUrl ? neon(databaseUrl) : null;

const SECRET_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, label: 'AWS key' },
  { pattern: /\bsk_(?:live|test)_[A-Za-z0-9]{12,}\b/g, label: 'Stripe secret key' },
  { pattern: /\bsk-ant-[A-Za-z0-9_-]{12,}\b/g, label: 'Anthropic API key' },
  { pattern: /\b(?:sk-proj-|sk-)[A-Za-z0-9_-]{20,}\b/g, label: 'API key' },
  { pattern: /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, label: 'JWT-like token' },
  { pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, label: 'private key' },
];

export function redactSensitiveText(value: string): string {
  let redacted = value;
  for (const { pattern, label } of SECRET_PATTERNS) {
    redacted = redacted.replace(pattern, (match) => `[REDACTED ${label}: ${match.slice(0, 4)}…]`);
  }
  // Redact values assigned to common secret-bearing variable names, retaining only a 4-char prefix.
  redacted = redacted.replace(
    /((?:api[_-]?key|secret|password|token|service_role|private[_-]?key)\s*[:=]\s*["']?)([A-Za-z0-9_./+=-]{16,})/gi,
    (_match, prefix: string, secret: string) => `${prefix}[REDACTED: ${secret.slice(0, 4)}…]`,
  );
  return redacted;
}

export function sanitizeAuditReport(report: AuditReport): AuditReport {
  return {
    ...report,
    summary: redactSensitiveText(report.summary),
    issues: report.issues.map((issue) => ({
      ...issue,
      title: redactSensitiveText(issue.title),
      description: redactSensitiveText(issue.description),
      impact: issue.impact ? redactSensitiveText(issue.impact) : undefined,
      remediation: redactSensitiveText(issue.remediation),
      evidence: issue.evidence ? redactSensitiveText(issue.evidence) : undefined,
      codeSnippet: issue.codeSnippet
        ? {
            original: issue.codeSnippet.original ? redactSensitiveText(issue.codeSnippet.original) : undefined,
            proposed: issue.codeSnippet.proposed ? redactSensitiveText(issue.codeSnippet.proposed) : undefined,
          }
        : undefined,
    })),
  };
}

function ensureDatabaseConfigured(): void {
  if (!sql && process.env.NODE_ENV === 'production') {
    throw new Error('DATABASE_URL must be configured in production for durable audit reports.');
  }
}

export async function persistAuditReport(report: AuditReport): Promise<void> {
  ensureDatabaseConfigured();
  if (!sql) return;

  const safeReport = sanitizeAuditReport(report);
  const targetValue = safeReport.target.target;
  const hasExposureFinding = safeReport.issues.some((issue) =>
    /exposed secret|\.env exposed|\.git exposed|source map exposed/i.test(issue.title),
  );

  await sql`
    INSERT INTO audit_reports
      (id, created_at, target_value, target_type, verdict, overall_score, report, has_exposure_finding, is_unlisted)
    VALUES
      (${safeReport.id}, ${safeReport.createdAt}, ${targetValue}, ${safeReport.target.type},
       ${safeReport.verdict}, ${safeReport.overallScore}, ${JSON.stringify(safeReport)}::jsonb,
       ${hasExposureFinding}, ${hasExposureFinding})
    ON CONFLICT (id) DO UPDATE SET
      report = EXCLUDED.report,
      verdict = EXCLUDED.verdict,
      overall_score = EXCLUDED.overall_score,
      has_exposure_finding = EXCLUDED.has_exposure_finding,
      is_unlisted = EXCLUDED.is_unlisted
  `;
}

export async function loadAuditReport(id: string): Promise<AuditReport | null> {
  ensureDatabaseConfigured();
  if (!sql) return null;
  const rows = await sql`SELECT report FROM audit_reports WHERE id = ${id} LIMIT 1`;
  if (!rows.length) return null;
  return sanitizeAuditReport(rows[0].report as AuditReport);
}
