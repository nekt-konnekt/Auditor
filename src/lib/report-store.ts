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
    target: { ...report.target, target: redactSensitiveText(report.target.target) },
    summary: redactSensitiveText(report.summary),
    metrics: report.metrics ? Object.fromEntries(Object.entries(report.metrics).map(([key, value]) => [redactSensitiveText(key), typeof value === 'string' ? redactSensitiveText(value) : value])) : undefined,
    issues: report.issues.map((issue) => ({
      ...issue,
      title: redactSensitiveText(issue.title),
      description: redactSensitiveText(issue.description),
      impact: issue.impact ? redactSensitiveText(issue.impact) : undefined,
      remediation: redactSensitiveText(issue.remediation),
      evidence: issue.evidence ? redactSensitiveText(issue.evidence) : undefined,
      references: issue.references?.map((reference) => ({ title: redactSensitiveText(reference.title), url: redactSensitiveText(reference.url) })),
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
      created_at = EXCLUDED.created_at,
      target_value = EXCLUDED.target_value,
      target_type = EXCLUDED.target_type,
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


export type LeadStatus = 'Not contacted' | 'Contacted' | 'Replied' | 'Interested in monitoring' | 'Not interested';

export interface LeadRecord {
  auditId: string;
  status: LeadStatus;
  ownerContact: string;
  sourceNote: string;
  contactChannel: string;
  notes: string;
  updatedAt: string;
  createdAt: string;
  targetValue: string;
  targetType: 'url' | 'code';
  verdict: string;
  overallScore: number;
  hasExposureFinding: boolean;
  report: AuditReport;
}

export async function listAuditLeads(): Promise<LeadRecord[]> {
  ensureDatabaseConfigured();
  if (!sql) return [];
  const rows = await sql`
    SELECT r.id AS audit_id, r.created_at, r.target_value, r.target_type,
           r.verdict, r.overall_score, r.has_exposure_finding, r.report,
           COALESCE(l.status, 'Not contacted') AS status,
           COALESCE(l.owner_contact, '') AS owner_contact,
           COALESCE(l.source_note, '') AS source_note,
           COALESCE(l.contact_channel, '') AS contact_channel,
           COALESCE(l.notes, '') AS notes,
           COALESCE(l.updated_at, r.created_at) AS updated_at
    FROM audit_reports r
    LEFT JOIN audit_leads l ON l.audit_id = r.id
    ORDER BY r.created_at DESC
    LIMIT 200
  `;
  return rows.map((row) => ({
    auditId: String(row.audit_id),
    status: row.status as LeadStatus,
    ownerContact: String(row.owner_contact || ''),
    sourceNote: String(row.source_note || ''),
    contactChannel: String(row.contact_channel || ''),
    notes: String(row.notes || ''),
    updatedAt: new Date(row.updated_at as string).toISOString(),
    createdAt: new Date(row.created_at as string).toISOString(),
    targetValue: String(row.target_value),
    targetType: row.target_type as 'url' | 'code',
    verdict: String(row.verdict),
    overallScore: Number(row.overall_score),
    hasExposureFinding: Boolean(row.has_exposure_finding),
    report: sanitizeAuditReport(row.report as AuditReport),
  }));
}

export async function upsertAuditLead(auditId: string, lead: {
  status: LeadStatus;
  ownerContact: string;
  sourceNote: string;
  contactChannel: string;
  notes: string;
}): Promise<boolean> {
  ensureDatabaseConfigured();
  if (!sql) return false;
  const rows = await sql`SELECT id FROM audit_reports WHERE id = ${auditId} LIMIT 1`;
  if (!rows.length) return false;
  await sql`
    INSERT INTO audit_leads
      (audit_id, status, owner_contact, source_note, contact_channel, notes, updated_at)
    VALUES
      (${auditId}, ${lead.status}, ${lead.ownerContact}, ${lead.sourceNote},
       ${lead.contactChannel}, ${lead.notes}, now())
    ON CONFLICT (audit_id) DO UPDATE SET
      status = EXCLUDED.status,
      owner_contact = EXCLUDED.owner_contact,
      source_note = EXCLUDED.source_note,
      contact_channel = EXCLUDED.contact_channel,
      notes = EXCLUDED.notes,
      updated_at = now()
  `;
  return true;
}

export async function getAuditValidationMetrics(): Promise<{
  totalAudits: number;
  verdicts: Record<string, number>;
  messagesSent: number;
  replies: number;
  interested: number;
  sourceBreakdown: Array<{ sourceNote: string; audits: number; contacted: number; replies: number; interested: number }>;
}> {
  ensureDatabaseConfigured();
  if (!sql) return { totalAudits: 0, verdicts: {}, messagesSent: 0, replies: 0, interested: 0, sourceBreakdown: [] };
  const rows = await sql`
    SELECT r.verdict,
           COALESCE(l.status, 'Not contacted') AS status,
           COALESCE(l.source_note, '') AS source_note,
           COUNT(*)::int AS total
    FROM audit_reports r
    LEFT JOIN audit_leads l ON l.audit_id = r.id
    GROUP BY r.verdict, COALESCE(l.status, 'Not contacted'), COALESCE(l.source_note, '')
  `;
  const verdicts: Record<string, number> = {};
  const sources = new Map<string, { audits: number; contacted: number; replies: number; interested: number }>();
  let totalAudits = 0, messagesSent = 0, replies = 0, interested = 0;
  for (const row of rows) {
    const count = Number(row.total);
    totalAudits += count;
    verdicts[String(row.verdict)] = (verdicts[String(row.verdict)] || 0) + count;
    const status = String(row.status);
    if (status !== 'Not contacted') messagesSent += count;
    if (status === 'Replied' || status === 'Interested in monitoring') replies += count;
    if (status === 'Interested in monitoring') interested += count;
    const sourceNote = String(row.source_note || 'Unspecified');
    const source = sources.get(sourceNote) || { audits: 0, contacted: 0, replies: 0, interested: 0 };
    source.audits += count;
    if (status !== 'Not contacted') source.contacted += count;
    if (status === 'Replied' || status === 'Interested in monitoring') source.replies += count;
    if (status === 'Interested in monitoring') source.interested += count;
    sources.set(sourceNote, source);
  }
  return {
    totalAudits, verdicts, messagesSent, replies, interested,
    sourceBreakdown: [...sources.entries()].map(([sourceNote, values]) => ({ sourceNote, ...values })),
  };
}
