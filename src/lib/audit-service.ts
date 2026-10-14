import { randomUUID } from 'node:crypto';
import { AuditReport, AuditRequestPayload } from '../types/audit.ts';
import {
  calculateAuditScores,
  runCodeDeterministicAudit,
  runUrlDeterministicAudit,
} from './audit-rules.ts';
import { analyzeWithGemini } from './gemini-auditor.ts';
import { auditGitHubRepo, parseGitHubUrl } from './github-auditor.ts';
import { fetchPublicPage } from './safe-fetch.ts';

// In-memory cache is intentionally bounded. Durable shared links require a database.
const reportsStore = new Map<string, AuditReport>();
const REPORT_TTL_MS = 60 * 60 * 1000;
const MAX_REPORTS = 100;

function generateId(): string {
  return 'aud-' + randomUUID();
}

function storeReport(report: AuditReport): void {
  const now = Date.now();
  for (const [id, saved] of reportsStore) {
    if (now - Date.parse(saved.createdAt) > REPORT_TTL_MS) reportsStore.delete(id);
  }
  reportsStore.delete(report.id);
  reportsStore.set(report.id, report);
  while (reportsStore.size > MAX_REPORTS) {
    const oldestId = reportsStore.keys().next().value;
    if (!oldestId) break;
    reportsStore.delete(oldestId);
  }
}

export async function executeAudit(payload: AuditRequestPayload): Promise<AuditReport> {
  const reportId = generateId();
  const createdAt = new Date().toISOString();
  const cleanTarget = (payload.target || payload.filename || '').trim();

  if (payload.type === 'url') {
    if (!cleanTarget) throw new Error('A target URL or GitHub repository is required.');
    const normalizedTarget = /^https?:\/\//i.test(cleanTarget) ? cleanTarget : 'https://' + cleanTarget;

    if (parseGitHubUrl(normalizedTarget)) {
      const ghReport = await auditGitHubRepo(normalizedTarget);
      storeReport(ghReport);
      return ghReport;
    }

    const startTime = Date.now();
    const { url, response, html } = await fetchPublicPage(normalizedTarget);
    const responseTimeMs = Date.now() - startTime;
    const headersMap: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headersMap[key.toLowerCase()] = value;
    });

    const { issues: deterministicIssues, metrics } = runUrlDeterministicAudit({
      url: url.toString(),
      statusCode: response.status,
      headers: headersMap,
      html,
      responseTimeMs,
    });

    const aiResult = await analyzeWithGemini('url', url.toString(), html, {
      statusCode: response.status,
      responseTimeMs,
      headers: headersMap,
    });

    const allIssues = [...deterministicIssues, ...aiResult.additionalIssues];
    const { overallScore, categories } = calculateAuditScores(allIssues);
    const report: AuditReport = {
      id: reportId,
      createdAt,
      target: {
        type: 'url',
        target: url.toString(),
        statusCode: response.status,
        contentType: response.headers.get('content-type') || 'text/html',
        responseTimeMs,
        resourceSizeKb: Math.round((new TextEncoder().encode(html).byteLength / 1024) * 10) / 10,
      },
      overallScore,
      categories,
      summary: aiResult.summary,
      issues: allIssues,
      metrics,
    };

    storeReport(report);
    return report;
  }

  const code = payload.code || '';
  const filename = payload.filename || cleanTarget || 'source-file';
  const language = payload.language || 'text';
  if (!code.trim()) throw new Error('Source code content cannot be empty.');
  if (code.length > 200_000) throw new Error('Source code is limited to 200,000 characters per audit.');

  const { issues: deterministicIssues, metrics } = runCodeDeterministicAudit({ code, language, filename });
  const aiResult = await analyzeWithGemini('code', filename, code, { language, filename });
  const allIssues = [...deterministicIssues, ...aiResult.additionalIssues];
  const { overallScore, categories } = calculateAuditScores(allIssues);
  const report: AuditReport = {
    id: reportId,
    createdAt,
    target: {
      type: 'code',
      target: filename,
      language,
      filename,
      resourceSizeKb: Math.round((new TextEncoder().encode(code).byteLength / 1024) * 10) / 10,
    },
    overallScore,
    categories,
    summary: aiResult.summary,
    issues: allIssues,
    metrics,
  };

  storeReport(report);
  return report;
}

export function getReportById(id: string): AuditReport | null {
  const report = reportsStore.get(id);
  if (!report) return null;
  if (Date.now() - Date.parse(report.createdAt) > REPORT_TTL_MS) {
    reportsStore.delete(id);
    return null;
  }
  return report;
}

export function saveReport(report: AuditReport): void {
  storeReport(report);
}
