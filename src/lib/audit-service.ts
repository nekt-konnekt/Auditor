import { AuditReport, AuditRequestPayload } from '../types/audit.ts';
import {
  calculateAuditScores,
  runCodeDeterministicAudit,
  runUrlDeterministicAudit,
} from './audit-rules.ts';
import { analyzeWithGemini } from './gemini-auditor.ts';
import { auditGitHubRepo, parseGitHubUrl } from './github-auditor.ts';

// In-memory report cache for permalinks & fast retrieval
const reportsStore = new Map<string, AuditReport>();

function generateId(): string {
  return 'aud-' + Math.random().toString(36).substring(2, 9) + Date.now().toString(36);
}

export async function executeAudit(payload: AuditRequestPayload): Promise<AuditReport> {
  const reportId = generateId();
  const createdAt = new Date().toISOString();

  let cleanTarget = payload.target.trim();

  // If payload type is 'url' or looks like a link/github repo
  if (payload.type === 'url' || cleanTarget.startsWith('http://') || cleanTarget.startsWith('https://') || cleanTarget.includes('github.com')) {
    if (!cleanTarget.startsWith('http://') && !cleanTarget.startsWith('https://')) {
      cleanTarget = 'https://' + cleanTarget;
    }

    // Check if it is a GitHub repository link!
    if (parseGitHubUrl(cleanTarget)) {
      const ghReport = await auditGitHubRepo(cleanTarget);
      reportsStore.set(ghReport.id, ghReport);
      return ghReport;
    }

    // Otherwise, inspect standard live website
    const startTime = Date.now();
    let response: Response;
    let html = '';
    const headersMap: Record<string, string> = {};

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 12000);

      response = await fetch(cleanTarget, {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 (Auditor Engine)',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
        signal: controller.signal,
        redirect: 'follow',
      });
      clearTimeout(timeoutId);

      response.headers.forEach((value, key) => {
        headersMap[key.toLowerCase()] = value;
      });

      html = await response.text();
    } catch (err: any) {
      throw new Error(`Failed to fetch URL ${cleanTarget}: ${err.message || 'Connection refused or timeout'}`);
    }

    const responseTimeMs = Date.now() - startTime;
    const { issues: detIssues, metrics } = runUrlDeterministicAudit({
      url: cleanTarget,
      statusCode: response.status,
      headers: headersMap,
      html,
      responseTimeMs,
    });

    // Run Gemini AI analysis
    const aiResult = await analyzeWithGemini('url', cleanTarget, html, {
      statusCode: response.status,
      responseTimeMs,
      headers: headersMap,
    });

    const allIssues = [...detIssues, ...aiResult.additionalIssues];
    const { overallScore, categories } = calculateAuditScores(allIssues);

    const report: AuditReport = {
      id: reportId,
      createdAt,
      target: {
        type: 'url',
        target: cleanTarget,
        statusCode: response.status,
        contentType: response.headers.get('content-type') || 'text/html',
        responseTimeMs,
        resourceSizeKb: Math.round((html.length / 1024) * 10) / 10,
      },
      overallScore,
      categories,
      summary: aiResult.summary,
      issues: allIssues,
      metrics,
    };

    reportsStore.set(reportId, report);
    return report;
  } else {
    // Direct Source Code Audit
    const code = payload.code || '';
    const filename = payload.filename || cleanTarget || 'source-file';
    const language = payload.language || 'typescript';

    if (!code.trim()) {
      throw new Error('Code content cannot be empty.');
    }

    const { issues: detIssues, metrics } = runCodeDeterministicAudit({
      code,
      language,
      filename,
    });

    const aiResult = await analyzeWithGemini('code', filename, code, {
      language,
      filename,
    });

    const allIssues = [...detIssues, ...aiResult.additionalIssues];
    const { overallScore, categories } = calculateAuditScores(allIssues);

    const report: AuditReport = {
      id: reportId,
      createdAt,
      target: {
        type: 'code',
        target: filename,
        language,
        filename,
        resourceSizeKb: Math.round((code.length / 1024) * 10) / 10,
      },
      overallScore,
      categories,
      summary: aiResult.summary,
      issues: allIssues,
      metrics,
    };

    reportsStore.set(reportId, report);
    return report;
  }
}

export function getReportById(id: string): AuditReport | null {
  return reportsStore.get(id) || null;
}

export function saveReport(report: AuditReport): void {
  reportsStore.set(report.id, report);
}
