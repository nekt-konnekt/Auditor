import { randomUUID } from 'node:crypto';
import type { AuditReport, AuditRequestPayload } from '../types/audit.ts';
import {
  calculateAuditScores,
  runCodeDeterministicAudit,
  runUrlDeterministicAudit,
} from './audit-rules.ts';
import { analyzeWithAI } from './ai-auditor.ts';
import { auditGitHubRepo, parseGitHubUrl } from './github-auditor.ts';
import { fetchPublicPage, validatePublicHttpUrl } from './safe-fetch.ts';
import { inspectReadinessPreflight } from './readiness-preflight.ts';
import { scanPublicExposure } from './exposure-scan.ts';
import { detectPlatform, getPlatformGuidance } from './platform-detection.ts';
import { crawlAdditionalRoutes, MAX_ADDITIONAL_ROUTES } from './route-crawler.ts';
import { loadAuditReport, persistAuditReport, redactSensitiveText, sanitizeAuditReport } from './report-store.ts';

// In-memory cache is intentionally bounded. Durable shared links require a database.
const reportsStore = new Map<string, AuditReport>();
const REPORT_TTL_MS = 60 * 60 * 1000;
const MAX_REPORTS = 100;

function generateId(): string {
  return 'aud-' + randomUUID();
}


/**
 * Collapse duplicate representations of the same URL rule. Deterministic rules
 * are authoritative; AI findings are retained only when they describe a distinct
 * issue. Route-specific findings remain separate because their IDs include a route.
 */
function canonicalFindingKey(issue: AuditReport['issues'][number]): string {
  const text = `${issue.category} ${issue.title} ${issue.id}`.toLowerCase();
  const rules: Array<[RegExp, string]> = [
    [/content.?security.?policy|\bcsp\b/, 'security:csp'],
    [/strict.?transport.?security|\bhsts\b/, 'security:hsts'],
    [/x.?frame.?options|clickjack|frame.?ancestors/, 'security:frame-protection'],
    [/x.?content.?type.?options|mime.?type.?sniff/, 'security:nosniff'],
    [/referrer.?policy|referrer header/, 'security:referrer-policy'],
    [/meta description/, 'seo:meta-description'],
    [/open.?graph|social card|og:title|og:image/, 'seo:open-graph'],
    [/canonical/, 'seo:canonical'],
    [/heading structure|missing.*h1|primary heading|heading element/, 'accessibility:h1'],
    [/cache.?control|caching directives/, 'performance:cache-control'],
  ];
  const matched = rules.find(([pattern]) => pattern.test(text));
  if (matched) return matched[1];
  // IDs are more stable than generated prose for all other rules.
  return issue.id.replace(/-route-[a-z0-9_-]+$/i, '');
}

function deduplicateFindings(issues: AuditReport['issues']): AuditReport['issues'] {
  const result: AuditReport['issues'] = [];
  const positions = new Map<string, number>();
  for (const issue of issues) {
    const key = canonicalFindingKey(issue);
    const existingIndex = positions.get(key);
    if (existingIndex === undefined) {
      positions.set(key, result.length);
      result.push(issue);
      continue;
    }
    const existing = result[existingIndex];
    // Prefer deterministic, evidence-backed findings over paraphrased AI copies.
    const existingDeterministic = /^(sec-|seo-|a11y-|perf-|tls-|domain-)/.test(existing.id);
    const incomingDeterministic = /^(sec-|seo-|a11y-|perf-|tls-|domain-)/.test(issue.id);
    if (incomingDeterministic && !existingDeterministic) result[existingIndex] = issue;
  }
  return result;
}

async function storeReport(report: AuditReport): Promise<void> {
  const now = Date.now();
  for (const [id, saved] of reportsStore) {
    if (now - Date.parse(saved.createdAt) > REPORT_TTL_MS) reportsStore.delete(id);
  }
  await persistAuditReport(report);
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
      const ghReport = sanitizeAuditReport(await auditGitHubRepo(normalizedTarget));
      await storeReport(ghReport);
      return ghReport;
    }

    const preflightUrl = await validatePublicHttpUrl(normalizedTarget);
    const preflight = await inspectReadinessPreflight(preflightUrl);

    // Never fetch page content over TLS when the certificate probe found it invalid.
    if (preflightUrl.protocol === 'https:' && preflight.tlsValid === false) {
      const { overallScore, categories, verdict } = calculateAuditScores(preflight.issues);
      const report: AuditReport = {
        id: reportId,
        createdAt,
        target: { type: 'url', target: preflightUrl.toString() },
        overallScore,
        verdict,
        categories,
        summary: 'Auditor completed a passive TLS/domain preflight but did not fetch page content because the TLS certificate failed validation. Page-level SEO, accessibility, headers, exposure, and route checks were not performed.',
        issues: preflight.issues,
        metrics: { ...preflight.metrics, 'Page Content Fetch': 'Not performed: TLS validation failed', 'Route Coverage': 'Not performed' },
      };
      const safeReport = sanitizeAuditReport(report);
      await storeReport(safeReport);
      return safeReport;
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

    const exposureResult = await scanPublicExposure(url, html);
    const platformSignals = detectPlatform(headersMap, html);
    const platformIssues = platformSignals.platforms.length
      ? [{ id: 'platform-fingerprint', category: 'quality' as const, severity: 'passed' as const, title: 'Platform Signals Detected', description: 'Auditor identified likely platform or infrastructure signals from public response headers and markup. Fingerprints are indicative, not definitive.', evidence: platformSignals.evidence.join('; '), remediation: getPlatformGuidance(platformSignals.platforms).join(' ') || 'Use these signals to select platform-specific deployment guidance, and confirm the platform from your hosting configuration.' }]
      : [];

    // Error pages are useful to inspect, but AI analysis can mistake their markup
    // for the intended page. Keep these reports deterministic and label their limits.
    const aiResult = response.ok
      ? await analyzeWithAI('url', url.toString(), redactSensitiveText(html), {
          statusCode: response.status,
          responseTimeMs,
          headers: headersMap,
          ruleBasedFindings: deterministicIssues.map(({ id, title }) => ({ id, title })),
        })
      : {
          summary: `The target returned HTTP ${response.status}. This report describes the returned error response, not necessarily the intended website page. Resolve the HTTP status and rerun the audit before relying on SEO or accessibility conclusions.`,
          additionalIssues: [],
        };

    const routeCrawl = await crawlAdditionalRoutes(url, html);
    const routeIssues = routeCrawl.routes.flatMap((route) => {
      const routeAudit = runUrlDeterministicAudit({
        url: route.url.toString(),
        statusCode: route.statusCode,
        headers: route.headers,
        html: route.html,
        responseTimeMs: route.responseTimeMs,
      });
      const routeLabel = route.url.pathname;
      return routeAudit.issues.map((issue) => ({
        ...issue,
        id: `${issue.id}-route-${Buffer.from(routeLabel).toString('base64url').slice(0, 24)}`,
        title: `[${routeLabel}] ${issue.title}`,
        description: `Route check for ${route.url.toString()}. ${issue.description}`,
      }));
    });
    const ruleBasedIssues = deduplicateFindings([...preflight.issues, ...exposureResult.issues, ...platformIssues, ...deterministicIssues, ...routeIssues]);
    const aiObservations = aiResult.additionalIssues.filter((issue) => !canonicalFindingKey(issue).startsWith('security:') && !canonicalFindingKey(issue).startsWith('seo:') && !canonicalFindingKey(issue).startsWith('accessibility:') && !canonicalFindingKey(issue).startsWith('performance:'));
    const { overallScore, categories, verdict } = calculateAuditScores(ruleBasedIssues);
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
      verdict,
      categories,
      summary: aiResult.summary,
      issues: ruleBasedIssues,
      aiObservations,
      metrics: { ...preflight.metrics, ...metrics, ...exposureResult.metrics, 'Route Coverage': `${routeCrawl.routes.length + 1} page(s) audited (submitted page plus ${routeCrawl.routes.length} additional routes)`, 'Additional Routes Attempted': routeCrawl.attempted, 'Additional Route Budget': MAX_ADDITIONAL_ROUTES, 'Robots.txt': routeCrawl.robotsStatus === 'checked' ? 'Checked before discovering additional same-origin routes' : 'Unavailable; additional route discovery skipped', 'Browser Runtime Checks': 'Not performed', 'Detected Platforms': platformSignals.platforms.join(', ') || 'No reliable fingerprint detected' },
    };

    const safeReport = sanitizeAuditReport(report);
    await storeReport(safeReport);
    return safeReport;
  }

  const code = payload.code || '';
  const filename = payload.filename || cleanTarget || 'source-file';
  const language = payload.language || 'text';
  if (!code.trim()) throw new Error('Source code content cannot be empty.');
  if (code.length > 200_000) throw new Error('Source code is limited to 200,000 characters per audit.');

  const { issues: deterministicIssues, metrics } = runCodeDeterministicAudit({ code, language, filename });
  const aiResult = await analyzeWithAI('code', filename, redactSensitiveText(code), {
    language,
    filename,
    ruleBasedFindings: deterministicIssues.map(({ id, title }) => ({ id, title })),
  });
  const allIssues = deduplicateFindings(deterministicIssues);
  const aiObservations = aiResult.additionalIssues;
  const { overallScore, categories, verdict } = calculateAuditScores(allIssues);
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
    verdict,
    categories,
    summary: aiResult.summary,
    issues: allIssues,
    aiObservations,
    metrics,
  };

  const safeReport = sanitizeAuditReport(report);
  await storeReport(safeReport);
  return safeReport;
}

export async function getReportById(id: string): Promise<AuditReport | null> {
  const report = reportsStore.get(id);
  if (report && Date.now() - Date.parse(report.createdAt) <= REPORT_TTL_MS) return report;
  if (report) reportsStore.delete(id);
  const saved = await loadAuditReport(id);
  if (!saved) return null;
  reportsStore.set(id, saved);
  while (reportsStore.size > MAX_REPORTS) {
    const oldestId = reportsStore.keys().next().value;
    if (!oldestId) break;
    reportsStore.delete(oldestId);
  }
  return saved;
}

export async function saveReport(report: AuditReport): Promise<void> {
  await storeReport(sanitizeAuditReport(report));
}
