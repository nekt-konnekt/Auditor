import * as cheerio from 'cheerio';
import type { AuditIssue } from '../types/audit.ts';
import { fetchPublicResource } from './safe-fetch.ts';

const MAX_PROBES = 10;
const MAX_BUNDLES = 5;
const DOMAIN_DELAY_MS = 200;
const lastRequestAt = new Map<string, number>();

const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: 'AWS access key', pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: 'Stripe secret key', pattern: /\bsk_(?:live|test)_[A-Za-z0-9]{12,}\b/g },
  { name: 'OpenAI-style API key', pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { name: 'Anthropic API key', pattern: /\bsk-ant-[A-Za-z0-9_-]{12,}\b/g },
  { name: 'Supabase service-role key', pattern: /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { name: 'private key block', pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { name: 'secret-like assigned token', pattern: /(?:service_role|api[_-]?key|secret|private[_-]?key|access[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{24,})/gi },
];

export interface ExposureScanResult {
  issues: AuditIssue[];
  metrics: Record<string, string | number | boolean>;
}

async function politeFetch(url: string, origin: string) {
  const hostname = new URL(url).hostname;
  const previous = lastRequestAt.get(hostname) || 0;
  const waitMs = DOMAIN_DELAY_MS - (Date.now() - previous);
  if (waitMs > 0) await new Promise((resolve) => setTimeout(resolve, waitMs));
  lastRequestAt.set(hostname, Date.now());
  return fetchPublicResource(url, origin);
}

function isHtml(contentType: string, body: string): boolean {
  return /text\/html|application\/xhtml\+xml/i.test(contentType)
    || /^\s*(?:<!doctype html|<html\b)/i.test(body);
}

function maskSecret(value: string): string {
  return value.length <= 4 ? '[REDACTED]' : `${value.slice(0, 4)}…[REDACTED]`;
}

export function detectExposureSecrets(body: string): Array<{ name: string; preview: string }> {
  const matches: Array<{ name: string; preview: string }> = [];
  for (const item of SECRET_PATTERNS) {
    // Reset state because global regex instances retain lastIndex between calls.
    item.pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = item.pattern.exec(body)) !== null && matches.length < 20) {
      const secret = match[1] || match[0];
      matches.push({ name: item.name, preview: maskSecret(secret) });
      if (!match[0].length) item.pattern.lastIndex += 1;
    }
  }
  return matches;
}

/**
 * Passive-only exposure checks. Paths are confirmed by content signatures rather
 * than HTTP 200 alone, so SPA fallback pages don't become false positives.
 * Secret values never enter issue evidence or metrics.
 */
export async function scanPublicExposure(baseUrl: URL, html: string): Promise<ExposureScanResult> {
  const issues: AuditIssue[] = [];
  const metrics: Record<string, string | number | boolean> = {};
  let requests = 0;
  let confirmedPaths = 0;
  let bundlesScanned = 0;
  let sourceMapsFound = 0;

  const probes = [
    { path: '/.env', label: '.env', signature: (body: string) => /(?:^|\n)\s*(?:DATABASE_URL|API_KEY|SECRET_KEY|SUPABASE_SERVICE_ROLE_KEY|STRIPE_SECRET_KEY|AWS_ACCESS_KEY_ID)\s*=/i.test(body) },
    { path: '/.git/config', label: '.git/config', signature: (body: string) => /\[core\]\s*[\s\S]{0,500}repositoryformatversion\s*=\s*\d+/i.test(body) || /\[remote "[^"]+"\]/i.test(body) },
    { path: '/.DS_Store', label: '.DS_Store', signature: (body: string) => body.startsWith('Bud1') || body.includes('BOOK') },
    { path: '/.aws/credentials', label: '.aws/credentials', signature: (body: string) => /^\s*\[[^\]]+\]\s*(?:\r?\n)\s*(?:aws_access_key_id|aws_secret_access_key)\s*=/im.test(body) },
  ];

  for (const probe of probes) {
    if (requests >= MAX_PROBES) break;
    requests += 1;
    const result = await politeFetch(new URL(probe.path, baseUrl).toString(), baseUrl.origin).catch(() => null);
    if (!result || result.status !== 200 || !result.body || isHtml(result.contentType, result.body) || !probe.signature(result.body)) continue;
    confirmedPaths += 1;
    issues.push({
      id: `exposure-path-${probe.label.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}`,
      category: 'security',
      severity: 'critical',
      readinessRelevant: true,
      readinessBlocker: true,
      title: `Confirmed Public Exposure: ${probe.label}`,
      description: `A passive request to ${probe.label} returned content matching the expected sensitive-file signature. HTTP 200 alone was not used as confirmation.`,
      evidence: `Confirmed signature at ${result.url.toString()}`,
      remediation: 'Remove the sensitive file from the public deployment, block direct access at the hosting layer, and rotate any credentials that may have been exposed.',
      references: [{ title: 'OWASP Sensitive Data Exposure', url: 'https://owasp.org/www-project-top-ten/' }],
    });
  }

  const $ = cheerio.load(html);
  const bundleUrls = new Set<string>();
  $('script[src]').each((_index, element) => {
    const src = $(element).attr('src');
    if (!src || bundleUrls.size >= MAX_BUNDLES) return;
    try {
      const url = new URL(src, baseUrl);
      if (url.origin === baseUrl.origin && /\.(?:m?js)(?:\?|$)/i.test(url.href)) bundleUrls.add(url.toString());
    } catch {
      // Ignore malformed script references.
    }
  });

  for (const bundleUrl of bundleUrls) {
    if (requests >= MAX_PROBES) break;
    requests += 1;
    const bundle = await politeFetch(bundleUrl, baseUrl.origin).catch(() => null);
    if (!bundle || bundle.status !== 200 || !bundle.body || isHtml(bundle.contentType, bundle.body)) continue;
    bundlesScanned += 1;

    const matches = detectExposureSecrets(bundle.body);
    for (const match of matches) {
      issues.push({
        id: `exposure-secret-${bundlesScanned}-${issues.length + 1}`,
        category: 'security',
        severity: 'critical',
        readinessRelevant: true,
        title: `Potential Exposed ${match.name}`,
        description: `A public JavaScript asset contains a value matching a ${match.name} pattern. The value has been masked and is not included in the report.`,
        evidence: `Masked preview: ${match.preview}; asset: ${bundle.url.toString()}`,
        remediation: 'Remove the secret from client-delivered code, revoke and rotate the credential immediately, and move privileged operations to a trusted server-side environment.',
      });
    }

    const mapReference = bundle.body.match(/[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)/);
    if (mapReference && requests < MAX_PROBES) {
      let mapUrl: URL | null = null;
      try {
        mapUrl = new URL(mapReference[1], bundle.url);
      } catch {
        // Ignore malformed source-map references from untrusted public bundles.
      }
      if (mapUrl && mapUrl.origin === baseUrl.origin && /\.map(?:\?|$)/i.test(mapUrl.href)) {
        requests += 1;
        const mapResult = await politeFetch(mapUrl.toString(), baseUrl.origin).catch(() => null);
        if (mapResult?.status === 200 && mapResult.body && !isHtml(mapResult.contentType, mapResult.body)
          && (/"sources"\s*:\s*\[/.test(mapResult.body) || /"version"\s*:\s*3/.test(mapResult.body))) {
          sourceMapsFound += 1;
          issues.push({
            id: `exposure-source-map-${sourceMapsFound}`,
            category: 'security',
            severity: 'high',
            readinessRelevant: true,
            title: 'Public JavaScript Source Map',
            description: 'A same-origin JavaScript source map is publicly retrievable and matches source-map content signatures.',
            evidence: `Confirmed source map at ${mapResult.url.toString()}`,
            remediation: 'Disable production source-map publication or restrict access if the source map exposes proprietary implementation details or sensitive comments.',
          });
          for (const match of detectExposureSecrets(mapResult.body)) {
            issues.push({
              id: `exposure-map-secret-${sourceMapsFound}-${issues.length + 1}`,
              category: 'security',
              severity: 'critical',
              readinessRelevant: true,
              title: `Potential Exposed ${match.name} in Source Map`,
              description: `A public source map contains a value matching a ${match.name} pattern. The value has been masked and is not included in the report.`,
              evidence: `Masked preview: ${match.preview}; source map: ${mapResult.url.toString()}`,
              remediation: 'Remove the secret from client-delivered code, revoke and rotate the credential immediately, and disable public source-map publication.',
            });
          }
        }
      }
    }
  }

  metrics['Exposure Probe Requests'] = requests;
  metrics['Confirmed Sensitive Paths'] = confirmedPaths;
  metrics['JavaScript Bundles Scanned'] = bundlesScanned;
  metrics['Public Source Maps'] = sourceMapsFound;
  metrics['Exposure Scan'] = 'Passive same-origin probes and bounded JavaScript/source-map scan';
  return { issues, metrics };
}
