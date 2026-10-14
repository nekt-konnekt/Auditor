import assert from 'node:assert/strict';
import test from 'node:test';
import { calculateAuditScores, runUrlDeterministicAudit } from '../src/lib/audit-rules.ts';
import type { UrlAuditInput } from '../src/lib/audit-rules.ts';

const cleanHtml = `<!doctype html>
<html lang="en">
<head>
  <title>Example product page with useful title</title>
  <meta name="description" content="A useful page description that explains the service and what visitors can do here.">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="canonical" href="https://example.com/">
  <meta property="og:title" content="Example">
  <meta property="og:image" content="https://example.com/social.png">
</head>
<body><h1>Example product</h1><img src="/logo.png" alt="Example"></body>
</html>`;

const secureHeaders: Record<string, string> = {
  'content-security-policy': "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
};

function audit(overrides: Partial<UrlAuditInput> = {}) {
  return runUrlDeterministicAudit({
    url: 'https://example.com/',
    statusCode: 200,
    headers: secureHeaders,
    html: cleanHtml,
    responseTimeMs: 300,
    ...overrides,
  });
}

test('clean HTTP 200 page passes the expected deterministic baseline checks', () => {
  const result = audit();
  assert.equal(result.metrics['HTTP Status'], 200);
  assert.equal(result.metrics['HTTP Status Class'], '2xx');
  assert.equal(result.issues.some((issue) => issue.id === 'http-server-error' || issue.id === 'http-client-error'), false);
  assert.equal(result.issues.some((issue) => issue.id === 'sec-csp-pass'), true);
  assert.equal(result.issues.some((issue) => issue.id === 'perf-ttfb-pass'), true);
});

test('HTTP 301 is recorded as a redirect-class response and is not marked as a server error', () => {
  const result = audit({ statusCode: 301 });
  assert.equal(result.metrics['HTTP Status Class'], '3xx');
  assert.equal(result.issues.some((issue) => issue.id === 'http-server-error' || issue.id === 'http-client-error'), false);
});

test('HTTP 404 is explicitly flagged as a client error response', () => {
  const result = audit({ statusCode: 404 });
  const issue = result.issues.find((item) => item.id === 'http-client-error');
  assert.equal(issue?.severity, 'high');
  assert.match(issue?.description || '', /may not represent the intended page/i);
});

test('HTTP 503 is explicitly flagged as a critical server error response', () => {
  const result = audit({ statusCode: 503, html: '<html><head><title>503: SERVICE_UNAVAILABLE</title></head><body>Unavailable</body></html>' });
  const issue = result.issues.find((item) => item.id === 'http-server-error');
  assert.equal(issue?.severity, 'critical');
  assert.match(issue?.title || '', /HTTP 503/);
  assert.equal(result.metrics['HTTP Status Class'], '5xx');
});

test('missing CSP remains a high-severity finding', () => {
  const result = audit({ headers: { ...secureHeaders, 'content-security-policy': '' } });
  assert.equal(result.issues.find((issue) => issue.id === 'sec-csp')?.severity, 'high');
});

test('a present but permissive CSP is not automatically counted as passed', () => {
  const result = audit({ headers: { ...secureHeaders, 'content-security-policy': "default-src *; script-src 'unsafe-inline' *" } });
  assert.equal(result.issues.some((issue) => issue.id === 'sec-csp-pass'), false);
  assert.equal(result.issues.find((issue) => issue.id === 'sec-csp-weak')?.severity, 'medium');
});

test('long meta descriptions are flagged while normal descriptions pass', () => {
  const longDescription = 'A'.repeat(194);
  const html = cleanHtml.replace(
    /<meta name="description" content="[^"]*">/,
    `<meta name="description" content="${longDescription}">`,
  );
  const result = audit({ html });
  assert.equal(result.issues.find((issue) => issue.id === 'seo-desc-length')?.severity, 'low');
  assert.equal(result.metrics['Meta Description Length'], 194);
});

test('a missing H1 is reported as a structural signal with calibrated medium severity', () => {
  const result = audit({ html: cleanHtml.replace('<h1>Example product</h1>', '') });
  const issue = result.issues.find((item) => item.id === 'a11y-h1-missing');
  assert.equal(issue?.severity, 'medium');
  assert.match(issue?.description || '', /not by itself proof of an accessibility failure/i);
});

test('multiple H1 elements are a low-severity observation, not an automatic failure', () => {
  const result = audit({ html: cleanHtml.replace('</body>', '<h1>Another section</h1></body>') });
  assert.equal(result.issues.find((item) => item.id === 'a11y-h1-multiple')?.severity, 'low');
});

test('large HTML payloads are measured in UTF-8 bytes and flagged', () => {
  const html = cleanHtml.replace('</body>', `${'x'.repeat(520 * 1024)}</body>`);
  const result = audit({ html });
  assert.equal(result.issues.find((item) => item.id === 'perf-html-bloat')?.severity, 'medium');
  assert.ok(Number.parseFloat(String(result.metrics['Decoded HTML Size'])) > 500);
});

test('response-time thresholds are deterministic at 800ms and 2000ms boundaries', () => {
  assert.equal(audit({ responseTimeMs: 800 }).issues.some((issue) => issue.id === 'perf-ttfb-pass'), true);
  assert.equal(audit({ responseTimeMs: 801 }).issues.find((issue) => issue.id === 'perf-moderate-ttfb')?.severity, 'medium');
  assert.equal(audit({ responseTimeMs: 2000 }).issues.some((issue) => issue.id === 'perf-moderate-ttfb' || issue.id === 'perf-slow-ttfb'), true);
  assert.equal(audit({ responseTimeMs: 2001 }).issues.find((issue) => issue.id === 'perf-slow-ttfb')?.severity, 'high');
  assert.equal(audit({ responseTimeMs: 799 }).issues.some((issue) => issue.id === 'perf-ttfb-pass'), true);
});

test('scores are severity-weighted and category pass counts remain distinct from scores', () => {
  const result = audit({ responseTimeMs: 1242 });
  const scores = calculateAuditScores(result.issues);
  assert.equal(scores.categories.performance.score, 92);
  assert.equal(scores.categories.performance.passedCount, 0);
  assert.equal(scores.categories.performance.totalChecks, 1);
  assert.equal(scores.overallScore, 98);
});
