import assert from 'node:assert/strict';
import test from 'node:test';
import { normalizeFindingText, overlapsRuleFinding, parseAnalysis } from '../src/lib/ai-auditor.ts';

const deterministic = [
  { id: 'sec-csp', title: 'Missing Content-Security-Policy (CSP) Header' },
  { id: 'sec-hsts', title: 'Missing Strict-Transport-Security (HSTS) Header' },
];

test('normalization unifies Unicode hyphens and case', () => {
  assert.equal(normalizeFindingText('Missing Content‑Security–Policy'), 'missing content security policy');
});

test('AI duplicate of a deterministic security-header finding is filtered', () => {
  const result = parseAnalysis(JSON.stringify({
    summary: 'Reviewed the page.',
    issues: [
      {
        category: 'security',
        severity: 'high',
        title: 'Content Security Policy header is missing',
        description: 'The site does not set a CSP header.',
        remediation: 'Configure CSP.',
      },
      {
        category: 'security',
        severity: 'medium',
        title: 'Potential insecure postMessage handler',
        description: 'The source appears to accept messages without checking their origin.',
        remediation: 'Validate the message origin.',
      },
    ],
  }), 'url', deterministic);

  assert.equal(result.additionalIssues.length, 1);
  assert.match(result.additionalIssues[0].title, /postMessage/i);
});

test('AI observation is retained when no deterministic rule overlaps', () => {
  assert.equal(overlapsRuleFinding({
    id: 'ai-finding',
    title: 'Potential insecure postMessage handler',
    description: 'The source appears to accept messages without checking their origin.',
  }, deterministic), false);
});
