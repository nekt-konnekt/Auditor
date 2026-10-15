import assert from 'node:assert/strict';
import test from 'node:test';
import { redactSensitiveText, sanitizeAuditReport } from '../src/lib/report-store.ts';
import type { AuditReport } from '../src/types/audit.ts';

test('secret redaction removes the entire credential rather than retaining a prefix', () => {
  const key = 'AKIA1234567890ABCDEF';
  const output = redactSensitiveText(`AWS_ACCESS_KEY_ID=${key}`);
  assert.equal(output.includes(key), false);
  assert.equal(output.includes(key.slice(0, 4)), false);
  assert.match(output, /\[REDACTED AWS key\]/);
});

test('report sanitization redacts secrets from summary, evidence, and code snippets', () => {
  const key = 'sk_live_abcdefghijklmnopQRSTUV';
  const report = {
    id: 'test-report',
    createdAt: new Date(0).toISOString(),
    target: { type: 'code', target: 'app.ts' },
    overallScore: 50,
    verdict: 'Risky',
    categories: {},
    summary: `Found ${key} in the public bundle`,
    issues: [{
      id: 'secret',
      category: 'security',
      severity: 'critical',
      title: 'Secret-like value detected',
      description: 'Credential should be rotated.',
      remediation: 'Rotate the credential and remove it from public assets.',
      evidence: `const API_KEY = "${key}"`,
      codeSnippet: { original: `const API_KEY = "${key}"` },
    }],
  } as unknown as AuditReport;
  const safe = sanitizeAuditReport(report);
  const serialized = JSON.stringify(safe);
  assert.equal(serialized.includes(key), false);
  assert.equal(serialized.includes(key.slice(0, 4)), false);
  assert.match(serialized, /\[REDACTED/);
});
