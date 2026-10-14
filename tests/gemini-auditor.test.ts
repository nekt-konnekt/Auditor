import assert from 'node:assert/strict';
import test from 'node:test';
import { analyzeWithGemini, filterEvidenceBackedIssues } from '../src/lib/gemini-auditor.ts';

const candidate = {
  category: 'security',
  severity: 'high',
  title: 'Potential unsafe operation',
  description: 'The supplied source contains a potentially unsafe operation.',
  remediation: 'Validate inputs and review the call context.',
  evidence: 'dangerouslySetInnerHTML',
};

test('AI findings without evidence from the supplied snapshot are discarded', () => {
  const result = filterEvidenceBackedIssues([
    { ...candidate, evidence: 'imaginarySecretFunction()' },
  ], 'code', 'const view = <div />;', {});
  assert.equal(result.length, 0);
});

test('AI findings with exact observed evidence are retained with evidence attached', () => {
  const result = filterEvidenceBackedIssues([
    candidate,
  ], 'code', 'return <div dangerouslySetInnerHTML={{ __html: value }} />;', {});
  assert.equal(result.length, 1);
  assert.equal(result[0].evidence, 'dangerouslySetInnerHTML');
  assert.match(result[0].title, /^Potential \(AI-assisted\):/);
  assert.match(result[0].description, /not independently validated/i);
});


test('AI-generated critical severity is capped until independently validated', () => {
  const result = filterEvidenceBackedIssues([
    { ...candidate, severity: 'critical' },
  ], 'code', 'dangerouslySetInnerHTML', {});
  assert.equal(result[0].severity, 'high');
});

test('AI-generated passed findings are discarded even when evidence is present', () => {
  const result = filterEvidenceBackedIssues([
    { ...candidate, severity: 'passed' },
  ], 'code', 'dangerouslySetInnerHTML', {});
  assert.equal(result.length, 0);
});

test('website findings can cite observed response headers', () => {
  const result = filterEvidenceBackedIssues([
    { ...candidate, evidence: 'strict-transport-security', severity: 'medium' },
  ], 'url', '<html><body>Example</body></html>', {
    headers: { 'strict-transport-security': 'max-age=31536000' },
  });
  assert.equal(result.length, 1);
});

test('fallback summary describes selected checks without claiming a comprehensive OWASP audit', async () => {
  const previousKey = process.env.GEMINI_API_KEY;
  delete process.env.GEMINI_API_KEY;
  try {
    const result = await analyzeWithGemini('code', 'example.ts', 'const value = 1;', {
      filename: 'example.ts',
      language: 'typescript',
    });
    assert.match(result.summary, /Selected deterministic pattern checks ran on the supplied snippet/i);
    assert.doesNotMatch(result.summary, /comprehensive|OWASP patterns/i);
  } finally {
    if (previousKey === undefined) delete process.env.GEMINI_API_KEY;
    else process.env.GEMINI_API_KEY = previousKey;
  }
});
