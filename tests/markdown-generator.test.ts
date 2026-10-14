import assert from 'node:assert/strict';
import test from 'node:test';
import { generateAuditMarkdown } from '../src/lib/markdown-generator.ts';
import { AuditReport, Category } from '../src/types/audit.ts';

const categories: Category[] = ['security', 'seo', 'accessibility', 'performance', 'quality'];

test('Markdown scorecard does not present issue-record counts as checks passed', () => {
  const report: AuditReport = {
    id: 'scorecard-regression',
    createdAt: '2026-01-01T00:00:00.000Z',
    target: { type: 'url', target: 'https://example.com' },
    overallScore: 92,
    summary: 'A diagnostic summary.',
    issues: [
      {
        id: 'one-passed-record',
        category: 'security',
        severity: 'passed',
        title: 'Header observed',
        description: 'A header was observed.',
        remediation: 'Keep it configured.',
      },
      {
        id: 'one-finding-record',
        category: 'security',
        severity: 'medium',
        title: 'Another header was missing',
        description: 'The header was not observed.',
        remediation: 'Configure the header.',
      },
    ],
    categories: Object.fromEntries(categories.map((category) => [
      category,
      {
        category,
        score: category === 'security' ? 92 : 100,
        passedCount: category === 'security' ? 1 : 0,
        totalChecks: category === 'security' ? 2 : 0,
      },
    ])) as AuditReport['categories'],
  };

  const markdown = generateAuditMarkdown(report);
  assert.match(markdown, /\| Category \| Score \| Status \|/);
  assert.doesNotMatch(markdown, /Passed Checks/);
  assert.doesNotMatch(markdown, /1 \/ 2/);
});
