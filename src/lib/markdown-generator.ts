import { getReadinessExplanation, type AuditReport, type Category, type Severity } from '../types/audit.ts';
import { getReadinessExplanation } from './audit-rules.ts';

const CATEGORY_NAMES: Record<Category, string> = {
  security: 'Security & Headers',
  seo: 'Search Engine Optimization (SEO)',
  accessibility: 'Accessibility & Semantics',
  performance: 'Performance & Architecture',
  quality: 'Code Quality & Robustness',
};

const SEVERITY_BADGES: Record<Severity, string> = {
  critical: '[CRITICAL]',
  high: '[HIGH]',
  medium: '[MEDIUM]',
  low: '[LOW]',
  passed: '[PASSED]',
};

export function generateAuditMarkdown(report: AuditReport): string {
  const dateFormatted = new Date(report.createdAt).toUTCString();
  const targetLabel = report.target.type === 'url' ? report.target.target : (report.target.filename || 'Code Snippet');

  const isHttpErrorResponse = report.target.type === 'url'
    && typeof report.target.statusCode === 'number'
    && report.target.statusCode >= 400;
  const scoreLabel = isHttpErrorResponse ? 'Diagnostic Score (Error Response)' : 'Severity-weighted Diagnostic Score';
  const criticalHighCount = report.issues.filter((issue) => issue.severity === 'critical' || issue.severity === 'high').length;
  const blockerCount = report.issues.filter((issue) => issue.readinessBlocker === true).length;
  const readinessExplanation = getReadinessExplanation(report.issues, report.verdict);

  let md = `# Audit Report: ${targetLabel}

- **Audit Date**: ${dateFormatted}
- **Audit ID**: \`${report.id}\`
- **Target Type**: ${report.target.type.toUpperCase()}
- **Readiness Verdict**: **${report.verdict}**
- **${scoreLabel}**: **${report.overallScore} / 100**
- **Scoring note**: This is a severity-weighted score, not the percentage of checks passed.
${report.target.responseTimeMs !== undefined ? `- **Initial HTML Fetch Duration**: ${report.target.responseTimeMs} ms\n` : ''}
${report.target.statusCode !== undefined ? `- **HTTP Status**: ${report.target.statusCode}\n` : ''}
${report.target.language ? `- **Language**: ${report.target.language}\n` : ''}
${isHttpErrorResponse ? `\n> **Target returned HTTP ${report.target.statusCode}.** This report describes the returned error response, not necessarily the intended website page. SEO and accessibility findings may not apply to the intended page.\n` : ''}

---

## Executive Summary

${report.summary}

**Readiness interpretation:** ${readinessExplanation}

**Severity review:** ${criticalHighCount} critical/high-severity finding(s); ${blockerCount} finding(s) explicitly marked as launch blockers. These counts answer different questions: severity contributes to diagnostic scoring, while the readiness verdict follows explicit blocker rules.

> Coverage limits: Auditor checks the submitted URL and may crawl a limited number of additional same-origin routes when robots.txt permits. The Performance score reflects initial HTML-fetch checks only. Browser rendering tests, Core Web Vitals or real-user performance measurement, and authenticated-flow checks are not performed. This report is not a guarantee of overall security or accessibility.

---

## Scorecard by Category

| Category | Score | Passed Checks | Status |
| :--- | :---: | :---: | :---: |
`;

  Object.entries(report.categories).forEach(([catKey, catScore]) => {
    const name = CATEGORY_NAMES[catKey as Category] || catKey;
    const scoreVal = `${catScore.score} / 100`;
    const checksVal = `${catScore.passedCount} / ${catScore.totalChecks}`;
    const status = catScore.score >= 85 ? 'Healthy' : catScore.score >= 60 ? 'Needs Attention' : 'Vulnerable';
    md += `| ${name} | ${scoreVal} | ${checksVal} | ${status} |\n`;
  });

  const isHardeningFinding = (issue: AuditReport['issues'][number]) =>
    ['sec-csp', 'sec-hsts', 'sec-xfo', 'sec-xcto', 'sec-refpolicy'].includes(issue.id);
  const hardeningFindings = report.issues.filter(isHardeningFinding);

  md += `\n---\n\n## Findings & Recommendations\n\n`;

  if (hardeningFindings.length > 0) {
    md += '### Hardening tips\n\nSecurity-header improvements affect the security score but do not change the launch-readiness verdict.\n\n';
    hardeningFindings.forEach((issue) => {
      md += `- **[${issue.severity.toUpperCase()}] ${issue.title}** — ${issue.description}\n  - **Recommended action:** ${issue.remediation}\n`;
    });
    md += '\n---\n\n';
  }

  const issuesGroupedByCat = report.issues.filter((issue) => !isHardeningFinding(issue)).reduce((acc, issue) => {
    if (!acc[issue.category]) acc[issue.category] = [];
    acc[issue.category].push(issue);
    return acc;
  }, {} as Record<Category, typeof report.issues>);

  const order: Category[] = ['security', 'seo', 'accessibility', 'performance', 'quality'];

  order.forEach((cat) => {
    const list = issuesGroupedByCat[cat];
    if (!list || list.length === 0) return;

    md += `### ${CATEGORY_NAMES[cat]}\n\n`;

    list.forEach((issue, idx) => {
      const badge = SEVERITY_BADGES[issue.severity];
      md += `#### ${idx + 1}. ${badge} ${issue.title}\n\n`;
      md += `**Severity**: \`${issue.severity.toUpperCase()}\`  \n`;
      if (issue.domSelector) {
        md += `**Target DOM**: \`${issue.domSelector}\`  \n`;
      }
      if (issue.lineNumber) {
        md += `**Line Number**: Line ${issue.lineNumber}  \n`;
      }

      md += `\n**Description**:\n${issue.description}\n\n`;

      if (issue.impact) {
        md += `**Risk / Impact**:\n${issue.impact}\n\n`;
      }

      if (issue.evidence) {
        md += `**Evidence / Observed Value**:\n\`\`\`\n${issue.evidence}\n\`\`\`\n\n`;
      }

      md += `**Remediation Recommendation**:\n${issue.remediation}\n\n`;

      if (issue.codeSnippet) {
        if (issue.codeSnippet.original) {
          md += `*Vulnerable Code Snippet*:\n\`\`\`${report.target.language || 'text'}\n${issue.codeSnippet.original}\n\`\`\`\n\n`;
        }
        if (issue.codeSnippet.proposed) {
          md += `*Proposed Fix / Solution*:\n\`\`\`${report.target.language || 'text'}\n${issue.codeSnippet.proposed}\n\`\`\`\n\n`;
        }
      }

      if (issue.references && issue.references.length > 0) {
        md += `**References**:\n`;
        issue.references.forEach((ref) => {
          md += `- [${ref.title}](${ref.url})\n`;
        });
        md += `\n`;
      }

      md += `---\n\n`;
    });
  });

  md += `\n*Report generated by Auditor Web & Code Intelligence Platform.*`;
  return md;
}
