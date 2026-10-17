import type { AuditReport, AuditIssue, Category } from '../types/audit.ts';

const CATEGORY_LABELS: Record<Category, string> = {
  security: 'Security & Headers',
  seo: 'Search Engine Optimization',
  accessibility: 'Accessibility',
  performance: 'Performance',
  quality: 'Code Quality',
};

const escapeHtml = (value: unknown): string =>
  String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

const paragraph = (label: string, value?: string) =>
  value ? `<div class="detail"><h4>${escapeHtml(label)}</h4><p>${escapeHtml(value)}</p></div>` : '';

function issueHtml(issue: AuditIssue): string {
  const severity = issue.severity.toUpperCase();
  return `<article class="finding">
    <div class="finding-top"><span class="severity severity-${escapeHtml(issue.severity)}">${escapeHtml(severity)}</span><span class="category">${escapeHtml(CATEGORY_LABELS[issue.category])}</span></div>
    <h3>${escapeHtml(issue.title)}</h3>
    <p>${escapeHtml(issue.description)}</p>
    ${paragraph('Risk / Impact', issue.impact)}
    ${paragraph('Evidence / Observed Value', issue.evidence)}
    ${paragraph('Recommended Remediation', issue.remediation)}
    ${issue.domSelector ? paragraph('DOM Selector', issue.domSelector) : ''}
    ${issue.lineNumber ? paragraph('Line Number', String(issue.lineNumber)) : ''}
    ${issue.codeSnippet?.original ? `<div class="detail"><h4>Original Code</h4><pre>${escapeHtml(issue.codeSnippet.original)}</pre></div>` : ''}
    ${issue.codeSnippet?.proposed ? `<div class="detail"><h4>Proposed Fix</h4><pre>${escapeHtml(issue.codeSnippet.proposed)}</pre></div>` : ''}
    ${issue.references?.length ? `<div class="detail"><h4>References</h4><ul>${issue.references.map(ref => `<li><a href="${escapeHtml(ref.url)}">${escapeHtml(ref.title)}</a></li>`).join('')}</ul></div>` : ''}
  </article>`;
}

/**
 * Opens a print-optimized, structured audit report. The browser's Print dialog
 * lets the user save a high-quality PDF without changing report data or scores.
 */
export function downloadAuditPdf(report: AuditReport): void {
  const printWindow = window.open('', '_blank');
  if (!printWindow) {
    window.alert('The PDF report window was blocked. Allow pop-ups for Auditor, then try again.');
    return;
  }

  const target = report.target.type === 'url'
    ? report.target.target
    : (report.target.filename || 'Source Code File');
  const date = new Date(report.createdAt).toUTCString();
  const isHttpError = report.target.type === 'url' && (report.target.statusCode ?? 0) >= 400;
  const categoryRows = (Object.entries(report.categories) as [Category, AuditReport['categories'][Category]][])
    .map(([key, score]) => `<tr><td>${escapeHtml(CATEGORY_LABELS[key])}</td><td>${score.score}/100</td><td>${score.passedCount} / ${score.totalChecks}</td><td>${score.score >= 85 ? 'Healthy' : score.score >= 60 ? 'Needs attention' : 'Vulnerable'}</td></tr>`)
    .join('');
  const hardeningIds = ['sec-csp', 'sec-hsts', 'sec-xfo', 'sec-xcto', 'sec-refpolicy'];
  const hardening = report.issues.filter(issue => hardeningIds.includes(issue.id));
  const findings = report.issues.filter(issue => !hardeningIds.includes(issue.id));
  const metrics = report.metrics && Object.keys(report.metrics).length
    ? `<div class="metrics">${Object.entries(report.metrics).map(([key, value]) => `<span><b>${escapeHtml(key)}:</b> ${escapeHtml(value)}</span>`).join('')}</div>`
    : '';
  const errorNotice = isHttpError
    ? `<div class="notice danger">HTTP ${report.target.statusCode}: this report describes the returned error response, not necessarily the intended website page. Treat the score as diagnostic only.</div>`
    : '';
  const hardeningSection = hardening.length
    ? `<section><h2>Security hardening tips</h2><p class="muted">These improvements affect the security score but do not independently change the launch-readiness verdict.</p>${hardening.map(issueHtml).join('')}</section>`
    : '';
  const observations = report.aiObservations?.length
    ? `<section><h2>AI observations</h2><p class="muted">Informational observations; excluded from scores and diffs.</p>${report.aiObservations.map(issueHtml).join('')}</section>`
    : '';

  printWindow.document.open();
  printWindow.document.write(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Auditor Report — ${escapeHtml(target)}</title>
<style>
@page{size:A4;margin:18mm 16mm 20mm}*{box-sizing:border-box}body{font-family:Arial,Helvetica,sans-serif;color:#172033;font-size:10pt;line-height:1.55;margin:0}h1,h2,h3,h4,p{margin-top:0}h1{font-size:27pt;line-height:1.15;letter-spacing:-.5pt;margin:12px 0;color:#10253f;overflow-wrap:anywhere}h2{font-size:16pt;color:#10253f;border-bottom:2px solid #0f766e;padding-bottom:7px;margin:0 0 12px}h3{font-size:12pt;line-height:1.35;margin:8px 0;color:#10253f;overflow-wrap:anywhere}h4{font-size:8pt;text-transform:uppercase;letter-spacing:.7px;color:#526174;margin:0 0 3px}p{margin-bottom:8px;overflow-wrap:anywhere}.cover{min-height:235mm;display:flex;flex-direction:column;justify-content:space-between;page-break-after:always}.brand{font-size:11pt;font-weight:800;letter-spacing:2px;color:#0f766e}.eyebrow{font-size:9pt;text-transform:uppercase;letter-spacing:1.8px;color:#64748b;font-weight:700;margin-top:65px}.meta{border-top:1px solid #dbe3ec;padding-top:15px;color:#526174;font-size:9pt}.meta div{margin:5px 0;overflow-wrap:anywhere}.verdict{display:inline-block;border-radius:4px;padding:5px 10px;font-weight:800;font-size:10pt;background:#e2e8f0;color:#334155}.verdict.ready{background:#d1fae5;color:#065f46}.verdict.risky{background:#fef3c7;color:#92400e}.verdict.not-ready{background:#ffe4e6;color:#9f1239}.score{font-size:39pt;font-weight:800;line-height:1.1;color:#10253f;margin:15px 0 5px}.subtle{color:#64748b;font-size:9pt}.section{margin:0 0 20px}.card{border:1px solid #dbe3ec;border-radius:8px;padding:14px;margin:12px 0}.notice{padding:11px 13px;border-left:4px solid #0f766e;background:#f0fdfa;margin:12px 0}.notice.danger{border-color:#be123c;background:#fff1f2}.score-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.score-card{border:1px solid #dbe3ec;border-radius:7px;padding:10px}.score-card b{display:block;font-size:17pt;color:#10253f}.score-card span{font-size:8pt;color:#526174}.metrics{display:flex;flex-wrap:wrap;gap:8px 18px;padding-top:10px;margin-top:12px;border-top:1px solid #e2e8f0;font-size:8pt}.table-wrap{width:100%}table{border-collapse:collapse;width:100%;font-size:9pt;margin:10px 0 18px}th{background:#10253f;color:white;text-align:left;font-weight:700}td,th{padding:8px;border:1px solid #dbe3ec;vertical-align:top}tr{break-inside:avoid}.finding{border:1px solid #dbe3ec;border-radius:7px;padding:13px;margin:11px 0 14px;break-inside:avoid}.finding-top{display:flex;gap:8px;align-items:center;margin-bottom:5px}.severity{font-size:8pt;font-weight:800;letter-spacing:.4px}.severity-critical,.severity-high{color:#b91c1c}.severity-medium{color:#a16207}.severity-low{color:#475569}.severity-passed{color:#047857}.category,.muted{font-size:9pt;color:#64748b}.detail{margin-top:10px;break-inside:avoid}.detail p{margin-bottom:0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f8fafc;border:1px solid #e2e8f0;padding:9px;border-radius:5px;font-size:8pt}a{color:#0f766e;overflow-wrap:anywhere}.footer{margin-top:25px;padding-top:8px;border-top:1px solid #dbe3ec;color:#64748b;font-size:8pt}.small{font-size:8.5pt;color:#526174}.section,.finding{break-inside:auto} .finding h3{break-after:avoid}.finding-top{break-after:avoid}@media print{body{-webkit-print-color-adjust:exact;print-color-adjust:exact}.no-print{display:none!important}a{color:#0f766e}.finding{break-inside:avoid}h2{break-after:avoid}}
</style></head><body>
<div class="cover"><div><div class="brand">AUDITOR <span style="color:#64748b;font-weight:400">/ LAUNCH READINESS</span></div><div class="eyebrow">Website &amp; Code Diagnostic Report</div><h1>${escapeHtml(target)}</h1><p class="subtle">Structured findings, evidence, risk context, and recommended remediation.</p><div class="card"><div class="subtle">LAUNCH READINESS</div><div style="margin-top:7px"><span class="verdict ${report.verdict === 'Ready' ? 'ready' : report.verdict === 'Risky' ? 'risky' : 'not-ready'}">${escapeHtml(report.verdict)}</span></div><div class="score">${report.overallScore}<span style="font-size:15pt;color:#64748b"> / 100</span></div><div class="subtle">Severity-weighted diagnostic score; not the percentage of checks passed.</div></div></div><div class="meta"><div><b>Audit ID:</b> ${escapeHtml(report.id)}</div><div><b>Audit date:</b> ${escapeHtml(date)}</div><div><b>Target type:</b> ${escapeHtml(report.target.type.toUpperCase())}</div>${report.target.statusCode !== undefined ? `<div><b>HTTP status:</b> ${report.target.statusCode}</div>` : ''}${report.target.responseTimeMs !== undefined ? `<div><b>Initial HTML fetch:</b> ${report.target.responseTimeMs} ms</div>` : ''}${report.target.resourceSizeKb !== undefined ? `<div><b>Resource size:</b> ${report.target.resourceSizeKb} KB</div>` : ''}<div style="margin-top:16px">Generated by Auditor Web &amp; Code Intelligence Platform</div></div></div>
<main>
${errorNotice}
<section class="section"><h2>Executive Summary</h2><p>${escapeHtml(report.summary)}</p><div class="score-grid"><div class="score-card"><span>OVERALL SCORE</span><b>${report.overallScore}/100</b></div><div class="score-card"><span>FINDINGS</span><b>${report.issues.length}</b></div><div class="score-card"><span>CRITICAL / HIGH</span><b>${report.issues.filter(i => i.severity === 'critical' || i.severity === 'high').length}</b></div><div class="score-card"><span>AI OBSERVATIONS</span><b>${report.aiObservations?.length ?? 0}</b></div></div>${metrics}</section>
<section class="section"><h2>Category Scorecard</h2><div class="table-wrap"><table><thead><tr><th>Category</th><th>Score</th><th>Checks passed</th><th>Status</th></tr></thead><tbody>${categoryRows}</tbody></table></div></section>
<section class="section"><h2>Findings &amp; Recommendations</h2>${findings.length ? findings.map(issueHtml).join('') : '<p>No additional findings were recorded.</p>'}</section>
${hardeningSection}${observations}
<section class="section"><h2>Methodology &amp; Scope</h2><p>This report summarizes the structured audit data produced by Auditor for the submitted target. The original readiness verdict, category scores, and finding severities are presented without recalculation.</p><p class="small">Coverage limits: browser rendering tests, Core Web Vitals or real-user performance measurement, authenticated-flow checks, and comprehensive testing of all routes are not performed. This report is not a guarantee of overall security or accessibility. For URL audits, findings may reflect only the fetched response and permitted checks.</p>${isHttpError ? '<p class="small">Because the target returned an HTTP error status, findings may describe an error page rather than the intended website.</p>' : ''}</section>
<div class="footer">Auditor · Report ID ${escapeHtml(report.id)} · ${escapeHtml(date)}</div>
</main><script>window.addEventListener('load',()=>setTimeout(()=>window.print(),350));</script></body></html>`);
  printWindow.document.close();
}
