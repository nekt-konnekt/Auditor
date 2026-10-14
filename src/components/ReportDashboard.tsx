import React, { useState } from 'react';
import { AuditIssue, AuditReport, Category, Severity } from '../types/audit.ts';

interface ReportDashboardProps {
  report: AuditReport;
  onBackToStudio: () => void;
  onOpenMarkdown: () => void;
}

export const ReportDashboard: React.FC<ReportDashboardProps> = ({
  report,
  onBackToStudio,
  onOpenMarkdown,
}) => {
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedLink, setCopiedLink] = useState(false);
  const [copiedSnippetId, setCopiedSnippetId] = useState<string | null>(null);
  const [expandedIssueIds, setExpandedIssueIds] = useState<Set<string>>(new Set());

  const toggleExpand = (id: string) => {
    const next = new Set(expandedIssueIds);
    if (next.has(id)) {
      next.delete(id);
    } else {
      next.add(id);
    }
    setExpandedIssueIds(next);
  };

  const handleShareLink = () => {
    const shareUrl = window.location.origin + '?auditId=' + report.id;
    navigator.clipboard.writeText(shareUrl);
    setCopiedLink(true);
    setTimeout(() => setCopiedLink(false), 2000);
  };

  const handleCopyCode = (snippet: string, id: string) => {
    navigator.clipboard.writeText(snippet);
    setCopiedSnippetId(id);
    setTimeout(() => setCopiedSnippetId(null), 2000);
  };

  const severityCounts = report.issues.reduce((acc, issue) => {
    acc[issue.severity] = (acc[issue.severity] || 0) + 1;
    return acc;
  }, {} as Record<Severity, number>);

  const filteredIssues = report.issues.filter((issue) => {
    if (selectedSeverity !== 'all' && issue.severity !== selectedSeverity) {
      return false;
    }
    if (selectedCategory !== 'all' && issue.category !== selectedCategory) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTitle = issue.title.toLowerCase().includes(q);
      const matchDesc = issue.description.toLowerCase().includes(q);
      const matchRem = issue.remediation.toLowerCase().includes(q);
      if (!matchTitle && !matchDesc && !matchRem) return false;
    }
    return true;
  });

  const getSeverityBadge = (severity: Severity) => {
    switch (severity) {
      case 'critical':
        return {
          label: 'CRITICAL',
          textClass: 'text-rose-700 font-bold',
        };
      case 'high':
        return {
          label: 'HIGH',
          textClass: 'text-orange-700 font-semibold',
        };
      case 'medium':
        return {
          label: 'MEDIUM',
          textClass: 'text-amber-700 font-medium',
        };
      case 'low':
        return {
          label: 'LOW',
          textClass: 'text-slate-700 font-medium',
        };
      case 'passed':
        return {
          label: 'PASSED',
          textClass: 'text-emerald-700 font-medium',
        };
    }
  };

  const targetLabel =
    report.target.type === 'url'
      ? report.target.target
      : report.target.filename || (report.target.type === 'repository' ? 'GitHub Repository' : 'Source Code File');
  const isHttpErrorResponse = report.target.type === 'url'
    && typeof report.target.statusCode === 'number'
    && report.target.statusCode >= 400;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-200">
        <div>
          <button
            onClick={onBackToStudio}
            className="text-xs font-semibold text-slate-500 hover:text-slate-900 transition-colors mb-2 inline-block"
          >
            Back to Audit Workspace
          </button>
          <div className="flex items-baseline gap-3">
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight font-mono truncate max-w-2xl">
              {targetLabel}
            </h1>
          </div>
          <div className="flex items-center gap-2 mt-1.5 text-xs text-slate-500 font-mono">
            <span>Audit ID: {report.id}</span>
            <span aria-hidden="true">·</span>
            <span>{new Date(report.createdAt).toUTCString()}</span>
            {report.target.responseTimeMs && (
              <>
                <span aria-hidden="true">·</span>
                <span className="tabular-nums">{report.target.responseTimeMs} ms fetch</span>
              </>
            )}
            {report.target.statusCode && (
              <>
                <span aria-hidden="true">·</span>
                <span>HTTP {report.target.statusCode}</span>
              </>
            )}
            {report.target.resourceSizeKb && (
              <>
                <span aria-hidden="true">·</span>
                <span className="tabular-nums">{report.target.resourceSizeKb} KB</span>
              </>
            )}
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2.5 shrink-0">
          <button
            onClick={handleShareLink}
            className="px-3.5 py-2 text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-slate-300 rounded-lg shadow-2xs transition-colors"
          >
            {copiedLink ? 'Link Copied' : 'Share Permalink'}
          </button>

          <button
            onClick={onOpenMarkdown}
            className="px-3.5 py-2 text-xs font-medium text-slate-900 bg-slate-100 hover:bg-slate-200 border border-slate-300 rounded-lg shadow-2xs transition-colors"
          >
            Markdown View
          </button>

          <a
            href={`/api/report/${report.id}/md?download=true`}
            download={`audit-report-${report.id}.md`}
            className="px-3.5 py-2 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-lg shadow-2xs transition-colors"
          >
            Download .md
          </a>
        </div>
      </div>

      {isHttpErrorResponse && (
        <div role="alert" className="p-5 rounded-xl border border-rose-300 bg-rose-50 text-rose-950">
          <p className="text-sm font-bold uppercase tracking-wide">HTTP {report.target.statusCode} — target returned an error</p>
          <p className="mt-1 text-sm leading-relaxed">This scan inspected the error response, not necessarily the intended website page. The score below is diagnostic only and must not be read as an overall website-health score. SEO and accessibility findings may describe the error page.</p>
        </div>
      )}

      {/* KPI Scores Row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {/* Overall Score */}
        <div className="col-span-2 md:col-span-1 p-5 rounded-xl border border-slate-200 bg-white shadow-2xs">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block">
            {isHttpErrorResponse ? 'Diagnostic Score · Error Response' : report.target.type === 'repository' ? 'Repository Hygiene Score' : report.target.type === 'code' ? 'Code Diagnostic Score' : 'Overall Health'}
          </span>
          <div className="mt-2 flex items-baseline gap-1">
            <span className="text-4xl font-extrabold text-slate-900 font-mono tabular-nums">
              {report.overallScore}
            </span>
            <span className="text-sm font-medium text-slate-400 font-mono">/100</span>
          </div>
          <p className="mt-2 text-[11px] leading-relaxed text-slate-500">Severity-weighted score, not the percentage of checks passed.</p>
          <div className="mt-3">
            <div className="w-full bg-slate-100 rounded-full h-1.5 overflow-hidden">
              <div
                className={`h-1.5 rounded-full ${
                  report.overallScore >= 80
                    ? 'bg-emerald-600'
                    : report.overallScore >= 50
                    ? 'bg-amber-500'
                    : 'bg-rose-600'
                }`}
                style={{ width: `${report.overallScore}%` }}
              />
            </div>
          </div>
        </div>

        {/* Security Category */}
        <div className="p-5 rounded-xl border border-slate-200 bg-white shadow-2xs">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block">
            Security & Headers
          </span>
          <div className="mt-2 flex items-baseline gap-1">
            <span className="text-3xl font-extrabold text-slate-900 font-mono tabular-nums">
              {report.categories.security?.score ?? 100}
            </span>
            <span className="text-xs font-medium text-slate-400 font-mono">/100</span>
          </div>
          <p className="mt-2 text-xs text-slate-500 font-mono">
            {report.categories.security?.passedCount ?? 0} / {report.categories.security?.totalChecks ?? 0} checks passed · {Math.max(0, (report.categories.security?.totalChecks ?? 0) - (report.categories.security?.passedCount ?? 0))} issues
          </p>
        </div>

        {/* SEO Category */}
        <div className="p-5 rounded-xl border border-slate-200 bg-white shadow-2xs">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block">
            Search SEO
          </span>
          <div className="mt-2 flex items-baseline gap-1">
            <span className="text-3xl font-extrabold text-slate-900 font-mono tabular-nums">
              {report.categories.seo?.score ?? 100}
            </span>
            <span className="text-xs font-medium text-slate-400 font-mono">/100</span>
          </div>
          <p className="mt-2 text-xs text-slate-500 font-mono">
            {report.categories.seo?.passedCount ?? 0} / {report.categories.seo?.totalChecks ?? 0} checks passed · {Math.max(0, (report.categories.seo?.totalChecks ?? 0) - (report.categories.seo?.passedCount ?? 0))} issues
          </p>
        </div>

        {/* Accessibility Category */}
        <div className="p-5 rounded-xl border border-slate-200 bg-white shadow-2xs">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block">
            Accessibility
          </span>
          <div className="mt-2 flex items-baseline gap-1">
            <span className="text-3xl font-extrabold text-slate-900 font-mono tabular-nums">
              {report.categories.accessibility?.score ?? 100}
            </span>
            <span className="text-xs font-medium text-slate-400 font-mono">/100</span>
          </div>
          <p className="mt-2 text-xs text-slate-500 font-mono">
            {report.categories.accessibility?.passedCount ?? 0} / {report.categories.accessibility?.totalChecks ?? 0} checks passed · {Math.max(0, (report.categories.accessibility?.totalChecks ?? 0) - (report.categories.accessibility?.passedCount ?? 0))} issues
          </p>
        </div>

        {/* Performance / Quality Category */}
        <div className="p-5 rounded-xl border border-slate-200 bg-white shadow-2xs">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block">
            {report.target.type === 'url' ? 'Performance' : report.target.type === 'repository' ? 'Repository Quality' : 'Code Quality'}
          </span>
          <div className="mt-2 flex items-baseline gap-1">
            <span className="text-3xl font-extrabold text-slate-900 font-mono tabular-nums">
              {report.target.type === 'url'
                ? report.categories.performance?.score ?? 100
                : report.categories.quality?.score ?? 100}
            </span>
            <span className="text-xs font-medium text-slate-400 font-mono">/100</span>
          </div>
          <p className="mt-2 text-xs text-slate-500 font-mono">
            {report.target.type === 'url'
              ? `${report.categories.performance?.passedCount ?? 0} / ${report.categories.performance?.totalChecks ?? 0} checks passed · ${Math.max(0, (report.categories.performance?.totalChecks ?? 0) - (report.categories.performance?.passedCount ?? 0))} issues`
              : `${report.categories.quality?.passedCount ?? 0} / ${report.categories.quality?.totalChecks ?? 0} checks passed · ${Math.max(0, (report.categories.quality?.totalChecks ?? 0) - (report.categories.quality?.passedCount ?? 0))} issues`}
          </p>
        </div>
      </div>

      {/* Executive Summary */}
      <div className="p-6 rounded-xl border border-slate-200 bg-white shadow-2xs">
        <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider mb-2">
          Executive Diagnostic Summary
        </h2>
        <p className="text-sm text-slate-700 leading-relaxed">
          {report.summary}
        </p>
        <p className="mt-3 text-xs leading-relaxed text-slate-500">{report.target.type === 'url' ? 'Not performed: browser rendering tests, Core Web Vitals or real-user performance measurement, authenticated-flow checks, and audits of other routes. This report evaluates listed rules against the submitted URL response; it is not a guarantee of overall security or accessibility.' : report.target.type === 'repository' ? 'Coverage: public repository metadata and selected root-level files on the default branch only. Not performed: full source-tree or git-history scanning, secret scanning across all files, dependency vulnerability database checks, private repository review, or deployed runtime testing. This is a repository-hygiene review, not a complete security audit.' : 'Coverage: only the supplied source-code snippet was inspected. Not performed: full-repository review, dependency analysis, build/runtime testing, authentication-flow review, or validation of surrounding application context. Findings are diagnostic signals, not proof of exploitability or a guarantee that other issues are absent.'}</p>

        {report.metrics && Object.keys(report.metrics).length > 0 && (
          <div className="mt-5 pt-4 border-t border-slate-100 flex flex-wrap gap-x-6 gap-y-2 text-xs text-slate-600 font-mono">
            {Object.entries(report.metrics).map(([key, value]) => (
              <div key={key}>
                <span className="text-slate-400">{key}:</span>{' '}
                <span className="font-semibold text-slate-800">{String(value)}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Filter and Findings Controls */}
      <div className="space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          {/* Severity Filter Tabs */}
          <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-lg overflow-x-auto">
            <button
              onClick={() => setSelectedSeverity('all')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                selectedSeverity === 'all'
                  ? 'bg-white text-slate-900 shadow-2xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              All Findings ({report.issues.length})
            </button>
            <button
              onClick={() => setSelectedSeverity('critical')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                selectedSeverity === 'critical'
                  ? 'bg-white text-rose-700 font-semibold shadow-2xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Critical ({severityCounts.critical || 0})
            </button>
            <button
              onClick={() => setSelectedSeverity('high')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                selectedSeverity === 'high'
                  ? 'bg-white text-orange-700 font-semibold shadow-2xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              High ({severityCounts.high || 0})
            </button>
            <button
              onClick={() => setSelectedSeverity('medium')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                selectedSeverity === 'medium'
                  ? 'bg-white text-amber-700 font-semibold shadow-2xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Medium ({severityCounts.medium || 0})
            </button>
            <button
              onClick={() => setSelectedSeverity('low')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                selectedSeverity === 'low'
                  ? 'bg-white text-slate-900 font-semibold shadow-2xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Low ({severityCounts.low || 0})
            </button>
            <button
              onClick={() => setSelectedSeverity('passed')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                selectedSeverity === 'passed'
                  ? 'bg-white text-emerald-700 font-semibold shadow-2xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Passed ({severityCounts.passed || 0})
            </button>
          </div>

          {/* Search Box */}
          <div className="w-full md:w-72">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search findings or fixes..."
              className="w-full px-3 py-1.5 text-xs bg-white border border-slate-200 rounded-lg text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-emerald-500 font-mono"
            />
          </div>
        </div>

        {/* Category Tabs */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs font-medium text-slate-600">
          <span className="text-slate-400 mr-1">Category:</span>
          <button
            onClick={() => setSelectedCategory('all')}
            className={`px-2.5 py-1 rounded-md transition-colors whitespace-nowrap ${
              selectedCategory === 'all'
                ? 'bg-slate-900 text-white font-semibold'
                : 'bg-slate-100 hover:bg-slate-200 text-slate-700'
            }`}
          >
            All Categories
          </button>
          <button
            onClick={() => setSelectedCategory('security')}
            className={`px-2.5 py-1 rounded-md transition-colors whitespace-nowrap ${
              selectedCategory === 'security'
                ? 'bg-slate-900 text-white font-semibold'
                : 'bg-slate-100 hover:bg-slate-200 text-slate-700'
            }`}
          >
            Security & Headers
          </button>
          <button
            onClick={() => setSelectedCategory('seo')}
            className={`px-2.5 py-1 rounded-md transition-colors whitespace-nowrap ${
              selectedCategory === 'seo'
                ? 'bg-slate-900 text-white font-semibold'
                : 'bg-slate-100 hover:bg-slate-200 text-slate-700'
            }`}
          >
            Search SEO
          </button>
          <button
            onClick={() => setSelectedCategory('accessibility')}
            className={`px-2.5 py-1 rounded-md transition-colors whitespace-nowrap ${
              selectedCategory === 'accessibility'
                ? 'bg-slate-900 text-white font-semibold'
                : 'bg-slate-100 hover:bg-slate-200 text-slate-700'
            }`}
          >
            Accessibility
          </button>
          <button
            onClick={() => setSelectedCategory('performance')}
            className={`px-2.5 py-1 rounded-md transition-colors whitespace-nowrap ${
              selectedCategory === 'performance'
                ? 'bg-slate-900 text-white font-semibold'
                : 'bg-slate-100 hover:bg-slate-200 text-slate-700'
            }`}
          >
            Performance
          </button>
          <button
            onClick={() => setSelectedCategory('quality')}
            className={`px-2.5 py-1 rounded-md transition-colors whitespace-nowrap ${
              selectedCategory === 'quality'
                ? 'bg-slate-900 text-white font-semibold'
                : 'bg-slate-100 hover:bg-slate-200 text-slate-700'
            }`}
          >
            Code Quality
          </button>
        </div>
      </div>

      {/* Issues List */}
      <div className="space-y-4">
        {filteredIssues.length === 0 ? (
          <div className="p-12 text-center bg-white border border-slate-200 rounded-xl">
            <h3 className="text-sm font-semibold text-slate-900">
              No matching findings
            </h3>
            <p className="text-xs text-slate-500 mt-1">
              Try adjusting your search criteria or severity filters.
            </p>
          </div>
        ) : (
          filteredIssues.map((issue) => {
            const badge = getSeverityBadge(issue.severity);
            const isExpanded = expandedIssueIds.has(issue.id) || issue.severity === 'critical';

            return (
              <div
                key={issue.id}
                className={`bg-white border rounded-xl overflow-hidden shadow-2xs transition-all ${
                  issue.severity === 'critical'
                    ? 'border-rose-200'
                    : issue.severity === 'passed'
                    ? 'border-emerald-200'
                    : 'border-slate-200'
                }`}
              >
                {/* Header Row */}
                <div
                  onClick={() => toggleExpand(issue.id)}
                  className="p-5 cursor-pointer hover:bg-slate-50/60 transition-colors flex items-start justify-between gap-4"
                >
                  <div className="space-y-1.5 flex-1 min-w-0">
                    <div className="flex items-center gap-2 text-xs font-mono">
                      <span className={badge.textClass}>
                        [{badge.label}]
                      </span>
                      <span className="text-slate-300" aria-hidden="true">·</span>
                      <span className="text-slate-500 capitalize">{issue.category}</span>
                      {issue.lineNumber && (
                        <>
                          <span className="text-slate-300" aria-hidden="true">·</span>
                          <span className="text-slate-500">Line {issue.lineNumber}</span>
                        </>
                      )}
                      {issue.domSelector && (
                        <>
                          <span className="text-slate-300" aria-hidden="true">·</span>
                          <span className="text-slate-500 truncate max-w-xs">{issue.domSelector}</span>
                        </>
                      )}
                    </div>

                    <h3 className="text-base font-bold text-slate-900 leading-snug">
                      {issue.title}
                    </h3>

                    <p className="text-xs text-slate-600 leading-relaxed">
                      {issue.description}
                    </p>
                  </div>

                  <span className="text-xs font-mono text-slate-400 hover:text-slate-600 shrink-0 mt-1">
                    {isExpanded ? '[-]' : '[+]'}
                  </span>
                </div>

                {/* Collapsible Expanded Body */}
                {isExpanded && (
                  <div className="px-5 pb-5 pt-2 border-t border-slate-100 bg-slate-50/40 space-y-4">
                    {/* Impact / Risk */}
                    {issue.impact && (
                      <div>
                        <span className="text-xs font-semibold text-slate-700 uppercase tracking-wider block mb-1">
                          Risk Impact
                        </span>
                        <p className="text-xs text-slate-600 leading-relaxed bg-white p-3 rounded-lg border border-slate-200">
                          {issue.impact}
                        </p>
                      </div>
                    )}

                    {/* Observed Evidence */}
                    {issue.evidence && (
                      <div>
                        <span className="text-xs font-semibold text-slate-700 uppercase tracking-wider block mb-1">
                          Evidence / Observed Value
                        </span>
                        <pre className="text-xs font-mono text-slate-800 bg-white p-3 rounded-lg border border-slate-200 overflow-x-auto">
                          {issue.evidence}
                        </pre>
                      </div>
                    )}

                    {/* Remediation Guide */}
                    <div>
                      <span className="text-xs font-semibold text-slate-700 uppercase tracking-wider block mb-1">
                        Remediation Action
                      </span>
                      <p className="text-xs text-slate-700 leading-relaxed bg-emerald-50/40 p-3 rounded-lg border border-emerald-200/60">
                        {issue.remediation}
                      </p>
                    </div>

                    {/* Code Snippets & Diff Fix */}
                    {issue.codeSnippet && (
                      <div className="space-y-2">
                        {issue.codeSnippet.original && (
                          <div>
                            <span className="text-xs font-semibold text-slate-600 block mb-1 font-mono">
                              Vulnerable Snippet:
                            </span>
                            <pre className="text-xs font-mono text-rose-900 bg-rose-50/70 p-3 rounded-lg border border-rose-200 overflow-x-auto">
                              {issue.codeSnippet.original}
                            </pre>
                          </div>
                        )}

                        {issue.codeSnippet.proposed && (
                          <div>
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-xs font-semibold text-emerald-800 font-mono">
                                Proposed Secure Fix:
                              </span>
                              <button
                                onClick={() => handleCopyCode(issue.codeSnippet!.proposed!, issue.id)}
                                className="text-xs text-emerald-700 hover:text-emerald-900 font-mono cursor-pointer"
                              >
                                {copiedSnippetId === issue.id ? 'Copied' : 'Copy Fix'}
                              </button>
                            </div>
                            <pre className="text-xs font-mono text-emerald-950 bg-emerald-50 p-3 rounded-lg border border-emerald-200 overflow-x-auto">
                              {issue.codeSnippet.proposed}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}

                    {/* References */}
                    {issue.references && issue.references.length > 0 && (
                      <div className="pt-2 flex flex-wrap items-center gap-3 text-xs text-slate-500">
                        <span className="font-semibold text-slate-700">Standards & References:</span>
                        {issue.references.map((ref, idx) => (
                          <a
                            key={idx}
                            href={ref.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-emerald-700 hover:underline"
                          >
                            {ref.title}
                          </a>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
