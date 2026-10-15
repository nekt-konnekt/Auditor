/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar.tsx';
import { AuditForm } from './components/AuditForm.tsx';
import { ReportDashboard } from './components/ReportDashboard.tsx';
import { MarkdownModal } from './components/MarkdownModal.tsx';
import { AuditHistoryModal } from './components/AuditHistoryModal.tsx';
import { AuditReport, AuditRequestPayload } from './types/audit.ts';

const STORAGE_KEY = 'auditor_history_reports_v1';

export default function App() {
  const [currentView, setCurrentView] = useState<'form' | 'report' | 'batch'>('form');
  const [batchTargets, setBatchTargets] = useState('');
  const [batchLoading, setBatchLoading] = useState(false);
  const [batchError, setBatchError] = useState<string | null>(null);
  const [batchResults, setBatchResults] = useState<Array<{ index: number; target: string; report?: AuditReport; error?: string }>>([]);
  const [activeReport, setActiveReport] = useState<AuditReport | null>(null);
  const [historyReports, setHistoryReports] = useState<AuditReport[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isMarkdownModalOpen, setIsMarkdownModalOpen] = useState(false);
  const [isHistoryModalOpen, setIsHistoryModalOpen] = useState(false);

  // Load history from localStorage on mount
  useEffect(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed)) {
          setHistoryReports(parsed);
        }
      }
    } catch (e) {
      console.warn('Failed to parse audit history from localStorage:', e);
    }

    // Check for auditId in URL query parameters (permalink sharing)
    const params = new URLSearchParams(window.location.search);
    const auditId = params.get('auditId');
    if (auditId) {
      fetchReportById(auditId);
    }
  }, []);

  const saveReportToHistory = (newReport: AuditReport) => {
    setHistoryReports((prev) => {
      const filtered = prev.filter((r) => r.id !== newReport.id);
      const updated = [newReport, ...filtered].slice(0, 25); // keep latest 25
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
      } catch (err) {
        console.warn('LocalStorage save failed:', err);
      }
      return updated;
    });
  };

  const fetchReportById = async (id: string) => {
    setIsLoading(true);
    try {
      const res = await fetch(`/api/report/${id}`);
      if (!res.ok) {
        throw new Error('Report not found');
      }
      const data: AuditReport = await res.json();
      setActiveReport(data);
      setCurrentView('report');
    } catch (err) {
      console.warn('Failed to load shared report:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleStartAudit = async (payload: AuditRequestPayload) => {
    setIsLoading(true);
    try {
      const response = await fetch('/api/audit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errJson = await response.json().catch(() => ({}));
        throw new Error(errJson.error || `HTTP error ${response.status}`);
      }

      const report: AuditReport = await response.json();
      setActiveReport(report);
      saveReportToHistory(report);
      setCurrentView('report');

      // Update URL query string without reloading
      const url = new URL(window.location.href);
      url.searchParams.set('auditId', report.id);
      window.history.pushState({}, '', url.toString());
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } finally {
      setIsLoading(false);
    }
  };

  const handleRunBatch = async () => {
    const targets = [...new Set(batchTargets.split(/\r?\n/).map((value) => value.trim()).filter(Boolean))];
    if (!targets.length) {
      setBatchError('Paste at least one public URL, one per line.');
      return;
    }
    if (targets.length > 20) {
      setBatchError('Batch audits support up to 20 unique URLs at a time.');
      return;
    }
    setBatchError(null);
    setBatchLoading(true);
    setBatchResults([]);
    try {
      const response = await fetch('/api/audit/batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targets: targets.map((target) => ({ target })) }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || `Batch request failed (HTTP ${response.status}).`);
      const results = Array.isArray(data.results) ? data.results as Array<{ index: number; target: string; report?: AuditReport; error?: string }> : [];
      setBatchResults(results);
      results.forEach((item) => { if (item.report) saveReportToHistory(item.report); });
    } catch (error) {
      setBatchError(error instanceof Error ? error.message : 'Batch audit failed. Try again.');
    } finally {
      setBatchLoading(false);
    }
  };

  const handleNewAudit = () => {
    setCurrentView('form');
    // Clear URL query
    const url = new URL(window.location.href);
    url.searchParams.delete('auditId');
    window.history.pushState({}, '', url.toString());
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleSelectHistoryReport = (report: AuditReport) => {
    setActiveReport(report);
    setCurrentView('report');
    const url = new URL(window.location.href);
    url.searchParams.set('auditId', report.id);
    window.history.pushState({}, '', url.toString());
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleClearHistory = () => {
    setHistoryReports([]);
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch (e) {
      // ignore
    }
  };

  const handleDeleteHistoryReport = (id: string) => {
    setHistoryReports((prev) => {
      const updated = prev.filter((r) => r.id !== id);
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
      } catch (e) {
        // ignore
      }
      return updated;
    });
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 text-slate-900 font-sans">
      <Navbar
        onNewAudit={handleNewAudit}
        onOpenHistory={() => setIsHistoryModalOpen(true)}
        onOpenBatch={() => { setCurrentView('batch'); setActiveReport(null); }}
        historyCount={historyReports.length}
        currentView={currentView}
        onNavigateHome={handleNewAudit}
      />

      <main className="flex-1">
        {currentView === 'batch' ? (
          <section className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
            <div className="max-w-3xl mb-8"><p className="text-xs font-semibold tracking-[0.2em] uppercase text-emerald-700 mb-3">Auditor / Batch workflow</p><h1 className="text-3xl font-extrabold tracking-tight">Audit multiple public sites</h1><p className="mt-3 text-slate-600">Paste up to 20 URLs, one per line. Each site is processed independently, so one failed target will not stop the rest. Audits are passive and read-only.</p></div>
            <div className="bg-white border border-slate-200 rounded-xl p-5 sm:p-7 shadow-sm">
              <label htmlFor="batch-targets" className="block text-sm font-semibold text-slate-800 mb-2">Target URLs</label>
              <textarea id="batch-targets" value={batchTargets} onChange={(event) => setBatchTargets(event.target.value)} disabled={batchLoading} rows={8} placeholder={'https://example.com\nhttps://another-site.com'} className="w-full rounded-lg border border-slate-300 p-3 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500 disabled:bg-slate-50" />
              <div className="mt-2 flex items-center justify-between text-xs text-slate-500"><span>Duplicates are removed automatically.</span><span>{batchTargets.split(/\r?\n/).map((value) => value.trim()).filter(Boolean).length} / 20 URLs</span></div>
              {batchError && <p role="alert" className="mt-4 rounded-lg border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">{batchError}</p>}
              <div className="mt-5 flex flex-wrap items-center gap-3"><button onClick={handleRunBatch} disabled={batchLoading} className="rounded-lg bg-slate-900 px-5 py-3 text-sm font-semibold text-white hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60">{batchLoading ? 'Running batch…' : 'Run batch audit'}</button>{batchLoading && <span className="text-sm text-slate-500">Limited concurrency is enabled. Results appear when the batch completes.</span>}</div>
            </div>
            {batchResults.length > 0 && <div className="mt-8 bg-white border border-slate-200 rounded-xl overflow-hidden"><div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between gap-4"><h2 className="font-bold text-slate-900">Batch results</h2><span className="text-sm text-slate-500">{batchResults.filter((item) => item.report).length} of {batchResults.length} completed</span></div><div className="overflow-x-auto"><table className="w-full text-sm"><thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500"><tr><th className="px-5 py-3">URL</th><th className="px-5 py-3">Verdict</th><th className="px-5 py-3">Score</th><th className="px-5 py-3">Worst finding</th><th className="px-5 py-3">Status</th></tr></thead><tbody className="divide-y divide-slate-100">{[...batchResults].sort((a, b) => { const rank = (item: typeof a) => item.report?.verdict === 'Not ready' ? 0 : item.report?.verdict === 'Risky' ? 1 : item.report?.verdict === 'Ready' ? 2 : 3; return rank(a) - rank(b) || a.index - b.index; }).map((item) => { const worst = item.report?.issues.filter((issue) => issue.severity !== 'passed').sort((a, b) => ({ critical: 0, high: 1, medium: 2, low: 3, passed: 4 }[a.severity] - { critical: 0, high: 1, medium: 2, low: 3, passed: 4 }[b.severity])[0]; return <tr key={item.index} className="align-top"><td className="px-5 py-4 max-w-xs break-all font-mono text-xs">{item.target}</td><td className="px-5 py-4 font-semibold">{item.report?.verdict || '—'}</td><td className="px-5 py-4 tabular-nums">{item.report ? item.report.overallScore : '—'}</td><td className="px-5 py-4">{worst?.title || (item.report ? 'No failing findings' : item.error || 'Audit failed')}</td><td className="px-5 py-4"><span className={item.report ? 'text-emerald-700' : 'text-rose-700'}>{item.report ? 'Complete' : 'Failed'}</span>{item.report && <button onClick={() => { setActiveReport(item.report!); setCurrentView('report'); const url = new URL(window.location.href); url.searchParams.set('auditId', item.report!.id); window.history.pushState({}, '', url.toString()); }} className="ml-3 text-emerald-700 underline underline-offset-2">Open report</button>}</td></tr>; })}</tbody></table></div></div>}
          </section>
        ) : currentView === 'form' || !activeReport ? (
          <AuditForm onStartAudit={handleStartAudit} isLoading={isLoading} />
        ) : (
          <ReportDashboard
            report={activeReport}
            onBackToStudio={handleNewAudit}
            onOpenMarkdown={() => setIsMarkdownModalOpen(true)}
          />
        )}
      </main>

      {/* Global Modals */}
      {activeReport && (
        <MarkdownModal
          report={activeReport}
          isOpen={isMarkdownModalOpen}
          onClose={() => setIsMarkdownModalOpen(false)}
        />
      )}

      <AuditHistoryModal
        isOpen={isHistoryModalOpen}
        onClose={() => setIsHistoryModalOpen(false)}
        reports={historyReports}
        onSelectReport={handleSelectHistoryReport}
        onClearHistory={handleClearHistory}
        onDeleteReport={handleDeleteHistoryReport}
      />
    </div>
  );
}
