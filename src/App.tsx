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
const severityRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, passed: 4 };
type LeadStatus = 'Not contacted' | 'Contacted' | 'Replied' | 'Interested in monitoring' | 'Not interested';
interface LeadRecord { auditId: string; status: LeadStatus; ownerContact: string; sourceNote: string; contactChannel: string; notes: string; updatedAt: string; createdAt: string; targetValue: string; targetType: 'url' | 'code'; verdict: string; overallScore: number; hasExposureFinding: boolean; report: AuditReport; }

export default function App() {
  const [currentView, setCurrentView] = useState<'form' | 'report' | 'batch' | 'leads'>('form');
  const [batchTargets, setBatchTargets] = useState('');
  const [batchLoading, setBatchLoading] = useState(false);
  const [batchError, setBatchError] = useState<string | null>(null);
  const [batchResults, setBatchResults] = useState<Array<{ index: number; target: string; report?: AuditReport; error?: string }>>([]);
  const [leads, setLeads] = useState<LeadRecord[]>([]);
  const [leadFilter, setLeadFilter] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [leadLoading, setLeadLoading] = useState(false);
  const [leadError, setLeadError] = useState<string | null>(null);
  const [savingLeadId, setSavingLeadId] = useState<string | null>(null);
  const [metrics, setMetrics] = useState<{ totalAudits: number; verdicts: Record<string, number>; messagesSent: number; replies: number; interested: number; sourceBreakdown?: Array<{ sourceNote: string; audits: number; contacted: number; replies: number; interested: number }> } | null>(null);
  const [outreachDrafts, setOutreachDrafts] = useState<Record<string, { dm: string; email: string }>>({});
  const [copiedOutreach, setCopiedOutreach] = useState<string | null>(null);
  const [rescanLoading, setRescanLoading] = useState(false);
  const [rescanError, setRescanError] = useState<string | null>(null);
  const [rescanDiff, setRescanDiff] = useState<{ target: string; scoreDelta: number; previousVerdict: string; currentVerdict: string; addedFindings: Array<{ title: string; severity: string }>; resolvedFindings: Array<{ title: string; severity: string }>; unchangedFindingCount: number } | null>(null);
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

  const handleRescan = async () => {
    if (!activeReport || activeReport.target.type !== 'url') return;
    setRescanLoading(true);
    setRescanError(null);
    setRescanDiff(null);
    const previousReport = activeReport;
    try {
      const response = await fetch('/api/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'url', target: previousReport.target.target }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Re-scan failed.');
      const nextReport = data as AuditReport;
      const compareResponse = await fetch(`/api/report/${encodeURIComponent(nextReport.id)}/compare/${encodeURIComponent(previousReport.id)}`);
      const compareData = await compareResponse.json().catch(() => ({}));
      if (!compareResponse.ok) throw new Error(compareData.error || 'Re-scan completed, but the comparison could not be loaded.');
      setRescanDiff(compareData);
      setActiveReport(nextReport);
      saveReportToHistory(nextReport);
      const url = new URL(window.location.href);
      url.searchParams.set('auditId', nextReport.id);
      window.history.pushState({}, '', url.toString());
    } catch (error) {
      setRescanError(error instanceof Error ? error.message : 'Re-scan failed.');
    } finally {
      setRescanLoading(false);
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

  const handleOpenLeads = async () => {
    setCurrentView('leads');
    setActiveReport(null);
    setLeadLoading(true);
    setLeadError(null);
    try {
      const [leadResponse, metricsResponse] = await Promise.all([fetch('/api/leads'), fetch('/api/metrics')]);
      const leadData = await leadResponse.json().catch(() => ({}));
      const metricData = await metricsResponse.json().catch(() => ({}));
      if (!leadResponse.ok) throw new Error(leadData.error || 'Unable to load lead tracker.');
      setLeads(Array.isArray(leadData.leads) ? leadData.leads : []);
      if (metricsResponse.ok) setMetrics(metricData);
    } catch (error) {
      setLeadError(error instanceof Error ? error.message : 'Unable to load lead tracker.');
    } finally {
      setLeadLoading(false);
    }
  };

  const updateLeadField = (auditId: string, field: 'status' | 'ownerContact' | 'sourceNote' | 'contactChannel' | 'notes', value: string) => {
    setLeads((current) => current.map((lead) => lead.auditId === auditId ? { ...lead, [field]: value } as LeadRecord : lead));
  };

  const prepareOutreach = (lead: LeadRecord) => {
    const worst = lead.report.issues.filter((issue) => issue.severity !== 'passed').sort((a, b) => severityRank[a.severity] - severityRank[b.severity])[0];
    const reportUrl = window.location.origin + '/?auditId=' + encodeURIComponent(lead.auditId);
    const exposedSecret = lead.hasExposureFinding || /exposed secret|\\.env|\\.git|private key|api key/i.test(worst?.title || '');
    const finding = exposedSecret
      ? 'A public asset appears to expose a credential-like value. The value is intentionally not reproduced here; rotate the affected key and remove it from client-delivered code.'
      : worst ? worst.title + ': ' + worst.remediation : 'The audit found opportunities to improve launch readiness.';
    const dm = 'Hi! I ran a passive check of ' + lead.targetValue + ' using public pages only. One finding worth reviewing: ' + finding + ' I did not attempt login or access private systems. Full report: ' + reportUrl;
    const email = 'Subject: A launch-readiness finding for ' + lead.targetValue + '\n\nHi,\n\nI ran a passive, external check of ' + lead.targetValue + ' using publicly accessible pages only. I did not attempt to log in, exploit anything, or access private systems.\\n\\nThe most important finding is: ' + finding + '\n\nSuggested next step: ' + (exposedSecret ? 'rotate the affected credential, remove it from public assets, and verify the deployed build no longer exposes it.' : (worst?.remediation || 'review the report and prioritize the highest-severity items.')) + '\\n\\nFull report: ' + reportUrl + '\n\nIf useful, I can share the specific check and help verify the fix.\n\nRegards';
    setOutreachDrafts((current) => ({ ...current, [lead.auditId]: { dm, email } }));
  };

  const copyOutreach = async (key: string, value: string) => {
    try { await navigator.clipboard.writeText(value); setCopiedOutreach(key); }
    catch { setLeadError('Clipboard access was blocked. Select the message and copy it manually.'); }
  };
  const handleSaveLead = async (lead: LeadRecord) => {
    setSavingLeadId(lead.auditId);
    setLeadError(null);
    try {
      const response = await fetch(`/api/leads/${encodeURIComponent(lead.auditId)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: lead.status, ownerContact: lead.ownerContact, sourceNote: lead.sourceNote, contactChannel: lead.contactChannel, notes: lead.notes }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Unable to save lead.');
      setLeads((current) => current.map((item) => item.auditId === lead.auditId ? { ...item, updatedAt: new Date().toISOString() } : item));
    } catch (error) {
      setLeadError(error instanceof Error ? error.message : 'Unable to save lead.');
    } finally {
      setSavingLeadId(null);
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
        onOpenLeads={handleOpenLeads}
        historyCount={historyReports.length}
        currentView={currentView}
        onNavigateHome={handleNewAudit}
      />

      <main className="flex-1">
        {currentView === 'leads' ? (
          <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
            <div className="flex flex-wrap items-end justify-between gap-4 mb-7"><div><p className="text-xs font-semibold tracking-[0.2em] uppercase text-emerald-700 mb-2">Internal pipeline</p><h1 className="text-3xl font-extrabold tracking-tight">Lead tracker</h1><p className="mt-2 text-slate-600">Track outreach status and source notes against persisted audit reports.</p></div><button onClick={handleOpenLeads} className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-semibold hover:bg-slate-50">Refresh</button></div>
            {metrics && <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 mb-7">{[['Audits', metrics.totalAudits], ['Not ready', metrics.verdicts['Not ready'] || 0], ['Risky', metrics.verdicts.Risky || 0], ['Contacted', metrics.messagesSent], ['Reply rate', (metrics.messagesSent ? Math.round(metrics.replies / metrics.messagesSent * 100) : 0) + '%'], ['Interest rate', (metrics.replies ? Math.round(metrics.interested / metrics.replies * 100) : 0) + '%']].map(([label, value]) => <div key={String(label)} className="rounded-xl border border-slate-200 bg-white p-4"><p className="text-xs text-slate-500">{label}</p><p className="mt-1 text-2xl font-bold tabular-nums">{value}</p></div>)}</div>}
            <div className="flex flex-wrap items-center gap-3 mb-5"><label htmlFor="lead-filter" className="text-sm font-semibold">Status</label><select id="lead-filter" value={leadFilter} onChange={(event) => setLeadFilter(event.target.value)} className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm"><option value="all">All statuses</option><option>Not contacted</option><option>Contacted</option><option>Replied</option><option>Interested in monitoring</option><option>Not interested</option></select><label htmlFor="source-filter" className="text-sm font-semibold">Source</label><select id="source-filter" value={sourceFilter} onChange={(event) => setSourceFilter(event.target.value)} className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm"><option value="all">All sources</option>{[...new Set(leads.map((lead) => lead.sourceNote || 'Unspecified'))].map((source) => <option key={source} value={source}>{source}</option>)}</select><span className="text-sm text-slate-500">{leads.filter((lead) => (leadFilter === 'all' || lead.status === leadFilter) && (sourceFilter === 'all' || (lead.sourceNote || 'Unspecified') === sourceFilter)).length} leads</span></div>
            {leadError && <p role="alert" className="mb-5 rounded-lg border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">{leadError}</p>}
            {leadLoading ? <div className="rounded-xl border border-slate-200 bg-white p-8 text-center text-slate-500">Loading persisted leads…</div> : leads.filter((lead) => (leadFilter === 'all' || lead.status === leadFilter) && (sourceFilter === 'all' || (lead.sourceNote || 'Unspecified') === sourceFilter)).length === 0 ? <div className="rounded-xl border border-slate-200 bg-white p-8 text-center text-slate-600">No saved audits match this filter yet. Run a website audit or batch first.</div> : <div className="space-y-4">{leads.filter((lead) => (leadFilter === 'all' || lead.status === leadFilter) && (sourceFilter === 'all' || (lead.sourceNote || 'Unspecified') === sourceFilter)).map((lead) => {
              const worst = lead.report.issues.filter((issue) => issue.severity !== 'passed').sort((a, b) => severityRank[a.severity] - severityRank[b.severity])[0];
              return <article key={lead.auditId} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
                <div className="flex flex-wrap items-start justify-between gap-3 mb-4"><div className="min-w-0"><p className="font-mono text-sm break-all text-slate-800">{lead.targetValue}</p><p className="mt-1 text-xs text-slate-500">Audited {new Date(lead.createdAt).toLocaleString()} · Score {lead.overallScore} · {lead.verdict}</p><p className="mt-2 text-sm text-slate-700"><span className="font-semibold">Top finding:</span> {worst?.title || 'No failing findings'}</p></div><button onClick={() => { setActiveReport(lead.report); setCurrentView('report'); const url = new URL(window.location.href); url.searchParams.set('auditId', lead.auditId); window.history.pushState({}, '', url.toString()); }} className="text-sm font-semibold text-emerald-700 underline underline-offset-2">Open report</button></div>
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                  <div><label className="block text-xs font-semibold text-slate-600 mb-1">Outreach status</label><select value={lead.status} onChange={(event) => updateLeadField(lead.auditId, 'status', event.target.value)} className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm"><option>Not contacted</option><option>Contacted</option><option>Replied</option><option>Interested in monitoring</option><option>Not interested</option></select></div>
                  <div><label className="block text-xs font-semibold text-slate-600 mb-1">Owner handle / email</label><input value={lead.ownerContact} onChange={(event) => updateLeadField(lead.auditId, 'ownerContact', event.target.value)} maxLength={320} className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" placeholder="Contact details" /></div>
                  <div><label className="block text-xs font-semibold text-slate-600 mb-1">Source note</label><input value={lead.sourceNote} onChange={(event) => updateLeadField(lead.auditId, 'sourceNote', event.target.value)} maxLength={300} className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" placeholder="e.g. launch directory" /></div>
                  <div><label className="block text-xs font-semibold text-slate-600 mb-1">Contact channel</label><input value={lead.contactChannel} onChange={(event) => updateLeadField(lead.auditId, 'contactChannel', event.target.value)} maxLength={120} className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" placeholder="Email, X, LinkedIn…" /></div>
                  <div className="md:col-span-2"><label className="block text-xs font-semibold text-slate-600 mb-1">Notes</label><textarea value={lead.notes} onChange={(event) => updateLeadField(lead.auditId, 'notes', event.target.value)} maxLength={4000} rows={2} className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" placeholder="Follow-up context and outcome" /></div>
                </div>
                <div className="mt-4 flex items-center justify-between gap-3"><span className="text-xs text-slate-500">Last saved: {new Date(lead.updatedAt).toLocaleString()}</span><button onClick={() => handleSaveLead(lead)} disabled={savingLeadId === lead.auditId} className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-60">{savingLeadId === lead.auditId ? 'Saving…' : 'Save lead'}</button></div>
                <div className="mt-5 border-t border-slate-100 pt-4"><div className="flex flex-wrap items-center justify-between gap-3"><h3 className="font-semibold text-slate-800">Outreach draft</h3><button onClick={() => prepareOutreach(lead)} className="rounded-lg border border-slate-300 px-3 py-2 text-sm font-semibold hover:bg-slate-50">{outreachDrafts[lead.auditId] ? 'Regenerate drafts' : 'Prepare outreach'}</button></div>
                  {outreachDrafts[lead.auditId] && <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
                    <div><label className="block text-xs font-semibold text-slate-600 mb-1">Short DM</label><textarea rows={6} value={outreachDrafts[lead.auditId].dm} onChange={(event) => setOutreachDrafts((current) => ({ ...current, [lead.auditId]: { ...current[lead.auditId], dm: event.target.value } }))} className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" /><button onClick={() => copyOutreach(lead.auditId + '-dm', outreachDrafts[lead.auditId].dm)} className="mt-2 rounded-lg border border-slate-300 px-3 py-2 text-sm font-semibold">{copiedOutreach === lead.auditId + '-dm' ? 'Copied' : 'Copy DM'}</button></div>
                    <div><label className="block text-xs font-semibold text-slate-600 mb-1">Email</label><textarea rows={6} value={outreachDrafts[lead.auditId].email} onChange={(event) => setOutreachDrafts((current) => ({ ...current, [lead.auditId]: { ...current[lead.auditId], email: event.target.value } }))} className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" /><button onClick={() => copyOutreach(lead.auditId + '-email', outreachDrafts[lead.auditId].email)} className="mt-2 rounded-lg border border-slate-300 px-3 py-2 text-sm font-semibold">{copiedOutreach === lead.auditId + '-email' ? 'Copied' : 'Copy email'}</button></div>
                  </div>}
                </div>
              </article>;
            })}</div>}
          </section>
        ) : currentView === 'batch' ? (
          <section className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
            <div className="max-w-3xl mb-8"><p className="text-xs font-semibold tracking-[0.2em] uppercase text-emerald-700 mb-3">Auditor / Batch workflow</p><h1 className="text-3xl font-extrabold tracking-tight">Audit multiple public sites</h1><p className="mt-3 text-slate-600">Paste up to 20 URLs, one per line. Each site is processed independently, so one failed target will not stop the rest. Audits are passive and read-only.</p></div>
            <div className="bg-white border border-slate-200 rounded-xl p-5 sm:p-7 shadow-sm">
              <label htmlFor="batch-targets" className="block text-sm font-semibold text-slate-800 mb-2">Target URLs</label>
              <textarea id="batch-targets" value={batchTargets} onChange={(event) => setBatchTargets(event.target.value)} disabled={batchLoading} rows={8} placeholder={'https://example.com\nhttps://another-site.com'} className="w-full rounded-lg border border-slate-300 p-3 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500 disabled:bg-slate-50" />
              <div className="mt-2 flex items-center justify-between text-xs text-slate-500"><span>Duplicates are removed automatically.</span><span>{batchTargets.split(/\r?\n/).map((value) => value.trim()).filter(Boolean).length} / 20 URLs</span></div>
              {batchError && <p role="alert" className="mt-4 rounded-lg border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">{batchError}</p>}
              <div className="mt-5 flex flex-wrap items-center gap-3"><button onClick={handleRunBatch} disabled={batchLoading} className="rounded-lg bg-slate-900 px-5 py-3 text-sm font-semibold text-white hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60">{batchLoading ? 'Running batch…' : 'Run batch audit'}</button>{batchLoading && <span className="text-sm text-slate-500">Limited concurrency is enabled. Results appear when the batch completes.</span>}</div>
            </div>
            {batchResults.length > 0 && <div className="mt-8 bg-white border border-slate-200 rounded-xl overflow-hidden"><div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between gap-4"><h2 className="font-bold text-slate-900">Batch results</h2><span className="text-sm text-slate-500">{batchResults.filter((item) => item.report).length} of {batchResults.length} completed</span></div><div className="overflow-x-auto"><table className="w-full text-sm"><thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500"><tr><th className="px-5 py-3">URL</th><th className="px-5 py-3">Verdict</th><th className="px-5 py-3">Score</th><th className="px-5 py-3">Worst finding</th><th className="px-5 py-3">Status</th></tr></thead><tbody className="divide-y divide-slate-100">{[...batchResults].sort((a, b) => { const rank = (item: typeof a) => item.report?.verdict === 'Not ready' ? 0 : item.report?.verdict === 'Risky' ? 1 : item.report?.verdict === 'Ready' ? 2 : 3; return rank(a) - rank(b) || a.index - b.index; }).map((item) => { const worst = item.report?.issues.filter((issue) => issue.severity !== 'passed').sort((a, b) => severityRank[a.severity] - severityRank[b.severity])[0]; return <tr key={item.index} className="align-top"><td className="px-5 py-4 max-w-xs break-all font-mono text-xs">{item.target}</td><td className="px-5 py-4 font-semibold">{item.report?.verdict || '—'}</td><td className="px-5 py-4 tabular-nums">{item.report ? item.report.overallScore : '—'}</td><td className="px-5 py-4">{worst?.title || (item.report ? 'No failing findings' : item.error || 'Audit failed')}</td><td className="px-5 py-4"><span className={item.report ? 'text-emerald-700' : 'text-rose-700'}>{item.report ? 'Complete' : 'Failed'}</span>{item.report && <button onClick={() => { setActiveReport(item.report!); setCurrentView('report'); const url = new URL(window.location.href); url.searchParams.set('auditId', item.report!.id); window.history.pushState({}, '', url.toString()); }} className="ml-3 text-emerald-700 underline underline-offset-2">Open report</button>}</td></tr>; })}</tbody></table></div></div>}
          </section>
        ) : currentView === 'form' || !activeReport ? (
          <AuditForm onStartAudit={handleStartAudit} isLoading={isLoading} />
        ) : (
          <ReportDashboard
            report={activeReport}
            onBackToStudio={handleNewAudit}
            onOpenMarkdown={() => setIsMarkdownModalOpen(true)}
            onRescan={handleRescan}
            rescanLoading={rescanLoading}
          />
          {rescanError && <p role="alert" className="mx-4 mb-5 rounded-lg border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">{rescanError}</p>}
          {rescanDiff && <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pb-10"><div className="rounded-xl border border-slate-200 bg-white p-5"><div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="text-xl font-bold">Re-scan comparison</h2><p className="mt-1 text-sm text-slate-600">{rescanDiff.target}</p></div><p className="text-sm font-semibold">Score change: {rescanDiff.scoreDelta > 0 ? '+' : ''}{rescanDiff.scoreDelta}</p></div><p className="mt-3 text-sm">Verdict: {rescanDiff.previousVerdict} → <strong>{rescanDiff.currentVerdict}</strong> · {rescanDiff.unchangedFindingCount} unchanged finding(s)</p><div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4"><div className="rounded-lg bg-rose-50 p-4"><h3 className="font-semibold text-rose-900">New findings ({rescanDiff.addedFindings.length})</h3>{rescanDiff.addedFindings.length ? <ul className="mt-2 list-disc pl-5 text-sm text-rose-900">{rescanDiff.addedFindings.map((item, index) => <li key={item.title + index}>{item.severity.toUpperCase()}: {item.title}</li>)}</ul> : <p className="mt-2 text-sm text-rose-800">No new findings.</p>}</div><div className="rounded-lg bg-emerald-50 p-4"><h3 className="font-semibold text-emerald-900">Resolved findings ({rescanDiff.resolvedFindings.length})</h3>{rescanDiff.resolvedFindings.length ? <ul className="mt-2 list-disc pl-5 text-sm text-emerald-900">{rescanDiff.resolvedFindings.map((item, index) => <li key={item.title + index}>{item.severity.toUpperCase()}: {item.title}</li>)}</ul> : <p className="mt-2 text-sm text-emerald-800">No previously recorded findings were resolved.</p>}</div></div></div></section>}
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
