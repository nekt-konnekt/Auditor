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
    const targets = [...new Set(batchTargets.split(/\\r?\\n/).map((value) => value.trim()).filter(Boolean))];
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
        {currentView === 'form' || !activeReport ? (
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
