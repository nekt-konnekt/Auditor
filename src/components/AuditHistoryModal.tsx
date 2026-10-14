import React from 'react';
import { AuditReport } from '../types/audit.ts';

interface AuditHistoryModalProps {
  isOpen: boolean;
  onClose: () => void;
  reports: AuditReport[];
  onSelectReport: (report: AuditReport) => void;
  onClearHistory: () => void;
  onDeleteReport: (id: string) => void;
}

export const AuditHistoryModal: React.FC<AuditHistoryModalProps> = ({
  isOpen,
  onClose,
  reports,
  onSelectReport,
  onClearHistory,
  onDeleteReport,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 sm:p-6">
      <div className="relative bg-white rounded-xl shadow-xl max-w-2xl w-full max-h-[85vh] flex flex-col border border-slate-200">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200">
          <div>
            <h2 className="text-base font-bold text-slate-900">
              Audit History
            </h2>
            <p className="text-xs text-slate-500">
              {reports.length} report{reports.length !== 1 ? 's' : ''} saved locally
            </p>
          </div>

          <div className="flex items-center gap-2">
            {reports.length > 0 && (
              <button
                onClick={onClearHistory}
                className="px-2.5 py-1.5 text-xs text-rose-600 hover:text-rose-700 hover:bg-rose-50 rounded-md transition-colors"
              >
                Clear All
              </button>
            )}
            <button
              onClick={onClose}
              className="px-2.5 py-1.5 text-xs text-slate-500 hover:text-slate-800 rounded-md hover:bg-slate-100 transition-colors"
            >
              Close
            </button>
          </div>
        </div>

        <div className="p-6 overflow-y-auto flex-1 divide-y divide-slate-100">
          {reports.length === 0 ? (
            <div className="text-center py-12 text-slate-500">
              <p className="text-sm font-medium">No previous audits yet.</p>
              <p className="text-xs text-slate-400 mt-1">
                Run an audit on a URL or repository to build your audit log.
              </p>
            </div>
          ) : (
            reports.map((r) => {
              const scoreColor =
                r.overallScore >= 80
                  ? 'text-emerald-700 bg-emerald-50 border-emerald-200'
                  : r.overallScore >= 50
                  ? 'text-amber-700 bg-amber-50 border-amber-200'
                  : 'text-rose-700 bg-rose-50 border-rose-200';

              return (
                <div
                  key={r.id}
                  className="py-3.5 flex items-center justify-between gap-4 group hover:bg-slate-50/80 px-2 rounded-lg transition-colors"
                >
                  <div
                    onClick={() => {
                      onSelectReport(r);
                      onClose();
                    }}
                    className="flex-1 min-w-0 cursor-pointer"
                  >
                    <span className="text-sm font-semibold text-slate-900 truncate block">
                      {r.target.target}
                    </span>

                    <div className="flex items-center gap-2 mt-1 text-xs text-slate-500 font-mono">
                      <span>{new Date(r.createdAt).toLocaleDateString()}</span>
                      <span aria-hidden="true">·</span>
                      <span>{new Date(r.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                      <span aria-hidden="true">·</span>
                      <span>{r.issues.length} checks</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <div className={`px-2.5 py-1 text-xs font-mono font-bold rounded-md border ${scoreColor}`}>
                      {r.overallScore}/100
                    </div>

                    <button
                      onClick={() => {
                        onSelectReport(r);
                        onClose();
                      }}
                      className="px-2 py-1 text-xs text-slate-600 hover:text-slate-900 hover:bg-slate-200 rounded-md transition-colors font-mono"
                    >
                      Open
                    </button>

                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onDeleteReport(r.id);
                      }}
                      className="px-2 py-1 text-xs text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-md transition-colors font-mono"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};
