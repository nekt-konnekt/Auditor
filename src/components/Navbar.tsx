import React from 'react';

interface NavbarProps {
  onNewAudit: () => void;
  onOpenHistory: () => void;
  onOpenBatch: () => void;
  onOpenLeads: () => void;
  historyCount: number;
  currentView: 'form' | 'report' | 'batch' | 'leads';
  onNavigateHome: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  onNewAudit,
  onOpenHistory,
  onOpenBatch,
  onOpenLeads,
  historyCount,
  currentView,
  onNavigateHome,
}) => {
  return (
    <header className="sticky top-0 z-40 bg-white/95 backdrop-blur-xs border-b border-slate-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-8">
        {/* Zone 1: Brand wordmark */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={onNavigateHome}
            className="flex items-center gap-2 text-left group focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 rounded-md"
          >
            <span className="text-lg font-bold tracking-tight text-slate-900 group-hover:text-emerald-700 transition-colors whitespace-nowrap">
              Auditor
            </span>
            <span className="hidden sm:inline-block text-xs font-mono text-slate-400">
              v2.4
            </span>
          </button>
        </div>

        {/* Zone 2: Navigation links */}
        <nav className="hidden md:flex items-center gap-7 text-sm font-medium text-slate-600">
          <button
            onClick={onNavigateHome}
            className={`hover:text-slate-900 transition-colors whitespace-nowrap shrink-0 ${
              currentView === 'form' ? 'text-slate-900 font-semibold' : ''
            }`}
          >
            Audit Workspace
          </button>
          <button
            onClick={onOpenBatch}
            className={`hover:text-slate-900 transition-colors whitespace-nowrap shrink-0 ${currentView === 'batch' ? 'text-slate-900 font-semibold' : ''}`}
          >
            Batch Audit
          </button>
          <button
            onClick={onOpenLeads}
            className={`hover:text-slate-900 transition-colors whitespace-nowrap shrink-0 ${currentView === 'leads' ? 'text-slate-900 font-semibold' : ''}`}
          >
            Lead Tracker
          </button>
          <button
            onClick={onOpenHistory}
            className="hover:text-slate-900 transition-colors whitespace-nowrap shrink-0"
          >
            <span>Audit History</span>
            {historyCount > 0 && (
              <span className="ml-1 text-xs font-mono text-slate-500">
                ({historyCount})
              </span>
            )}
          </button>
        </nav>

        {/* Zone 3: Primary Action */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={onNewAudit}
            className="px-4 py-2 text-xs font-medium text-white bg-slate-900 rounded-lg hover:bg-slate-800 active:bg-slate-950 transition-colors whitespace-nowrap shrink-0 focus-visible:ring-2 focus-visible:ring-slate-900 focus-visible:ring-offset-2"
          >
            New Audit
          </button>
        </div>
      </div>
    </header>
  );
};
