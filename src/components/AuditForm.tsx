import React, { useState } from 'react';

interface AuditFormProps {
  onStartAudit: (payload: {
    type: 'url' | 'code';
    target: string;
  }) => Promise<void>;
  isLoading: boolean;
}

export const AuditForm: React.FC<AuditFormProps> = ({ onStartAudit, isLoading }) => {
  const [targetUrl, setTargetUrl] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [auditStep, setAuditStep] = useState<string>('Initializing');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    const cleanInput = targetUrl.trim();
    if (!cleanInput) {
      setErrorMsg('Please enter a target link or GitHub repository to audit.');
      return;
    }

    try {
      if (cleanInput.includes('github.com')) {
        setAuditStep('Inspecting GitHub repository, manifests & security policies...');
      } else {
        setAuditStep('Fetching HTTP response, security headers & markup...');
      }

      await onStartAudit({
        type: 'url',
        target: cleanInput,
      });
    } catch (err: any) {
      setErrorMsg(err.message || 'Audit execution failed. Please verify the URL or repository.');
    }
  };

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-14">
      {/* Studio Header Intro */}
      <div className="text-center max-w-2xl mx-auto mb-10">
        <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-900 tracking-tight text-balance">
          Deep Website & Code Intelligence Engine
        </h1>
        <p className="mt-3 text-base text-slate-600 leading-relaxed text-balance">
          Enter any live website address or GitHub repository link to inspect security posture, architecture, and code quality.
        </p>
      </div>

      {/* Main Workspace Card */}
      <div className="bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden">
        {/* Input Form Body */}
        <form onSubmit={handleSubmit} className="p-6 sm:p-8">
          {errorMsg && (
            <div className="mb-6 p-4 rounded-lg bg-rose-50 border border-rose-200 text-rose-800 text-sm">
              <span className="font-semibold block">Audit Execution Error</span>
              <span>{errorMsg}</span>
            </div>
          )}

          <div className="space-y-6">
            <div>
              <input
                id="target-input"
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://github.com/halftone/auditor-core"
                disabled={isLoading}
                className="block w-full px-4 py-3 bg-white border border-slate-300 rounded-lg text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 font-mono"
              />
            </div>
          </div>

          {/* Action Row */}
          <div className="mt-8 pt-6 border-t border-slate-200 flex flex-col sm:flex-row items-center justify-end gap-4">
            <button
              type="submit"
              disabled={isLoading}
              className="w-full sm:w-auto px-6 py-3 bg-emerald-600 hover:bg-emerald-700 active:bg-emerald-800 disabled:bg-emerald-400 text-white text-sm font-semibold rounded-lg shadow-xs transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-600 focus-visible:ring-offset-2 shrink-0 cursor-pointer"
            >
              {isLoading ? 'Auditing Target...' : 'Run Intelligence Audit'}
            </button>
          </div>
        </form>
      </div>

      {/* Loading Progress State */}
      {isLoading && (
        <div className="mt-6 p-5 bg-white border border-slate-200 rounded-xl shadow-xs">
          <div className="text-slate-800 text-sm font-semibold mb-3">
            Audit Pipeline Running
          </div>
          <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden mb-3">
            <div className="bg-emerald-600 h-2 rounded-full animate-pulse w-3/4"></div>
          </div>
          <div className="flex items-center justify-between text-xs font-mono text-slate-500">
            <span>{auditStep}</span>
            <span>Parsing Heuristics & AI Model</span>
          </div>
        </div>
      )}
    </div>
  );
};
