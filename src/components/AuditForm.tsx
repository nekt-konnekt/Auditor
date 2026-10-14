import React, { useState } from 'react';
import { AuditRequestPayload } from '../types/audit.ts';

interface AuditFormProps {
  onStartAudit: (payload: AuditRequestPayload) => Promise<void>;
  isLoading: boolean;
}

type AuditMode = 'url' | 'code';

export const AuditForm: React.FC<AuditFormProps> = ({ onStartAudit, isLoading }) => {
  const [mode, setMode] = useState<AuditMode>('url');
  const [targetUrl, setTargetUrl] = useState('');
  const [filename, setFilename] = useState('source-file.ts');
  const [language, setLanguage] = useState('typescript');
  const [sourceCode, setSourceCode] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [auditStep, setAuditStep] = useState('Preparing audit');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    if (mode === 'url') {
      const cleanInput = targetUrl.trim();
      if (!cleanInput) {
        setErrorMsg('Enter a public website URL or GitHub repository link.');
        return;
      }
      setAuditStep(cleanInput.includes('github.com')
        ? 'Inspecting repository metadata and security files…'
        : 'Checking public website response, headers and markup…');
      try {
        await onStartAudit({ type: 'url', target: cleanInput });
      } catch (err: unknown) {
        setErrorMsg(err instanceof Error ? err.message : 'Audit failed. Check the target and try again.');
      }
      return;
    }

    if (!sourceCode.trim()) {
      setErrorMsg('Paste source code before starting the audit.');
      return;
    }
    if (sourceCode.length > 200_000) {
      setErrorMsg('Source code is limited to 200,000 characters per audit.');
      return;
    }

    setAuditStep('Scanning source patterns and preparing findings…');
    try {
      await onStartAudit({
        type: 'code',
        target: filename.trim() || 'source-file',
        code: sourceCode,
        language,
        filename: filename.trim() || 'source-file',
      });
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : 'Audit failed. Check the source and try again.');
    }
  };

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-14">
      <div className="text-center max-w-2xl mx-auto mb-10">
        <p className="text-xs font-semibold tracking-[0.2em] uppercase text-emerald-700 mb-3">Auditor / Intelligence Studio</p>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-900 tracking-tight text-balance">
          Find the gaps before your users do.
        </h1>
        <p className="mt-3 text-base text-slate-600 leading-relaxed text-balance">
          Inspect public websites and GitHub repositories, or review a source-code snippet for security and quality risks.
        </p>
      </div>

      <div className="bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden">
        <div className="flex border-b border-slate-200 p-2 gap-2" role="tablist" aria-label="Audit type">
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'url'}
            onClick={() => { setMode('url'); setErrorMsg(null); }}
            disabled={isLoading}
            className={`flex-1 rounded-lg px-4 py-3 text-sm font-semibold transition-colors ${mode === 'url' ? 'bg-emerald-50 text-emerald-800 border border-emerald-200' : 'text-slate-600 hover:bg-slate-50'}`}
          >
            Website / GitHub
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'code'}
            onClick={() => { setMode('code'); setErrorMsg(null); }}
            disabled={isLoading}
            className={`flex-1 rounded-lg px-4 py-3 text-sm font-semibold transition-colors ${mode === 'code' ? 'bg-emerald-50 text-emerald-800 border border-emerald-200' : 'text-slate-600 hover:bg-slate-50'}`}
          >
            Source code
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 sm:p-8">
          {errorMsg && (
            <div className="mb-6 p-4 rounded-lg bg-rose-50 border border-rose-200 text-rose-800 text-sm" role="alert">
              <span className="font-semibold block mb-1">Audit could not start</span>
              <span>{errorMsg}</span>
            </div>
          )}

          {mode === 'url' ? (
            <div>
              <label htmlFor="target-input" className="block text-sm font-semibold text-slate-800 mb-2">Public website or repository URL</label>
              <input
                id="target-input"
                type="url"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://example.com or https://github.com/owner/repo"
                disabled={isLoading}
                required
                autoComplete="url"
                className="block w-full px-4 py-3 bg-white border border-slate-300 rounded-lg text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 font-mono"
              />
            </div>
          ) : (
            <div className="space-y-5">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="source-filename" className="block text-sm font-semibold text-slate-800 mb-2">Filename</label>
                  <input id="source-filename" value={filename} onChange={(e) => setFilename(e.target.value)} disabled={isLoading} maxLength={160} className="w-full px-4 py-3 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500" />
                </div>
                <div>
                  <label htmlFor="source-language" className="block text-sm font-semibold text-slate-800 mb-2">Language</label>
                  <select id="source-language" value={language} onChange={(e) => setLanguage(e.target.value)} disabled={isLoading} className="w-full px-4 py-3 border border-slate-300 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-emerald-500">
                    <option value="typescript">TypeScript</option>
                    <option value="javascript">JavaScript</option>
                    <option value="python">Python</option>
                    <option value="go">Go</option>
                    <option value="rust">Rust</option>
                    <option value="solidity">Solidity</option>
                    <option value="html">HTML</option>
                    <option value="css">CSS</option>
                    <option value="sql">SQL</option>
                    <option value="text">Other / plain text</option>
                  </select>
                </div>
              </div>
              <div>
                <label htmlFor="source-code" className="block text-sm font-semibold text-slate-800 mb-2">Source code</label>
                <textarea
                  id="source-code"
                  value={sourceCode}
                  onChange={(e) => setSourceCode(e.target.value)}
                  disabled={isLoading}
                  required
                  rows={12}
                  maxLength={200_000}
                  spellCheck={false}
                  placeholder="Paste the code you want to inspect…"
                  className="block w-full px-4 py-3 bg-slate-950 text-slate-100 border border-slate-800 rounded-lg text-sm font-mono leading-relaxed focus:outline-none focus:ring-2 focus:ring-emerald-500"
                />
                <div className="mt-2 flex justify-between text-xs text-slate-500">
                  <span>Do not paste production secrets or private customer data.</span>
                  <span className="tabular-nums">{sourceCode.length.toLocaleString()} / 200,000</span>
                </div>
              </div>
            </div>
          )}

          <div className="mt-8 pt-6 border-t border-slate-200 flex flex-col sm:flex-row items-center justify-between gap-4">
            <button
              type="submit"
              disabled={isLoading}
              className="w-full sm:w-auto px-6 py-3 bg-emerald-600 hover:bg-emerald-700 active:bg-emerald-800 disabled:bg-emerald-400 text-white text-sm font-semibold rounded-lg shadow-sm transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-600 focus-visible:ring-offset-2 shrink-0"
            >
              {isLoading ? 'Auditing…' : mode === 'url' ? 'Run website audit' : 'Audit source code'}
            </button>
          </div>
        </form>
      </div>

      {isLoading && (
        <div className="mt-6 p-5 bg-white border border-slate-200 rounded-xl shadow-sm" role="status" aria-live="polite">
          <div className="text-slate-800 text-sm font-semibold mb-3">Audit pipeline running</div>
          <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden mb-3">
            <div className="bg-emerald-600 h-2 rounded-full animate-pulse w-3/4" />
          </div>
          <p className="text-xs font-mono text-slate-500">{auditStep}</p>
        </div>
      )}
    </div>
  );
};
