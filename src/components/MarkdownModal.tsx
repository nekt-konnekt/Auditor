import React, { useState } from 'react';
import { AuditReport } from '../types/audit.ts';
import { generateAuditMarkdown } from '../lib/markdown-generator.ts';

interface MarkdownModalProps {
  report: AuditReport;
  isOpen: boolean;
  onClose: () => void;
}

export const MarkdownModal: React.FC<MarkdownModalProps> = ({ report, isOpen, onClose }) => {
  const [copied, setCopied] = useState(false);
  if (!isOpen) return null;

  const markdownContent = generateAuditMarkdown(report);

  const handleCopy = () => {
    navigator.clipboard.writeText(markdownContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([markdownContent], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `audit-report-${report.id}.md`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 sm:p-6">
      <div className="relative bg-white rounded-xl shadow-xl max-w-4xl w-full max-h-[88vh] flex flex-col border border-slate-200">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200">
          <div>
            <h2 className="text-base font-bold text-slate-900">
              Markdown Audit Report
            </h2>
            <div className="flex items-center gap-2 text-xs text-slate-500 font-mono">
              <span>ID: {report.id}</span>
              <span aria-hidden="true">·</span>
              <span>Ready for GitHub PRs, Notion, or Slack</span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors"
            >
              {copied ? 'Copied' : 'Copy Markdown'}
            </button>
            <button
              onClick={handleDownload}
              className="px-3 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-md transition-colors"
            >
              Download .md
            </button>
            <button
              onClick={onClose}
              className="px-2.5 py-1.5 text-xs font-medium text-slate-500 hover:text-slate-800 rounded-md hover:bg-slate-100 transition-colors ml-2"
              aria-label="Close"
            >
              Close
            </button>
          </div>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto flex-1 bg-slate-950">
          <pre className="font-mono text-xs text-slate-200 whitespace-pre-wrap leading-relaxed select-all">
            {markdownContent}
          </pre>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-200 bg-slate-50 flex items-center justify-between text-xs text-slate-500">
          <span>{markdownContent.length} characters</span>
          <button
            onClick={onClose}
            className="text-slate-700 hover:text-slate-900 font-medium"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
