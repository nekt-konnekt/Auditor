/**
 * @deprecated Compatibility shim for older imports.
 * Gemini is the default provider; configure AI_FALLBACK_PROVIDERS to select fallbacks.
 */
export { analyzeWithAI as analyzeWithGemini, analyzeWithAI } from './ai-auditor.ts';
export type { AiAuditAnalysis as GeminiAuditAnalysis } from './ai-auditor.ts';
