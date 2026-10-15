import { AuditIssue } from '../types/audit.ts';

export interface AiAuditAnalysis {
  summary: string;
  additionalIssues: AuditIssue[];
}

type AuditKind = 'url' | 'code';
type Provider = 'gemini' | 'alibaba' | 'groq' | 'openrouter' | 'openai-compatible';

const validCategories = ['security', 'seo', 'accessibility', 'performance', 'quality'];
const validSeverities = ['critical', 'high', 'medium', 'low', 'passed'];
const fallbackSummary = (type: AuditKind, target: string, provider: string) =>
  type === 'url'
    ? 'Audit conducted on ' + target + '. Deterministic checks evaluated HTTP headers, SEO metadata, markup accessibility, and response timing. AI analysis was unavailable; configure GEMINI_API_KEY or a fallback provider to enable deeper analysis.'
    : 'Static source code audit performed for ' + target + '. Deterministic checks scanned common patterns. AI analysis was unavailable; configure GEMINI_API_KEY or a fallback provider to enable deeper analysis.';

function buildPrompt(type: AuditKind, target: string, content: string, meta: Record<string, any>): string {
  if (type === 'url') {
    return 'You are an expert web application security, SEO, accessibility, and performance auditor. Analyze this website inspection snapshot.\\n' +
      'URL: ' + target + '\\nHTTP status: ' + (meta.statusCode || 200) +
      '\\nResponse time: ' + (meta.responseTimeMs || 0) + ' ms\\nObserved headers: ' +
      JSON.stringify(meta.headers || {}) + '\\nHTML snippet / structure:\\n' + content.slice(0, 3000) +
      '\\nIdentify only evidence-based, actionable issues. Do not infer vulnerabilities unsupported by this snapshot. Consider security headers, CORS, SEO metadata, and accessibility.';
  }
  return 'You are an expert software security auditor and static analysis specialist. Analyze source code (' +
    (meta.language || 'text') + '), file: ' + (meta.filename || target) + '.\\nSource:\\n' +
    content.slice(0, 4000) +
    '\\nLook for evidence-based vulnerabilities and quality issues including OWASP Top 10, CWE patterns, logic errors, input validation, authentication/authorization gaps, and unsafe execution. Do not claim vulnerabilities without evidence. Give actionable remediation.';
}

const schemaHint = 'Return only a valid JSON object with shape: {"summary":"2-4 sentence executive summary","issues":[{"category":"security|seo|accessibility|performance|quality","severity":"critical|high|medium|low|passed","title":"short title","description":"evidence-based explanation","impact":"real-world impact","remediation":"concrete fix","originalCode":"optional evidence snippet","proposedFix":"optional replacement"}]}. Use an empty issues array when no additional findings are justified.';

function parseAnalysis(raw: string, type: AuditKind): AiAuditAnalysis {
  const parsed = JSON.parse(raw);
  const rawIssues = Array.isArray(parsed.issues) ? parsed.issues : [];
  const additionalIssues: AuditIssue[] = rawIssues
    .filter((item: any) => item && typeof item.title === 'string' && typeof item.description === 'string')
    .slice(0, 30)
    .map((item: any, idx: number) => {
      const category = validCategories.includes(item.category) ? item.category : (type === 'url' ? 'seo' : 'security');
      const severity = validSeverities.includes(item.severity) ? item.severity : 'medium';
      return {
        id: 'ai-finding-' + (idx + 1) + '-' + Date.now().toString(36),
        category,
        severity,
        title: item.title.slice(0, 180),
        description: item.description.slice(0, 3000),
        impact: typeof item.impact === 'string' ? item.impact.slice(0, 1500) : undefined,
        remediation: typeof item.remediation === 'string' ? item.remediation.slice(0, 3000) : 'Review the evidence and apply an appropriate fix.',
        codeSnippet: item.originalCode || item.proposedFix ? {
          original: typeof item.originalCode === 'string' ? item.originalCode.slice(0, 1500) : undefined,
          proposed: typeof item.proposedFix === 'string' ? item.proposedFix.slice(0, 1500) : undefined,
        } : undefined,
      };
    });
  return {
    summary: typeof parsed.summary === 'string' && parsed.summary.trim()
      ? parsed.summary.slice(0, 3000)
      : 'Audit completed. Review the findings and evidence below.',
    additionalIssues,
  };
}

async function analyzeWithGemini(prompt: string, apiKey: string, model: string): Promise<string> {
  const response = await fetch('https://generativelanguage.googleapis.com/v1beta/models/' +
    encodeURIComponent(model) + ':generateContent?key=' + encodeURIComponent(apiKey), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: schemaHint }] },
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.1, maxOutputTokens: 2200, responseMimeType: 'application/json' },
    }),
    signal: AbortSignal.timeout(45000),
  });
  if (!response.ok) throw new Error('Gemini API returned HTTP ' + response.status + ': ' + (await response.text()).slice(0, 300));
  const body = await response.json() as any;
  const text = body.candidates?.[0]?.content?.parts?.map((p: any) => p.text || '').join('');
  if (!text) throw new Error('Gemini returned an empty response.');
  return text;
}

async function analyzeOpenAICompatible(provider: Provider, prompt: string, apiKey: string, baseUrl: string, model: string): Promise<string> {
  const response = await fetch(baseUrl.replace(/\\/+$/, '') + '/chat/completions', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + apiKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model,
      temperature: 0.1,
      max_tokens: 2200,
      response_format: { type: 'json_object' },
      messages: [{ role: 'system', content: schemaHint }, { role: 'user', content: prompt }],
    }),
    signal: AbortSignal.timeout(45000),
  });
  if (!response.ok) throw new Error(provider + ' API returned HTTP ' + response.status + ': ' + (await response.text()).slice(0, 300));
  const body = await response.json() as any;
  const text = body.choices?.[0]?.message?.content;
  if (typeof text !== 'string' || !text) throw new Error(provider + ' returned an empty response.');
  return text;
}

function getProviderConfig(provider: Provider): { key?: string; baseUrl: string; model: string } {
  if (provider === 'gemini') {
    return { key: process.env.GEMINI_API_KEY, baseUrl: '', model: process.env.GEMINI_MODEL || 'gemini-2.5-flash' };
  }
  if (provider === 'alibaba') {
    return {
      key: process.env.DASHSCOPE_API_KEY || (process.env.AI_PROVIDER === 'alibaba' ? process.env.AI_API_KEY : undefined),
      baseUrl: process.env.DASHSCOPE_BASE_URL || process.env.AI_BASE_URL || 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1',
      model: process.env.DASHSCOPE_MODEL || process.env.AI_MODEL || 'qwen-plus',
    };
  }
  if (provider === 'groq') {
    return { key: process.env.GROQ_API_KEY, baseUrl: 'https://api.groq.com/openai/v1', model: process.env.GROQ_MODEL || '' };
  }
  if (provider === 'openrouter') {
    return { key: process.env.OPENROUTER_API_KEY, baseUrl: 'https://openrouter.ai/api/v1', model: process.env.OPENROUTER_MODEL || '' };
  }
  return { key: process.env.AI_API_KEY, baseUrl: process.env.AI_BASE_URL || '', model: process.env.AI_MODEL || '' };
}

/**
 * Gemini is the primary provider. AI_FALLBACK_PROVIDERS is an ordered,
 * comma-separated list (default: alibaba). Missing keys are skipped.
 * If every AI provider fails, deterministic audit results remain available.
 */
export async function analyzeWithAI(
  type: AuditKind,
  target: string,
  contentSnippet: string,
  contextMeta: Record<string, any>,
): Promise<AiAuditAnalysis> {
  const prompt = buildPrompt(type, target, contentSnippet, contextMeta);
  const primary = (process.env.AI_PRIMARY_PROVIDER || 'gemini').toLowerCase() as Provider;
  const fallbacks = (process.env.AI_FALLBACK_PROVIDERS || 'alibaba')
    .split(',').map((p) => p.trim().toLowerCase()).filter(Boolean) as Provider[];
  const providers = [...new Set<Provider>([primary, ...fallbacks])];
  const supported: Provider[] = ['gemini', 'alibaba', 'groq', 'openrouter', 'openai-compatible'];
  const errors: string[] = [];

  for (const provider of providers) {
    if (!supported.includes(provider)) {
      errors.push('Unsupported provider: ' + provider);
      continue;
    }
    const config = getProviderConfig(provider);
    if (!config.key || (provider !== 'gemini' && (!config.baseUrl || !config.model))) continue;
    try {
      const raw = provider === 'gemini'
        ? await analyzeWithGemini(prompt, config.key, config.model)
        : await analyzeOpenAICompatible(provider, prompt, config.key, config.baseUrl, config.model);
      return parseAnalysis(raw, type);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'unknown error';
      errors.push(provider + ': ' + message);
      console.warn('Auditor AI provider failed; trying next configured provider:', provider, message);
    }
  }

  if (errors.length) console.warn('All configured Auditor AI providers failed:', errors.join(' | '));
  return { summary: fallbackSummary(type, target, primary), additionalIssues: [] };
}

/** Compatibility export for older imports. */
export { analyzeWithAI as analyzeWithAlibabaCloud };
