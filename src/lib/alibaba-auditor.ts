import { AuditIssue } from '../types/audit.ts';

export interface AiAuditAnalysis {
  summary: string;
  additionalIssues: AuditIssue[];
}

const FALLBACK_BASE_URL = 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1';

function fallback(type: 'url' | 'code', target: string, contextMeta: Record<string, any>): AiAuditAnalysis {
  return {
    summary: type === 'url'
      ? `Audit conducted on ${target}. Deterministic checks evaluated HTTP headers, SEO metadata, markup accessibility, and response timing. Configure DASHSCOPE_API_KEY to enable deeper AI analysis.`
      : `Static source code audit performed for ${contextMeta.filename || 'input code'}. Deterministic checks scanned common patterns. Configure DASHSCOPE_API_KEY to enable deeper AI analysis.`,
    additionalIssues: [],
  };
}

/** Deep contextual analysis through Alibaba Cloud Model Studio's OpenAI-compatible API. */
export async function analyzeWithAlibabaCloud(
  type: 'url' | 'code',
  target: string,
  contentSnippet: string,
  contextMeta: Record<string, any>,
): Promise<AiAuditAnalysis> {
  const apiKey = process.env.DASHSCOPE_API_KEY;
  if (!apiKey) return fallback(type, target, contextMeta);

  const baseUrl = (process.env.DASHSCOPE_BASE_URL || FALLBACK_BASE_URL).replace(/\/+$/, '');
  const model = process.env.DASHSCOPE_MODEL || 'qwen-plus';

  const prompt = type === 'url'
    ? `You are an expert web application security, SEO, accessibility, and performance auditor.
Analyze this website inspection snapshot.
URL: ${target}
HTTP status: ${contextMeta.statusCode || 200}
Response time: ${contextMeta.responseTimeMs || 0} ms
Observed headers: ${JSON.stringify(contextMeta.headers || {})}
HTML snippet / structure:
${contentSnippet.substring(0, 3000)}

Identify only evidence-based, actionable issues. Do not infer vulnerabilities that cannot be supported by this snapshot. Consider security headers, cookie flags only when cookie evidence is provided, CORS, SEO metadata, and accessibility. Return a concise executive summary and findings.`
    : `You are an expert software security auditor and static analysis specialist.
Analyze this source code (${contextMeta.language || 'text'}), file: ${contextMeta.filename || target}.
Source:
\`\`\`${contextMeta.language || ''}
${contentSnippet.substring(0, 4000)}
\`\`\`

Look for evidence-based vulnerabilities and quality issues including OWASP Top 10, CWE patterns, logic errors, input validation, authentication/authorization gaps, and unsafe execution. Do not claim a vulnerability without evidence. Give actionable remediation and, when useful, a small proposed fix.`;

  const schemaHint = `Return ONLY a valid JSON object with this shape:
{
  "summary": "2-4 sentence executive summary",
  "issues": [{
    "category": "security|seo|accessibility|performance|quality",
    "severity": "critical|high|medium|low|passed",
    "title": "short title",
    "description": "evidence-based explanation",
    "impact": "real-world impact",
    "remediation": "concrete fix",
    "originalCode": "optional evidence snippet",
    "proposedFix": "optional replacement"
  }]
}
Use empty strings for unavailable optional text and an empty issues array if no additional findings are justified.`;

  try {
    const response = await fetch(`${baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model,
        temperature: 0.1,
        max_tokens: 1800,
        response_format: { type: 'json_object' },
        messages: [
          { role: 'system', content: schemaHint },
          { role: 'user', content: prompt },
        ],
      }),
      signal: AbortSignal.timeout(45_000),
    });

    if (!response.ok) {
      const detail = (await response.text()).slice(0, 500);
      throw new Error(`Alibaba Cloud API returned HTTP ${response.status}: ${detail}`);
    }

    const body = await response.json() as {
      choices?: Array<{ message?: { content?: string | null } }>;
    };
    const text = body.choices?.[0]?.message?.content;
    if (!text) throw new Error('Alibaba Cloud API returned an empty response.');

    const parsed = JSON.parse(text);
    const validCategories = ['security', 'seo', 'accessibility', 'performance', 'quality'];
    const validSeverities = ['critical', 'high', 'medium', 'low', 'passed'];
    const rawIssues = Array.isArray(parsed.issues) ? parsed.issues : [];
    const additionalIssues: AuditIssue[] = rawIssues
      .filter((item: any) => item && typeof item.title === 'string' && typeof item.description === 'string')
      .slice(0, 30)
      .map((item: any, idx: number) => {
        const category = validCategories.includes(item.category) ? item.category : (type === 'url' ? 'seo' : 'security');
        const severity = validSeverities.includes(item.severity) ? item.severity : 'medium';
        return {
          id: `ai-finding-${idx + 1}-${Date.now().toString(36)}`,
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
  } catch (err) {
    // Keep the deterministic audit available if the optional AI service is down.
    console.warn('Alibaba Cloud analysis failed; using deterministic findings only:', err instanceof Error ? err.message : 'unknown error');
    return fallback(type, target, contextMeta);
  }
}
