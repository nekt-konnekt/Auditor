import { GoogleGenAI, Type } from '@google/genai';
import { AuditIssue } from '../types/audit.ts';

let aiInstance: GoogleGenAI | null = null;

function getAIClient(): GoogleGenAI | null {
  if (!process.env.GEMINI_API_KEY) {
    return null;
  }
  if (!aiInstance) {
    aiInstance = new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return aiInstance;
}

export interface GeminiAuditAnalysis {
  summary: string;
  additionalIssues: AuditIssue[];
}

/**
 * Validate AI-generated findings against the exact material supplied to the model.
 * This is a provenance check, not proof that the model's interpretation is correct.
 */
export function filterEvidenceBackedIssues(
  candidateIssues: unknown,
  type: 'url' | 'code',
  contentSnippet: string,
  contextMeta: Record<string, any>,
): AuditIssue[] {
  if (!Array.isArray(candidateIssues)) return [];
  const validCategories = ['security', 'seo', 'accessibility', 'performance', 'quality'];
  const validSeverities = ['critical', 'high', 'medium', 'low'];
  const observableText = contentSnippet.substring(0, type === 'url' ? 3000 : 4000);
  const observedHeaders = type === 'url' ? JSON.stringify(contextMeta.headers || {}) : '';

  return candidateIssues.flatMap((item: any, idx: number) => {
    if (!item || typeof item !== 'object') return [];
    const evidence = typeof item.evidence === 'string' ? item.evidence.trim() : '';
    const evidenceIsObserved = evidence.length >= 12
      && (observableText.includes(evidence) || observedHeaders.includes(evidence));
    if (!evidenceIsObserved || item.severity === 'passed') return [];
    if (
      typeof item.title !== 'string' || !item.title.trim()
      || typeof item.description !== 'string' || !item.description.trim()
      || typeof item.remediation !== 'string' || !item.remediation.trim()
    ) return [];

    const cat = validCategories.includes(item.category) ? item.category : (type === 'url' ? 'seo' : 'security');
    const sev = validSeverities.includes(item.severity) ? item.severity : 'medium';

    return [{
      id: `ai-finding-${idx + 1}-${Date.now().toString(36)}`,
      category: cat,
      severity: sev === 'critical' ? 'high' : sev,
      title: `Potential (AI-assisted): ${item.title}`,
      description: `AI-assisted interpretation; surrounding context and exploitability were not independently validated. ${item.description}`,
      impact: typeof item.impact === 'string' ? item.impact : undefined,
      remediation: item.remediation,
      evidence,
      codeSnippet: item.originalCode || item.proposedFix ? {
        original: item.originalCode,
        proposed: item.proposedFix,
      } : undefined,
    }];
  });
}

/**
 * Perform deep contextual AI security and code quality analysis using Gemini 3.8 Flash
 */
export async function analyzeWithGemini(
  type: 'url' | 'code',
  target: string,
  contentSnippet: string,
  contextMeta: Record<string, any>
): Promise<GeminiAuditAnalysis> {
  const ai = getAIClient();
  if (!ai) {
    return {
      summary:
        type === 'url'
          ? `Auditor evaluated the submitted HTTP response against selected checks for transport/security headers, SEO metadata, selected HTML accessibility signals, and HTML fetch duration. Browser/runtime behavior and other routes were not tested.`
          : `Selected deterministic pattern checks ran on the supplied snippet for credential-like values, query construction, dynamic execution, HTML injection sinks, weak hashing, and empty catch blocks. This is not a complete security review.`,
      additionalIssues: [],
    };
  }

  try {
    const prompt =
      type === 'url'
        ? `You are an elite web application security and SEO auditor.
Analyze this website inspection snapshot:
URL: ${target}
HTTP Status: ${contextMeta.statusCode || 200}
Response Time: ${contextMeta.responseTimeMs || 0} ms
Observed Headers: ${JSON.stringify(contextMeta.headers || {})}
HTML Snippet / Structure:
${contentSnippet.substring(0, 3000)}

Report only issues directly supported by the supplied snapshot. Do not infer that a header, cookie, route, runtime behavior, or security control is missing unless the supplied evidence supports that conclusion. Do not report cookie attributes unless a relevant Set-Cookie header is present; do not report CORS behavior unless relevant CORS headers are present. Every issue must include an exact evidence excerpt copied from the supplied headers or HTML. If you cannot cite an exact excerpt, omit the issue. Do not return "passed" findings; deterministic checks handle pass results. Treat recommendations and best practices as low-severity observations unless concrete impact is evidenced.
Provide a concise summary limited to the observed snapshot, not a claim that the whole website is secure or insecure.`
        : `You are an expert software security auditor and static analysis specialist.
Analyze this source code (${contextMeta.language || 'text'}):
File: ${contextMeta.filename || 'Snippet'}
Source:
\`\`\`${contextMeta.language || ''}
${contentSnippet.substring(0, 4000)}
\`\`\`

Review only the source text provided. Do not infer surrounding application behavior, runtime exploitability, authentication flow, deployment configuration, or missing controls that are not visible in the supplied code. A suspicious API or pattern is not automatically a vulnerability; explain the condition required for risk. Every finding must include an exact evidence excerpt copied verbatim from the supplied source. If no exact excerpt supports a finding, omit it. Do not return "passed" findings; deterministic checks handle pass results.
For each supported finding, provide:
1. Severity (critical, high, medium, or low), calibrated to the evidence
2. Category (security, quality, performance, seo, or accessibility)
3. Clear title and description
4. Risk impact, including uncertainty where relevant
5. Concrete remediation
6. An exact evidence excerpt copied verbatim from the supplied source.`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            summary: {
              type: Type.STRING,
              description: 'Comprehensive 2-4 sentence executive summary of the overall audit findings, security posture, and top priorities.',
            },
            issues: {
              type: Type.ARRAY,
              description: 'List of specific audit findings',
              items: {
                type: Type.OBJECT,
                properties: {
                  category: {
                    type: Type.STRING,
                    description: 'One of: security, seo, accessibility, performance, quality',
                  },
                  severity: {
                    type: Type.STRING,
                    description: 'One of: critical, high, medium, low, passed',
                  },
                  title: {
                    type: Type.STRING,
                    description: 'Concise issue title',
                  },
                  description: {
                    type: Type.STRING,
                    description: 'Detailed explanation of why this is an issue',
                  },
                  impact: {
                    type: Type.STRING,
                    description: 'Real-world risk or impact if left unaddressed',
                  },
                  remediation: {
                    type: Type.STRING,
                    description: 'Concrete actionable steps to fix or mitigate',
                  },
                  evidence: {
                    type: Type.STRING,
                    description: 'Exact verbatim excerpt from the provided headers, HTML, or source code that supports this finding.',
                  },
                  originalCode: {
                    type: Type.STRING,
                    description: 'Optional snippet of problematic code or selector',
                  },
                  proposedFix: {
                    type: Type.STRING,
                    description: 'Optional proposed secure code replacement or fix',
                  },
                },
                required: ['category', 'severity', 'title', 'description', 'remediation', 'evidence'],
              },
            },
          },
          required: ['summary', 'issues'],
        },
      },
    });

    const parsed = JSON.parse(response.text || '{}');
    const additionalIssues = filterEvidenceBackedIssues(parsed.issues, type, contentSnippet, contextMeta);

    const summary = additionalIssues.length > 0
      ? `AI-assisted review returned ${additionalIssues.length} additional finding(s) whose cited evidence appears in the supplied snapshot. Validate the context and impact of each finding before treating it as confirmed.`
      : 'AI-assisted review returned no additional findings that met the evidence requirement. This is not evidence that no other issues exist; review the deterministic findings and stated coverage limits.';

    return {
      summary,
      additionalIssues,
    };
  } catch (err) {
    console.warn('Gemini analysis skipped or failed, using heuristic fallback:', err);
    return {
      summary:
        type === 'url'
          ? `Automated diagnostic checks evaluated selected security headers, mobile viewport metadata, SEO tags, and HTML accessibility signals for ${target}. Browser behavior and other routes were not tested.`
          : `Selected static pattern checks ran on ${contextMeta.filename || 'the supplied snippet'} for credential-like values, SQL query construction, dynamic execution, and HTML injection sinks. Findings require context review; untested code and runtime behavior are outside this scan.`,
      additionalIssues: [],
    };
  }
}
