import { GoogleGenAI, Type } from '@google/genai';
import type { AuditIssue } from '../types/audit.ts';

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
          ? `Audit conducted on ${target}. Analyzed live HTTP headers, SEO tags, markup accessibility, and response timing against modern web standards.`
          : `Static source code audit performed for ${contextMeta.filename || 'input code'}. Scanned for common vulnerabilities, OWASP patterns, and insecure implementations.`,
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

Identify any subtle security vulnerabilities, missing best practices (like Content Security Policy, Permissions-Policy, Cookie flags, CORS, SEO meta, or accessibility pitfalls).
Provide an executive summary and a list of specific actionable issues with severity ratings.`
        : `You are an expert software security auditor and static analysis specialist.
Analyze this source code (${contextMeta.language || 'text'}):
File: ${contextMeta.filename || 'Snippet'}
Source:
\`\`\`${contextMeta.language || ''}
${contentSnippet.substring(0, 4000)}
\`\`\`

Perform an in-depth vulnerability audit covering OWASP Top 10, CWE patterns, logic errors, race conditions, authentication/authorization gaps, input validation, and code smells.
For each finding, provide:
1. Exact severity (critical, high, medium, low, or passed)
2. Category (security, quality, performance)
3. Clear human title and description
4. Risk impact
5. Concrete remediation instructions and a code snippet showing the fix.`;

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
                  originalCode: {
                    type: Type.STRING,
                    description: 'Optional snippet of problematic code or selector',
                  },
                  proposedFix: {
                    type: Type.STRING,
                    description: 'Optional proposed secure code replacement or fix',
                  },
                },
                required: ['category', 'severity', 'title', 'description', 'remediation'],
              },
            },
          },
          required: ['summary', 'issues'],
        },
      },
    });

    const parsed = JSON.parse(response.text || '{}');
    const additionalIssues: AuditIssue[] = (parsed.issues || []).map((item: any, idx: number) => {
      const validCategories = ['security', 'seo', 'accessibility', 'performance', 'quality'];
      const validSeverities = ['critical', 'high', 'medium', 'low', 'passed'];

      const cat = validCategories.includes(item.category) ? item.category : (type === 'url' ? 'seo' : 'security');
      const sev = validSeverities.includes(item.severity) ? item.severity : 'medium';

      return {
        id: `ai-finding-${idx + 1}-${Date.now().toString(36)}`,
        category: cat,
        severity: sev,
        title: item.title,
        description: item.description,
        impact: item.impact,
        remediation: item.remediation,
        codeSnippet: item.originalCode || item.proposedFix ? {
          original: item.originalCode,
          proposed: item.proposedFix,
        } : undefined,
      };
    });

    return {
      summary: parsed.summary || 'Audit completed successfully.',
      additionalIssues,
    };
  } catch (err) {
    console.warn('Gemini analysis skipped or failed, using heuristic fallback:', err);
    return {
      summary:
        type === 'url'
          ? `Automated diagnostic audit of ${target}. Evaluated security headers, mobile viewport, metadata indexing, and DOM accessibility.`
          : `Static vulnerability audit for ${contextMeta.filename || 'code'}. Scanned for hardcoded credentials, SQL injection, and insecure execution patterns.`,
      additionalIssues: [],
    };
  }
}
