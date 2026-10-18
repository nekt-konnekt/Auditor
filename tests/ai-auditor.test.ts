import assert from 'node:assert/strict';
import test from 'node:test';
import { analyzeWithAI, normalizeFindingText, overlapsRuleFinding, parseAnalysis } from '../src/lib/ai-auditor.ts';

const deterministic = [
  { id: 'sec-csp', title: 'Missing Content-Security-Policy (CSP) Header' },
  { id: 'sec-hsts', title: 'Missing Strict-Transport-Security (HSTS) Header' },
];

test('normalization unifies Unicode hyphens and case', () => {
  assert.equal(normalizeFindingText('Missing Content‑Security–Policy'), 'missing content security policy');
});

test('AI duplicate of a deterministic security-header finding is filtered', () => {
  const result = parseAnalysis(JSON.stringify({
    summary: 'Reviewed the page.',
    issues: [
      {
        category: 'security',
        severity: 'high',
        title: 'Content Security Policy header is missing',
        description: 'The site does not set a CSP header.',
        remediation: 'Configure CSP.',
      },
      {
        category: 'security',
        severity: 'medium',
        title: 'Potential insecure postMessage handler',
        description: 'The source appears to accept messages without checking their origin.',
        remediation: 'Validate the message origin.',
      },
    ],
  }), 'url', deterministic);

  assert.equal(result.additionalIssues.length, 1);
  assert.match(result.additionalIssues[0].title, /postMessage/i);
});

test('AI observation is retained when no deterministic rule overlaps', () => {
  assert.equal(overlapsRuleFinding({
    id: 'ai-finding',
    title: 'Potential insecure postMessage handler',
    description: 'The source appears to accept messages without checking their origin.',
  }, deterministic), false);
});


test('Ollama Cloud uses the server-side key and OpenAI-compatible endpoint', async () => {
  const oldEnv = {
    primary: process.env.AI_PRIMARY_PROVIDER,
    fallbacks: process.env.AI_FALLBACK_PROVIDERS,
    ollamaKey: process.env.OLLAMA_API_KEY,
    ollamaModel: process.env.OLLAMA_MODEL,
  };
  const oldFetch = globalThis.fetch;
  let requestUrl = '';
  let requestHeaders: HeadersInit | undefined;
  try {
    process.env.AI_PRIMARY_PROVIDER = 'ollama-cloud';
    process.env.AI_FALLBACK_PROVIDERS = '';
    process.env.OLLAMA_API_KEY = 'test-ollama-secret';
    process.env.OLLAMA_MODEL = 'gemma4:31b';
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      requestUrl = String(input);
      requestHeaders = init?.headers;
      return new Response(JSON.stringify({
        choices: [{ message: { content: JSON.stringify({ summary: 'Ollama review complete.', issues: [] }) } }],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }) as typeof fetch;

    const result = await analyzeWithAI('url', 'https://example.com', '<html></html>', {});
    assert.equal(requestUrl, 'https://ollama.com/v1/chat/completions');
    assert.equal(new Headers(requestHeaders).get('authorization'), 'Bearer test-ollama-secret');
    assert.equal(result.summary, 'Ollama review complete.');
  } finally {
    globalThis.fetch = oldFetch;
    if (oldEnv.primary === undefined) delete process.env.AI_PRIMARY_PROVIDER; else process.env.AI_PRIMARY_PROVIDER = oldEnv.primary;
    if (oldEnv.fallbacks === undefined) delete process.env.AI_FALLBACK_PROVIDERS; else process.env.AI_FALLBACK_PROVIDERS = oldEnv.fallbacks;
    if (oldEnv.ollamaKey === undefined) delete process.env.OLLAMA_API_KEY; else process.env.OLLAMA_API_KEY = oldEnv.ollamaKey;
    if (oldEnv.ollamaModel === undefined) delete process.env.OLLAMA_MODEL; else process.env.OLLAMA_MODEL = oldEnv.ollamaModel;
  }
});

test('Ollama Cloud failure falls through to Groq when configured', async () => {
  const keys = ['AI_PRIMARY_PROVIDER', 'AI_FALLBACK_PROVIDERS', 'OLLAMA_API_KEY', 'GROQ_API_KEY', 'GROQ_MODEL'];
  const oldEnv = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  const oldFetch = globalThis.fetch;
  const calls: string[] = [];
  try {
    process.env.AI_PRIMARY_PROVIDER = 'ollama-cloud';
    process.env.AI_FALLBACK_PROVIDERS = 'groq,gemini';
    process.env.OLLAMA_API_KEY = 'test-ollama-secret';
    process.env.GROQ_API_KEY = 'test-groq-secret';
    process.env.GROQ_MODEL = 'openai/gpt-oss-120b';
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      calls.push(url);
      if (url.startsWith('https://ollama.com/')) return new Response('temporary failure', { status: 503 });
      return new Response(JSON.stringify({
        choices: [{ message: { content: JSON.stringify({ summary: 'Groq fallback succeeded.', issues: [] }) } }],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }) as typeof fetch;

    const result = await analyzeWithAI('url', 'https://example.com', '<html></html>', {});
    assert.equal(calls[0], 'https://ollama.com/v1/chat/completions');
    assert.equal(calls[1], 'https://api.groq.com/openai/v1/chat/completions');
    assert.equal(result.summary, 'Groq fallback succeeded.');
  } finally {
    globalThis.fetch = oldFetch;
    for (const key of keys) {
      const value = oldEnv[key];
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
});
