import assert from 'node:assert/strict';
import test from 'node:test';
import { auditGitHubRepo, parseGitHubUrl } from '../src/lib/github-auditor.ts';

test('GitHub URL parser accepts a public owner/repository URL', () => {
  assert.deepEqual(parseGitHubUrl('https://github.com/octocat/Hello-World'), {
    owner: 'octocat',
    repo: 'Hello-World',
  });
});

test('GitHub URL parser strips a .git suffix', () => {
  assert.deepEqual(parseGitHubUrl('https://github.com/octocat/Hello-World.git'), {
    owner: 'octocat',
    repo: 'Hello-World',
  });
});

test('a missing or private repository fails without generating a report', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ message: 'Not Found' }), {
    status: 404,
    headers: { 'content-type': 'application/json' },
  })) as typeof fetch;

  try {
    await assert.rejects(
      auditGitHubRepo('https://github.com/example/nonexistent-private-repository'),
      /not found or is not publicly accessible.*no report was generated/i,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('GitHub API rate limiting fails without generating a report', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ message: 'API rate limit exceeded' }), {
    status: 403,
    headers: { 'content-type': 'application/json' },
  })) as typeof fetch;

  try {
    await assert.rejects(
      auditGitHubRepo('https://github.com/octocat/Hello-World'),
      /rate-limited or denied.*no repository audit report was generated/i,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});
