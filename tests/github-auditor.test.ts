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

test('repository audit distinguishes an unclassified license file from no license file', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url === 'https://api.github.com/repos/octocat/Hello-World') {
      return new Response(JSON.stringify({
        default_branch: 'main',
        description: 'Example repository',
        license: null,
        stargazers_count: 1,
        forks_count: 0,
        open_issues_count: 0,
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (url.endsWith('/main/.gitignore')) return new Response('node_modules/\n', { status: 200 });
    if (url.endsWith('/main/README.md')) return new Response('# Example\n\n' + 'Documentation text. '.repeat(20), { status: 200 });
    if (url.endsWith('/main/package.json')) return new Response(JSON.stringify({ dependencies: { example: '1.0.0' } }), { status: 200 });
    if (url.endsWith('/main/LICENSE')) return new Response('Custom license terms requiring review.', { status: 200 });
    if (url.endsWith('/main/SECURITY.md') || /\/main\/(LICENSE\.md|LICENSE\.txt|COPYING|COPYING\.md)$/.test(url)) {
      return new Response('Not Found', { status: 404 });
    }
    return new Response('Not Found', { status: 404 });
  }) as typeof fetch;

  try {
    const report = await auditGitHubRepo('https://github.com/octocat/Hello-World');
    assert.equal(report.issues.some((item) => item.id === 'gh-license-missing'), false);
    assert.equal(report.issues.some((item) => item.id === 'gh-license-unclassified'), true);
    assert.match(report.summary, /did not scan all source files/i);
    assert.equal(report.issues.find((item) => item.id === 'gh-gitignore-env')?.severity, 'medium');
  } finally {
    globalThis.fetch = originalFetch;
  }
});
