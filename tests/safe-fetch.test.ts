import assert from 'node:assert/strict';
import test from 'node:test';
import { fetchPublicPage, validatePublicHttpUrl } from '../src/lib/safe-fetch.ts';

test('rejects local, private, link-local, documentation, and reserved IPv4 targets', async () => {
  const targets = [
    'http://127.0.0.1/',
    'http://10.0.0.1/',
    'http://172.16.0.1/',
    'http://192.168.1.1/',
    'http://169.254.169.254/',
    'http://100.64.0.1/',
    'http://192.0.2.1/',
    'http://203.0.113.4/',
    'http://240.0.0.1/',
  ];
  for (const target of targets) {
    await assert.rejects(validatePublicHttpUrl(target), /Local and private network targets are not allowed/);
  }
});

test('rejects local and non-global IPv6 targets', async () => {
  for (const target of ['http://[::1]/', 'http://[fd00::1]/', 'http://[fe80::1]/', 'http://[::ffff:127.0.0.1]/']) {
    await assert.rejects(validatePublicHttpUrl(target), /Local and private network targets are not allowed/);
  }
});

test('rejects localhost aliases, local domains, unsupported protocols, and URL credentials', async () => {
  await assert.rejects(validatePublicHttpUrl('http://localhost/'), /Local and private network targets/);
  await assert.rejects(validatePublicHttpUrl('http://app.localhost/'), /Local and private network targets/);
  await assert.rejects(validatePublicHttpUrl('http://printer.local/'), /Local and private network targets/);
  await assert.rejects(validatePublicHttpUrl('file:///etc/passwd'), /Only HTTP and HTTPS/);
  await assert.rejects(validatePublicHttpUrl('https://user:password@example.com/'), /usernames or passwords/);
});

test('accepts a public IP literal and removes URL fragments', async () => {
  const url = await validatePublicHttpUrl('https://8.8.8.8/path#fragment');
  assert.equal(url.hostname, '8.8.8.8');
  assert.equal(url.hash, '');
});

test('redirects to private addresses are blocked before a second request', async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls += 1;
    return new Response(null, {
      status: 302,
      headers: { location: 'http://127.0.0.1/admin' },
    });
  }) as typeof fetch;
  try {
    await assert.rejects(fetchPublicPage('http://93.184.216.34/'), /Local and private network targets/);
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('response bodies over the configured size limit are rejected', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response('small body', {
    status: 200,
    headers: {
      'content-type': 'text/html',
      'content-length': String(2 * 1024 * 1024 + 1),
    },
  })) as typeof fetch;
  try {
    await assert.rejects(fetchPublicPage('http://93.184.216.34/'), /larger than the 2 MB audit limit/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
