import assert from 'node:assert/strict';
import test from 'node:test';
import { validatePublicHttpUrl } from '../src/lib/safe-fetch.ts';

test('SSRF guard rejects loopback, link-local, and private IPv4 targets', async () => {
  for (const url of [
    'http://127.0.0.1/',
    'http://10.0.0.1/',
    'http://192.168.1.1/',
    'http://169.254.169.254/latest/meta-data/',
  ]) {
    await assert.rejects(() => validatePublicHttpUrl(url), /Local and private network targets/);
  }
});

test('SSRF guard rejects local IPv6 and non-HTTP schemes', async () => {
  await assert.rejects(() => validatePublicHttpUrl('http://[::1]/'), /Local and private network targets/);
  await assert.rejects(() => validatePublicHttpUrl('file:///etc/passwd'), /Only HTTP and HTTPS/);
});

test('SSRF guard rejects URLs containing embedded credentials', async () => {
  await assert.rejects(() => validatePublicHttpUrl('https://user:pass@8.8.8.8/'), /usernames or passwords/);
});

test('SSRF guard accepts a public IP literal and strips URL fragments', async () => {
  const url = await validatePublicHttpUrl('https://8.8.8.8/path#section');
  assert.equal(url.hostname, '8.8.8.8');
  assert.equal(url.hash, '');
});
