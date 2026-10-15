import assert from 'node:assert/strict';
import test from 'node:test';
import { detectPlatform } from '../src/lib/platform-detection.ts';

test('detects platform signals from public markup and headers', () => {
  const result = detectPlatform(
    { 'x-vercel-id': 'iad1::test', 'content-type': 'text/html' },
    '<html><script src="/_next/static/chunks/app.js"></script><img src="https://cdn.shopify.com/a.png"></html>',
  );
  assert.ok(result.platforms.includes('Next.js'));
  assert.ok(result.platforms.includes('Shopify'));
  assert.ok(result.platforms.includes('Vercel'));
});

test('does not infer a platform when no known signals are present', () => {
  assert.deepEqual(detectPlatform({ 'content-type': 'text/html' }, '<html><body>Hello</body></html>').platforms, []);
});
