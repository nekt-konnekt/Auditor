import assert from 'node:assert/strict';
import test from 'node:test';
import { detectExposureSecrets } from '../src/lib/exposure-scan.ts';

test('exposure scanner detects a fake secret pattern but only returns a masked preview', () => {
  const fakeSecret = 'sk_live_abcdefghijklmnopQRSTUV';
  const findings = detectExposureSecrets(`const STRIPE_SECRET_KEY = "${fakeSecret}";`);
  assert.ok(findings.length > 0);
  assert.ok(findings.some((finding) => finding.name === 'Stripe secret key' || finding.name === 'secret-like assigned token'));
  for (const finding of findings) {
    assert.ok(finding.preview.length < fakeSecret.length);
    assert.equal(finding.preview.includes(fakeSecret), false);
    assert.match(finding.preview, /\[REDACTED\]/);
  }
});

test('exposure scanner identifies AWS access-key patterns without returning the full value', () => {
  const fakeKey = 'AKIA1234567890ABCDEF';
  const findings = detectExposureSecrets(`AWS_ACCESS_KEY_ID=${fakeKey}`);
  assert.ok(findings.some((finding) => finding.name === 'AWS access key'));
  assert.equal(findings.some((finding) => finding.preview.includes(fakeKey)), false);
});

test('exposure scanner ignores ordinary text without secret-like patterns', () => {
  assert.deepEqual(detectExposureSecrets('This is a normal public JavaScript bundle.'), []);
});
