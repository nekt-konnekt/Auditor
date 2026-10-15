import assert from 'node:assert/strict';
import test from 'node:test';
import { getRegistrableDomain } from '../src/lib/readiness-preflight.ts';

test('registrable domain uses public suffix rules for multi-label suffixes', () => {
  assert.equal(getRegistrableDomain('app.example.co.uk'), 'example.co.uk');
  assert.equal(getRegistrableDomain('shop.example.com.au'), 'example.com.au');
});

test('registrable domain removes ordinary subdomains without relying on a www-only rule', () => {
  assert.equal(getRegistrableDomain('api.example.com'), 'example.com');
  assert.equal(getRegistrableDomain('www.example.com'), 'example.com');
});

test('registrable domain safely falls back for IP literals', () => {
  assert.equal(getRegistrableDomain('8.8.8.8'), '8.8.8.8');
});
