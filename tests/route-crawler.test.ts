import assert from 'node:assert/strict';
import test from 'node:test';
import { parseRobotsDisallowRules } from '../src/lib/route-crawler.ts';

test('robots parser reads wildcard disallow rules and ignores comments', () => {
  const rules = parseRobotsDisallowRules(`User-agent: *
Disallow: /private
Disallow: /admin/ # internal pages
Allow: /private/public
`);
  assert.deepEqual(rules, ['/private', '/admin/']);
});

test('robots parser does not apply rules scoped only to a named crawler', () => {
  const rules = parseRobotsDisallowRules(`User-agent: AuditBot
Disallow: /internal
User-agent: *
Disallow: /members
`);
  assert.deepEqual(rules, ['/members']);
});

test('robots parser tolerates empty and malformed directives', () => {
  assert.deepEqual(parseRobotsDisallowRules('User-agent: *\nDisallow:\nNot a directive'), []);
});
