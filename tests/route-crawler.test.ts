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

test('robots parser combines adjacent user-agent declarations in one group', () => {
  const rules = parseRobotsDisallowRules(`User-agent: *
User-agent: AuditorBot
Disallow: /private
`);
  assert.deepEqual(rules, ['/private']);
});

test('robots parser tolerates empty and malformed directives', () => {
  assert.deepEqual(parseRobotsDisallowRules('User-agent: *\nDisallow:\nNot a directive'), []);
});
