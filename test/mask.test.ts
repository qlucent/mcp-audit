import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mask, excerpt, redact } from '../src/mask.ts';
import { audit } from '../src/engine.ts';
import { parseFile } from '../src/parse.ts';
import { normalize } from '../src/normalize.ts';

test('mask short', () => assert.equal(mask('short'), '••••••'));
test('mask github prefix', () => assert.equal(mask('ghp_EXAMPLEexampleEXAMPLEexample0000'), 'ghp_••••0000'));
test('mask aws prefix', () => assert.equal(mask('AKIAEXAMPLEEXAMPLE00'), 'AKIA••••LE00'));
test('mask no prefix', () => assert.equal(mask('abcdefghijklmnopqrst'), '••••qrst'));


const run = (cfg: unknown) => audit([{ name: 'a.json', text: JSON.stringify(cfg, null, 2) }]);

test('redacts unmatched low-entropy password', () => {
  const r = run({ mcpServers: { s: { url: 'http://example.com/mcp', env: { DB_PASSWORD: 'hunter2hunter2' } } } });
  const f = r.findings.find((x) => x.ruleId === 'remote-http');
  assert.ok(f && f.excerpt.length > 0);
  assert.ok(f.excerpt.some((l) => l.text.includes('••••')));
  assert.ok(!JSON.stringify(r).includes('hunter2'));
});
test('redacts --token arg value and =form', () => {
  const text = JSON.stringify({ mcpServers: { s: { command: 'npx', args: ['--token', 'hunter2hunter2', '--password=hunter3hunter3'] } } }, null, 2);
  const f = parseFile({ name: 'a.json', text });
  const out = redact(f).text;
  assert.ok(!out.includes('hunter'));
  assert.ok(out.includes('"--password=••••••"'));
  JSON.parse(out);
});
test("excerpt only covers the finding's line ±2", () => {
  const text = Array.from({ length: 20 }, (_, i) => `l${i + 1}`).join('\n');
  const ex = excerpt(redact(parseFile({ name: 'x', text })), 3, text.indexOf('l3'));
  assert.deepEqual(ex.map((e) => e.line), [1, 2, 3, 4, 5]);
  assert.deepEqual(ex.filter((e) => e.hit).map((e) => e.line), [3]);
});

test('redact masks --auth= and --key= values', () => {
  const text = JSON.stringify({ mcpServers: { s: { command: 'npx', args: ['--auth=abcdefghijklmnop1234', '--key=abcdefghijklmnop1234'] } } }, null, 2);
  const f = parseFile({ name: 'a.json', text });
  const out = redact(f).text;
  assert.ok(!out.includes('abcdefghijklmnop'));
  assert.ok(out.includes('"--auth=••••1234"') && out.includes('"--key=••••1234"'));
});
