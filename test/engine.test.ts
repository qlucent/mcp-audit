import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { audit, computeVerdict } from '../src/engine.ts';
import type { Finding, Severity } from '../src/types.ts';

const http = JSON.stringify({ mcpServers: { r: { url: 'http://example.com/mcp' } } }, null, 2);
const f = (severity: Severity, file = 'a.json', line = 1): Finding => ({
  ruleId: 'x', severity, title: 't', file, line, column: 1, excerpt: [], why: '', fix: '', helpUri: '',
});
const many = (s: Severity, n: number) => Array.from({ length: n }, () => f(s));

test('audit continues past a broken file', () => {
  const r = audit([{ name: 'bad.json', text: '{ nope' }, { name: 'good.json', text: http }]);
  assert.ok(r.files[0].error);
  assert.ok(r.findings.some((x) => x.file === 'good.json'));
});

test('same config twice yields findings per file', () => {
  const r = audit([{ name: 'a.json', text: http }, { name: 'b.json', text: http }]);
  const hits = r.findings.filter((x) => x.ruleId === 'remote-http');
  assert.equal(hits.length, 2);
  assert.notEqual(hits[0].file, hits[1].file);
});

test('verdict tiers', () => {
  assert.equal(computeVerdict([...many('critical', 1), ...many('high', 2), ...many('medium', 1)], 20).text,
    'Not ready to roll out: 1 critical, 2 high, 1 medium');
  assert.equal(computeVerdict([...many('medium', 2), ...many('low', 1)], 20).text,
    'Review before rollout: 2 medium, 1 low');
  assert.equal(computeVerdict([], 20).text, 'None of the 20 rules matched this config');
});

test('findings sorted by severity then file then line', () => {
  const r = audit([{ name: 'b.json', text: http }, { name: 'a.json', text: http }]);
  assert.deepEqual(r.findings.filter((x) => x.ruleId === 'remote-http').map((x) => x.file), ['a.json', 'b.json']);
});

test('helpUri points to rule page', () => {
  const r = audit([{ name: 'a.json', text: http }]);
  assert.equal(r.findings[0].helpUri, 'https://qlucent.com/tools/mcp-audit/rules/remote-http');
});

test('audits a 5 MB pretty-printed .claude.json with ~100 findings quickly', () => {
  const hist = Array.from({ length: 42000 }, (_, i) => ({ display: `prompt number ${i} `.repeat(3), n: i }));
  const projects = Object.fromEntries(Array.from({ length: 50 }, (_, i) =>
    [`/p/${i}`, { mcpServers: { r: { url: 'http://example.com/mcp' } }, history: hist.slice(0, 100) }]));
  const text = JSON.stringify({ history: hist, projects }, null, 2);
  assert.ok(text.length > 5_000_000, String(text.length));
  const t0 = performance.now();
  const r = audit([{ name: '.claude.json', text }]);
  const ms = performance.now() - t0;
  assert.ok(r.findings.length >= 100, String(r.findings.length));
  // ponytail: wall-clock budget; ~0.6 s alone, up to ~3 s while the leak suite spawns CLIs in parallel. The
  // pre-I2 code took ~5 s alone (far more under load). Move to a load-independent check if this flakes.
  assert.ok(ms < 4000, `${ms} ms`);
});

test('an unrecognised file is flagged and never reads as clear (I3)', () => {
  const vscodeSettings = JSON.stringify({ 'editor.fontSize': 14, 'files.autoSave': 'off' });
  const r = audit([{ name: 'settings.json', text: vscodeSettings }]);
  assert.equal(r.files[0].unrecognised, true);
  assert.equal(r.verdict.level, 'unrecognised');
  assert.ok(!r.verdict.text.includes('None of'), r.verdict.text);
  const mixed = audit([{ name: 'settings.json', text: vscodeSettings }, { name: 'a.json', text: JSON.stringify({ mcpServers: {} }) }]);
  assert.equal(mixed.verdict.level, 'clear');
  assert.equal(mixed.files[1].unrecognised, undefined);
});

test('n2: 5,000 secret-bearing servers (20,000 findings) stay fast', { timeout: 60_000 }, () => {
  const tok = (i: number) => 'Zq' + i.toString(36).padStart(6, '0') + 'mXc0vB7nPLk2Ra9s';
  const servers = Object.fromEntries(Array.from({ length: 5000 }, (_, i) => [`s${i}`, {
    command: 'npx', args: ['-y', `pkg${i}@latest`, '--header', `X-Api-Key: ${tok(i)}`, `--token=${tok(i)}x`],
    env: { API_KEY: tok(i) + 'e', DB_URL: `postgres://u:${tok(i)}p@h/db` },
  }]));
  const t0 = performance.now();
  const r = audit([{ name: 'mcp.json', text: JSON.stringify({ mcpServers: servers }, null, 1) }]);
  const ms = performance.now() - t0;
  assert.ok(r.findings.length >= 20000, String(r.findings.length));
  assert.ok(!/Zq[0-9a-z]{6}mXc0vB7nPLk2Ra9s/.test(JSON.stringify(r)));
  // ponytail: wall-clock budget; the regressed (quadratic) code took 16-28 s here, the fixed code 4-7 s in the suite.
  assert.ok(ms < 12000, `${ms} ms`);
});

test('n9: same-named inputs get their own excerpts and summaries', () => {
  const a = JSON.stringify({ mcpServers: { alpha: { url: 'http://admin:Pa55w0rdXyz9Qk@api.example.com/mcp' } } }, null, 2);
  const b = JSON.stringify({ mcpServers: { beta: { url: 'http://x.example.com/mcp' } } }, null, 2);
  const r = audit([{ name: 'mcp.json', text: a }, { name: 'mcp.json', text: b }]);
  assert.deepEqual(r.files.map((x) => x.file), ['mcp.json', 'mcp.json (2)']);
  const hit = (file: string) => r.findings.find((x) => x.ruleId === 'remote-http' && x.file === file)!;
  assert.ok(hit('mcp.json').excerpt.some((l) => JSON.stringify(l).includes('api.example.com')));
  assert.ok(hit('mcp.json (2)').excerpt.some((l) => JSON.stringify(l).includes('x.example.com')));
  assert.ok(!JSON.stringify(r.findings.map((x) => x.excerpt)).includes('Pa55w0rd'));
  const broken = audit([{ name: 'mcp.json', text: a }, { name: 'mcp.json', text: '{ nope' }]);
  assert.ok(broken.files[1].error);
  assert.ok(broken.findings.find((x) => x.ruleId === 'remote-http' && x.file === 'mcp.json')!.excerpt.length > 0);
});
