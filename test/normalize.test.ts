import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { parseFile } from '../src/parse.ts';
import { normalize } from '../src/normalize.ts';

const n = (name: string, text: string) => normalize([parseFile({ name, text })]);

test('reads mcpServers stdio server', () => {
  const text = '{\n  "mcpServers": {\n    "s": {\n      "command": "npx",\n      "args": ["-y", "pkg"],\n      "env": {"K": "v"}\n    }\n  }\n}';
  const [s] = n('claude_desktop_config.json', text).servers;
  assert.equal(s.transport, 'stdio');
  assert.equal(s.command, 'npx');
  assert.deepEqual(s.args, ['-y', 'pkg']);
  assert.deepEqual({ ...s.env }, { K: 'v' });
  assert.equal(s.loc.line, 3);
  assert.equal(s.fieldLocs.command.line, 4);
  assert.equal(s.fieldLocs['args.1'].line, 5);
  assert.equal(s.fieldLocs['env.K'].line, 6);
});

test('reads vscode servers with type and url', () => {
  const [s] = n('.vscode/mcp.json', '{"servers":{"r":{"type":"http","url":"https://x"}}}').servers;
  assert.equal(s.transport, 'http');
  assert.equal(s.url, 'https://x');
  assert.deepEqual(s.groups, ['vscode']);
});

test('reads claude.json projects', () => {
  const text = '{"mcpServers":{"u":{"command":"a"}},"projects":{"/p/a":{"mcpServers":{"a":{"command":"a"}}},"/p/b":{"mcpServers":{"b":{"command":"b"}}}}}';
  const by = Object.fromEntries(n('.claude.json', text).servers.map((s) => [s.name, s.groups]));
  assert.deepEqual(by.a, ['claude-code:/p/a']);
  assert.deepEqual(by.b, ['claude-code:/p/b']);
  assert.deepEqual(by.u, ['claude-code:/p/a', 'claude-code:/p/b', 'claude-code']);
});

test('claude-code without projects groups as claude-code', () => {
  assert.deepEqual(n('.mcp.json', '{"mcpServers":{"u":{"command":"a"}}}').servers[0].groups, ['claude-code']);
});

test('groups by client across files', () => {
  const t = '{"mcpServers":{"x":{"command":"a"}}}';
  const c = normalize([parseFile({ name: 'a/.cursor/mcp.json', text: t }), parseFile({ name: 'b/.cursor/mcp.json', text: t })]);
  assert.deepEqual(c.servers.map((s) => s.groups), [['cursor'], ['cursor']]);
  const p = normalize([parseFile({ name: 'pasted-1', text: t }), parseFile({ name: 'pasted-2', text: t })]);
  assert.deepEqual(p.servers.map((s) => s.groups), [['file:pasted-1'], ['file:pasted-2']]);
});

test('collects claude-code-settings and vscode settings', () => {
  const r = n('.claude/settings.json', '{"permissions":{"allow":[]}}');
  assert.equal(r.settings.length, 1);
  assert.equal(r.settings[0].client, 'claude-code-settings');
  assert.equal(n('.vscode/mcp.json', '{"servers":{}}').settings.length, 1);
});

test('infers transport', () => {
  const t = (o: string) => n('x.json', `{"mcpServers":{"s":${o}}}`).servers[0].transport;
  assert.equal(t('{"url":"https://x/mcp"}'), 'http');
  assert.equal(t('{"url":"https://x/sse"}'), 'sse');
  assert.equal(t('{"type":"sse","url":"https://x"}'), 'sse');
  assert.equal(t('{}'), 'unknown');
  assert.equal(n('.gemini/settings.json', '{"mcpServers":{"s":{"httpUrl":"https://x"}}}').servers[0].url, 'https://x');
});

test('ignores non-string args and env values without crashing', () => {
  const [s] = n('x.json', '{"mcpServers":{"s":{"command":"c","args":[1,null,"a"],"env":{"A":1,"B":null,"C":"c"}}}}').servers;
  assert.deepEqual(s.args, ['a']);
  assert.deepEqual({ ...s.env }, { C: 'c' });
});

test('normalizes large claude.json quickly', () => {
  const hist = Array.from({ length: 50000 }, (_, i) => ({ display: `prompt number ${i} `.repeat(3), n: i }));
  const proj = (p: string) => [p, { mcpServers: { s: { command: 'x' } }, history: hist.slice(0, 100) }];
  const text = JSON.stringify({ history: hist, projects: Object.fromEntries(['/a', '/b', '/c'].map(proj)) });
  assert.ok(text.length > 4_000_000);
  const f = parseFile({ name: '.claude.json', text });
  const t0 = performance.now();
  const r = normalize([f]);
  assert.ok(performance.now() - t0 < 2000);
  assert.equal(r.servers.length, 3);
});
