import { test } from 'node:test';
import assert from 'node:assert/strict';
import { audit } from '../src/engine.ts';

const run = (file: string, text: string, id: string) =>
  audit([{ name: file, text }]).findings.filter((f) => f.ruleId === id);
const S = '.claude/settings.json';

test('bypass-permissions is high at the value', () => {
  const [f] = run(S, '{\n  "permissions": {"defaultMode": "bypassPermissions"}\n}', 'bypass-permissions');
  assert.equal(f.severity, 'high');
  assert.equal(f.line, 2);
});
test('enableAllProjectMcpServers is high; false is clean', () => {
  assert.equal(run(S, '{"enableAllProjectMcpServers": true}', 'auto-approve-all')[0].severity, 'high');
  assert.equal(run(S, '{"enableAllProjectMcpServers": false}', 'auto-approve-all').length, 0);
});
test('alwaysAllow and autoApprove "*" are high and name the server; specific lists are clean', () => {
  const t = (k: string, v: string) => `{"mcpServers":{"x":{"command":"node","${k}":${v}}}}`;
  for (const k of ['alwaysAllow', 'autoApprove']) {
    const [f] = run('mcp.json', t(k, '["*"]'), 'auto-approve-all');
    assert.equal(f.severity, 'high');
    assert.equal(f.server, 'x');
    assert.equal(run('mcp.json', t(k, '["a","b"]'), 'auto-approve-all').length, 0);
  }
});
test('broad-permissions is medium for broad rules only', () => {
  for (const r of ['mcp__*', 'Bash', 'Bash(*)', 'Bash(*:*)']) {
    const [f] = run(S, JSON.stringify({ permissions: { allow: [r] } }), 'broad-permissions');
    assert.equal(f.severity, 'medium', r);
  }
  assert.equal(run(S, '{"permissions":{"allow":["Bash(npm test:*)"]}}', 'broad-permissions').length, 0);
});
test('settings rules ignore non-Claude-Code settings files', () => {
  assert.equal(run('.cursor/mcp.json', '{"permissions":{"defaultMode":"bypassPermissions"}}', 'bypass-permissions').length, 0);
});
