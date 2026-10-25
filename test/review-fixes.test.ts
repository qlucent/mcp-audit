// Final-review items I5-I8 and the Task 5 gaps.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { audit } from '../src/engine.ts';
import { checks } from '../src/checks/index.ts';
import { KNOWN_CHECKS } from '../src/checks/names.ts';

const findings = (server: object, name = 'mcp.json') =>
  audit([{ name, text: JSON.stringify({ mcpServers: { s: server } }, null, 2) }]).findings;
const ids = (server: object, name?: string) => findings(server, name).map((f) => f.ruleId);

test('I5: remote-no-auth is low and does not push OAuth users to a Bearer header', () => {
  const [f] = findings({ url: 'https://mcp.notion.com/mcp' }).filter((x) => x.ruleId === 'remote-no-auth');
  assert.equal(f!.severity, 'low');
  assert.match(f!.why, /OAuth/);
  assert.match(f!.fix, /OAuth/);
  assert.ok(!/^Add a header/.test(f!.fix), f!.fix);
});

test('I6: placeholders and prose are not secrets', () => {
  for (const [k, v] of [
    ['GITHUB_PERSONAL_ACCESS_TOKEN', 'your-github-personal-access-token-here'],
    ['OPENAI_API_KEY', 'sk-your-openai-key-goes-here-xx'],
    ['SLACK_BOT_TOKEN', 'xoxb-your-bot-token'],
    ['AUTH_MODE', 'interactive-browser-login'],
    ['SECRET_ARN', 'arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf'],
    ['API_KEY', '<paste your api key>'],
    ['DB_PASSWORD', 'changeme'],
    ['TOKEN_TYPE', 'Bearer'],
    ['AUTH_REGION', 'eu-west-1-zone-a-b'],
    ['AUTH_ENDPOINT', 'login.example.com:8443'],
    ['SECRET_ID', 'prod-database-credentials'],
    ['AUTH_TOKEN', 'placeholder-value-for-docs'],
  ])
    assert.ok(!ids({ command: 'node', env: { [k]: v } }).includes('secret-in-env'), `${k}=${v}`);
  // EXAMPLE fixtures and real-looking values still fire.
  assert.ok(ids({ command: 'node', env: { GH: 'ghp_EXAMPLEexampleEXAMPLEexample0000' } }).includes('secret-in-env'));
  assert.ok(ids({ command: 'node', env: { API_TOKEN: 'aZ3kQ9xLm2PvR7tYc5WbN8dF' } }).includes('secret-in-env'));
  // No digit: not a high-entropy secret.
  assert.ok(!ids({ command: 'node', env: { API_TOKEN: 'aZkQxLmPvRtYcWbNdFhJsGeU' } }).includes('secret-in-env'));
});

test('I7: wrapped Windows launchers get the package rules', () => {
  assert.ok(ids({ command: 'cmd', args: ['/c', 'npx', '-y', '@modelcontextprotocol/server-filesystem', 'C:\\'] }).includes('fs-root'));
  const latest = findings({ command: 'cmd', args: ['/c', 'npx', 'pkg@latest'] }).find((f) => f.ruleId === 'npx-latest');
  assert.ok(latest);
  assert.equal(latest.field, 'args.2');
  assert.ok(ids({ command: 'cmd', args: ['/c', 'npx -y pkg'] }).includes('npx-unpinned'));
  assert.ok(ids({ command: 'cmd', args: ['/c', 'npx', '-y', 'git+https://github.com/o/r.git'] }).includes('package-from-url'));
  assert.ok(ids({ command: 'cmd', args: ['/c', 'uvx', 'mcp-server-fetch'] }).includes('uvx-unpinned'));
  const pctHome = ids({ command: 'cmd', args: ['/c', 'npx', '-y', '@modelcontextprotocol/server-filesystem@2025.8.21', '%USERPROFILE%\\Documents'] });
  assert.ok(!pctHome.includes('shell-server'), pctHome.join());
  assert.ok(ids({ command: 'cmd', args: ['/c', 'npx', '-y', '@modelcontextprotocol/server-filesystem@2025.8.21', '%USERPROFILE%'] }).includes('fs-root'));
});

test('I8: Windsurf serverUrl is read', () => {
  const r = audit([{ name: '.codeium/windsurf/mcp_config.json', text: JSON.stringify({ mcpServers: { w: { serverUrl: 'http://example.com/mcp' } } }) }]);
  assert.ok(r.findings.some((f) => f.ruleId === 'remote-http'));
  assert.ok(!r.findings.some((f) => f.ruleId === 'unknown-transport'));
});

test('Task 5 gaps: references in url userinfo and after a secret flag are fine', () => {
  assert.ok(!ids({ url: 'https://u:${TOKEN}@h.example/mcp' }).includes('secret-in-url'));
  assert.ok(!ids({ command: 'node', args: ['s.js', '--token', '${TOKEN}'] }).includes('secret-in-args'));
  assert.ok(!ids({ command: 'node', args: ['s.js', '--api-key=${env:KEY}'] }).includes('secret-in-args'));
});

test('fs-sensitive-path: a docker -v mount ends at the colon', () =>
  assert.ok(ids({ command: 'docker', args: ['run', '-v', '~/.aws:/root/.aws:ro', 'mcp/aws:1.0.0'] }).includes('fs-sensitive-path')));

test('every named check is registered', () => assert.deepEqual(Object.keys(checks).sort(), [...KNOWN_CHECKS].sort()));

test('R19: context7 counts as untrusted input', () => {
  const r = audit([{ name: 'mcp.json', text: JSON.stringify({ mcpServers: {
    c7: { command: 'npx', args: ['-y', '@upstash/context7-mcp@1.0.0'] },
    gh: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github@1.0.0'] },
  } }) }]);
  assert.ok(r.findings.some((f) => f.ruleId === 'dangerous-mix' && f.severity === 'high'));
});

test('R14: settings wording', () => {
  const d = (name: string, cfg: object) => audit([{ name, text: JSON.stringify(cfg) }]).findings.map((f) => f.detail).join(' ');
  assert.match(d('.claude/settings.json', { permissions: { defaultMode: 'bypassPermissions' } }), /where honoured \(user\/managed settings\)/);
  assert.match(d('mcp.json', { mcpServers: { s: { command: 'node', alwaysAllow: ['*'] } } }), /approve-everything entry \(not documented as a wildcard\)/);
});
