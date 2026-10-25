import { test } from 'node:test';
import assert from 'node:assert/strict';
import { findSecret } from '../src/secrets.ts';
import { audit } from '../src/engine.ts';

const run = (server: unknown) =>
  audit([{ name: 'a.json', text: JSON.stringify({ mcpServers: { s: server } }, null, 2) }]).findings;
const ids = (server: unknown) => run(server).map((f) => f.ruleId);

test('detects provider tokens', () => {
  const fakes = [
    'ghp_EXAMPLEexampleEXAMPLEexample0000',
    'github_pat_EXAMPLEexampleEXAMPLE0000',
    'AKIAEXAMPLEEXAMPLE00',
    'xoxb-1234567890-EXAMPLEexample',
    'sk-EXAMPLEexampleEXAMPLE0000',
    'sk-proj-EXAMPLEexampleEXAMPLE0000',
    'sk-ant-EXAMPLEexampleEXAMPLE0000',
    'sk_live_EXAMPLEexampleEXAMPLE0000',
    'rk_live_EXAMPLEexampleEXAMPLE0000',
    'AIza' + 'EXAMPLEexampleEXAMPLEexample00000000'.slice(0, 35),
    '-----BEGIN RSA PRIVATE KEY-----',
  ];
  for (const f of fakes) assert.ok(findSecret(f)?.kind, f);
});
test('detects high-entropy value under secret-like key', () => {
  const v = 'aZ3kQ9xLm2PvR7tYc5WbN8dFh1JsGe4U';
  assert.ok(findSecret(v, 'MY_SERVICE_TOKEN'));
  assert.equal(findSecret(v, 'LOG_LEVEL'), null);
});
test('references are not secrets', () => {
  for (const r of ['${env:GITHUB_TOKEN}', '${input:token}', '${GITHUB_TOKEN}', '$GITHUB_TOKEN', '{{TOKEN}}']) {
    assert.equal(findSecret(r, 'API_TOKEN'), null, r);
  }
});
test('plain prose is not a secret', () => {
  assert.equal(findSecret('Read-only access to the docs folder', 'DESCRIPTION_KEY'), null);
});
test('secret-in-headers', () => {
  assert.ok(!ids({ url: 'https://h/mcp', headers: { Authorization: 'Bearer ${input:tok}' } }).includes('secret-in-headers'));
  assert.ok(ids({ url: 'https://h/mcp', headers: { Authorization: 'Bearer aZ3kQ9xLm2PvR7tYc5WbN8dFh1JsGe4U' } }).includes('secret-in-headers'));
});
test('secret-in-url', () => {
  assert.ok(ids({ url: 'https://user:pass123456789@host/mcp' }).includes('secret-in-url'));
  assert.ok(ids({ url: 'https://host/mcp?api_key=aZ3kQ9xLm2PvR7tYc5WbN8dF' }).includes('secret-in-url'));
  assert.ok(!ids({ url: 'https://host/mcp' }).includes('secret-in-url'));
});
test('secret-in-env and args', () => {
  assert.ok(ids({ command: 'x', env: { GH: 'ghp_EXAMPLEexampleEXAMPLEexample0000' } }).includes('secret-in-env'));
  assert.ok(ids({ command: 'x', args: ['--api-key=aZ3kQ9xLm2PvR7tYc5WbN8dFh1JsGe4U'] }).includes('secret-in-args'));
  assert.ok(ids({ command: 'x', args: ['--token', 'aZ3kQ9xLm2PvR7tYc5WbN8dFh1JsGe4U'] }).includes('secret-in-args'));
});

test('paths and non-secret key names are not secrets', () => {
  assert.ok(!ids({ command: 'x', env: { PATH: '/usr/local/bin:/usr/bin:/bin' } }).includes('secret-in-env'));
  assert.ok(!ids({ command: 'x', env: { SSH_AUTH_SOCK: '/tmp/ssh-XXXX/agent.1' } }).includes('secret-in-env'));
  assert.ok(!ids({ command: 'x', args: ['--secret-file', '/etc/x/y'] }).includes('secret-in-args'));
  assert.ok(!ids({ command: 'x', args: ['--path', '/home/me/dir'] }).includes('secret-in-args'));
  assert.equal(findSecret('aZ3kQ9xLm2PvR7tYc5WbN8dFh1JsGe4U', 'PATH'), null);
  assert.equal(findSecret('aZ3kQ9xLm2PvR7tYc5WbN8dFh1JsGe4U', '--key-file'), null);
});
test('GITHUB_PAT with random value is flagged; provider prefix fires on any key', () => {
  assert.ok(findSecret('aZ3kQ9xLm2PvR7tYc5WbN8dFh1JsGe4U', 'GITHUB_PAT'));
  assert.ok(findSecret('ghp_EXAMPLEexampleEXAMPLEexample0000', 'PATH'));
});
