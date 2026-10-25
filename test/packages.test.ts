import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePackageRef } from '../src/packages.ts';
import { audit } from '../src/engine.ts';
import type { Server } from '../src/types.ts';

const loc = { line: 1, column: 1, offset: 0, length: 1 };
const p = (command: string, ...args: string[]) =>
  parsePackageRef({ name: 's', file: 'f', client: null, groups: [], transport: 'stdio', command, args, env: {}, headers: {}, loc, fieldLocs: {} } as Server);

test('npx', () => {
  assert.deepEqual(p('npx', '-y', '@modelcontextprotocol/server-filesystem', '/tmp'),
    { manager: 'npm', name: '@modelcontextprotocol/server-filesystem', source: 'registry', argIndex: 1 });
  assert.equal(p('npx.cmd', '@scope/pkg@1.2.3')?.version, '1.2.3');
  assert.equal(p('npx', 'pkg@latest')?.tag, 'latest');
  const r = p('npx', '--package=pkg@2', 'cmd');
  assert.equal(r?.name, 'pkg'); assert.equal(r?.version, undefined); assert.equal(r?.tag, '2');
  assert.equal(p('pnpm', 'dlx', 'pkg')?.argIndex, 1);
  assert.equal(p('bunx', 'pkg')?.name, 'pkg');
  assert.equal(p('node', 'x.js'), null);
});
test('uvx / pipx', () => {
  assert.equal(p('uvx', 'mcp-server-fetch')?.manager, 'pypi');
  assert.equal(p('uvx', 'mcp-server-fetch')?.version, undefined);
  assert.equal(p('uvx', 'mcp-server-fetch==0.6.2')?.version, '0.6.2');
  const r = p('uvx', '--from', 'mcp-server-fetch==1', 'mcp-server-fetch');
  assert.equal(r?.version, '1'); assert.equal(r?.name, 'mcp-server-fetch'); assert.equal(r?.argIndex, 1);
  assert.equal(p('pipx', 'run', 'pkg')?.manager, 'pypi');
});
test('docker', () => {
  const r = p('docker', 'run', '-i', '--rm', '-e', 'A=b', '-v', '/a:/b', '--name', 'n', 'mcp/fetch');
  assert.equal(r?.name, 'mcp/fetch'); assert.equal(r?.tag, undefined); assert.equal(r?.argIndex, 9);
  assert.equal(p('docker', 'run', 'mcp/fetch:latest')?.tag, 'latest');
  assert.equal(p('docker', 'run', 'mcp/fetch@sha256:abc123')?.digest, 'sha256:abc123');
  const g = p('docker', 'run', 'ghcr.io/o/i:1.0');
  assert.equal(g?.tag, '1.0'); assert.equal(g?.name, 'ghcr.io/o/i');
  assert.equal(p('docker', 'run', 'localhost:5000/i')?.tag, undefined);
});
test('url sources', () => {
  for (const [c, ...a] of [['npx', 'github:user/repo'], ['npx', 'git+https://x/y.git'], ['npx', 'https://x/y.tgz'],
    ['uvx', '--from', 'git+https://x/y.git', 'cmd']] as string[][])
    assert.equal(p(c!, ...a)?.source, 'url', a.join(' '));
});
test('fix round 1', () => {
  assert.equal(p('npx', 'some-mcp', '-p', '8080')?.name, 'some-mcp');
  assert.equal(p('uvx', 'some-mcp', '--from', 'x')?.name, 'some-mcp');
  for (const a of ['./server', '.', '/opt/srv/index.js', 'C:\\srv\\x.js', '~/x']) assert.equal(p('npx', a), null, a);
  const d = p('docker', 'run', '--security-opt', 'no-new-privileges', 'mcp/x:1.0');
  assert.equal(d?.name, 'mcp/x'); assert.equal(d?.tag, '1.0');
});
test('no supply-chain finding for local paths', () => {
  const r = audit([{ name: 'a.json', text: JSON.stringify({ mcpServers: { s: { command: 'npx', args: ['./server'] } } }) }]);
  assert.equal(r.findings.length, 0);
});
const ids = (command: string, ...args: string[]) =>
  audit([{ name: 'a.json', text: JSON.stringify({ mcpServers: { s: { command, args } } }) }]).findings.map((f) => f.ruleId);
test('exact pins vs ranges and tags', () => {
  assert.deepEqual(ids('npx', 'pkg@^1.2.3'), ['npx-latest']);
  assert.deepEqual(ids('npx', 'pkg@1.2.3'), []);
  assert.deepEqual(ids('npx', 'pkg@beta'), ['npx-latest']);
  assert.deepEqual(ids('npx', 'pkg'), ['npx-unpinned']);
  assert.deepEqual(ids('uvx', 'pkg>=1.0'), ['uvx-unpinned']);
  assert.deepEqual(ids('uvx', 'pkg~=1.0'), ['uvx-unpinned']);
  assert.deepEqual(ids('uvx', 'pkg@latest'), ['uvx-unpinned']);
  assert.deepEqual(ids('uvx', 'pkg==1.0.0'), []);
});

test('URL specs drop credentials from the name (C4)', () => {
  assert.equal(p('npx', 'git+https://ghp_EXAMPLEexampleEXAMPLEexample1111@github.com/o/r.git')?.name, 'git+https://••••••@github.com/o/r.git');
  assert.equal(p('uvx', '--from', 'git+https://u:pw123456@h.example/r.git', 'r')?.name, 'git+https://••••••@h.example/r.git');
  assert.equal(p('npx', 'git+ssh://git@github.com/o/r.git')?.name, 'git+ssh://git@github.com/o/r.git');
});
