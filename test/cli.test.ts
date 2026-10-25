import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const cli = path.resolve(import.meta.dirname, '../src/cli.ts');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'mcpaudit-'));
const SECRET = 'ghp_EXAMPLEexampleEXAMPLEexample0000';

function run(args: string[], o: { home?: string; cwd?: string } = {}) {
  const home = o.home ?? tmp();
  const r = spawnSync(process.execPath, [cli, ...args], {
    cwd: o.cwd ?? tmp(), encoding: 'utf8',
    env: { ...process.env, HOME: home, USERPROFILE: home, APPDATA: path.join(home, 'AppData'), NO_COLOR: '1' },
  });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
function write(file: string, body: unknown) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(body));
}
const http = { mcpServers: { r: { url: 'http://example.com/mcp' } } };

test('no args discovers configs', () => {
  const home = tmp();
  const f = path.join(home, '.cursor', 'mcp.json');
  write(f, http);
  const r = run([], { home });
  assert.ok(r.out.includes(f), r.out);
  assert.ok(r.out.includes('remote-http'), r.out);
  assert.equal(r.code, 1);
});

test('no args and nothing found exits 2', () => {
  const r = run([]);
  assert.equal(r.code, 2);
  assert.ok(r.err.includes('claude_desktop_config.json') && r.err.includes('.cursor'), r.err);
});

test('sarif output file is valid JSON', () => {
  const d = tmp(); const f = path.join(d, '.mcp.json'); write(f, http);
  const out = path.join(d, 'out.sarif');
  run([f, '--format', 'sarif', '--output', out]);
  assert.equal(JSON.parse(fs.readFileSync(out, 'utf8')).version, '2.1.0');
});

test('--fail-on none exits 0; critical ignores high-only', () => {
  const d = tmp(); const f = path.join(d, '.mcp.json'); write(f, http);
  assert.equal(run([f, '--fail-on', 'none']).code, 0);
  assert.equal(run([f, '--fail-on', 'critical']).code, 0);
  assert.equal(run([f]).code, 1);
});

test('unknown flag exits 2', () => assert.equal(run(['--nope']).code, 2));

test('never prints raw secret', () => {
  const d = tmp(); const f = path.join(d, '.mcp.json');
  write(f, { mcpServers: { s: { command: 'node', args: ['s.js'], env: { GITHUB_TOKEN: SECRET } } } });
  for (const fmt of ['table', 'md', 'sarif']) {
    const r = run([f, '--format', fmt]);
    assert.ok(!r.out.includes(SECRET) && !r.err.includes(SECRET), fmt);
  }
  assert.equal(run([f]).code, 1);
});

test('--version prints package version', () => {
  const v = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, '../package.json'), 'utf8')).version;
  assert.equal(run(['--version']).out.trim(), v);
});

test('a named file that fails to parse is reported and exits 2', () => {
  const d = tmp(); const ok = path.join(d, 'ok', '.mcp.json'); const bad = path.join(d, 'bad', '.mcp.json');
  write(ok, http);
  fs.mkdirSync(path.dirname(bad), { recursive: true });
  fs.writeFileSync(bad, '{ "mcpServers": ');
  for (const fmt of ['table', 'md', 'sarif']) {
    const r = run([ok, bad, '--format', fmt]);
    assert.ok(r.err.includes(`mcp-audit: ${bad}: couldn't parse at line`), r.err);
    assert.equal(r.code, 2);
  }
  assert.ok(run([ok, bad]).out.includes(`NOT AUDITED ${bad}`));
});

test('discovered file that fails to parse: exit follows the valid file', () => {
  const home = tmp();
  write(path.join(home, '.cursor', 'mcp.json'), http);
  fs.writeFileSync(path.join(home, '.claude.json'), '{ "mcpServers": ');
  assert.equal(run([], { home }).code, 1);
});

test('partly parsed file with findings says "parsed with errors"; rows carry the rule URL', () => {
  const d = tmp(); const f = path.join(d, '.mcp.json');
  fs.writeFileSync(f, '{"mcpServers":{"r":{"url":"http://example.com/mcp"}}, nope');
  const ok = path.join(d, 'ok', '.mcp.json'); write(ok, http);
  const r = run([f, ok]);
  assert.ok(r.out.includes(`PARSED WITH ERRORS ${f}`), r.out);
  assert.ok(!r.out.includes('NOT AUDITED'), r.out);
  assert.ok(r.out.includes('https://qlucent.com/tools/mcp-audit/rules/remote-http'), r.out);
});

test('control characters are escaped in md and sarif stdout, kept in --output (I9)', () => {
  const d = tmp(); const f = path.join(d, '.mcp.json');
  // Raw ESC and C1 control in a comment, shown in the excerpt. (A broken file shows no excerpt since round 6.)
  fs.writeFileSync(f, '{"mcpServers":{"r":{ // x\u001b[2J\u009b\n "url":"http://example.com/mcp"}}}');
  const ok = path.join(d, 'ok', '.mcp.json'); write(ok, http);
  for (const fmt of ['md', 'sarif', 'table']) {
    const r = run([f, ok, '--format', fmt]);
    assert.ok(!/[\u001b\u009b]/.test(r.out) && !/[\u001b\u009b]/.test(r.err), fmt);
  }
  const md = run([f, ok, '--format', 'md']).out;
  assert.ok(md.includes('\n') && md.includes('\\x1b'), md);
  const out = path.join(d, 'out.md');
  run([f, ok, '--format', 'md', '--output', out]);
  assert.ok(fs.readFileSync(out, 'utf8').includes('\u001b'));
});

test('no-config message escapes the checked paths', () => {
  const home = path.join(tmp(), 'x\u001b[2J'); // never created, only listed
  const r = run([], { home });
  assert.equal(r.code, 2);
  assert.ok(!r.err.includes('\u001b'), r.err);
});

test('unwritable --output exits 2', () => {
  const d = tmp(); const f = path.join(d, '.mcp.json'); write(f, http);
  const r = run([f, '--output', path.join(d, 'missing', 'dir', 'out.sarif')]);
  assert.equal(r.code, 2);
  assert.ok(r.err.includes('cannot write'), r.err);
});

test('control characters from config are escaped in table output', () => {
  const d = tmp(); const f = path.join(d, '.mcp.json');
  write(f, { mcpServers: { 'evil\u001b[2Kx': { url: 'http://example.com/mcp' } } });
  const r = run([f]);
  assert.ok(!r.out.includes('\u001b') && !r.err.includes('\u001b'));
  assert.ok(r.out.includes('\\x1b'), r.out);
});

test('discovery dedupes when cwd is home', () => {
  const home = tmp();
  write(path.join(home, '.cursor', 'mcp.json'), http);
  const r = run([], { home, cwd: home });
  assert.equal(r.out.split('Auditing').length - 1, 1, r.out);
});

test('only unrecognised files: says so and exits 2 (I3)', () => {
  const d = tmp(); const f = path.join(d, 'settings.json');
  write(f, { 'editor.fontSize': 14 });
  const r = run([f]);
  assert.equal(r.code, 2);
  assert.ok(r.err.includes(`Couldn't recognise ${f} as an MCP config`), r.err);
  assert.ok(!r.out.includes('None of'), r.out);
});

test('unrecognised file next to a real one is listed in the table', () => {
  const d = tmp(); const f = path.join(d, 'settings.json'); const ok = path.join(d, '.mcp.json');
  write(f, { foo: 1 }); write(ok, http);
  const r = run([f, ok]);
  assert.equal(r.code, 1);
  assert.ok(r.out.includes(`Couldn't recognise ${f} as an MCP config`), r.out);
});
