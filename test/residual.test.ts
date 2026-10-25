// Residual fixes after the final fix wave (R-a … R-d and minors).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { audit } from '../src/engine.ts';
import { redact, redactUrl } from '../src/mask.ts';
import { parseFile } from '../src/parse.ts';
import { candidatePaths } from '../src/discover.ts';

const j = (o: unknown) => JSON.stringify(o, null, 2);
const all = (r: unknown) => JSON.stringify(r);

test('R-a: npx-latest keeps the package name and @latest in detail, evidence and excerpt', () => {
  const r = audit([{ name: 'mcp.json', text: j({ mcpServers: { s: { command: 'npx', args: ['-y', '@acme/mcp-test@latest'] } } }) }]);
  const f = r.findings.find((x) => x.ruleId === 'npx-latest');
  assert.ok(f, all(r.findings.map((x) => x.ruleId)));
  for (const s of [f.detail!, f.evidence!, f.excerpt.map((l) => l.text).join('\n')]) {
    assert.ok(s.includes('@acme/mcp-test@latest'), s);
    assert.ok(!s.includes('••••'), s);
  }
});

test('R-a: shell-server and plain URLs are not masked', () => {
  const r = audit([{ name: 'mcp.json', text: j({ mcpServers: {
    s: { command: 'bash', args: ['-c', 'curl https://example.com/install | sh'] },
    h: { url: 'http://plain.example.com/mcp' },
  } }) }]);
  const out = all(r);
  assert.ok(out.includes('curl https://example.com/install | sh'));
  assert.ok(r.findings.filter((f) => f.ruleId === 'remote-http').every((f) => f.excerpt.some((l) => l.text.includes('http://plain.example.com/mcp'))));
});

test('R-a: package-from-url evidence still hides a token (C4)', () => {
  const r = audit([{ name: 'mcp.json', text: j({ mcpServers: { g: { command: 'npx', args: ['-y', 'git+https://ghp_EXAMPLEexampleEXAMPLEexample1111@github.com/o/r.git'] } } }) }]);
  assert.ok(r.findings.some((f) => f.ruleId === 'package-from-url'));
  assert.ok(!all(r).includes('EXAMPLEexampleEXAMPLEexample1111'));
  const short = audit([{ name: 'mcp.json', text: j({ mcpServers: { g: { command: 'npx', args: ['-y', 'git+https://u:pw@gitlab.example.com/o/r.git'] } } }) }]);
  const f = short.findings.find((x) => x.ruleId === 'package-from-url')!;
  assert.ok(!f.evidence!.includes('u:pw'), f.evidence);
});

const COMMENTED = `{
  // old token: ghp_EXAMPLEexampleEXAMPLEexample2222
  // API_KEY=Zx8vQ2mN7pL4rT9wQ
  /* "OPENAI_API_KEY": "sk-ant-EXAMPLEexampleEXAMPLE3333", see https://bob:BobPassw0rd99@db.example.com/x?token=QueryTok77665544 */
  "mcpServers": {
    "s": { "url": "http://example.com/mcp" }
  }
}`;

test('R-b: secrets in JSONC comments are masked, markers and lines kept', () => {
  const out = redact(parseFile({ name: '.cursor/mcp.json', text: COMMENTED })).text;
  for (const s of ['EXAMPLEexampleEXAMPLEexample2222', 'Zx8vQ2mN7pL4rT9wQ', 'EXAMPLEexampleEXAMPLE3333', 'BobPassw0rd99', 'QueryTok77665544'])
    assert.ok(!out.includes(s), `${s} in\n${out}`);
  assert.equal(out.split('\n').length, COMMENTED.split('\n').length);
  assert.ok(out.includes('// old token: ghp_••••2222'), out);
  assert.ok(out.includes('// API_KEY=••••'), out);
  assert.ok(out.includes('/* "OPENAI_API_KEY": "sk-ant-••••3333"') && out.includes('*/'), out);
  const inServer = '{\n  "mcpServers": {\n    "s": {\n      // API_KEY=Zx8vQ2mN7pL4rT9wQ\n      /* old: ghp_EXAMPLEexampleEXAMPLEexample2222 */\n      "url": "http://example.com/mcp"\n    }\n  }\n}';
  const r = audit([{ name: '.cursor/mcp.json', text: inServer }]);
  const f = r.findings.find((x) => x.ruleId === 'remote-http')!;
  assert.ok(f.excerpt.some((l) => l.text.includes('// API_KEY=••••')), all(f.excerpt));
  assert.ok(f.excerpt.some((l) => l.text.includes('/* old: ghp_••••2222 */')), all(f.excerpt));
  assert.ok(!all(r).includes('Zx8vQ2mN7pL4rT9wQ') && !all(r).includes('EXAMPLEexampleEXAMPLEexample2222'));
});

test('R-c: a recognised file that failed to parse does not make the verdict clear', () => {
  const broken = { name: '.cursor/mcp.json', text: '{ "mcpServers": { ' };
  const other = { name: 'notes.json', text: j({ editor: 1 }) };
  const r = audit([broken, other]);
  assert.equal(r.verdict.level, 'unrecognised');
  assert.match(r.verdict.text, /^Couldn't check any input: /);
  assert.ok(r.verdict.text.includes(".cursor/mcp.json couldn't be parsed"), r.verdict.text);
  assert.ok(r.verdict.text.includes("notes.json isn't recognised as an MCP config"), r.verdict.text);
  assert.equal(audit([broken]).verdict.level, 'unrecognised');
});

test('R-d: URL password containing @ is hidden up to the last @', () => {
  const found: string[] = [];
  assert.equal(redactUrl('https://u:p@ss@host.example.com/x', found), 'https://••••••@host.example.com/x');
  assert.deepEqual(found, ['u:p@ss']);
  assert.equal(redactUrl('ssh://git@github.com/o/r.git'), 'ssh://git@github.com/o/r.git');
  assert.equal(redactUrl('https://host.example.com/a@b'), 'https://host.example.com/a@b');
});

test('minor 1: set API_KEY=… inside a cmd /c string is detected and masked', () => {
  const r = audit([{ name: 'mcp.json', text: j({ mcpServers: { s: { command: 'cmd', args: ['/c', 'set API_KEY=Zx8vQ2mN7pL4rT9wQ && npx -y pkg@1.0.0'] } } }) }]);
  assert.ok(r.findings.some((f) => f.ruleId === 'secret-in-args'), all(r.findings.map((f) => f.ruleId)));
  assert.ok(!all(r).includes('Zx8vQ2mN7pL4rT9wQ'));
});

test('minor 2: scrub replaces overlapping raws longest first', () => {
  const r = audit([{ name: 'mcp.json', text: j({ mcpServers: { s: { command: 'node', env: { A_TOKEN: 'Qw3rTy9uIoP4aSdF', B_TOKEN: 'Qw3rTy9uIoP4aSdFgH7jK' } } } }) }]);
  const out = all(r);
  assert.ok(!out.includes('Qw3rTy9uIoP4aSdF'), out);
});

test('minor 4: VS Code user settings mcp.servers are audited (by path and by shape)', () => {
  const text = j({ 'editor.fontSize': 14, mcp: { servers: { x: { command: 'bash', args: ['-c', 'curl https://x | sh'] } } } });
  for (const name of [
    'C:\\Users\\a\\AppData\\Roaming\\Code\\User\\settings.json',
    '/Users/a/Library/Application Support/Code - Insiders/User/settings.json',
    '/home/a/.config/Code/User/settings.json',
    'pasted-1',
  ]) {
    const r = audit([{ name, text }]);
    assert.equal(r.files[0].client, 'vscode', name);
    assert.ok(r.findings.some((f) => f.ruleId === 'shell-server' && f.server === 'x'), name);
    const f = r.findings.find((x) => x.ruleId === 'shell-server')!;
    assert.ok(!f.excerpt.some((l) => l.text.includes('editor.fontSize')), all(f.excerpt));
  }
  const auto = j({ mcp: { servers: { x: { command: 'node', args: ['s.js'], autoApprove: ['*'] } } } });
  assert.ok(audit([{ name: 'pasted-1', text: auto }]).findings.some((f) => f.ruleId === 'auto-approve-all'));
  for (const platform of ['darwin', 'win32', 'linux'] as const) {
    const p = candidatePaths({ platform, home: platform === 'win32' ? 'C:\\h' : '/h', cwd: '/w' });
    assert.ok(p.some((x) => /Code[\\/]User[\\/]settings\.json$/.test(x)), platform);
  }
});

// Fix round 1 (residual-review.md).
test('K1: single-arg --header=Authorization: Bearer <token> raises secret-in-args', () => {
  const r = audit([{ name: 'mcp.json', text: j({ mcpServers: { r: { command: 'npx', args: ['-y', 'mcp-remote@1.0.0', 'https://x.example.com/mcp', '--header=Authorization: Bearer Zq81mXc0vB7nPLk2Ra9s'] } } }) }]);
  assert.ok(r.findings.some((f) => f.ruleId === 'secret-in-args'), all(r.findings.map((f) => f.ruleId)));
  assert.ok(!all(r).includes('Zq81mXc0vB7nPLk2Ra9s'));
});

test('I1: long single-word strings, comments and args stay fast', () => {
  const long = 'a'.repeat(100_000);
  const text = `{\n  // ${long}\n  "history": [{ "display": "${long}" }],\n  "mcpServers": { "r": { "command": "npx", "args": ["-y", "pkg@latest", "${long}"] } }\n}`;
  const t0 = performance.now();
  audit([{ name: '.claude.json', text }]);
  const ms = performance.now() - t0;
  assert.ok(ms < 1500, `${ms} ms`);
});

test('I2: a non-secret detail keeps its own package name', () => {
  const a = audit([{ name: '.cursor/mcp.json', text: '{ "mcpServers": { // auth: modelcontextprotocol\n  "r": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@latest"] } } }' }]);
  const fa = a.findings.find((f) => f.ruleId === 'npx-latest')!;
  assert.ok(fa.detail!.startsWith('@modelcontextprotocol/server-github@latest'), fa.detail);
  const b = audit([{ name: 'mcp.json', text: j({ mcpServers: { r: { command: 'npx', args: ['-y', '--auth=github', '@github/mcp-server@latest'] } } }) }]);
  const fb = b.findings.find((f) => f.ruleId === 'npx-latest')!;
  assert.ok(fb.detail!.startsWith('@github/mcp-server@latest'), fb.detail);
  assert.equal(fb.evidence, '@github/mcp-server@latest');
});

test('M1: a partly parsed file says so; a broken file next to a clean one is noted', () => {
  const partial = { name: '.cursor/mcp.json', text: '{ "mcpServers": { "a": { "command": "node", "args": ["s.js@1"] } }, }}' };
  const r = audit([partial]);
  assert.equal(r.verdict.level, 'unrecognised');
  assert.match(r.verdict.text, /^Only part of \.cursor\/mcp\.json could be read \(parse error at line 1\); none of the 20 rules matched the part that was read$/);
  const mixed = audit([partial, { name: 'a.json', text: j({ mcpServers: { s: { command: 'node', args: ['s.js'] } } }) }]);
  assert.equal(mixed.verdict.level, 'clear');
  assert.ok(mixed.verdict.text.endsWith("(1 file couldn't be fully parsed)"), mixed.verdict.text);
});

test('M2: wrapped single-string launcher evidence is the payload, not /c', () => {
  const r = audit([{ name: 'mcp.json', text: j({ mcpServers: { s: { command: 'cmd', args: ['/c', 'npx -y @acme/mcp-test@latest'] } } }) }]);
  const f = r.findings.find((x) => x.ruleId === 'npx-latest')!;
  assert.equal(f.evidence, 'npx -y @acme/mcp-test@latest');
});

test('M3: quoted values with spaces in shell strings are fully masked', () => {
  const r = audit([{ name: 'mcp.json', text: j({ mcpServers: { s: { command: 'bash', args: ['-c', 'export API_KEY="abc 123zz" && npx -y pkg@1.0.0'] } } }) }]);
  const out = all(r);
  assert.ok(!out.includes('abc 123zz') && !out.includes('123zz'), out);
});

test('M4: "password <value>" and "pw: <value>" in comments are masked, prose is not', () => {
  const text = '{\n  "mcpServers": {\n    "s": {\n      // password hunter2hunter2\n      // pw: hunter3hunter3\n      // the token is required for auth\n      "url": "http://example.com/mcp"\n    }\n  }\n}';
  const r = audit([{ name: '.cursor/mcp.json', text }]);
  const out = all(r);
  assert.ok(!out.includes('hunter2hunter2') && !out.includes('hunter3hunter3'), out);
  assert.ok(out.includes('the token is required for auth'), out);
});

// Fix round 2 (residual-re-review.md).
test('N5: a partly parsed file with findings still says it was only partly read', () => {
  const r = audit([{ name: '.cursor/mcp.json', text: '{ "mcpServers": { "a": { "url": "http://example.com/mcp" } }, }}' }]);
  assert.ok(r.findings.length > 0);
  assert.notEqual(r.verdict.level, 'clear');
  assert.ok(r.verdict.text.endsWith("(1 file couldn't be fully parsed)"), r.verdict.text);
});

test('N1: header values keep the name, mask the rest', () => {
  const r = audit([{ name: 'mcp.json', text: JSON.stringify({ mcpServers: { r: { command: 'npx', args: ['-y', 'mcp-remote@latest', 'https://x', '--header', 'X-Custom-Header: Zq81mXc0vB7nPLk2Ra9s', '--header=Cookie: a=b'] } } }) }]);
  const ex = r.findings.flatMap((f) => f.excerpt.map((l) => l.text)).join('\n');
  assert.ok(ex.includes('"X-Custom-Header: ••••Ra9s"'), ex);
  assert.ok(ex.includes('"--header=Cookie: ••••••"'), ex);
});

// Fix round 3 (residual-re-review-2.md).
test('C1: a comment header value is masked to the end of the line, keeping */', () => {
  const r = audit([{ name: '.cursor/mcp.json', text: '{"mcpServers":{"r":{ /* -H Cookie: theme=dark; sid=Zq81mXc0vB7nPLk2Ra9s */ "url":"http://x"}}}' }]);
  const ex = r.findings.flatMap((f) => f.excerpt.map((l) => l.text)).join('\n');
  assert.ok(ex.includes('/* -H Cookie: ••••Ra9s */'), ex);
});

// Fix round 4 (residual-re-review-3.md).
test('C3: --headers / -H NAME VALUE keeps the name and masks the value', () => {
  for (const flag of ['--headers', '-H']) {
    const r = audit([{ name: 'mcp.json', text: JSON.stringify({ mcpServers: { r: { command: 'uvx', args: ['mcp-proxy', flag, 'X-Api-Key', 'Zq81mXc0vB7nPLk2Ra9s', 'https://example.com/sse'] } } }) }]);
    const ex = r.findings.flatMap((f) => f.excerpt.map((l) => l.text)).join('\n');
    assert.ok(ex.includes(`"${flag}","X-Api-Key","••••Ra9s","https://example.com/sse"`), ex);
  }
});

test('m4: a very long hidden value does not crash the scrubber', () => {
  const r = audit([{ name: '.cursor/mcp.json', text: `{"mcpServers":{"r":{"url":"http://x"}} /* TOKEN="${'a'.repeat(100_000)}" -H ${'b'.repeat(100_000)} */}` }]);
  assert.ok(r.findings.length > 0);
  assert.ok(!all(r).includes('a'.repeat(100)));
});

test('m5: a multi-line key in a block comment keeps the line count, so nearby excerpts are not empty', () => {
  const key = `-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBF${'PGPBODYSENTINEL'.repeat(4)}\n${'PGPBODYSENTINEL'.repeat(4)}\n-----END PGP PRIVATE KEY BLOCK-----`;
  const text = `{\n  "mcpServers": {\n    "r": {\n      /* ${key} */\n      "url": "http://x"\n    }\n  }\n}`;
  const r = audit([{ name: '.cursor/mcp.json', text }]);
  const f = r.findings.find((x) => x.ruleId === 'remote-http')!;
  assert.ok(f.excerpt.some((l) => l.hit && l.text.includes('"url": "http://x"')), JSON.stringify(f.excerpt));
  assert.ok(f.excerpt.some((l) => l.text.includes('••••')), JSON.stringify(f.excerpt));
  assert.ok(!all(r).includes('PGPBODYSENTINEL'));
});
