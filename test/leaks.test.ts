// Regression for the final-review leaks C1-C4: each fake secret must reach no output.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { audit } from '../src/engine.ts';
import { toMarkdown } from '../src/report/markdown.ts';
import { toSarif } from '../src/report/sarif.ts';

const j = (o: unknown) => JSON.stringify(o, null, 2);
// [label, file name, text, secrets that must never appear]
const CASES: Array<[string, string, string, string[]]> = [
  ['C1 url userinfo', 'mcp.json',
    j({ mcpServers: { db: { url: 'https://admin:hunter2hunter2xyzQ@db.example.com/mcp' } } }), ['hunter2hunter2xyzQ']],
  ['C1 url query value', 'mcp.json',
    j({ mcpServers: { q: { url: 'https://api.example.com/mcp?api_key=Zx8vQ2mN7pL4rT9w' } } }), ['Zx8vQ2mN7pL4rT9w']],
  ['C1 url query, low entropy', 'mcp.json',
    j({ mcpServers: { q: { url: 'http://api.example.com/mcp?session=plainsessionvalue' } } }), ['plainsessionvalue']],
  ['C1 --client-secret X', 'mcp.json',
    j({ mcpServers: { a: { command: 'node', args: ['s.js', '--client-secret', 'Q7wErTy8uIoP3aSd5f'] } } }), ['Q7wErTy8uIoP3aSd5f']],
  ['C1 --access-token=X', 'mcp.json',
    j({ mcpServers: { a: { command: 'node', args: ['s.js', '--access-token=Lk9Jh8Gf7Ds6Aq5WzX'] } } }), ['Lk9Jh8Gf7Ds6Aq5WzX']],
  ['C2 settings env block', '.claude/settings.json',
    '{\n  "env": {"ANTHROPIC_API_KEY": "sk-ant-EXAMPLEexampleEXAMPLE7777", "OTHER": "otherEnvPlain1"},\n  "permissions": {"defaultMode": "bypassPermissions"}\n}',
    ['EXAMPLEexampleEXAMPLE7777', 'otherEnvPlain1']],
  ['C2 minified claude.json', '.claude.json',
    JSON.stringify({ oauthAccount: { accountUuid: 'OAUTHSENTINELuuid', emailAddress: 'sentinel@example.com' }, mcpServers: { r: { url: 'http://example.com/mcp' } }, userID: 'USERIDSENTINEL' }),
    ['OAUTHSENTINELuuid', 'sentinel@example.com', 'USERIDSENTINEL']],
  ['C2 windsurf serverUrl', '.codeium/windsurf/mcp_config.json',
    j({ mcpServers: { w: { serverUrl: 'http://mcp.example.com/sse?token=WsTokenValue99887766' } } }), ['WsTokenValue99887766']],
  ['C3 duplicate key', 'mcp.json',
    '{\n  "mcpServers": {\n    "s": {\n      "url": "http://example.com/mcp",\n      "env": {\n        "TOKEN": "dupSecretValue123456",\n        "TOKEN": "x"\n      }\n    }\n  }\n}',
    ['dupSecretValue123456']],
  ['C3 duplicate env object', 'mcp.json',
    '{\n  "mcpServers": {\n    "s": {\n      "env": {"A": "firstEnvObjValue1"},\n      "url": "http://example.com/mcp",\n      "env": {"K": "dupEnvSecret987654"}\n    }\n  }\n}',
    ['firstEnvObjValue1', 'dupEnvSecret987654']],
  ['C3 __proto__ key', 'mcp.json',
    '{\n  "mcpServers": {\n    "s": {\n      "url": "http://example.com/mcp",\n      "env": {"__proto__": "protoSecret55555"}\n    }\n  }\n}',
    ['protoSecret55555']],
  ['C3 numeric env value', 'mcp.json',
    '{\n  "mcpServers": {\n    "s": {\n      "url": "http://example.com/mcp",\n      "env": {"PIN": 98765432123456789, "B": true}\n    }\n  }\n}',
    ['98765432123456789']],
  ['C4 package-from-url token userinfo', 'mcp.json',
    j({ mcpServers: { g: { command: 'npx', args: ['-y', 'git+https://ghp_EXAMPLEexampleEXAMPLEexample1111@github.com/o/r.git'] } } }),
    ['EXAMPLEexampleEXAMPLEexample1111']],
  ['C4 package-from-url user:password', 'mcp.json',
    j({ mcpServers: { g: { command: 'npx', args: ['-y', 'git+https://deploy:plainpassw0rdXYZ@gitlab.example.com/o/r.git'] } } }),
    ['plainpassw0rdXYZ']],
  ['C4 wrapped launcher url spec', 'mcp.json',
    j({ mcpServers: { g: { command: 'cmd', args: ['/c', 'npx', '-y', 'https://example.com/pkg.tgz?token=TgzTokenValue445566'] } } }),
    ['TgzTokenValue445566']],
  ['K1 --header=Authorization: Bearer', 'mcp.json',
    j({ mcpServers: { r: { command: 'npx', args: ['-y', 'mcp-remote@latest', 'https://x.example.com/mcp', '--header=Authorization: Bearer Zq81mXc0vB7nPLk2Ra9s'] } } }),
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ['K1 --header=Authorization:Bearer', 'mcp.json',
    j({ mcpServers: { r: { command: 'npx', args: ['-y', 'mcp-remote@latest', 'https://x.example.com/mcp', '--header=Authorization:Bearer abc123xyz'] } } }),
    ['abc123xyz']],
  ['K1 --header=X-API-Key:', 'mcp.json',
    j({ mcpServers: { r: { command: 'npx', args: ['-y', 'mcp-remote@latest', 'https://x.example.com/mcp', '--header=X-API-Key: abc123xyz'] } } }),
    ['abc123xyz']],
  // One-line configs, so the excerpt always contains the probed value.
  ['N1 --header, Cookie (two args)', 'mcp.json',
    JSON.stringify({ mcpServers: { r: { command: 'npx', args: ['-y', 'mcp-remote@latest', 'https://x', '--header', 'Cookie: session=Zq81mXc0vB7nPLk2Ra9s'] } } }),
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ['N1 --header=Cookie (one arg)', 'mcp.json',
    JSON.stringify({ mcpServers: { r: { command: 'npx', args: ['-y', 'mcp-remote@latest', 'https://x', '--header=Cookie: session=Zq81mXc0vB7nPLk2Ra9s'] } } }),
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ['N1 --header, X-Custom-Header (two args)', 'mcp.json',
    JSON.stringify({ mcpServers: { r: { command: 'npx', args: ['-y', 'mcp-remote@latest', 'https://x', '--header', 'X-Custom-Header: Zq81mXc0vB7nPLk2Ra9s'] } } }),
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ['N1 --header=X-Custom-Header (one arg)', 'mcp.json',
    JSON.stringify({ mcpServers: { r: { command: 'npx', args: ['-y', 'mcp-remote@latest', 'https://x', '--header=X-Custom-Header: Zq81mXc0vB7nPLk2Ra9s'] } } }),
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ['N1 -H in a shell string', 'mcp.json',
    JSON.stringify({ mcpServers: { r: { command: 'bash', args: ['-c', "npx -y mcp-remote@1.0.0 https://x -H 'Cookie: sid=Zq81mXc0vB7nPLk2Ra9s; theme=dark'"] } } }),
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ['N2 PEM in a JSONC comment', '.cursor/mcp.json',
    `{ "mcpServers": { "s": { // "PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC${'PEMBODYSENTINEL'.repeat(16)}\\n-----END PRIVATE KEY-----"\n "url": "http://example.com/mcp" } } }`,
    ['PEMBODYSENTINEL']],
  ['N2 bare PEM in a // comment', '.cursor/mcp.json',
    `{ "mcpServers": { "s": { // -----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC${'BAREPEMSENTINEL'.repeat(16)}\n "url": "http://example.com/mcp" } } }`,
    ['BAREPEMSENTINEL']],
  ['N2 GCP service-account JSON in a comment', '.cursor/mcp.json',
    `{ "mcpServers": { "s": { // GOOGLE_CREDENTIALS='{"type": "service_account", "client_email": "svc@proj.iam.example.com", "private_key": "-----BEGIN PRIVATE KEY-----\\n${'GCPKEYSENTINEL'.repeat(16)}\\n-----END PRIVATE KEY-----\\n"}'\n "url": "http://example.com/mcp" } } }`,
    ['GCPKEYSENTINEL', 'svc@proj.iam.example.com']],
  ['N3 escaped quote in a quoted value', 'mcp.json',
    JSON.stringify({ mcpServers: { s: { command: 'bash', args: ['-c', 'export API_KEY="ab\\"c d3fghSENT" && npx -y pkg@1.0.0'] } } }),
    ['d3fghSENT']],
  ['C1a cookie after ; in a comment', '.cursor/mcp.json',
    '{"mcpServers":{"r":{ // --header Cookie: theme=dark; sid=Zq81mXc0vB7nPLk2Ra9s\n "url":"http://x"}}}',
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ['C1a cookie after ; in a block comment', '.cursor/mcp.json',
    '{"mcpServers":{"r":{ /* -H Cookie: theme=dark; sid=Zq81mXc0vB7nPLk2Ra9s */ "url":"http://x"}}}',
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ['C1 --header=Cookie with ; (one arg)', 'mcp.json',
    JSON.stringify({ mcpServers: { r: { command: 'npx', args: ['-y', 'mcp-remote@latest', 'https://x', '--header=Cookie: theme=dark; sid=Zq81mXc0vB7nPLk2Ra9s'] } } }),
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ['C1b -H"…" with no space', 'mcp.json',
    JSON.stringify({ mcpServers: { r: { command: 'bash', args: ['-c', 'curl -H"X-Custom: Zq81mXc0vB7nPLk2Ra9s" https://x && npx -y p@1.0.0'] } } }),
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ["C1b -H'…' with no space", 'mcp.json',
    JSON.stringify({ mcpServers: { r: { command: 'bash', args: ['-c', "curl -H'X-Custom: Zq81mXc0vB7nPLk2Ra9s' https://x && npx -y p@1.0.0"] } } }),
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ['C2 PGP private key block in a comment', '.cursor/mcp.json',
    `{"mcpServers":{"r":{ /* -----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBF${'PGPBODYSENTINEL'.repeat(20)}\n-----END PGP PRIVATE KEY BLOCK----- */ "url":"http://x"}}}`,
    ['PGPBODYSENTINEL']],
  ['m1 --header TOKEN (two args, no colon)', 'mcp.json',
    JSON.stringify({ mcpServers: { r: { command: 'npx', args: ['-y', 'mcp-remote@latest', 'https://x', '--header', 'Zq81mXc0vB7nPLk2Ra9s'] } } }),
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ['m1 --header=TOKEN (one arg, no colon)', 'mcp.json',
    JSON.stringify({ mcpServers: { r: { command: 'npx', args: ['-y', 'mcp-remote@latest', 'https://x', '--header=Zq81mXc0vB7nPLk2Ra9s'] } } }),
    ['Zq81mXc0vB7nPLk2Ra9s']],
  // Fix round 4 (residual-re-review-3.md).
  ['C3 mcp-proxy --headers KEY VALUE', 'claude_desktop_config.json',
    '{\n  "mcpServers": {\n    "remote": {\n      "command": "uvx",\n      "args": ["mcp-proxy", "--headers", "X-Api-Key", "Zq81mXc0vB7nPLk2Ra9s", "https://example.com/sse"]\n    }\n  }\n}',
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ['C3 mcp-proxy -H KEY VALUE', 'claude_desktop_config.json',
    '{\n  "mcpServers": {\n    "remote": {\n      "command": "uvx",\n      "args": ["mcp-proxy", "-H", "X-Api-Key", "Zq81mXc0vB7nPLk2Ra9s", "https://example.com/sse"]\n    }\n  }\n}',
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ['C3 --headers KEY VALUE in a shell string', 'mcp.json',
    JSON.stringify({ mcpServers: { r: { command: 'bash', args: ['-c', 'uvx mcp-proxy --headers X-Api-Key Zq81mXc0vB7nPLk2Ra9s https://example.com/sse'] } } }),
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ['C3 --headers KEY VALUE in a comment', '.cursor/mcp.json',
    '{"mcpServers":{"r":{ // uvx mcp-proxy --headers X-Api-Key Zq81mXc0vB7nPLk2Ra9s https://example.com/sse\n "url":"http://x"}}}',
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ['m2 -HName:value unquoted in a shell string', 'mcp.json',
    JSON.stringify({ mcpServers: { r: { command: 'bash', args: ['-c', 'curl -HX-Custom:Zq81mXc0vB7nPLk2Ra9s https://x && npx -y p@1.0.0'] } } }),
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ['m3 quoted header over two lines in a block comment', '.cursor/mcp.json',
    '{"mcpServers":{"r":{ /* --header "Cookie: a=b;\n sid=Zq81mXc0vB7nPLk2Ra9s " */ "url":"http://x"}}}',
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ['m3 quoted header over two lines in a shell string', 'mcp.json',
    JSON.stringify({ mcpServers: { r: { command: 'bash', args: ['-c', 'curl -H "Cookie: a=b;\n sid=Zq81mXc0vB7nPLk2Ra9s" https://x && npx -y p@1.0.0'] } } }),
    ['Zq81mXc0vB7nPLk2Ra9s']],
  // Fix round 5 (residual-re-review-4.md).
  ['C4 PEM with real newlines in env, then a PAT (parse error)', 'claude_desktop_config.json',
    '{\n "mcpServers": {\n  "a": { "command": "npx", "args": ["-y", "pkg@latest"],\n   "env": { "PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxK9mQ2pR7vN4bodybody\n-----END RSA PRIVATE KEY-----",\n "GITHUB_TOKEN": "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "API_KEY": "Zq81mXc0vB7nPLk2Ra9s" } }\n }\n}',
    ['MIIEowIBAAKCAQEAxK9mQ2pR7vN4', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6', 'Zq81mXc0vB7nPLk2Ra9s']],
  ['C4 single-quoted (Python dict) paste', 'claude_desktop_config.json',
    `{\n "mcpServers": {\n  "a": { "command": "npx", "args": ["-y", "pkg@latest"], 'env': { 'API_KEY': 'Zq81mXc0vB7nPLk2Ra9s', 'GH': 'ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8' } }\n }\n}`,
    ['Zq81mXc0vB7nPLk2Ra9s', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6']],
  ['n1 --headers x_api_key VALUE', 'mcp.json',
    JSON.stringify({ mcpServers: { r: { command: 'uvx', args: ['mcp-proxy', '--headers', 'x_api_key', 'Zq81mXc0vB7nPLk2Ra9s', 'https://x/sse'] } } }),
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ['n1 -H X2-Key VALUE', 'mcp.json',
    JSON.stringify({ mcpServers: { r: { command: 'uvx', args: ['mcp-proxy', '-H', 'X2-Key', 'Zq81mXc0vB7nPLk2Ra9s', 'https://x/sse'] } } }),
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ['n3 --headers NAME -VALUE', 'mcp.json',
    JSON.stringify({ mcpServers: { r: { command: 'uvx', args: ['mcp-proxy', '--headers', 'X-A', '-Zq81mXc0vB7nPLk2Ra9s', 'https://x/sse'] } } }),
    ['Zq81mXc0vB7nPLk2Ra9s']],
  // Fix round 6 (residual-re-review-5.md): no excerpt for a file that failed to parse.
  ['C5 smart-quoted env line (parse error)', 'claude_desktop_config.json',
    '{\n "mcpServers": {\n  "a": { "command": "npx", "args": ["-y", "pkg@latest"],\n   "env": { “API_KEY”: “Zq81mXc0vB7nPLk2Ra9s” } }\n }\n}',
    ['Zq81mXc0vB7nPLk2Ra9s']],
  ['C5 smart-quoted PEM and PAT (parse error)', 'claude_desktop_config.json',
    '{\n "mcpServers": {\n  "a": { "command": "npx", "args": ["-y", "pkg@latest"],\n   "env": { “PRIVATE_KEY”: “-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxK9mQ2pR7vN4bodybody\n-----END RSA PRIVATE KEY-----”,\n “GITHUB_TOKEN”: “ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8” } }\n }\n}',
    ['MIIEowIBAAKCAQEAxK9mQ2pR7vN4', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6']],
];

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'mcpaudit-leak-'));
const cli = path.resolve(import.meta.dirname, '../src/cli.ts');

for (const [label, name, text, secrets] of CASES) {
  test(`no leak: ${label}`, () => {
    const r = audit([{ name, text }]);
    assert.ok(r.findings.length > 0, `${label}: expected a finding so an excerpt is built`);
    const outputs = {
      json: JSON.stringify(r),
      md: toMarkdown(r),
      sarif: JSON.stringify(toSarif(r, '0.0.0')),
    };
    for (const [fmt, out] of Object.entries(outputs))
      for (const s of secrets) assert.ok(!out.includes(s), `${label}: ${s} in ${fmt}`);

    const d = tmp();
    const file = path.join(d, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, text);
    for (const fmt of ['table', 'md', 'sarif']) {
      const p = spawnSync(process.execPath, [cli, file, '--format', fmt, '--fail-on', 'none'], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
      for (const s of secrets) assert.ok(!p.stdout.includes(s) && !p.stderr.includes(s), `${label}: ${s} in CLI ${fmt}`);
    }
  });
}

test('excerpts are clipped to the server or settings node and to ~160 chars', () => {
  const big = 'x'.repeat(500);
  const r = audit([{ name: '.claude.json', text: JSON.stringify({ pad: big, mcpServers: { r: { url: 'http://example.com/mcp' } }, tail: big }) }]);
  const f = r.findings.find((x) => x.ruleId === 'remote-http')!;
  assert.equal(f.excerpt.length, 1);
  assert.ok(f.excerpt[0].text.includes('"url"'), f.excerpt[0].text);
  assert.ok(f.excerpt[0].text.length <= 170, String(f.excerpt[0].text.length));
  assert.ok(!f.excerpt[0].text.includes('pad') && !f.excerpt[0].text.includes('tail'));
});

test('C4: a broken paste keeps package specs and URLs readable', () => {
  const r = audit([{ name: 'claude_desktop_config.json', text: CASES.find(([l]) => l.startsWith('C4 PEM with real'))![2] }]);
  const f = r.findings.find((x) => x.ruleId === 'npx-latest')!;
  // Round 6: a broken file has no excerpt; detail and evidence still name the package.
  assert.deepEqual(f.excerpt, []);
  assert.ok(f.detail!.includes('pkg@latest') && f.evidence === 'pkg@latest', JSON.stringify(f));
  const u = audit([{ name: 'mcp.json', text: '{ "mcpServers": { "r": { "url": "http://example.com/mcp", "args": ["@scope/pkg@1.2.3"] }, }, oops }' }]);
  const all = JSON.stringify(u);
  assert.ok(all.includes('http://example.com/mcp'), all);
});

test('n1: header names with _ and digits keep the name visible', () => {
  for (const name of ['x_api_key', 'X2-Key']) {
    const r = audit([{ name: 'mcp.json', text: JSON.stringify({ mcpServers: { r: { command: 'uvx', args: ['mcp-proxy', '--headers', name, 'Zq81mXc0vB7nPLk2Ra9s', 'https://x/sse'] } } }) }]);
    assert.ok(JSON.stringify(r.findings[0]!.excerpt).includes(`\\"${name}\\"`), JSON.stringify(r.findings[0]!.excerpt));
  }
});

test('C5: a file that failed to parse shows no excerpt or snippet, and says why', () => {
  for (const [label, name, text] of CASES.filter(([l]) => /parse error/.test(l))) {
    const r = audit([{ name, text }]);
    assert.ok(r.files[0]!.error && r.findings.length, label);
    for (const f of r.findings) assert.deepEqual(f.excerpt, [], `${label}: ${f.ruleId}`);
    const sarif = toSarif(r, '0.0.0') as any;
    for (const res of sarif.runs[0].results) assert.equal(res.locations[0].physicalLocation.region.snippet, undefined, label);
    const md = toMarkdown(r);
    assert.ok(md.includes("Excerpt hidden: this file couldn't be fully parsed") && !md.includes('```\n>'), label);
  }
});

test('n6: a broken file with 160k secret-named pairs does not overflow the stack', { timeout: 60000 }, () => {
  const text = '{"mcpServers":{"a":{"command":"npx","args":["-y","p@latest"]}}, oops ' + 'password=Zq81mXc0vB7nPLk2 '.repeat(160000) + '}';
  const r = audit([{ name: 'claude_desktop_config.json', text }]);
  assert.ok(r.findings.length > 0);
});

test('n7: a PEM BEGIN with no END in a valid file does not hide later servers\' excerpts', () => {
  const text = JSON.stringify({ mcpServers: {
    a: { command: 'npx', args: ['-y', 'a-pkg@1.0.0'], env: { PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC' } },
    b: { command: 'npx', args: ['-y', 'b-pkg@latest'], url: 'http://b.example/mcp' },
  } }, null, 1);
  const r = audit([{ name: 'mcp.json', text }]);
  const b = r.findings.filter((f) => f.server === 'b');
  assert.ok(b.length >= 2);
  for (const f of b) assert.ok(f.excerpt.some((l) => l.hit), `${f.ruleId}: ${JSON.stringify(f.excerpt)}`);
  assert.ok(r.findings.find((f) => f.ruleId === 'npx-latest')!.excerpt.some((l) => l.text.includes('b-pkg@latest')));
  assert.ok(!JSON.stringify(r).includes('MIIEvQIBADANBgkqhkiG9w0BAQEFAASC'));
  assert.ok(JSON.stringify(toSarif(r, '0.0.0')).includes('b.example'));
});
