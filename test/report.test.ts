import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import AjvMod from 'ajv-draft-04';
import { audit } from '../src/engine.ts';
import { toMarkdown } from '../src/report/markdown.ts';
import { toSarif, uri } from '../src/report/sarif.ts';
import type { AuditResult, Finding, Severity } from '../src/types.ts';

const Ajv = ((AjvMod as any).default ?? AjvMod) as typeof AjvMod.default;
const run = (cfg: unknown) => audit([{ name: 'a.json', text: JSON.stringify(cfg, null, 2) }]);
const base = run({ mcpServers: { s: { url: 'http://example.com/mcp', env: { DB_PASSWORD: 'hunter2hunter2' } } } });
const f0 = base.findings[0]!;
const sevs: Severity[] = ['critical', 'high', 'medium', 'low'];
// one real finding re-labelled per severity so all four are covered
const multi: AuditResult = {
  ...base,
  findings: sevs.map((severity, i): Finding => ({ ...f0, severity, ruleId: `r${i}` })),
};
const sarif = (r: AuditResult) => toSarif(r, '1.2.3') as any;

test('sarif validates against 2.1.0 schema', () => {
  const ajv = new (Ajv as any)({ strict: false });
  const validate = ajv.compile(JSON.parse(readFileSync(new URL('./fixtures/sarif-schema-2.1.0.json', import.meta.url), 'utf8')));
  assert.ok(validate(sarif(multi)), JSON.stringify(validate.errors));
});
test('sarif maps severity', () => {
  assert.deepEqual(sarif(multi).runs[0].results.map((r: any) => r.level), ['error', 'error', 'warning', 'note']);
});
test('sarif rule metadata', () => {
  const d = sarif(base).runs[0].tool.driver;
  assert.equal(d.name, 'qlucent-mcp-audit');
  assert.equal(d.informationUri, 'https://qlucent.com/tools/mcp-audit/');
  assert.ok(d.rules.length > 0 && d.rules.every((r: any) => r.helpUri.startsWith('https://qlucent.com/tools/mcp-audit/rules/')));
});
test('sarif location', () => {
  const f = base.findings.find((x) => x.excerpt.some((l) => l.hit))!;
  const res = sarif({ ...base, findings: [f] }).runs[0].results[0].locations[0].physicalLocation;
  assert.equal(res.artifactLocation.uri, f.file);
  assert.equal(res.region.startLine, f.line);
  assert.equal(res.region.startColumn, f.column);
  assert.equal(res.region.snippet.text, f.excerpt.find((l) => l.hit)!.text);
});
test('markdown has verdict, table and fixes', () => {
  const md = toMarkdown(base);
  assert.ok(md.startsWith('# MCP config audit'));
  assert.ok(md.includes(base.verdict.text));
  assert.ok(md.includes('| Severity |'));
  assert.equal(md.split('\n').filter((l) => l.startsWith('## ')).length, base.findings.length);
  assert.ok(md.includes('Why it matters') && md.includes('**Fix**'));
});
test('markdown zero findings note', () => {
  const md = toMarkdown(run({ mcpServers: {} }));
  assert.ok(md.includes("That doesn't make it safe"));
});
test('exports never contain raw secrets', () => {
  const gh = run({ mcpServers: { s: { url: 'http://example.com/mcp', env: { GITHUB_TOKEN: 'ghp_EXAMPLEexampleEXAMPLEexample0000' } } } });
  for (const r of [base, gh]) {
    const all = toMarkdown(r) + JSON.stringify(toSarif(r, '1'));
    assert.ok(!all.includes('hunter2') && !all.includes('EXAMPLEexample'));
  }
});
test('sarif uri: file:/// for Windows absolute paths, encoded relative paths', () => {
  assert.equal(uri('C:\\Users\\me\\.cursor\\mcp.json'), 'file:///C:/Users/me/.cursor/mcp.json');
  assert.equal(uri('my dir\\a#1.json'), 'my%20dir/a%231.json');
  assert.equal(uri('.vscode/mcp.json'), '.vscode/mcp.json');
});
test('markdown escapes config text and cannot be broken out of', () => {
  const evil = 'x](https://evil.example)![i](https://evil.example/p.png)|<img src=x>';
  const r = audit([{ name: `a|${evil}.json`, text: JSON.stringify({ mcpServers: { [evil]: { url: 'http://example.com/mcp', env: { A: '```' } } } }, null, 2) }]);
  const md = toMarkdown(r).replace(/^(`{3,})\n[^]*?\n\1$/gm, ''); // fenced text is inert
  assert.ok(!/(?<!\\)\]\\?\(https:\/\/evil/.test(md) && !/(?<!\\)<img/.test(md), md);
  for (const row of md.split('\n').filter((l) => l.startsWith('| ') && !l.startsWith('| Severity') && !l.startsWith('| ---')))
    assert.equal(row.split(/(?<!\\)\|/).length, 5, row);
  const f = { ...r.findings[0]!, excerpt: [{ line: 1, text: '```\n## injected', hit: true }], fix: 'a ```` b' };
  const md2 = toMarkdown({ ...r, findings: [f] });
  assert.ok(md2.includes('`````\na ```` b\n`````'), md2);
  assert.ok(md2.includes('````\n> 1: ```'), md2);
});
test('markdown lists unrecognised and unparsable files', () => {
  const md = toMarkdown(audit([{ name: 'settings.json', text: '{"foo":1}' }, { name: 'b.json', text: '{ nope' }]));
  assert.ok(md.includes("Couldn't recognise settings.json as an MCP config"), md);
  assert.ok(md.includes("Couldn't parse b.json"), md);
  assert.ok(!md.includes('None of') && !md.includes("doesn't make it safe"), md);
});
