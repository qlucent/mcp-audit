import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseFile, locOf } from '../src/parse.ts';

test('parses JSONC with comments and trailing commas', () => {
  const p = parseFile({ name: '.vscode/mcp.json', text: '{\n  // c\n  "servers": { "a": { "command": "x", }, },\n}' });
  assert.equal(p.error, undefined);
  assert.ok(p.tree);
});

test('detects client from path', () => {
  const cases: Array<[string, string]> = [
    ['C:\\Users\\me\\AppData\\Roaming\\Claude\\claude_desktop_config.json', 'claude-desktop'],
    ['~/Library/Application Support/Claude/claude_desktop_config.json', 'claude-desktop'],
    ['proj/.cursor/mcp.json', 'cursor'],
    ['.cursor\\mcp.json', 'cursor'],
    ['~/.codeium/windsurf/mcp_config.json', 'windsurf'],
    ['~/.config/devin/mcp_config.json', 'windsurf'],
    ['AppData\\Roaming\\devin\\mcp_config.json', 'windsurf'],
    ['~/.gemini/settings.json', 'gemini'],
    ['.vscode/mcp.json', 'vscode'],
    ['~/.config/Code/User/mcp.json', 'vscode'],
    ['AppData\\Roaming\\Code\\User\\mcp.json', 'vscode'],
    ['proj/.mcp.json', 'claude-code'],
    ['~/.claude.json', 'claude-code'],
    ['proj/.claude/settings.json', 'claude-code-settings'],
    ['proj\\.claude\\settings.local.json', 'claude-code-settings'],
  ];
  for (const [name, client] of cases) assert.equal(parseFile({ name, text: '{}' }).client, client, name);
});

test('detects client from shape when pasted', () => {
  const c = (text: string) => parseFile({ name: 'pasted-1', text }).client;
  assert.equal(c('{"servers":{}}'), 'vscode');
  assert.equal(c('{"mcpServers":{}}'), 'mcp-servers');
  assert.equal(c('{"permissions":{}}'), 'claude-code-settings');
  assert.equal(c('{"projects":{"/p":{"mcpServers":{}}}}'), 'claude-code');
  assert.equal(c('{"foo":1}'), null);
});

test('reports parse error with location', () => {
  const p = parseFile({ name: 'pasted-1', text: '{\n  "mcpServers": {\n    "a": \n}' });
  assert.ok(p.error);
  assert.equal(p.error.line, 4);
  assert.ok(p.error.column >= 1);
  assert.ok(p.error.message.length > 0);
});

test('line numbers correct with CRLF', () => {
  const text = '{\r\n  "x": 1\r\n}';
  const l = locOf(text, text.indexOf('"x"'), 3);
  assert.equal(l.line, 2);
  assert.equal(l.column, 3);
});

test('enableAllProjectMcpServers alone marks Claude Code settings (I3)', () =>
  assert.equal(parseFile({ name: 'pasted-1', text: '{"enableAllProjectMcpServers": true}' }).client, 'claude-code-settings'));

test('a leading BOM parses and keeps offsets', () => {
  const p = parseFile({ name: 'pasted-1', text: '\uFEFF{"mcpServers":{}}' });
  assert.equal(p.error, undefined);
  assert.equal(p.client, 'mcp-servers');
  assert.equal(p.text.length, 18);
});
