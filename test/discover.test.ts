import { test } from 'node:test';
import assert from 'node:assert/strict';
import { candidatePaths } from '../src/discover.ts';
import { parseFile } from '../src/parse.ts';

test('darwin', () => {
  assert.deepEqual(candidatePaths({ platform: 'darwin', home: '/Users/a', cwd: '/w' }), [
    '/Users/a/Library/Application Support/Claude/claude_desktop_config.json',
    '/Users/a/.cursor/mcp.json', '/w/.cursor/mcp.json',
    '/Users/a/Library/Application Support/Code/User/mcp.json', '/w/.vscode/mcp.json',
    '/Users/a/.codeium/windsurf/mcp_config.json', '/Users/a/.config/devin/mcp_config.json',
    '/Users/a/.gemini/settings.json', '/w/.gemini/settings.json',
    '/Users/a/.claude.json', '/w/.mcp.json',
    '/Users/a/.claude/settings.json', '/w/.claude/settings.json', '/w/.claude/settings.local.json',
    '/Users/a/Library/Application Support/Code/User/settings.json',
  ]);
});

test('linux', () => {
  const p = candidatePaths({ platform: 'linux', home: '/home/a', cwd: '/w' });
  assert.equal(p[0], '/home/a/.config/Claude/claude_desktop_config.json');
  assert.equal(p[3], '/home/a/.config/Code/User/mcp.json');
  assert.equal(p.length, 15);
});

test('win32 uses appData and backslashes', () => {
  const p = candidatePaths({ platform: 'win32', home: 'C:\\Users\\a', cwd: 'C:\\w', appData: 'C:\\Users\\a\\AppData\\Roaming' });
  assert.equal(p[0], 'C:\\Users\\a\\AppData\\Roaming\\Claude\\claude_desktop_config.json');
  assert.equal(p[3], 'C:\\Users\\a\\AppData\\Roaming\\Code\\User\\mcp.json');
  assert.equal(p[4], 'C:\\w\\.vscode\\mcp.json');
  assert.equal(p[5], 'C:\\Users\\a\\.codeium\\windsurf\\mcp_config.json');
});

test('every discovered path is detected as a known client', () => {
  for (const platform of ['darwin', 'win32', 'linux'] as const) {
    const home = platform === 'win32' ? 'C:\\h' : '/h';
    const cwd = platform === 'win32' ? 'C:\\w' : '/w';
    for (const name of candidatePaths({ platform, home, cwd })) {
      assert.notEqual(parseFile({ name, text: '{}' }).client, null, name);
    }
  }
});
