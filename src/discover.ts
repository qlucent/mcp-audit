import path from 'node:path';

export interface DiscoverEnv { platform: NodeJS.Platform; home: string; cwd: string; appData?: string }

/** Where MCP-capable clients keep config. Pure: no filesystem access. */
export function candidatePaths(env: DiscoverEnv): string[] {
  const p = env.platform === 'win32' ? path.win32 : path.posix;
  const { home, cwd } = env;
  const appData = env.appData ?? p.join(home, 'AppData', 'Roaming');
  const [desktop, vscodeUser] =
    env.platform === 'darwin'
      ? [p.join(home, 'Library', 'Application Support', 'Claude'), p.join(home, 'Library', 'Application Support', 'Code', 'User')]
      : env.platform === 'win32'
        ? [p.join(appData, 'Claude'), p.join(appData, 'Code', 'User')]
        : [p.join(home, '.config', 'Claude'), p.join(home, '.config', 'Code', 'User')];
  return [
    p.join(desktop, 'claude_desktop_config.json'),
    p.join(home, '.cursor', 'mcp.json'),
    p.join(cwd, '.cursor', 'mcp.json'),
    p.join(vscodeUser, 'mcp.json'),
    p.join(cwd, '.vscode', 'mcp.json'),
    p.join(home, '.codeium', 'windsurf', 'mcp_config.json'),
    env.platform === 'win32' ? p.join(appData, 'devin', 'mcp_config.json') : p.join(home, '.config', 'devin', 'mcp_config.json'),
    p.join(home, '.gemini', 'settings.json'),
    p.join(cwd, '.gemini', 'settings.json'),
    p.join(home, '.claude.json'),
    p.join(cwd, '.mcp.json'),
    p.join(home, '.claude', 'settings.json'),
    p.join(cwd, '.claude', 'settings.json'),
    p.join(cwd, '.claude', 'settings.local.json'),
    p.join(vscodeUser, 'settings.json'),
  ];
}
