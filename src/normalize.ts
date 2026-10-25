import type { Node } from 'jsonc-parser';
import { locOf } from './parse.ts';
import type { Normalized, ParsedFile, Server, Settings, Transport } from './types.ts';

const SETTINGS_CLIENTS = new Set(['claude-code-settings', 'vscode', 'cursor']);

/** Property entries of an object node: [key, valueNode, keyNode]. */
function props(node: Node | undefined): Array<[string, Node, Node]> {
  if (node?.type !== 'object') return [];
  const out: Array<[string, Node, Node]> = [];
  for (const p of node.children ?? []) {
    const [k, v] = p.children ?? [];
    if (k && v) out.push([String(k.value), v, k]);
  }
  return out;
}
// Last duplicate wins, as with JSON.parse in the clients.
const prop = (node: Node | undefined, key: string) => props(node).findLast(([k]) => k === key)?.[1];
const str = (n: Node | undefined) => (n?.type === 'string' ? (n.value as string) : undefined);

function readServer(f: ParsedFile, name: string, node: Node, key: Node, groups: string[]): Server {
  const loc = (n: Node) => locOf(f.text, n.offset, n.length);
  const fieldLocs: Server['fieldLocs'] = Object.create(null);

  const cmdNode = prop(node, 'command');
  const command = str(cmdNode);
  if (command !== undefined && cmdNode) fieldLocs.command = loc(cmdNode);

  // Windsurf uses serverUrl, Gemini httpUrl.
  const urlNode = prop(node, 'url') ?? prop(node, 'serverUrl') ?? prop(node, 'httpUrl');
  const url = str(urlNode);
  if (url !== undefined && urlNode) fieldLocs.url = loc(urlNode);

  const args: string[] = [];
  const argsNode = prop(node, 'args');
  for (const a of argsNode?.type === 'array' ? (argsNode.children ?? []) : []) {
    if (a.type !== 'string') continue;
    fieldLocs[`args.${args.length}`] = loc(a);
    args.push(a.value as string);
  }
  const strMap = (field: string) => {
    const out: Record<string, string> = Object.create(null);
    for (const [k, v] of props(prop(node, field))) {
      if (v.type !== 'string') { delete out[k]; delete fieldLocs[`${field}.${k}`]; continue; }
      out[k] = v.value as string;
      fieldLocs[`${field}.${k}`] = loc(v);
    }
    return out;
  };
  const env = strMap('env');
  const headers = strMap('headers');

  const type = str(prop(node, 'type'))?.toLowerCase();
  let transport: Transport = 'unknown';
  if (type === 'sse') transport = 'sse';
  else if (type === 'http' || type === 'streamable-http') transport = 'http';
  else if (type === 'stdio') transport = 'stdio';
  else if (url !== undefined) transport = /\/sse\/?$/.test(url) ? 'sse' : 'http';
  else if (command !== undefined) transport = 'stdio';

  const server: Server = { name, file: f.file, client: f.client, groups, transport, args, env, headers, loc: loc(key), fieldLocs };
  if (command !== undefined) server.command = command;
  if (url !== undefined) server.url = url;
  return server;
}

const slash = (p: string) => p.replaceAll('\\', '/').replace(/\/+$/, '').toLowerCase();
const isMcpJson = (f: ParsedFile) => /(^|[\\/])\.mcp\.json$/.test(f.file);

export function normalize(files: ParsedFile[]): Normalized {
  const servers: Server[] = [];
  const settings: Settings[] = [];
  // Claude Code projects named in any ~/.claude.json, so a project's .mcp.json joins that project's group.
  const projects = new Map<string, string>();
  for (const f of files) {
    if (f.client !== 'claude-code' || isMcpJson(f)) continue;
    for (const [path] of props(prop(f.tree, 'projects'))) projects.set(slash(path), path);
  }
  const mcpJsonProjects = new Set<string>();
  for (const f of files) {
    if (f.client !== 'claude-code' || !isMcpJson(f)) continue;
    const p = projects.get(slash(f.file.replace(/[\\/]?\.mcp\.json$/, '')));
    if (p !== undefined) mcpJsonProjects.add(p);
  }

  for (const f of files) {
    const root = f.tree;
    if (root?.type !== 'object') continue;
    if (f.client && SETTINGS_CLIENTS.has(f.client)) settings.push({ file: f.file, client: f.client, node: root });

    const containers: Array<{ project?: string; node: Node }> = [];
    for (const [k, v] of props(root)) {
      if (k === 'mcpServers' || (k === 'servers' && f.client === 'vscode')) containers.push({ node: v });
      const sv = k === 'mcp' && f.client === 'vscode' ? prop(v, 'servers') : undefined; // VS Code user settings.json
      if (sv) containers.push({ node: sv });
      if (k === 'projects' && f.client === 'claude-code') {
        for (const [path, p] of props(v)) {
          const m = prop(p, 'mcpServers');
          if (m) containers.push({ project: path, node: m });
        }
      }
    }
    let fileGroups: string[];
    if (f.client === 'claude-code' && isMcpJson(f)) {
      // Project scope: the matching project's group when ~/.claude.json lists it, else plain claude-code.
      const p = projects.get(slash(f.file.replace(/[\\/]?\.mcp\.json$/, '')));
      fileGroups = [p !== undefined ? `claude-code:${p}` : 'claude-code'];
    } else if (f.client === 'claude-code') {
      // User scope applies in every project, and alongside a .mcp.json whose project is not listed.
      const withServers = containers.filter((c) => c.project !== undefined).map((c) => c.project!);
      fileGroups = [...new Set([...withServers, ...mcpJsonProjects])].map((p) => `claude-code:${p}`).concat('claude-code');
    } else fileGroups = f.client === null || f.client === 'mcp-servers' ? ['file:' + f.file] : [f.client];

    for (const c of containers) {
      const groups = c.project !== undefined ? [`claude-code:${c.project}`] : fileGroups;
      for (const [name, v, k] of props(c.node)) {
        if (v.type === 'object') servers.push(readServer(f, name, v, k, groups));
      }
    }
  }
  return { servers, settings };
}
