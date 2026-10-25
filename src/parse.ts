import { parseTree, findNodeAtLocation, printParseErrorCode, type ParseError } from 'jsonc-parser';
import type { Client, InputFile, Loc, ParsedFile } from './types.ts';

/** Offsets where each line starts (0, then after each `\n`). */
export function lineStarts(text: string): number[] {
  const out = [0];
  for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) out.push(i + 1);
  return out;
}

// ponytail: one-entry cache; locOf is called per node while one file is normalised.
let cached: { text: string; starts: number[] } | undefined;

/** 1-based line/column for an offset. Counts `\n`; a preceding `\r` is part of the line ending. */
export function locOf(text: string, offset: number, length: number): Loc {
  if (cached?.text !== text) cached = { text, starts: lineStarts(text) };
  const { starts } = cached;
  let lo = 0, hi = starts.length - 1;
  while (lo < hi) { const m = (lo + hi + 1) >> 1; if (starts[m]! <= offset) lo = m; else hi = m - 1; }
  return { line: lo + 1, column: offset - starts[lo]! + 1, offset, length };
}


const PATH_RULES: Array<[RegExp, Client]> = [
  [/(^|\/)\.claude\/settings(\.local)?\.json$/, 'claude-code-settings'],
  [/(^|\/)claude_desktop_config\.json$/, 'claude-desktop'],
  [/(^|\/)\.cursor\/mcp\.json$/, 'cursor'],
  [/(^|\/)\.codeium\/windsurf\/mcp_config\.json$/, 'windsurf'],
  [/(^|\/)(\.config\/)?devin\/mcp_config\.json$/, 'windsurf'],
  [/(^|\/)\.gemini\/settings\.json$/, 'gemini'],
  [/(^|\/)(\.vscode|Code( - Insiders)?\/User)\/mcp\.json$/, 'vscode'],
  // VS Code user settings; MCP servers sit under "mcp": { "servers": … }.
  [/(^|\/)Code( - Insiders)?\/User\/settings\.json$/, 'vscode'],
  [/(^|\/)\.(mcp|claude)\.json$/, 'claude-code'],
];

function clientFromPath(name: string): Client | null {
  const p = name.replaceAll('\\', '/');
  return PATH_RULES.find(([re]) => re.test(p))?.[1] ?? null;
}

function clientFromShape(tree: ParsedFile['tree']): Client | null {
  if (tree?.type !== 'object') return null;
  const has = (k: string) => findNodeAtLocation(tree, [k]) !== undefined;
  if (has('servers') || findNodeAtLocation(tree, ['mcp', 'servers'])) return 'vscode';
  if (has('permissions') || has('enableAllProjectMcpServers')) return 'claude-code-settings';
  if (has('projects')) return 'claude-code';
  if (has('mcpServers')) return 'mcp-servers';
  return null;
}

export function parseFile(input: InputFile): ParsedFile {
  const errors: ParseError[] = [];
  // A leading BOM becomes a space so the parser accepts it and offsets stay the same.
  const text = input.text.replace(/^\uFEFF/, ' ');
  const tree = parseTree(text, errors, { allowTrailingComma: true, disallowComments: false });
  const client = clientFromPath(input.name) ?? clientFromShape(tree);
  const out: ParsedFile = { file: input.name, text, client, tree };
  const first = errors[0];
  if (first) {
    const { line, column } = locOf(text, first.offset, first.length);
    out.error = { message: printParseErrorCode(first.error), line, column };
  }
  return out;
}
