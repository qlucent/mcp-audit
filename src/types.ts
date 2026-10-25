export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type Client =
  | 'claude-desktop'
  | 'cursor'
  | 'windsurf'
  | 'gemini'
  | 'vscode'
  | 'claude-code'
  | 'claude-code-settings'
  | 'mcp-servers';
/** 1-based line and column. */
export interface Loc { line: number; column: number; offset: number; length: number }
/** name = file path or "pasted-1" */
export interface InputFile { name: string; text: string }
export interface ParsedFile {
  file: string;
  text: string;
  client: Client | null;
  tree: import('jsonc-parser').Node | undefined;
  error?: { message: string; line: number; column: number };
}

export type Transport = 'stdio' | 'http' | 'sse' | 'unknown';
export interface Server {
  name: string;
  file: string;
  client: Client | null;
  groups: string[];
  transport: Transport;
  command?: string;
  args: string[];
  env: Record<string, string>;
  url?: string;
  headers: Record<string, string>;
  /** The server's key. */
  loc: Loc;
  /** 'command' | 'url' | `args.${i}` | `env.${KEY}` | `headers.${KEY}` -> value loc */
  fieldLocs: Record<string, Loc>;
}
/** Whole settings object of a file. */
export interface Settings { file: string; client: Client; node: import('jsonc-parser').Node }
export interface Normalized { servers: Server[]; settings: Settings[] }

export type Cap = 'untrusted_input' | 'outbound' | 'private_data' | 'code_exec' | 'writes';
export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  applies_to: 'servers' | 'settings' | 'groups';
  match?: {
    target: 'command' | 'args' | 'env' | 'headers' | 'url';
    pattern: string;
    flags?: string;
    key_pattern?: string;
    not_pattern?: string;
  };
  check?: string;
  why: string;
  fix: string;
  references: string[];
}
export interface CatalogEntry {
  id: string;
  match: { npm?: string[]; pypi?: string[]; docker?: string[]; url?: string[] };
  label: string;
  caps: Cap[];
}
export interface Hit {
  file: string; loc: Loc; server?: string; servers?: string[];
  field?: string; value?: string; detail?: string; severity?: Severity;
}
export interface CheckContext { normalized: Normalized; files: ParsedFile[]; catalog: CatalogEntry[] }
export type Check = (ctx: CheckContext, rule: Rule) => Hit[];
export interface ExcerptLine { line: number; text: string; hit: boolean }
export interface Finding {
  ruleId: string; severity: Severity; title: string; detail?: string;
  file: string; line: number; column: number;
  server?: string; servers?: string[]; field?: string; evidence?: string;
  excerpt: ExcerptLine[]; why: string; fix: string; helpUri: string;
}
export interface Verdict { level: 'not-ready' | 'review' | 'clear' | 'unrecognised'; text: string; counts: Record<Severity, number> }
export interface MixNode { server: string; label: string; caps: Cap[] }
export interface Mix { group: string; nodes: MixNode[]; unknown: string[]; label: string }
export interface FileSummary {
  file: string; client: Client | null; servers: number; error?: ParsedFile['error'];
  /** Parsed, but not recognised as any MCP config format; nothing in it was checked. */
  unrecognised?: boolean;
}
export interface AuditResult {
  files: FileSummary[]; findings: Finding[]; verdict: Verdict; mixes: Mix[]; rulesChecked: number;
}
export interface Fixture { file?: string; config: unknown }
