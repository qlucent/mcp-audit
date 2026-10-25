import type { Node } from 'jsonc-parser';
import { locOf } from '../parse.ts';
import type { Check, CheckContext, Hit, ParsedFile } from '../types.ts';

const entries = (n: Node | undefined): Array<[string, Node]> =>
  n?.type === 'object' ? (n.children ?? []).flatMap((p) => (p.children?.[0] && p.children[1] ? [[String(p.children[0].value), p.children[1]] as [string, Node]] : [])) : [];
const get = (n: Node | undefined, ...path: string[]): Node | undefined =>
  path.reduce<Node | undefined>((cur, k) => entries(cur).findLast(([key]) => key === k)?.[1], n); // last duplicate wins, as in the clients

const claudeSettings = (ctx: CheckContext) =>
  ctx.normalized.settings.filter((s) => s.client === 'claude-code-settings');
const fileOf = (ctx: CheckContext, name: string): ParsedFile => ctx.files.find((f) => f.file === name)!;
const hitAt = (ctx: CheckContext, file: string, n: Node, detail: string, field?: string): Hit =>
  ({ file, loc: locOf(fileOf(ctx, file).text, n.offset, n.length), field, detail });

// Documented: https://code.claude.com/docs/en/settings-reference (enableAllProjectMcpServers);
// Cline `autoApprove` and Roo Code `alwaysAllow` per-server arrays. "*" is not documented as a wildcard; treat it as approve-everything.
export const autoApproveAll: Check = (ctx) => {
  const out: Hit[] = [];
  for (const s of claudeSettings(ctx)) {
    const n = get(s.node, 'enableAllProjectMcpServers');
    if (n?.value === true) out.push(hitAt(ctx, s.file, n, 'approves every server in project .mcp.json without a prompt', 'enableAllProjectMcpServers'));
  }
  for (const f of ctx.files) {
    for (const [ck, top] of entries(f.tree)) {
      if (ck !== 'mcpServers' && !(f.client === 'vscode' && (ck === 'servers' || ck === 'mcp'))) continue;
      const container = ck === 'mcp' ? get(top, 'servers') : top; // VS Code user settings.json
      for (const [name, srv] of entries(container)) {
        for (const key of ['alwaysAllow', 'autoApprove']) {
          const arr = get(srv, key);
          for (const item of arr?.type === 'array' ? (arr.children ?? []) : []) {
            if (item.value === '*') out.push({ ...hitAt(ctx, f.file, item, `${key} has "*", an approve-everything entry (not documented as a wildcard)`, key), server: name });
          }
        }
      }
    }
  }
  return out;
};

export const bypassPermissions: Check = (ctx) =>
  claudeSettings(ctx).flatMap((s) => {
    const n = get(s.node, 'permissions', 'defaultMode');
    return n?.value === 'bypassPermissions' ? [hitAt(ctx, s.file, n, 'sessions start with all permission prompts skipped, where honoured (user/managed settings)', 'permissions.defaultMode')] : [];
  });

const BROAD = /^(?:mcp__\*|Bash|Bash\(\*\)|Bash\(\*:\*\))$/;
export const broadPermissions: Check = (ctx) =>
  claudeSettings(ctx).flatMap((s) => {
    const arr = get(s.node, 'permissions', 'allow');
    return (arr?.type === 'array' ? (arr.children ?? []) : [])
      .filter((i) => typeof i.value === 'string' && BROAD.test(i.value))
      .map((i) => hitAt(ctx, s.file, i, `allow rule "${i.value}" approves every use without a prompt`, 'permissions.allow'));
  });
