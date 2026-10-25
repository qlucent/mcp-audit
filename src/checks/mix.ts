import { packageOf } from './exec-fs-remote.ts';
import type { Cap, CatalogEntry, Check, CheckContext, Hit, Mix, Server } from '../types.ts';

const hostPath = (u: string): string | null => {
  try { const { host, pathname } = new URL(u); return (host + pathname).toLowerCase().replace(/\/+$/, ''); } catch { return null; }
};

/** The catalogue entry for a server, or null when it is not recognised. */
export function capsOf(server: Server, catalog: CatalogEntry[]): CatalogEntry | null {
  if (server.url) {
    const hp = hostPath(server.url);
    return (hp && catalog.find((e) => e.match.url?.some((m) => hp === m || hp.startsWith(m + '/')))) || null;
  }
  const p = packageOf(server)?.ref;
  if (!p || p.source === 'url') return null;
  const name = p.manager === 'pypi' ? p.name.replace(/\[.*\]$/, '').toLowerCase() : p.name;
  return catalog.find((e) => e.match[p.manager]?.includes(name)) ?? null;
}

const LEGS: Array<[Cap, string]> = [['untrusted_input', 'untrusted input'], ['outbound', 'outbound'], ['private_data', 'private data']];

const cache = new WeakMap<CheckContext, { mixes: Mix[]; hits: Hit[] }>();

export function findMixes(ctx: CheckContext): { mixes: Mix[]; hits: Hit[] } {
  const cached = cache.get(ctx);
  if (cached) return cached;
  const mixes: Mix[] = [], hits: Hit[] = [];
  // One finding per distinct set of involved servers; a user-level pair repeated across many Claude Code projects is one finding.
  const seen = new Map<string, { mix: Mix; hit: Hit; groups: string[] }>();
  const noted = new Set<Server>();
  const groups = new Map<string, Server[]>();
  for (const s of ctx.normalized.servers) for (const g of s.groups) groups.set(g, [...(groups.get(g) ?? []), s]);

  for (const [group, servers] of groups) {
    const known: Array<{ s: Server; e: CatalogEntry }> = [];
    const unknown: string[] = [];
    for (const s of servers) {
      const e = capsOf(s, ctx.catalog);
      if (e) known.push({ s, e }); else unknown.push(s.name);
    }
    const has = (c: Cap) => known.filter((k) => k.e.caps.includes(c));
    const first = has('untrusted_input').find((u) => has('outbound').some((o) => o.s !== u.s));
    if (first) {
      const nodes = known.filter((k) => k.e.caps.some((c) => LEGS.some(([l]) => l === c)))
        .map(({ s, e }) => ({ server: s.name, label: e.label, caps: e.caps }));
      const triangle = has('private_data').length > 0;
      const legs = LEGS.filter(([c]) => c !== 'private_data' || triangle)
        .map(([c, t]) => `${t}: ${has(c).map((k) => k.s.name).join(', ')}`).join('; ');
      const label = triangle ? 'exfiltration path' : 'untrusted input can reach an outbound tool';
      const key = [...known.filter((k) => k.e.caps.some((c) => LEGS.some(([l]) => l === c))).map((k) => k.s.file + '\0' + k.s.name), '|', ...unknown].join('\0');
      const dup = seen.get(key);
      if (dup) { dup.groups.push(group); continue; }
      const mix = { group, nodes, unknown, label };
      const hit: Hit = {
        file: first.s.file, loc: first.s.loc, server: first.s.name, servers: nodes.map((n) => n.server),
        detail: `${label} (${legs})` + (unknown.length ? `. Not recognised, not counted: ${unknown.join(', ')}` : ''),
      };
      mixes.push(mix); hits.push(hit);
      seen.set(key, { mix, hit, groups: [group] });
      continue;
    }
    for (const { s, e } of known) {
      if (!e.caps.includes('untrusted_input') || !e.caps.includes('outbound') || noted.has(s)) continue;
      noted.add(s);
      hits.push({ file: s.file, loc: s.loc, server: s.name, severity: 'low', detail: `this server alone can read untrusted content and send data out (${e.label})` });
    }
  }
  for (const { hit, groups } of seen.values()) {
    const projects = groups.filter((g) => g.startsWith('claude-code:')).map((g) => g.slice(12));
    if (projects.length) hit.detail += ` in ${projects.length === 1 ? 'project' : projects.length + ' projects:'} ${projects.slice(0, 3).join(', ')}${projects.length > 3 ? ', ...' : ''}`;
  }
  const out = { mixes, hits };
  cache.set(ctx, out);
  return out;
}

export const dangerousMix: Check = (ctx) => findMixes(ctx).hits;
