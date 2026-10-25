import { findSecret, inlinePairs } from '../secrets.ts';
import type { Check, Hit, Server } from '../types.ts';

const SCHEME = /^(?:bearer|basic|token)\s+/i;
const FLAG = /^--?([A-Za-z][\w-]*)$/;

const each = (ctx: Parameters<Check>[0], f: (s: Server) => Hit[]): Hit[] => ctx.normalized.servers.flatMap(f);
const hit = (s: Server, field: string, value: string, detail: string): Hit => ({
  file: s.file, loc: s.fieldLocs[field] ?? s.loc, server: s.name, field, value, detail,
});

export const secretEnv: Check = (ctx) =>
  each(ctx, (s) =>
    Object.entries(s.env).flatMap(([k, v]) => {
      const f = findSecret(v, k);
      return f ? [hit(s, `env.${k}`, v, `${k} looks like a ${f.kind}`)] : [];
    }));

export const secretHeaders: Check = (ctx) =>
  each(ctx, (s) =>
    Object.entries(s.headers).flatMap(([k, v]) => {
      const f = findSecret(v.replace(SCHEME, ''), k);
      return f ? [hit(s, `headers.${k}`, v, `${k} header looks like a ${f.kind}`)] : [];
    }));

export const secretArgs: Check = (ctx) =>
  each(ctx, (s) =>
    s.args.flatMap((a, i) => {
      const eq = a.indexOf('=');
      const prev = FLAG.exec(s.args[i - 1] ?? '')?.[1];
      const f =
        findSecret(a) ?? (eq > 0 ? findSecret(a.slice(eq + 1), a.slice(0, eq).replace(/^-+/, '')) : null) ??
        (prev ? findSecret(a, prev) : null) ??
        // `set API_KEY=x && npx …` inside a shell-wrapper string.
        inlinePairs(a).map((p) => findSecret(p.value, p.name)).find(Boolean) ?? null;
      return f ? [hit(s, `args.${i}`, a, `argument looks like a ${f.kind}`)] : [];
    }));

export const secretUrl: Check = (ctx) =>
  each(ctx, (s) => {
    if (!s.url) return [];
    let u: URL;
    try { u = new URL(s.url); } catch { return findSecret(s.url) ? [hit(s, 'url', s.url, 'URL contains a credential')] : []; }
    const pw = decodeURIComponent(u.password);
    const bad =
      (pw && !findSecret(pw) && !/^(\$\{.*\}|\$\w+|\{\{.*\}\})$/.test(pw)) || findSecret(s.url) ||
      [...u.searchParams].some(([k, v]) => findSecret(v, k));
    return bad ? [hit(s, 'url', s.url, 'URL contains a credential')] : [];
  });
