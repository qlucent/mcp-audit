import { createScanner, type Node } from 'jsonc-parser';
import { lineStarts } from './parse.ts';
import { findSecret, inlinePairs, isReference, secretLikeKey } from './secrets.ts';
import type { ExcerptLine, ParsedFile } from './types.ts';

// Longest first so e.g. github_pat_ wins over shorter prefixes.
const PREFIXES = [
  'github_pat_', 'sk-proj-', 'sk-ant-', 'sk_live_', 'rk_live_',
  'xoxb-', 'xoxp-', 'xoxa-', 'xoxr-',
  'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_',
  'AKIA', 'ASIA', 'AIza', 'sk-',
];

export function mask(value: string): string {
  if (value.length < 16) return '••••••';
  const p = PREFIXES.find((x) => value.startsWith(x)) ?? '';
  return `${p}••••${value.slice(-4)}`;
}

const HIDDEN = '••••••';
const FLAG = /^--?([A-Za-z][\w-]*)$/;
// `--token=x`, `GITHUB_TOKEN=x` (docker -e), `Authorization: Bearer x` (mcp-remote --header).
const PAIR = /^(-{0,2}([A-Za-z_][\w.-]*)\s*[=:]\s*)([^]+)$/;
// Userinfo (`user:pass@`, `token@`; up to the last `@` of the authority, so `u:p@ss@host` hides `u:p@ss`)
// and query values; a bare `git@` user is not a credential.
const USERINFO = /([a-z][a-z0-9+.-]*:\/\/)(?!git@[^/?#\s@]*(?:[/?#\s]|$))([^/?#\s]+)@/gi;
const QUERY = /([?&][^=&#\s]*=)([^&#\s]+)/g;

/** `s` with URL userinfo and query values hidden. Hidden parts are pushed to `found`. */
export function redactUrl(s: string, found: string[] = []): string {
  if (!s.includes('://')) return s;
  const hide = (end: string) => (_: string, pre: string, v: string) => { found.push(v); return pre + HIDDEN + end; };
  return s.replace(USERINFO, hide('@')).replace(QUERY, hide(''));
}

const SCHEME = /^(?:bearer|basic|token)\s+/i;
// A bare header name (`X-Api-Key`, `x_api_key`, `X2-Key`), as in mcp-proxy's `--headers KEY VALUE`. A token
// with a digit needs a `-` or `_` too, so a random token (`Zq81…`) is not taken for a name.
const HEADER_NAME = /^[A-Za-z][\w-]*$/;
const headerName = (v: string) => HEADER_NAME.test(v) && (/[-_]/.test(v) || !/\d/.test(v)) && !findSecret(v);
// An option after the header name (`-y`, `--transport`), not a value that starts with `-` (`-Zq81…`).
const OPTION = /^--?[A-Za-z][a-z-]*$/;
/** Where the part of a header value to hide starts: after `Name:` or `Name ` and spaces, else 0.
 * -1 when there is nothing to hide (empty, or a `${…}` reference). Same as a `headers` entry. */
function headerRest(v: string): number {
  const at = (/^[^\s:]+:\s*/.exec(v) ?? /^[A-Za-z]+(?:-[A-Za-z0-9]+)*\s+/.exec(v))?.[0].length ?? 0;
  const rest = v.slice(at);
  return rest && !isReference(rest.replace(SCHEME, '')) ? at : -1;
}
// `--header V`, `--headers V`, `--header=V`, `-H V`, `-H"V"`, `-HName:V`: the value is a quoted string, else
// unquoted to the end of its argument: the comment line (up to `*/`), or in a shell string up to a separator.
const HEADER_FLAG = String.raw`(?<![\w.-])(?:--headers?|-H)(?:=|\s+|(?=["'])|(?<=-H)(?=[A-Za-z][\w-]*:))("(?:[^"\\\n]|\\.)*"?|'(?:[^'\\\n]|\\.)*'?|`;
const HEADER_IN_COMMENT = new RegExp(HEADER_FLAG + String.raw`(?:(?!\*\/)[^\n])*)`, 'g');
const HEADER_IN_STRING = new RegExp(HEADER_FLAG + String.raw`[^\n;&|]*)`, 'g');
// A PEM or PGP private key, up to its END line or the end of the text.
const PEM = /-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[^]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)/g;

/** `mask(v)`, or one HIDDEN per line when `v` spans lines, so a block comment keeps its line count. */
const maskLines = (v: string) =>
  v.includes('\n') ? v.split('\n').map((l) => HIDDEN + (l.endsWith('\r') ? '\r' : '')).join('\n') : mask(v);

/** Free text (a comment, a shell string) with secret-like `NAME=value` pairs, header values, private keys,
 * provider tokens and URL credentials hidden. */
function redactFree(s: string, found: string[], comment = false): string {
  // The first `q` at or after `from`; memoised, so many unclosed quotes stay linear.
  const close: Record<string, number> = {};
  const nextQuote = (q: string, from: number) => {
    const c = close[q];
    return c === undefined || (c >= 0 && c < from) ? (close[q] = s.indexOf(q, from)) : c;
  };
  const spans: Array<{ start: number; end: number }> = [...inlinePairs(s)];
  if (s.includes('-----BEGIN')) for (const m of s.matchAll(PEM)) spans.push({ start: m.index, end: m.index + m[0].length });
  if (s.includes('-H') || s.includes('--header')) for (const m of s.matchAll(comment ? HEADER_IN_COMMENT : HEADER_IN_STRING)) {
    const start = m.index + m[0].length - m[1]!.length;
    // A string that starts with the flag is the argument itself (`--header=Cookie: a; b`): its value runs to the end.
    let raw = !comment && m.index === 0 && !/^["']/.test(m[1]!) ? s.slice(start) : m[1]!;
    const q = /^["']/.test(raw) ? 1 : 0;
    // A quoted value not closed on its line runs to its closing quote on a later line.
    if (q && !(raw.length > 1 && raw.endsWith(raw[0]!))) {
      const c = nextQuote(raw[0]!, start + raw.length);
      if (c >= 0) raw = s.slice(start, c + 1);
    }
    const v = raw.slice(q, q && raw.length > 1 && raw.endsWith(raw[0]!) ? -1 : undefined).replace(/\s+$/, '');
    const at = headerRest(v);
    if (at >= 0) spans.push({ start: start + q + at, end: start + q + v.length });
  }
  spans.sort((a, b) => a.start - b.start || b.end - a.end);
  let out = '', pos = 0;
  for (const p of spans) {
    if (p.start < pos) continue;
    const v = s.slice(p.start, p.end);
    found.push(v);
    out += s.slice(pos, p.start) + maskLines(v);
    pos = p.end;
  }
  return (out + s.slice(pos))
    .replace(/[^\s"'`,;<>]+/g, (w) => (findSecret(w) ? (found.push(w), mask(w)) : redactUrl(w, found)));
}

export interface Redacted {
  text: string;
  starts: number[];
  /** Original offset -> offset in `text`. */
  map: (offset: number) => number;
  /** Raw substrings that were hidden. */
  raws: string[];
}

/**
 * File text with every sensitive value masked, keeping JSON quotes and line breaks. Walks every
 * property node (duplicate keys, `__proto__` and non-string values included) and masks:
 * all scalars under any `env` / `headers` object or under a secret-like key; the item after a
 * secret-like flag; `name=value` / `name: value` pairs with a secret-like name; every
 * `findSecret` hit; URL userinfo and query values; and the location of every hit that carries a value.
 */
export function redact(file: ParsedFile, valued: Array<{ offset: number; length: number; value: string }> = []): Redacted {
  const { text } = file;
  const edits = new Map<number, { offset: number; length: number; to: string }>();
  const raws: string[] = [];
  const put = (offset: number, length: number, to: string, ...raw: string[]) => {
    edits.set(offset, { offset, length, to: JSON.stringify(to) });
    raws.push(...raw);
  };

  // Comments (JSONC): never inside a node, so these edits cannot overlap the ones below.
  const scan = createScanner(text, false);
  for (let t = scan.scan(); t !== 17 /* EOF */; t = scan.scan()) {
    if (t !== 12 && t !== 13 /* line, block comment; SyntaxKind is a const enum */) continue;
    const c = scan.getTokenValue();
    const found: string[] = [];
    const to = redactFree(c, found, true);
    if (to !== c) {
      edits.set(scan.getTokenOffset(), { offset: scan.getTokenOffset(), length: scan.getTokenLength(), to });
      raws.push(...found);
    }
  }

  const walk = (n: Node | undefined, force: boolean): void => {
    if (!n) return;
    if (n.type === 'object') {
      for (const p of n.children ?? []) {
        const [k, v] = p.children ?? [];
        const key = String(k?.value ?? '');
        walk(v, force || key === 'env' || key === 'headers' || secretLikeKey(key));
      }
    } else if (n.type === 'array') {
      const items = n.children ?? [];
      for (let i = 0; i < items.length; i++) {
        const c = items[i]!, prev = items[i - 1], next = items[i + 1];
        const flag = prev?.type === 'string' ? FLAG.exec(prev.value as string)?.[1] : undefined;
        const header = !force && (flag === 'header' || flag === 'headers' || flag === 'H') && c.type === 'string';
        const v = c.value as string;
        // `--headers KEY VALUE` / `-H KEY VALUE` (mcp-proxy): keep the name, hide the next item.
        if (header && headerName(v) && next?.type === 'string' && !OPTION.test(next.value as string) && !(next.value as string).includes('://')) {
          const nv = next.value as string;
          if (!isReference(nv.replace(SCHEME, ''))) put(next.offset, next.length, mask(nv), nv);
          i++;
          continue;
        }
        // The item after `--header` / `-H`: hide the value after `Name:`, as for a `headers` entry.
        const at = header ? headerRest(v) : -1;
        if (at >= 0) put(c.offset, c.length, v.slice(0, at) + mask(v.slice(at)), v.slice(at));
        else walk(c, force || (flag !== undefined && secretLikeKey(flag)));
      }
    } else if (force) {
      const raw = n.type === 'string' ? (n.value as string) : text.slice(n.offset, n.offset + n.length);
      put(n.offset, n.length, mask(raw), raw);
    } else if (n.type === 'string') {
      const v = n.value as string;
      const pair = PAIR.exec(v);
      if (findSecret(v)) put(n.offset, n.length, mask(v), v);
      else if (pair && secretLikeKey(pair[2]!)) put(n.offset, n.length, pair[1] + mask(pair[3]!), pair[3]!);
      else {
        const found: string[] = [];
        const u = redactFree(v, found);
        if (u !== v) put(n.offset, n.length, u, ...found);
      }
    }
  };
  walk(file.tree, false);

  for (const h of valued) {
    if (edits.has(h.offset)) continue;
    try {
      if (JSON.parse(text.slice(h.offset, h.offset + h.length)) !== h.value) continue;
    } catch { continue; }
    put(h.offset, h.length, mask(h.value), h.value);
  }

  // Last pass over the original text, for what the walk never saw as a node (a paste that fails to parse):
  // private-key blocks, provider tokens and, in a broken file, secret-like `name: value` pairs. A span inside
  // an edit is already covered; a span that crosses edits absorbs them, except a key that starts inside one.
  const spans: Array<{ start: number; end: number; pem?: true }> = [];
  if (text.includes('-----BEGIN')) for (const m of text.matchAll(PEM)) spans.push({ start: m.index, end: m.index + m[0].length, pem: true });
  // Every provider token is 15+ characters, so shorter words skip `findSecret`.
  for (const m of text.matchAll(/[^\s"'`,;<>]{15,}/g)) if (findSecret(m[0])) spans.push({ start: m.index, end: m.index + m[0].length });
  if (file.error) for (const p of inlinePairs(text)) spans.push(p); // no spread: 150k+ pairs overflow the stack
  spans.sort((a, b) => a.start - b.start || b.end - a.end);
  const ex = [...edits.values()].sort((a, b) => a.offset - b.offset);
  for (let i = 0, pos = 0, k = 0; k < spans.length; k++) {
    let { start: s, end: e } = spans[k]!;
    if (s < pos) continue;
    while (i < ex.length && ex[i]!.offset + ex[i]!.length <= s) i++;
    if (i < ex.length && ex[i]!.offset <= s && ex[i]!.offset + ex[i]!.length >= e) continue;
    // In a parsed file a key that starts inside an edit was masked with its node; with no END line it would run
    // to the end of the text. A broken file keeps the span: its node may hold only the BEGIN line.
    if (!file.error && spans[k]!.pem && i < ex.length && ex[i]!.offset <= s) continue;
    const raw = text.slice(s, e);
    for (; i < ex.length && ex[i]!.offset < e; i++) {
      s = Math.min(s, ex[i]!.offset);
      e = Math.max(e, ex[i]!.offset + ex[i]!.length);
      edits.delete(ex[i]!.offset);
    }
    edits.set(s, { offset: s, length: e - s, to: maskLines(text.slice(s, e)) });
    raws.push(raw);
    pos = e;
  }

  const sorted = [...edits.values()].sort((a, b) => a.offset - b.offset);
  const parts: string[] = [];
  const shift: number[] = []; // cumulative length change after each edit
  let pos = 0, delta = 0;
  for (const e of sorted) {
    parts.push(text.slice(pos, e.offset), e.to);
    pos = e.offset + e.length;
    delta += e.to.length - e.length;
    shift.push(delta);
  }
  parts.push(text.slice(pos));
  const out = parts.join('');
  const map = (o: number) => {
    let lo = 0, hi = sorted.length - 1, i = -1;
    while (lo <= hi) { const m = (lo + hi) >> 1; if (sorted[m]!.offset <= o) { i = m; lo = m + 1; } else hi = m - 1; }
    if (i < 0) return o;
    const e = sorted[i]!;
    const before = i ? shift[i - 1]! : 0;
    return o < e.offset + e.length ? e.offset + before : o + shift[i]!;
  };
  return { text: out, starts: lineStarts(out), map, raws: raws.filter((r) => r.length >= 6) };
}

const WIDTH = 160;

/**
 * Lines line-2 … line+2 of the redacted text; `hit` marks `line`. Each line is cut to the `clip`
 * range (the enclosing server or top-level setting, original offsets) and to WIDTH characters
 * around `at` (the hit's original offset); cuts are shown as `…`.
 */
export function excerpt(r: Redacted, line: number, at: number, clip?: { offset: number; length: number }): ExcerptLine[] {
  const lo = clip ? r.map(clip.offset) : 0;
  const hi = clip ? r.map(clip.offset + clip.length) : r.text.length;
  const atR = r.map(at);
  const out: ExcerptLine[] = [];
  const last = r.starts.length;
  for (let n = Math.max(1, line - 2); n <= Math.min(last, line + 2); n++) {
    const ls = r.starts[n - 1]!;
    let le = n < last ? r.starts[n]! - 1 : r.text.length;
    if (r.text[le - 1] === '\r') le--;
    let s = Math.max(ls, lo), e = Math.min(le, hi);
    if (s >= e) continue;
    // Indentation and a trailing comma are not worth a cut mark.
    if (/^\s*$/.test(r.text.slice(ls, s))) s = ls;
    if (/^[\s,]*$/.test(r.text.slice(e, le))) e = le;
    if (e - s > WIDTH) {
      if (n === line) s = Math.max(s, Math.min(atR - WIDTH / 2, e - WIDTH));
      e = s + WIDTH;
    }
    out.push({ line: n, text: (s > ls ? '…' : '') + r.text.slice(s, e) + (e < le ? '…' : ''), hit: n === line });
  }
  return out;
}
