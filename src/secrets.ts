const REFERENCE = [/^\$\{[^}]*\}$/, /^\$[A-Za-z_][A-Za-z0-9_]*$/, /^\{\{[^}]*\}\}$/];
/** True when the whole value is a variable reference such as ${env:X}, $X or {{X}}. */
export const isReference = (v: string): boolean => REFERENCE.some((r) => r.test(v));
const PROVIDERS: [string, RegExp][] = [
  ['github-token', /(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/],
  ['aws-access-key', /(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])/],
  ['slack-token', /(?<![A-Za-z0-9])xox[bpar]-[A-Za-z0-9-]{10,}/],
  ['anthropic-key', /(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{20,}/],
  ['openai-key', /(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{20,}/],
  ['stripe-key', /(?<![A-Za-z0-9])[sr]k_live_[A-Za-z0-9]{20,}/],
  ['google-api-key', /(?<![A-Za-z0-9])AIza[A-Za-z0-9_-]{35}/],
  ['private-key', /-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----/],
];
const SECRET_TOKENS = new Set(['token', 'secret', 'key', 'apikey', 'password', 'passwd', 'pwd', 'pat', 'auth', 'authorization', 'credential', 'credentials', 'bearer', 'pw']);
const NON_SECRET_LAST = new Set(['file', 'path', 'dir', 'url', 'uri', 'env', 'sock', 'socket', 'name', 'mode', 'type', 'arn', 'id', 'region', 'endpoint']);
// Template text such as "your-token-here", "<api key>" or "changeme"; whole words only, so random tokens are unaffected.
const PLACEHOLDER = /(?<![a-z0-9])(?:your|here|placeholder|changeme)(?![a-z0-9])|<[^<>]*>/i;
const PATH_OR_URL = /^[/~]|^[A-Za-z]:[\\/]|[/\\]|:\/\//;

/** Key-name words split on non-alphanumerics and camelCase: GITHUB_PAT -> github, pat; PATH -> path.
 * Shared by detection and redaction, so whatever a check treats as a secret name is also masked. */
export function secretLikeKey(key: string): boolean {
  const w = key.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  return w.some((x) => SECRET_TOKENS.has(x)) && !NON_SECRET_LAST.has(w[w.length - 1]!);
}

function entropy(s: string): number {
  const n = new Map<string, number>();
  for (const c of s) n.set(c, (n.get(c) ?? 0) + 1);
  let h = 0;
  for (const c of n.values()) h -= (c / s.length) * Math.log2(c / s.length);
  return h;
}

export function findSecret(value: string, keyName?: string): { kind: string } | null {
  const v = value.trim();
  if (isReference(v) || PLACEHOLDER.test(v)) return null;
  for (const [kind, re] of PROVIDERS) if (re.test(v)) return { kind };
  if (keyName && secretLikeKey(keyName) && v.length >= 16 && /\d/.test(v) && !/\s/.test(v) && !PATH_OR_URL.test(v) && entropy(v) >= 3.5) {
    return { kind: 'high-entropy' };
  }
  return null;
}

// The lookbehind starts a name only at a word boundary, so a long [\w.-] run is tried once, not at every
// offset (no quadratic backtracking). A quoted value may hold spaces and `\"` escapes; each try stops at the line end.
const PAIR_RE = /(?<![\w.-])-{0,2}([A-Za-z_][\w.-]*)(["']?\s*[=:]\s*(?:(?:bearer|basic|token)\s+)?)("(?:[^"\\\n]|\\.)+"|'(?:[^'\\\n]|\\.)+'|["']?[^\s"'`,;&|<>]+)/gi;
// `password hunter2hunter2`: a value of 8+ characters with a letter and a digit, so prose after a secret word is left alone.
const WORD_RE = /(?<![\w.-])-{0,2}([A-Za-z_][\w-]*)\s+(?=[^\s"'`,;&|<>]*\d)(?=[^\s"'`,;&|<>]*[A-Za-z])([^\s"'`,;&|<>]{8,})/gi;
// A value that is itself `Name:` / `Name=…` (`--header=Authorization: Bearer x`): scanned again once for its own pair.
const NESTED = /^["']?[A-Za-z_][\w.-]*["']?\s*[=:]/;

export interface Pair { name: string; value: string; start: number; end: number }

/** Secret-named `NAME=value`, `"NAME": "value"`, `Authorization: Bearer x` and `password value` pairs in free text, by value span. */
export function inlinePairs(s: string): Pair[] {
  const out: Pair[] = [];
  const push = (name: string, raw: string, at: number) => {
    const q = /^["']/.test(raw) ? 1 : 0;
    const value = raw.slice(q, q && raw.length > 1 && raw.endsWith(raw[0]!) ? -1 : undefined);
    out.push({ name, value, start: at + q, end: at + q + value.length });
  };
  const re = new RegExp(PAIR_RE);
  let nested = false;
  for (let m; (m = re.exec(s)); ) {
    const raw = m[3]!, at = m.index + m[0].length - raw.length;
    push(m[1]!, raw, at);
    // Depth 1 only, so `a=a=a=…` stays linear.
    if (!nested && !secretLikeKey(m[1]!) && NESTED.test(raw)) { re.lastIndex = at; nested = true; } else nested = false;
  }
  for (const m of s.matchAll(WORD_RE)) push(m[1]!, m[2]!, m.index + m[0].length - m[2]!.length);
  out.sort((a, b) => a.start - b.start);
  let end = -1;
  return out.filter((p) => secretLikeKey(p.name) && !isReference(p.value) && p.start >= end && ((end = p.end), true));
}
