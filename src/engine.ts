import data from './generated/data.json' with { type: 'json' };
import { parseFile } from './parse.ts';
import { normalize } from './normalize.ts';
import { checks } from './checks/index.ts';
import { findMixes } from './checks/mix.ts';
import { findNodeAtOffset, type Node } from 'jsonc-parser';
import { mask, redact, excerpt, type Redacted } from './mask.ts';
import type {
  AuditResult, CatalogEntry, CheckContext, Finding, Fixture, Hit, InputFile, Rule, Server, Severity, Verdict,
} from './types.ts';

export const rules = data.rules as (Rule & { fixtures: { fail: Fixture[]; pass: Fixture[] } })[];
const catalog = data.catalog as CatalogEntry[];

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

/** `recognised` is false when no input was recognised and parsed, so "no findings" means nothing was checked; `why` then replaces the default text. */
export function computeVerdict(findings: Finding[], rulesChecked: number, recognised = true, why?: string): Verdict {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity]++;
  const list = ORDER.filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`).join(', ');
  if (counts.critical || counts.high) return { level: 'not-ready', text: `Not ready to roll out: ${list}`, counts };
  if (list) return { level: 'review', text: `Review before rollout: ${list}`, counts };
  if (!recognised) return { level: 'unrecognised', text: why ?? "Couldn't recognise any input as an MCP config", counts };
  return { level: 'clear', text: `None of the ${rulesChecked} rules matched this config`, counts };
}

function matchRule(rule: Rule, servers: Server[]): Hit[] {
  const m = rule.match!;
  const re = new RegExp(m.pattern, m.flags);
  const not = m.not_pattern ? new RegExp(m.not_pattern, m.flags) : undefined;
  const keyRe = m.key_pattern ? new RegExp(m.key_pattern, m.flags) : undefined;
  const ok = (v: string) => re.test(v) && !not?.test(v);
  const hits: Hit[] = [];
  for (const s of servers) {
    const add = (field: string, value: string) =>
      hits.push({ file: s.file, loc: s.fieldLocs[field] ?? s.loc, server: s.name, field, value });
    if (m.target === 'command' || m.target === 'url') {
      const v = s[m.target];
      if (v !== undefined && ok(v)) add(m.target, v);
    } else if (m.target === 'args') {
      s.args.forEach((a, i) => ok(a) && add(`args.${i}`, a));
    } else {
      for (const [k, v] of Object.entries(s[m.target])) {
        if ((!keyRe || keyRe.test(k)) && ok(v)) add(`${m.target}.${k}`, v);
      }
    }
  }
  return hits;
}

/** The node an excerpt may show: the enclosing server entry, else the enclosing top-level setting. */
function clipNode(tree: Node | undefined, offset: number): Node | undefined {
  let top: Node | undefined;
  for (let n = tree && findNodeAtOffset(tree, offset); n?.parent; n = n.parent) {
    if (n.type !== 'property') continue;
    const container = n.parent?.parent;
    const ck = container?.type === 'property' ? container.children?.[0]?.value : undefined;
    if (ck === 'mcpServers' || ck === 'servers') return n;
    if (n.parent === tree) top = n;
  }
  return top;
}

export function audit(inputs: InputFile[]): AuditResult {
  // Per-file state is keyed by name, so make names unique first: mcp.json, mcp.json (2), ...
  const seen = new Map<string, number>();
  const files = inputs.map((i) => {
    const n = (seen.get(i.name) ?? 0) + 1;
    seen.set(i.name, n);
    return parseFile(n > 1 ? { ...i, name: `${i.name} (${n})` } : i);
  });
  const normalized = normalize(files);
  const ctx: CheckContext = { normalized, files, catalog };
  const ruleHits = rules.map((rule) => ({
    rule, hits: rule.match ? matchRule(rule, normalized.servers) : (checks[rule.check!]?.(ctx, rule) ?? []),
  }));
  // Redact after the checks, so the value of every secret hit is masked wherever it sits. Other rules'
  // values (package specs, commands, URLs) stay readable apart from what the structural redaction hides.
  const isSecret = (id: string) => id.startsWith('secret-');
  const valued = ruleHits.filter((r) => isSecret(r.rule.id)).flatMap((r) => r.hits).filter((h) => h.value !== undefined);
  const redacted = new Map<string, Redacted>(files.map((f) => [f.file,
    redact(f, valued.filter((h) => h.file === f.file).map((h) => ({ offset: h.loc.offset, length: h.loc.length, value: h.value! })))]));
  const trees = new Map(files.map((f) => [f.file, f.tree]));
  const fileText = new Map(files.map((f) => [f.file, f.text]));
  // No excerpt for a file that failed to parse: masking can't be trusted where the structure is unknown.
  const brokenFiles = new Set(files.filter((f) => f.error).map((f) => f.file));
  // Backstop: a detail never repeats a value the redactor hid. Raws (6+ characters) are indexed by their first
  // 6 characters, so a scrub costs the length of the string, not the number of raws. Overlapping hits merge
  // into one mask.
  const K = 6;
  const scrubbers = new Map([...redacted].map(([file, r]) => {
    const idx = new Map<string, string[]>();
    for (const raw of new Set(r.raws)) {
      const list = idx.get(raw.slice(0, K));
      if (list) list.push(raw); else idx.set(raw.slice(0, K), [raw]);
    }
    return [file, idx];
  }));
  const scrub = (file: string, s: string | undefined) => {
    const idx = scrubbers.get(file);
    if (!s || !idx?.size) return s;
    let out = '', pos = 0, cs = -1, ce = -1;
    const flush = () => { if (cs >= 0) out += s.slice(pos, cs) + mask(s.slice(cs, ce)), pos = ce; };
    for (let i = 0; i + K <= s.length; i++) {
      for (const raw of idx.get(s.slice(i, i + K)) ?? []) {
        if (!s.startsWith(raw, i)) continue;
        if (i >= ce) { flush(); cs = i; ce = i + raw.length; } else ce = Math.max(ce, i + raw.length);
      }
    }
    flush();
    return out + s.slice(pos);
  };
  // A non-secret value as the redacted file shows it at its own location, else scrubbed.
  const shown = (r: Redacted, h: Hit) => {
    try {
      if (JSON.parse(fileText.get(h.file)!.slice(h.loc.offset, h.loc.offset + h.loc.length)) === h.value)
        return String(JSON.parse(r.text.slice(r.map(h.loc.offset), r.map(h.loc.offset + h.loc.length))));
    } catch { /* not a plain string node */ }
    return scrub(h.file, h.value);
  };

  const findings: Finding[] = [];
  for (const { rule, hits } of ruleHits) {
    for (const h of hits) {
      const r = redacted.get(h.file)!;
      const clip = clipNode(trees.get(h.file), h.loc.offset);
      findings.push({
        ruleId: rule.id,
        severity: h.severity ?? rule.severity,
        title: rule.title,
        // A non-secret detail names its own subject (a package, a path): scrub it only when the redactor
        // hid part of that subject, so masks raised elsewhere in the file (comments, flags) don't eat it.
        detail: isSecret(rule.id) || h.value === undefined || shown(r, h) !== h.value ? scrub(h.file, h.detail) : h.detail,
        file: h.file,
        line: h.loc.line,
        column: h.loc.column,
        server: h.server,
        servers: h.servers,
        field: h.field,
        evidence: h.value ? (isSecret(rule.id) ? mask(h.value) : shown(r, h)) : undefined,
        excerpt: brokenFiles.has(h.file) ? [] : excerpt(r, h.loc.line, h.loc.offset, clip),
        why: rule.why,
        fix: rule.fix,
        helpUri: `https://qlucent.com/tools/mcp-audit/rules/${rule.id}`,
      });
    }
  }
  findings.sort((a, b) =>
    ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity) || a.file.localeCompare(b.file) || a.line - b.line);
  const summaries = files.map((f) => ({
    file: f.file,
    client: f.client,
    servers: normalized.servers.filter((s) => s.file === f.file).length,
    error: f.error,
    ...(f.client === null && !f.error ? { unrecognised: true } : {}),
  }));
  const partly = summaries.some((f) => f.error && f.servers);
  const why = summaries.map((f) => !f.error ? `${f.file} isn't recognised as an MCP config`
    : f.servers ? `Only part of ${f.file} could be read (parse error at line ${f.error.line}); none of the ${rules.length} rules matched the part that was read`
    : `${f.file} couldn't be parsed`).join('; ');
  const verdict = computeVerdict(findings, rules.length, files.some((f) => f.client !== null && !f.error), partly ? why : `Couldn't check any input: ${why}`);
  const broken = summaries.filter((f) => f.error).length;
  if (verdict.level !== 'unrecognised' && broken) verdict.text += ` (${broken} file${broken === 1 ? '' : 's'} couldn't be fully parsed)`;
  return {
    files: summaries,
    findings,
    verdict,
    mixes: findMixes(ctx).mixes,
    rulesChecked: rules.length,
  };
}
