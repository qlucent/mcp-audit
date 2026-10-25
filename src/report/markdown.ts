import type { AuditResult } from '../types.ts';

/** Config-derived text outside a fence: no links, images, HTML, table breaks or new lines. */
const esc = (s: string) => s.replace(/\s*[\r\n]+\s*/g, ' ').replace(/[\\`*_[\]()<>!|~#]/g, '\\$&');
/** A fence longer than any backtick run inside, so content cannot close it. */
const fence = (lines: string[]) => {
  const run = Math.max(2, ...lines.map((l) => Math.max(0, ...(l.match(/`+/g) ?? []).map((m) => m.length))));
  const f = '`'.repeat(run + 1);
  return [f, ...lines, f];
};

export function toMarkdown(result: AuditResult): string {
  const { verdict, findings } = result;
  const out = ['# MCP config audit', '', `**${verdict.text}**`, ''];
  for (const f of result.files) {
    if (f.error) out.push(`- Couldn't parse ${esc(f.file)} at line ${f.error.line}, column ${f.error.column}: ${esc(f.error.message)}`);
    else if (f.unrecognised) out.push(`- Couldn't recognise ${esc(f.file)} as an MCP config`);
  }
  if (out.length > 4) out.push('');
  if (findings.length) {
    out.push('| Severity | Rule | Location |', '| --- | --- | --- |');
    for (const f of findings) out.push(`| ${f.severity} | ${f.ruleId} | ${esc(f.file)}:${f.line}:${f.column} |`);
    out.push('');
  } else if (verdict.level === 'clear') {
    out.push("That doesn't make it safe: this checks the config, not what the servers' code does.", '');
  }
  for (const f of findings) {
    out.push(`## ${f.severity.toUpperCase()}: ${f.title}`, '', `${esc(f.file)}:${f.line}:${f.column} · [${f.ruleId}](${f.helpUri})`, '');
    if (f.detail) out.push(esc(f.detail), '');
    if (f.excerpt.length) out.push(...fence(f.excerpt.map((l) => `${l.hit ? '>' : ' '} ${l.line}: ${l.text}`)), '');
    else if (result.files.some((x) => x.file === f.file && x.error)) out.push("_Excerpt hidden: this file couldn't be fully parsed_", '');
    out.push('**Why it matters**', '', f.why, '', '**Fix**', '', ...fence(f.fix.split('\n')), '');
  }
  return out.join('\n');
}
