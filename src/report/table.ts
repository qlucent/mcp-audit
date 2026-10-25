import type { AuditResult, FileSummary } from '../types.ts';

const color = { critical: 31, high: 31, medium: 33, low: 36 } as const;

/** Makes config-derived text safe for a terminal: control chars become visible \xNN. */
export function clean(s: string): string {
  return s.replace(/[\u0000-\u001f\u007f-\u009f]/g, (c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'));
}

/** Like clean(), but keeps line breaks and tabs: for whole multi-line reports written to a terminal. */
export function cleanBlock(s: string): string {
  return s.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, (c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'));
}

export const unrecognisedNote = (f: FileSummary) => `Couldn't recognise ${clean(f.file)} as an MCP config`;

/** Plain-text table. Colour only when the caller says the terminal supports it. */
export function toTable(result: AuditResult, useColor = false): string {
  const out: string[] = [];
  for (const f of result.findings) {
    const sev = f.severity.toUpperCase().padEnd(8);
    out.push(`${useColor ? `\x1b[${color[f.severity]}m${sev}\x1b[0m` : sev} ${clean(f.file)}:${f.line}  ${f.ruleId}  ${clean(f.title)}${f.server ? ` (${clean(f.server)})` : ''}`);
    out.push(`${' '.repeat(9)}${f.helpUri}`);
  }
  for (const f of result.files) {
    if (f.error) {
      const partial = result.findings.some((x) => x.file === f.file);
      out.push(`${partial ? 'PARSED WITH ERRORS' : 'NOT AUDITED'} ${clean(f.file)}: couldn't parse at line ${f.error.line}, column ${f.error.column}: ${clean(f.error.message)}`);
    } else if (f.unrecognised) out.push(unrecognisedNote(f));
  }
  if (out.length) out.push('');
  out.push(clean(result.verdict.text));
  if (result.verdict.level === 'clear') out.push("That doesn't make it safe: this checks the config, not what the servers' code does.");
  return out.join('\n');
}
