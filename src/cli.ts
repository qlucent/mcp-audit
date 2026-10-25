#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import { parseArgs } from 'node:util';
import { audit, toMarkdown, toSarif } from './index.ts';
import { toTable, clean, cleanBlock, unrecognisedNote } from './report/table.ts';
import { candidatePaths } from './discover.ts';
import type { Severity } from './types.ts';

const HELP = `Usage: mcp-audit [files...] [options]

Audits MCP / agent client configs. With no files, checks well-known config locations.
Runs locally; makes no network calls.

Options:
  --format table|md|sarif   output format (default table)
  --output <file>           write the report to a file instead of stdout
  --fail-on <level>         critical|high|medium|low|none (default high)
  --help, --version
`;

const parseErr = (f: { file: string; error?: { message: string; line: number; column: number } }) =>
  `mcp-audit: ${clean(f.file)}: couldn't parse at line ${f.error!.line}, column ${f.error!.column}: ${clean(f.error!.message)}`;

const rank: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };

function main(): number {
  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: {
        format: { type: 'string', default: 'table' },
        output: { type: 'string' },
        'fail-on': { type: 'string', default: 'high' },
        help: { type: 'boolean' },
        version: { type: 'boolean' },
      },
    });
  } catch (e) {
    console.error(`mcp-audit: ${clean((e as Error).message)}\n\n${HELP}`);
    return 2;
  }
  const { values, positionals } = parsed;
  const version: string = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
  if (values.help) { console.log(HELP); return 0; }
  if (values.version) { console.log(version); return 0; }
  const format = values.format!;
  const failOn = values['fail-on']!;
  if (!['table', 'md', 'sarif'].includes(format) || !['none', ...Object.keys(rank)].includes(failOn)) {
    console.error(`mcp-audit: invalid --format or --fail-on value\n\n${HELP}`);
    return 2;
  }
  // Progress notes must not corrupt machine-readable stdout.
  const note = format === 'table' && !values.output ? console.log : console.error;

  let paths = positionals;
  if (!paths.length) {
    const checked = candidatePaths({ platform: process.platform, home: os.homedir(), cwd: process.cwd(), appData: process.env.APPDATA });
    paths = [...new Set(checked)].filter((p) => fs.existsSync(p));
    if (!paths.length) {
      console.error(`mcp-audit: no MCP config files found. Locations checked:\n${checked.map((p) => `  ${clean(p)}`).join('\n')}\nPass file paths explicitly: mcp-audit <file...>`);
      return 2;
    }
  }
  const inputs = [];
  for (const p of paths) {
    try {
      inputs.push({ name: p, text: fs.readFileSync(p, 'utf8') });
      note(`Auditing ${clean(p)}`);
    } catch {
      console.error(`mcp-audit: skipping ${clean(p)} (cannot read)`);
    }
  }
  if (!inputs.length) { console.error('mcp-audit: no readable files'); return 2; }

  const result = audit(inputs);
  for (const f of result.files) {
    if (f.error) console.error(parseErr(f));
    else if (f.unrecognised) console.error(`mcp-audit: ${unrecognisedNote(f)}`);
  }
  // Nothing auditable: no report, usage-style exit.
  if (result.files.every((f) => f.error || f.unrecognised)) return 2;
  const color = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR && !values.output;
  const text = format === 'md' ? toMarkdown(result) : format === 'sarif' ? JSON.stringify(toSarif(result, version), null, 2) : toTable(result, color);
  if (values.output) {
    try {
      fs.writeFileSync(values.output, text + '\n');
    } catch (e) {
      console.error(`mcp-audit: cannot write ${clean(values.output)}: ${clean((e as Error).message)}`);
      return 2;
    }
    console.error(`mcp-audit: wrote ${clean(values.output)}`);
  } else console.log(format === 'table' ? text : cleanBlock(text)); // table fields are already clean()ed

  // A file named on the command line that could not be parsed fully is an error, whatever was found.
  if (positionals.length && result.files.some((f) => f.error)) return 2;
  return failOn !== 'none' && result.findings.some((f) => rank[f.severity] >= rank[failOn as Severity]) ? 1 : 0;
}

process.exitCode = main();
