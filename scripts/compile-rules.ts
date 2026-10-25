// Compiles rules/*.yaml and catalog/servers.yaml into src/generated/data.json.
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename } from 'node:path';
import { Ajv } from 'ajv';
import { parse } from 'yaml';
import { KNOWN_CHECKS } from '../src/checks/names.ts';

// scripts/ -> repo root
const root = new URL('../', import.meta.url);
const readJson = (p: string) => JSON.parse(readFileSync(new URL(p, root), 'utf8'));
const ajv = new Ajv({ allErrors: true, strict: false });
const vRule = ajv.compile(readJson('schemas/rule.schema.json'));
const vCatalog = ajv.compile(readJson('schemas/catalog.schema.json'));

const errors: string[] = [];
const fmt = (file: string, errs: typeof vRule.errors) =>
  (errs ?? []).forEach((e) => errors.push(`${file}: ${e.instancePath || '/'} ${e.message}`));
const load = (file: string) => {
  try {
    return parse(readFileSync(new URL(file, root), 'utf8'));
  } catch (e) {
    errors.push(`${file}: ${(e as Error).message}`);
  }
};

interface R { id: string; check?: string; match?: { pattern: string; flags?: string; key_pattern?: string; not_pattern?: string } }
const rules: unknown[] = [];
for (const name of readdirSync(new URL('rules/', root)).filter((f) => f.endsWith('.yaml')).sort()) {
  const file = `rules/${name}`;
  const rule = load(file);
  if (rule === undefined) continue;
  if (!vRule(rule)) { fmt(file, vRule.errors); continue; }
  const r = rule as R;
  if (r.id !== basename(name, '.yaml')) errors.push(`${file}: id "${r.id}" must equal the filename`);
  if (r.check && !KNOWN_CHECKS.includes(r.check)) errors.push(`${file}: unknown check "${r.check}"`);
  for (const k of ['pattern', 'key_pattern', 'not_pattern'] as const) {
    const p = r.match?.[k];
    if (p) {
      try { new RegExp(p, r.match?.flags); } catch (e) { errors.push(`${file}: match.${k}: ${(e as Error).message}`); }
    }
  }
  rules.push(rule);
}

const catalog = load('catalog/servers.yaml') ?? [];
if (!vCatalog(catalog)) fmt('catalog/servers.yaml', vCatalog.errors);

if (errors.length) {
  console.error(errors.join('\n'));
  process.exit(1);
}
const out = new URL('../src/generated/', import.meta.url);
mkdirSync(out, { recursive: true });
writeFileSync(new URL('data.json', out), JSON.stringify({ rules, catalog }, null, 2) + '\n');
console.log(`compiled ${rules.length} rules, ${(catalog as unknown[]).length} catalog entries`);
