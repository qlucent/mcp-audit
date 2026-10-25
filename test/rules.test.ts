import { test } from 'node:test';
import assert from 'node:assert/strict';
import { audit, rules } from '../src/engine.ts';

for (const r of rules) {
  const run = (f: { file?: string; config: unknown }) =>
    audit([{ name: f.file ?? 'pasted-1', text: JSON.stringify(f.config, null, 2) }]).findings.filter((x) => x.ruleId === r.id);
  r.fixtures.fail.forEach((f, i) =>
    test(`${r.id} fail #${i + 1}`, () => assert.ok(run(f).length >= 1)));
  r.fixtures.pass.forEach((f, i) =>
    test(`${r.id} pass #${i + 1}`, () => assert.equal(run(f).length, 0)));
}
