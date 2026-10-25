# Contributing

Thanks for helping. Before you open a PR:

1. `npm run typecheck && npm run build && npm test` must pass.
2. The engine must not make network requests.
3. Keep dependencies minimal and pinned to exact versions. Say why you need any new dependency in the PR.
4. Use conventional commit messages (`feat:`, `fix:`, `docs:` and so on).

## Adding a rule

Add `rules/<id>.yaml`. `schemas/rule.schema.json` checks it. Fields:

- `id`: lowercase words joined by hyphens. Match the file name.
- `title`, `severity` (`critical`, `high`, `medium` or `low`). Keep severity conservative. False positives cost more than misses.
- `applies_to`: `servers`, `settings` or `groups`.
- `why`: why it matters. `fix`: what to change instead.
- `references`: a list of public `http(s)` URLs.
- `fixtures`: see below.
- Exactly one of `match` or `check`.

**`match`** is declarative. Use it when one regex over one field is enough:

- `target`: `command`, `args`, `env`, `headers` or `url`.
- `pattern`: the regex. `flags`: any of `i`, `m`, `s`, `u`.
- `key_pattern`: only look at keys that match (for `env` and `headers`).
- `not_pattern`: skip values that match.

**`check`** names a TypeScript check. Use it when you need logic. Write the function in `src/checks/`, add it to the `checks` map in `src/checks/index.ts`, and add its name to `KNOWN_CHECKS` in `src/checks/names.ts`. Then set `check: <name>` in the rule.

**Fixtures** are required: at least one under `fixtures.fail` (the rule must fire) and at least one under `fixtures.pass` (it must not). Each is `{ config, file? }`: `config` (required) is the parsed config; `file` (optional) is the file name it is audited as, e.g. `.claude/settings.json`, and defaults to a pasted file. Use fake secrets only (`ghp_EXAMPLE...`, `AKIAEXAMPLE...`). `npm test` runs every fixture automatically.

### Catalogue entries

`catalog/servers.yaml` says what well-known MCP servers can do. It feeds the risky-combination rule. Use public READMEs and docs only, and leave out anything unclear. Format (`schemas/catalog.schema.json` checks it):

```yaml
- id: fetch
  match: { pypi: [mcp-server-fetch], docker: [mcp/fetch] }  # also npm: [...] and url: [...]
  label: reads untrusted web pages
  caps: [untrusted_input, outbound]
```

`caps` may use `untrusted_input`, `outbound`, `private_data`, `code_exec` and `writes`.

## Reporting a false positive

Open a [false positive issue](https://github.com/qlucent/mcp-audit/issues/new?template=false-positive.md). Give the rule id, the smallest input that triggers it (with fake values in place of real secrets and hostnames) and why it is safe.
