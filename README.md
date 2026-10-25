# @qlucent/mcp-audit

**Live: [qlucent.com/tools/mcp-audit](https://qlucent.com/tools/mcp-audit/?utm_source=github)**

Audits MCP and AI agent client configs (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Gemini CLI) for plaintext secrets, unpinned servers, shell execution, broad filesystem roots, plain-HTTP remotes, allow-all permissions and risky tool combinations. Same engine as the web page: https://qlucent.com/tools/mcp-audit/?utm_source=github

Nothing leaves your machine: no network calls, and secrets are masked in every output.

## Usage

```sh
npx @qlucent/mcp-audit                      # checks well-known config locations
npx @qlucent/mcp-audit .mcp.json .vscode/mcp.json
npx @qlucent/mcp-audit --format sarif --output mcp-audit.sarif
```

## Flags

- `--format table|md|sarif` output format (default `table`)
- `--output <file>` write the report to a file
- `--fail-on critical|high|medium|low|none` exit threshold (default `high`)
- `--help`, `--version`

## Exit codes

- `0` nothing at or above the threshold
- `1` findings at or above the threshold
- `2` usage error, no files found, no file recognised as an MCP config, every file failed to parse, or a file named on the command line failed to parse

## GitHub Actions

```yaml
jobs:
  mcp-audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # upload-sarif needs it
    steps:
      - uses: actions/checkout@v5
      - run: npx @qlucent/mcp-audit .mcp.json .vscode/mcp.json --format sarif --output mcp-audit.sarif --fail-on none
      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: mcp-audit.sarif
```

## Library use

The rule engine is a standalone TypeScript library, the same one the web page runs.

```ts
import { audit, toMarkdown } from '@qlucent/mcp-audit';

const result = audit([{ name: '.mcp.json', text: '{"mcpServers":{}}' }]);
console.log(toMarkdown(result));
```

## Repo layout

- `src/` is the engine, the checks and the CLI.
- `rules/` holds the auditor rules as YAML. `schemas/` validates them.
- `catalog/` lists the capabilities of well-known MCP servers.
- `test/` holds the unit tests.

## Develop

Requires Node >= 22.23.4.

```sh
npm install
npm run typecheck
npm run build
npm test
```

## Licence

[Apache-2.0](LICENSE). Built by [Qlucent](https://qlucent.com/?utm_source=github).
