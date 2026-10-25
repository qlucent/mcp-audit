# Security policy

Please report vulnerabilities privately through [GitHub security advisories](https://github.com/qlucent/mcp-audit/security/advisories/new) rather than in public issues.

Anything that makes the CLI or library send data off the machine, or print a secret unmasked, is in scope and treated as high severity, because this tool promises that nothing leaves your machine and secrets are masked in every output.
