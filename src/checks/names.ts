/** Named TS checks a rule may reference with `check:`. Later tasks add entries. */
export const KNOWN_CHECKS: string[] = [
  'secret-env', 'secret-args', 'secret-headers', 'secret-url',
  'npx-unpinned', 'npx-latest', 'uvx-unpinned', 'docker-unpinned', 'package-from-url',
  'shell-server', 'docker-privileged', 'fs-root', 'remote-no-auth', 'unknown-transport', 'fs-sensitive-path',
  'auto-approve-all', 'bypass-permissions', 'broad-permissions', 'dangerous-mix',
];
