import type { Check } from '../types.ts';
import { secretArgs, secretEnv, secretHeaders, secretUrl } from './secrets.ts';
import { dockerUnpinned, npxLatest, npxUnpinned, packageFromUrl, uvxUnpinned } from './supply-chain.ts';
import { dockerPrivileged, fsRoot, fsSensitivePath, remoteNoAuth, shellServer, unknownTransport } from './exec-fs-remote.ts';
import { dangerousMix } from './mix.ts';
import { autoApproveAll, bypassPermissions, broadPermissions } from './settings.ts';

export const checks: Record<string, Check> = {
  'secret-env': secretEnv,
  'secret-args': secretArgs,
  'secret-headers': secretHeaders,
  'secret-url': secretUrl,
  'npx-unpinned': npxUnpinned,
  'npx-latest': npxLatest,
  'uvx-unpinned': uvxUnpinned,
  'docker-unpinned': dockerUnpinned,
  'package-from-url': packageFromUrl,
  'shell-server': shellServer,
  'docker-privileged': dockerPrivileged,
  'fs-root': fsRoot,
  'remote-no-auth': remoteNoAuth,
  'unknown-transport': unknownTransport,
  'fs-sensitive-path': fsSensitivePath,
  'auto-approve-all': autoApproveAll,
  'bypass-permissions': bypassPermissions,
  'broad-permissions': broadPermissions,
  'dangerous-mix': dangerousMix,
};
