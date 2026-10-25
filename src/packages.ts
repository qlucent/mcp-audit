import { redactUrl } from './mask.ts';
import type { Server } from './types.ts';

export interface PackageRef { manager: 'npm' | 'pypi' | 'docker'; name: string; version?: string; tag?: string; digest?: string; source?: 'registry' | 'url'; argIndex: number }

const URLISH = /^(?:[a-z+]+:\/\/|git\+|github:|gitlab:|bitbucket:|file:|git@)/i;
const EXACT_NPM = /^v?=?\d+\.\d+\.\d+(?:[-+][\w.+-]*)?$/;
const NPM_VALUE_FLAGS = new Set(['--registry', '--prefix', '--cache', '--userconfig', '-c', '--call']);
const UV_VALUE_FLAGS = new Set(['--with', '--python', '-p', '--index', '--index-url', '--default-index', '--extra-index-url', '--with-requirements', '--env-file', '--directory', '--project']);
const DOCKER_VALUE_FLAGS = new Set(['-e', '--env', '-v', '--volume', '--name', '-p', '--publish', '-w', '--workdir', '-u', '--user', '--network', '--net', '--entrypoint', '--mount', '-l', '--label', '--env-file', '--platform', '--add-host', '-m', '--memory', '--cpus', '-h', '--hostname', '--pull', '--cap-add', '--cap-drop', '--device', '--tmpfs', '--restart', '--log-driver', '--security-opt', '--ulimit', '--gpus', '--group-add', '--dns', '--pid', '--ipc', '--shm-size', '--memory-swap', '--pids-limit', '--cpu-shares', '--stop-signal', '--userns', '--uts', '--cgroupns', '--sysctl', '--link', '--expose', '--ip', '--mac-address', '--health-cmd', '--runtime', '--storage-opt', '--cidfile', '--cpuset-cpus', '--dns-search', '--dns-option']);

const base = (c: string) => (c.split(/[\\/]/).pop() ?? '').replace(/\.(?:cmd|exe|bat|ps1)$/i, '').toLowerCase();

const LOCAL = /^(?:[./~]|[A-Za-z]:[\\/])/;

function npmSpec(spec: string, argIndex: number): PackageRef | null {
  if (LOCAL.test(spec)) return null;
  if (URLISH.test(spec) || /^[\w-][\w.-]*\/[\w.-]+$/.test(spec)) return { manager: 'npm', name: redactUrl(spec), source: 'url', argIndex };
  const at = spec.lastIndexOf('@');
  if (at <= 0) return { manager: 'npm', name: spec, source: 'registry', argIndex };
  const name = spec.slice(0, at), v = spec.slice(at + 1);
  // Only an exact x.y.z is a pin; dist-tags and ranges (^1, ~1.2, 1.x, 2) float, so keep them as `tag`.
  return { manager: 'npm', name, ...(EXACT_NPM.test(v) ? { version: v } : v ? { tag: v } : {}), source: 'registry', argIndex };
}

function pypiSpec(spec: string, argIndex: number): PackageRef | null {
  if (LOCAL.test(spec)) return null;
  if (URLISH.test(spec)) return { manager: 'pypi', name: redactUrl(spec), source: 'url', argIndex };
  const m = /^([A-Za-z0-9][\w.-]*(?:\[[^\]]*\])?)\s*(?:(===?)\s*(.+)|@(.+)|.+)?$/.exec(spec);
  if (!m) return { manager: 'pypi', name: spec, source: 'registry', argIndex };
  // Only == / === / @ with an exact version pins; ~=, >=, <, !=, ranges, wildcards and @latest do not.
  const v = (m[3] ?? m[4])?.trim();
  return { manager: 'pypi', name: m[1]!, ...(v && /^v?\d[\w.+!-]*$/.test(v) ? { version: v } : {}), source: 'registry', argIndex };
}

function dockerImage(spec: string, argIndex: number): PackageRef {
  const [rest, digest] = spec.split('@') as [string, string | undefined];
  const slash = rest.lastIndexOf('/');
  const colon = rest.indexOf(':', slash + 1);
  const name = colon < 0 ? rest : rest.slice(0, colon);
  const tag = colon < 0 ? undefined : rest.slice(colon + 1);
  return { manager: 'docker', name, ...(tag ? { tag } : {}), ...(digest ? { digest } : {}), source: 'registry', argIndex };
}

/** A `pick` flag (e.g. --from / --package) counts only before the first positional; everything after belongs to the server. */
function scan(args: string[], from: number, valueFlags: Set<string>, pick: string[]): { spec: string; i: number } | null {
  for (let i = from; i < args.length; i++) {
    const a = args[i]!;
    const eq = a.indexOf('=');
    const flag = a.startsWith('-') ? (eq > 0 ? a.slice(0, eq) : a) : '';
    if (pick.includes(flag)) {
      if (eq > 0) return { spec: a.slice(eq + 1), i };
      if (args[i + 1] !== undefined) return { spec: args[i + 1]!, i: i + 1 };
    } else if (flag) {
      if (eq < 0 && valueFlags.has(flag)) i++;
    } else return { spec: a, i };
  }
  return null;
}

export function parsePackageRef(server: Server): PackageRef | null {
  if (!server.command) return null;
  const cmd = base(server.command), args = server.args;
  const first = args[0]?.toLowerCase();
  let r;
  switch (cmd) {
    case 'npx': case 'bunx':
      r = scan(args, 0, NPM_VALUE_FLAGS, ['-p', '--package']);
      return r && npmSpec(r.spec, r.i);
    case 'pnpm': case 'yarn': case 'bun':
      if (first !== 'dlx' && !(cmd === 'bun' && first === 'x')) return null;
      r = scan(args, 1, NPM_VALUE_FLAGS, ['-p', '--package']);
      return r && npmSpec(r.spec, r.i);
    case 'uvx':
      r = scan(args, 0, UV_VALUE_FLAGS, ['--from']);
      return r && pypiSpec(r.spec, r.i);
    case 'pipx':
      if (first !== 'run') return null;
      r = scan(args, 1, UV_VALUE_FLAGS, ['--spec']);
      return r && pypiSpec(r.spec, r.i);
    case 'docker': case 'podman': {
      const at = first === 'run' ? 1 : first === 'container' && args[1] === 'run' ? 2 : -1;
      if (at < 0) return null;
      r = scan(args, at, DOCKER_VALUE_FLAGS, []);
      return r && dockerImage(r.spec, r.i);
    }
    default: return null;
  }
}
