import { parsePackageRef, type PackageRef } from '../packages.ts';
import { isReference } from '../secrets.ts';
import type { Check, Hit, Server } from '../types.ts';

const each = (ctx: Parameters<Check>[0], f: (s: Server) => Hit[]): Hit[] => ctx.normalized.servers.flatMap(f);
const hit = (s: Server, field: string, detail: string): Hit => ({
  file: s.file, loc: s.fieldLocs[field] ?? s.loc, server: s.name, field,
  value: field.startsWith('args.') ? s.args[Number(field.slice(5))] : undefined, detail,
});
const base = (c: string) => (c.split(/[\\/]/).pop() ?? '').replace(/\.(?:cmd|exe|bat|ps1)$/i, '').toLowerCase();

const SHELLS = new Set(['bash', 'sh', 'zsh', 'cmd', 'powershell', 'pwsh']);
const INTERPRETERS = new Set(['node', 'python', 'python3', 'bun', 'deno']);
const INLINE_LONG = /^(?:-e|--eval|-p|--print|-c|-r|--require|--import|--loader)(?:=|$)/i;
const INLINE_CLUSTER = /^-[a-z]*[epc][a-z]*$/i;
const RUNNERS = new Set(['npx', 'bunx', 'pnpm', 'yarn']);
// Only the launcher's own options count: stop at the first positional (script, module or package),
// so the launched program's flags (`node app.js -p 3000`) are not mistaken for inline code.
const runsInline = (launcher: string, rest: string[]): boolean => {
  const own: string[] = [];
  let j = 0;
  for (; j < rest.length && rest[j].startsWith('-'); j++) {
    own.push(rest[j]);
    if (/^python3?$/.test(launcher) && rest[j] === '-m') return false;
    if (RUNNERS.has(launcher) && /^(?:-p|--package)$/i.test(rest[j])) j++; // skip the option's value
  }
  if (INTERPRETERS.has(launcher))
    return own.some((t) => INLINE_LONG.test(t) || (t.length >= 3 && INLINE_CLUSTER.test(t))) || (launcher === 'deno' && rest[j]?.toLowerCase() === 'eval');
  return RUNNERS.has(launcher) && own.some((t) => /^(?:-c|--call)(?:=|$)/i.test(t));
};
const LAUNCHERS = new Set(['npx', 'uvx', 'pipx', 'node', 'python', 'python3', 'docker', 'podman', 'bunx', 'bun', 'pnpm', 'yarn', 'deno']);
const SHELL_PKG = /(shell|terminal|exec|command-runner|run-command)/i;

/** For `cmd /c …`, `bash -c "…"` etc.: the payload words, and whether it is a plain launcher call (no chaining, no inline code). */
export function shellPayload(s: Server): { index: number; words: string[]; plain: boolean; inline: boolean } | null {
  if (!s.command || !SHELLS.has(base(s.command))) return null;
  const index = s.args.findIndex((a) => /^(?:-c|\/c|-command)$/i.test(a));
  if (index < 0) return null;
  const payload = s.args.slice(index + 1).join(' ').trim();
  const words = payload.split(/\s+/);
  // `%VAR%` / `$VAR` expansion is not chaining (ruling R13), so `%` is not a metacharacter here.
  const plain = !(base(s.command) === 'cmd' ? /[;&|`<>\n^]|\$[({]/ : /[;&|`<>\n]|\$[({]/).test(payload);
  return { index, words, plain, inline: runsInline(base(words[0] ?? ''), words.slice(1)) };
}
/** A wrapped plain launcher call (e.g. `cmd /c npx -y pkg`) read as the server's own command and args. */
export function unwrapLauncher(s: Server): Server | null {
  const w = shellPayload(s);
  if (!w || !w.plain || w.inline || !LAUNCHERS.has(base(w.words[0] ?? ''))) return null;
  const [command, ...args] = w.words.map((t) => t.replace(/^(["'])(.*)\1$/, '$2'));
  return { ...s, command, args };
}

/**
 * The package a server runs, looking through a wrapper such as `cmd /c npx …`. `args` are the
 * launcher's args; `field(i)` maps args[i] to the server's own field (the `/c` when words and args don't line up).
 */
export function packageOf(s: Server): { ref: PackageRef; args: string[]; field: (i: number) => string } | null {
  const ref = parsePackageRef(s);
  if (ref) return { ref, args: s.args, field: (i) => `args.${i}` };
  const u = unwrapLauncher(s);
  const wref = u && parsePackageRef(u);
  if (!u || !wref) return null;
  const w = shellPayload(s)!;
  const oneEach = s.args.length - w.index - 1 === w.words.length;
  // Words and args do not line up (one payload string): point at the payload, not the `/c`.
  return { ref: wref, args: u.args, field: (i) => `args.${oneEach ? w.index + 2 + i : w.index + 1}` };
}

export const shellServer: Check = (ctx) =>
  each(ctx, (s) => {
    // A shell wrapper around a known launcher (e.g. `cmd /c npx ...`) is the normal Windows setup, not a shell server.
    const w = shellPayload(s);
    if (w && !unwrapLauncher(s)) return [hit(s, `args.${w.index}`, `${base(s.command!)} ${s.args[w.index]} runs arbitrary shell commands`)];
    const p = packageOf(s);
    return p && p.ref.manager !== 'docker' && SHELL_PKG.test(p.ref.name) ? [hit(s, p.field(p.ref.argIndex), `${p.ref.name} looks like a shell or command-execution server`)] : [];
  });

export const dockerPrivileged: Check = (ctx) =>
  each(ctx, (s) => {
    if (!s.command || !['docker', 'podman'].includes(base(s.command))) return [];
    const out: Hit[] = [];
    s.args.forEach((a, i) => {
      const prev = s.args[i - 1] ?? '';
      let why = '';
      if (/^--privileged(?:=true)?$/i.test(a)) why = 'runs privileged';
      else if (/^--(?:net|network)=host$/i.test(a) || (a === 'host' && /^--(?:net|network)$/i.test(prev))) why = 'uses the host network';
      else if (/docker\.sock/.test(a)) why = 'mounts the Docker socket';
      else if (/^(?:-v|--volume)=\/:/.test(a) || (/^\/:/.test(a) && /^(?:-v|--volume)$/.test(prev))) why = 'mounts the host root';
      else if (/^--cap-add=SYS_ADMIN$/i.test(a) || (/^SYS_ADMIN$/i.test(a) && prev === '--cap-add')) why = 'adds SYS_ADMIN';
      if (why) out.push(hit(s, `args.${i}`, `container ${why}`));
    });
    return out;
  });

const SENSITIVE_DIR = /(?:^|[\\/])(?:\.ssh|\.aws|\.gnupg|\.kube)(?:[\\/:]|$)|\.config[\\/]gcloud|\.docker[\\/]config\.json/i;
const DOTENV = /\.env$/i;

export const fsSensitivePath: Check = (ctx) =>
  each(ctx, (s) =>
    s.args.flatMap((a, i) =>
      SENSITIVE_DIR.test(a) || (DOTENV.test(a) && s.args[i - 1]?.toLowerCase() !== '--env-file' && !/^--env-file=/i.test(a))
        ? [hit(s, `args.${i}`, 'path to credentials or secrets')] : []));

const ROOT = /^(?:\/|~|\$HOME|\$\{(?:env:)?HOME\}|\$\{userHome\}|%USERPROFILE%|[A-Za-z]:|\/Users\/[^/\\]+|\/home\/[^/\\]+)[\\/]?$/;

export const fsRoot: Check = (ctx) =>
  each(ctx, (s) => {
    const p = packageOf(s);
    if (!p || !/filesystem/i.test(p.ref.name)) return [];
    return p.args.flatMap((a, i) => (i > p.ref.argIndex && ROOT.test(a) ? [hit(s, p.field(i), `${p.ref.name} is given ${a}`)] : []));
  });

const LOCAL_URL = /^[a-z][a-z0-9+.-]*:\/\/(?:localhost|127(?:\.\d+){3}|\[::1\]|0\.0\.0\.0)(?:[:/?#]|$)/i;
const AUTH_KEY = /auth|api[-_]?key|token|secret|bearer/i;

export const remoteNoAuth: Check = (ctx) =>
  each(ctx, (s) => {
    if (!s.url || LOCAL_URL.test(s.url)) return [];
    const authed = Object.entries(s.headers).some(([k, v]) => AUTH_KEY.test(k) || isReference(v.replace(/^\w+\s+/, '')));
    return authed ? [] : [hit(s, 'url', 'no authentication header or credential reference')];
  });

export const unknownTransport: Check = (ctx) =>
  each(ctx, (s) => (s.command || s.url ? [] : [{ file: s.file, loc: s.loc, server: s.name, detail: 'no command or url' }]));
