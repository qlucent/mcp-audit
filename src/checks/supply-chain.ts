import type { PackageRef } from '../packages.ts';
import type { Check, Hit } from '../types.ts';
import { packageOf } from './exec-fs-remote.ts';

// Names of URL sources come from parsePackageRef with credentials already removed.
const make = (test: (p: PackageRef) => boolean, detail: (p: PackageRef) => string): Check => (ctx) =>
  ctx.normalized.servers.flatMap((s): Hit[] => {
    const pk = packageOf(s);
    if (!pk || !test(pk.ref)) return [];
    const field = pk.field(pk.ref.argIndex);
    return [{ file: s.file, loc: s.fieldLocs[field] ?? s.loc, server: s.name, field, value: s.args[Number(field.slice(5))], detail: detail(pk.ref) }];
  });

const registry = (p: PackageRef) => p.source !== 'url';

export const npxUnpinned = make((p) => p.manager === 'npm' && registry(p) && !p.version && !p.tag, (p) => `${p.name} has no version`);
export const npxLatest = make((p) => p.manager === 'npm' && registry(p) && !!p.tag, (p) => `${p.name}@${p.tag} is a moving tag or range, not an exact version`);
export const uvxUnpinned = make((p) => p.manager === 'pypi' && registry(p) && !p.version, (p) => `${p.name} has no version`);
export const dockerUnpinned = make((p) => p.manager === 'docker' && !p.digest && (!p.tag || p.tag === 'latest'), (p) => `${p.name} has no pinned tag or digest`);
export const packageFromUrl = make((p) => p.source === 'url', (p) => `${p.name} is installed from a URL, not a registry release`);
