import type { Ecosystem } from './lockfiles';

/*
 * Which version fixes a vulnerable package, and the command that installs it.
 *
 * OSV lists, per advisory, the versions where each affected range ends: affected[].ranges[].events[].fixed.
 * For one advisory the fix is the lowest of those above the installed version (a 1.x line and a 2.x
 * line can each have their own). To clear every advisory on the package, the upgrade has to reach the
 * highest of those per-advisory fixes.
 */

export type OsvAffected = {
  package?: { name?: string; ecosystem?: string };
  ranges?: { type?: string; events?: { introduced?: string; fixed?: string; last_affected?: string }[] }[];
};

/** Tags that sort before the release they precede: 1.0.0-rc.1 < 1.0.0, 2.0b1 < 2.0. */
const PRE_RELEASE = /^(dev|snapshot|alpha|a|beta|b|preview|pre|c|rc|cr|m|milestone)$/i;

const tokens = (v: string) =>
  v
    .trim()
    .replace(/^v(?=\d)/i, '')
    .replace(/\+.*$/, '') // build metadata never affects order
    .split(/[.\-_~]|(?<=\d)(?=[a-z])|(?<=[a-z])(?=\d)/i)
    .filter(Boolean);

/**
 * Orders versions across ecosystems well enough to pick a fix: numeric parts compare as numbers,
 * pre-release tags (alpha, beta, rc, dev…) sort before the release, anything else after it
 * (1.0.post1, 1.0.0.1 > 1.0.0). Returns <0, 0 or >0.
 */
export function compareVersions(a: string, b: string): number {
  const x = tokens(a);
  const y = tokens(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const p = x[i];
    const q = y[i];
    if (p === undefined) return PRE_RELEASE.test(q!) ? 1 : -1;
    if (q === undefined) return PRE_RELEASE.test(p) ? -1 : 1;
    const pn = /^\d+$/.test(p);
    const qn = /^\d+$/.test(q);
    if (pn && qn) {
      const d = Number(p) - Number(q);
      if (d) return d;
      continue;
    }
    if (pn !== qn) return pn ? (PRE_RELEASE.test(q) ? 1 : -1) : PRE_RELEASE.test(p) ? -1 : 1;
    const c = p.toLowerCase().localeCompare(q.toLowerCase());
    if (c) return c;
  }
  return 0;
}

/**
 * Semantic Versioning order, for Go: everything after `-` is a pre-release, so the pseudo-version
 * v1.2.4-0.20240101120000-abcdef123456 comes before v1.2.4, and v0.0.0-2024…-abcdef before anything.
 */
export function compareSemver(a: string, b: string): number {
  const split = (v: string) => {
    const t = v.trim().replace(/^v/i, '').replace(/\+.*$/, '');
    const dash = t.indexOf('-');
    return { core: (dash === -1 ? t : t.slice(0, dash)).split('.').map(Number), pre: dash === -1 ? null : t.slice(dash + 1).split('.') };
  };
  const x = split(a);
  const y = split(b);
  for (let i = 0; i < Math.max(x.core.length, y.core.length); i++) {
    const d = (x.core[i] ?? 0) - (y.core[i] ?? 0);
    if (d) return d;
  }
  if (!x.pre || !y.pre) return x.pre ? -1 : y.pre ? 1 : 0;
  for (let i = 0; i < Math.max(x.pre.length, y.pre.length); i++) {
    const p = x.pre[i];
    const q = y.pre[i];
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    const pn = /^\d+$/.test(p);
    const qn = /^\d+$/.test(q);
    if (pn && qn && Number(p) !== Number(q)) return Number(p) - Number(q);
    if (pn !== qn) return pn ? -1 : 1;
    if (!pn && p !== q) return p < q ? -1 : 1;
  }
  return 0;
}

/** How to order this ecosystem's versions. */
export const versionOrder = (eco: Ecosystem): ((a: string, b: string) => number) => (eco === 'Go' ? compareSemver : compareVersions);

/** PyPI names compare case-insensitively with -, _ and . treated alike (PEP 503). */
const sameName = (eco: Ecosystem, a: string, b: string) =>
  eco === 'PyPI' ? a.toLowerCase().replace(/[-_.]+/g, '-') === b.toLowerCase().replace(/[-_.]+/g, '-') : eco === 'NuGet' ? a.toLowerCase() === b.toLowerCase() : a === b;

/** The lowest version above `installed` that one advisory says is fixed, or null if it has none. */
export function advisoryFix(affected: OsvAffected[] | undefined, eco: Ecosystem, name: string, installed: string): string | null {
  const fixes = (affected ?? [])
    .filter((a) => !a.package?.name || (a.package.ecosystem?.split(':')[0] === eco && sameName(eco, a.package.name, name)))
    .flatMap((a) => a.ranges ?? [])
    .filter((r) => r.type !== 'GIT')
    .flatMap((r) => r.events ?? [])
    .map((e) => e.fixed)
    .filter((f): f is string => Boolean(f) && versionOrder(eco)(f!, installed) > 0)
    .sort(versionOrder(eco));
  return fixes[0] ?? null;
}

/**
 * The version that clears every advisory, or null when at least one has no fix yet. `partial` is the
 * version that clears the ones that do have a fix; `unfixed` names the ones that don't.
 */
export function fixedVersion(
  advisories: { id: string; affected?: OsvAffected[] }[],
  eco: Ecosystem,
  name: string,
  installed: string,
): { version: string | null; partial: string | null; unfixed: string[] } {
  let best: string | null = null;
  const unfixed: string[] = [];
  for (const a of advisories) {
    const f = advisoryFix(a.affected, eco, name, installed);
    if (!f) unfixed.push(a.id);
    else if (!best || versionOrder(eco)(f, best) > 0) best = f;
  }
  return { version: unfixed.length ? null : best, partial: best, unfixed };
}

/** The command that moves `name` to `version`, picked from the lockfile that listed it. */
export function upgradeCommand(file: string, eco: Ecosystem, name: string, version: string, direct = true): string {
  const base = file.split('/').pop() ?? file;
  switch (eco) {
    case 'npm':
      if (base === 'pnpm-lock.yaml') return direct ? `pnpm up ${name}@${version}` : `pnpm up -r ${name}`;
      if (base === 'yarn.lock') return direct ? `yarn up ${name}@${version}` : `yarn up -R ${name}`;
      if (/^bun\.lockb?$/.test(base)) return direct ? `bun add ${name}@${version}` : `bun update ${name}`;
      return direct ? `npm install ${name}@${version}` : `npm update ${name}`;
    case 'Packagist':
      return direct ? `composer require ${name}:^${version}` : `composer update ${name} --with-dependencies`;
    case 'PyPI':
      if (base === 'poetry.lock') return `poetry add "${name}>=${version}"`;
      if (base === 'uv.lock') return `uv add "${name}>=${version}"`;
      if (base === 'Pipfile.lock') return `pipenv install "${name}>=${version}"`;
      return `set ${name}==${version} in ${base}`;
    case 'crates.io':
      return `cargo update -p ${name} --precise ${version}`;
    case 'Go':
      return `go get ${name}@${version.startsWith('v') ? version : `v${version}`}`;
    case 'RubyGems':
      return `bundle update ${name} --conservative`;
    case 'NuGet':
      return `dotnet add package ${name} --version ${version}`;
    case 'Maven':
      return `set ${name} to ${version} in ${base}`;
    case 'Pub':
      return `dart pub add ${name}:^${version}`;
  }
}

type FixTarget = { file: string; ecosystem: Ecosystem; name: string; version: string; direct?: boolean; via?: string };

/** The text after "fix" for one vulnerable package. */
export function fixMessage(p: FixTarget, fix: { version: string | null; partial: string | null; unfixed: string[] }): string {
  const indirect = p.direct === false;
  const through = indirect ? ` ${p.name} comes in through ${p.via ?? 'another dependency'}; if the command doesn't move it, upgrade ${p.via ?? 'that dependency'}.` : '';
  if (fix.version) return `Upgrade to ${fix.version}: ${upgradeCommand(p.file, p.ecosystem, p.name, fix.version, !indirect)}.${through}`;
  const which = fix.unfixed.length === 1 ? fix.unfixed[0] : `${fix.unfixed.length} of its advisories`;
  const others = fix.partial ? ` Upgrading to ${fix.partial} (${upgradeCommand(p.file, p.ecosystem, p.name, fix.partial, !indirect)}) clears the rest.` : '';
  const where = indirect ? ` ${p.name} comes in through ${p.via ?? 'another dependency'}; a newer version of that may drop it.` : ' Check the advisory for a workaround, or replace the package.';
  return `No fixed version yet for ${which}.${others}${where}`;
}
