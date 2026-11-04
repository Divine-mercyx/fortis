import type { Locked, Parsed } from './lockfiles';
import { lineOf } from './types';

/*
 * Python's lockfiles: poetry.lock, uv.lock, pdm.lock, pylock.toml, Pipfile.lock and requirements
 * files. Line readers, because these are machine-written and the CLI stays dependency-free.
 *
 * Telling dev packages apart matters: a vulnerable test tool shouldn't block a push. When a file
 * can't say, a package counts as production, because leaving one out hides its vulnerabilities.
 */

export const pypiName = (name: string) => name.toLowerCase().replace(/[-_.]+/g, '-');

const pypi = (name: string, version: string, dev = false, line = 0): Locked => ({ name: pypiName(name), version, ecosystem: 'PyPI', dev, line });

type Block = {
  name: string;
  version: string;
  line: number;
  /** The project itself, or a workspace member: uv lists these with an editable or virtual source. */
  isProject: boolean;
  /** The keys before the first sub-table. */
  top: string;
  /** Everything up to the next package, sub-tables included. */
  whole: string;
};

/** Every `[[package]]` (or pylock's `[[packages]]`) table, with its own sub-tables. */
function blocks(text: string, heading: 'package' | 'packages'): Block[] {
  const heads = [...text.matchAll(new RegExp(`^\\[\\[${heading}\\]\\]\\s*$`, 'gm'))];
  const out: Block[] = [];
  heads.forEach((head, i) => {
    const start = head.index + head[0].length;
    const raw = text.slice(start, heads[i + 1]?.index ?? text.length);
    const whole = raw.split(/^\[(?!\[?packages?\.)/m)[0]!;
    const top = whole.split(/^\[/m)[0]!;
    const name = /^name\s*=\s*"([^"]+)"/m.exec(top)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(top)?.[1];
    if (!name) return;
    const isProject = /^source\s*=\s*\{\s*(editable|virtual)\b/m.test(top);
    if (!version && !isProject) return;
    out.push({ name, version: version ?? '', line: lineOf(text, head.index), isProject, top, whole });
  });
  return out;
}

/** The text of `key = [ ... ]`, which may span lines and hold nested arrays. */
function tomlArray(text: string, key: string): string {
  const m = new RegExp(`^${key}\\s*=\\s*\\[`, 'm').exec(text);
  if (!m) return '';
  let depth = 1;
  let i = m.index + m[0].length;
  const start = i;
  for (; i < text.length && depth > 0; i++) {
    if (text[i] === '[') depth++;
    else if (text[i] === ']') depth--;
  }
  return text.slice(start, i - 1);
}

/** The lines of one `[section]`, up to the next table. */
function tomlSection(text: string, section: string): string {
  const escaped = section.replace(/[.\-]/g, '\\$&');
  const m = new RegExp(`^\\[${escaped}\\]\\s*$`, 'm').exec(text);
  if (!m) return '';
  const rest = text.slice(m.index + m[0].length);
  return rest.split(/^\[/m)[0]!;
}

/** Package names in an array of `{ name = "x" }` tables or of `"x>=1"` requirement strings. */
function namesIn(array: string): string[] {
  const tables = [...array.matchAll(/\bname\s*=\s*"([^"]+)"/g)].map((m) => m[1]!);
  if (tables.length) return tables;
  return [...array.matchAll(/["']\s*([A-Za-z0-9][A-Za-z0-9._-]*)/g)].map((m) => m[1]!);
}

const sectionKeys = (section: string) => [...section.matchAll(/^"?([A-Za-z0-9][A-Za-z0-9._-]*)"?\s*=/gm)].map((m) => m[1]!);

/** Packages this one needs: uv and PDM's `dependencies = [...]`, or Poetry's `[package.dependencies]`. */
function edgesOf(block: Block): string[] {
  return [...namesIn(tomlArray(block.top, 'dependencies')), ...sectionKeys(tomlSection(block.whole, 'package.dependencies'))].map(pypiName);
}

/** The names reachable from `roots`, or null if the walk finds nothing, so nothing gets marked dev by mistake. */
function reachable(all: Block[], roots: string[]): Set<string> | null {
  const byName = new Map(all.map((b) => [pypiName(b.name), b]));
  const stack = roots.map(pypiName).filter((r) => byName.has(r));
  if (!stack.length) return null;
  const seen = new Set<string>();
  while (stack.length) {
    const name = stack.pop()!;
    if (seen.has(name)) continue;
    seen.add(name);
    stack.push(...edgesOf(byName.get(name)!));
  }
  return seen;
}

/** What a project needs at run time, from pyproject.toml. Dev groups aren't listed in these tables. */
function pyprojectRoots(manifest: string): string[] {
  const poetry = sectionKeys(tomlSection(manifest, 'tool.poetry.dependencies')).filter((k) => k.toLowerCase() !== 'python');
  const project = namesIn(tomlArray(tomlSection(manifest, 'project'), 'dependencies'));
  const extras = tomlSection(manifest, 'project.optional-dependencies');
  return [...poetry, ...project, ...sectionKeys(extras).flatMap((k) => namesIn(tomlArray(extras, k)))];
}

/** poetry.lock, uv.lock and pdm.lock: `[[package]]` tables. `manifest` is the pyproject.toml beside the lockfile. */
export function tomlPythonLock(text: string, _file: string, manifest?: string): Parsed {
  const all = blocks(text, 'package');
  const installed = all.filter((b) => !b.isProject);
  const groupsOf = (b: Block) => /^groups\s*=/m.test(b.top) ? namesIn(tomlArray(b.top, 'groups')).map((g) => g.toLowerCase()) : null;

  let isDev: (b: Block) => boolean = () => false;
  if (installed.some((b) => groupsOf(b))) {
    // Poetry 2 and PDM list the groups that need each package.
    isDev = (b) => {
      const groups = groupsOf(b);
      return Boolean(groups) && !groups!.includes('main') && !groups!.includes('default');
    };
  } else if (installed.some((b) => /^category\s*=/m.test(b.top))) {
    // Poetry before 1.5.
    isDev = (b) => /^category\s*=\s*"dev"/m.test(b.top);
  } else {
    // uv, and Poetry 1.5 to 1.8: neither marks dev packages, so walk from what production needs.
    const projects = all.filter((b) => b.isProject);
    const roots = projects.length
      ? projects.flatMap((p) => {
          const extras = tomlSection(p.whole, 'package.optional-dependencies');
          return [...edgesOf(p), ...sectionKeys(extras).flatMap((k) => namesIn(tomlArray(extras, k)))];
        })
      : manifest
        ? pyprojectRoots(manifest)
        : [];
    const production = reachable(installed, roots);
    if (production) isDev = (b) => !production.has(pypiName(b.name));
  }
  return { packages: installed.map((b) => pypi(b.name, b.version, isDev(b), b.line)), skipped: 0 };
}

/** pylock.toml (PEP 751): `[[packages]]` tables. Packages from version control have no version to check. */
export function pylockToml(text: string): Parsed {
  const heads = [...text.matchAll(/^\[\[packages\]\]\s*$/gm)].length;
  const packages = blocks(text, 'packages').map((b) => pypi(b.name, b.version, false, b.line));
  return { packages, skipped: heads - packages.length };
}

export function pipfileLock(text: string): Parsed {
  const lock = JSON.parse(text) as { default?: Record<string, { version?: string }>; develop?: Record<string, { version?: string }> };
  const packages: Locked[] = [];
  let skipped = 0;
  const add = (section: Record<string, { version?: string }> | undefined, dev: boolean) => {
    for (const [name, meta] of Object.entries(section ?? {})) {
      if (meta.version?.startsWith('==')) packages.push(pypi(name, meta.version.slice(2), dev));
      else skipped++;
    }
  };
  add(lock.default, false);
  add(lock.develop, true);
  return { packages, skipped };
}

/** Output of pip-compile or `uv pip compile` lists every package, not only the direct ones. */
const FULLY_COMPILED = /#\s+via\b|autogenerated by pip-compile|uv pip compile|--hash=/;

export function requirementsTxt(text: string, file: string): Parsed {
  const base = file.slice(file.lastIndexOf('/') + 1);
  const dev = /dev|test/i.test(base);
  const packages: Locked[] = [];
  let skipped = 0;
  for (const [i, raw] of text.split(/\r?\n/).entries()) {
    const line = raw.replace(/\s#.*$/, '').trim();
    // Options, includes, comments and the `--hash` lines that continue a requirement.
    if (!line || line.startsWith('#') || line.startsWith('-') || line.startsWith('\\')) continue;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;,\\]+)\s*(?:[;\\].*)?$/.exec(line);
    // `django==3.2.*` doesn't name one version, so there's nothing exact to look up.
    if (m && !m[2]!.includes('*')) packages.push(pypi(m[1]!, m[2]!, dev, i + 1));
    else if (/^[A-Za-z0-9]/.test(line) && !line.includes('://')) skipped++;
  }
  const directOnly = packages.length > 0 && !/^constraints/i.test(base) && !FULLY_COMPILED.test(text);
  return { packages, skipped, directOnly };
}
