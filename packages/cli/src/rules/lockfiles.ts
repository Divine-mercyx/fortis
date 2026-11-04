import { globToRegExp } from '../files';
import { lineOf, TEST_PATH } from './types';

/*
 * Reads the exact package versions a project uses, for any language. Each format gets a small
 * hand-written reader, so the CLI stays one dependency-free file. Ecosystem names are OSV's.
 */

export type Ecosystem = 'npm' | 'Packagist' | 'PyPI' | 'Maven' | 'Go' | 'NuGet' | 'RubyGems' | 'crates.io';
/** `line` is where the package sits in its file, or 0 where a reader can't tell (JSON formats). */
export type Locked = { name: string; version: string; ecosystem: Ecosystem; dev: boolean; line: number };
/** `skipped` counts declared packages with no exact version to check. */
export type Parsed = { packages: Locked[]; skipped: number };

const pkg = (ecosystem: Ecosystem, name: string, version: string, dev = false, line = 0): Locked => ({ name, version, ecosystem, dev, line });

function npmLock(text: string): Parsed {
  const lock = JSON.parse(text) as {
    packages?: Record<string, { name?: string; version?: string; dev?: boolean; link?: boolean }>;
    dependencies?: Record<string, { version: string; dev?: boolean }>;
  };
  const packages: Locked[] = [];
  if (lock.packages) {
    for (const [path, meta] of Object.entries(lock.packages)) {
      // Keys without node_modules/ are the project and its workspaces, not installed packages.
      const at = path.lastIndexOf('node_modules/');
      if (at === -1 || !meta.version || meta.link) continue;
      packages.push(pkg('npm', meta.name ?? path.slice(at + 'node_modules/'.length), meta.version, Boolean(meta.dev)));
    }
  } else if (lock.dependencies) {
    for (const [name, meta] of Object.entries(lock.dependencies)) packages.push(pkg('npm', name, meta.version, Boolean(meta.dev)));
  }
  return { packages, skipped: 0 };
}

const unquote = (s: string) => s.trim().replace(/^['"]|['"]$/g, '');
const withoutPeers = (id: string) => id.replace(/\(.*$/, '');

/** `name@range` → name; an alias `foo@npm:bar@^1` → bar. */
function yarnDescriptorName(descriptor: string): string {
  const at = descriptor.indexOf('@', 1);
  if (at === -1) return descriptor;
  return /^npm:(@?[^@]+)@/.exec(descriptor.slice(at + 1))?.[1] ?? descriptor.slice(0, at);
}

/**
 * Yarn classic and Berry: an unindented `"name@range", "name@range2":` line, then its fields.
 * The lockfile doesn't mark dev packages, so walk from package.json's run-time dependencies.
 * Without that file, or in a workspace root whose packages have their own, everything counts
 * as production: leaving a package out hides its vulnerabilities.
 */
function yarnLock(text: string, _file: string, sibling: Sibling): Parsed {
  const berry = /^__metadata:/m.test(text);
  type Node = Locked & { edges: string[] };
  const nodes = new Map<string, Node>();
  const byDescriptor = new Map<string, string>();

  let descriptors: string[] = [];
  let headLine = 0;
  let version = '';
  let resolution = '';
  let edges: string[] = [];
  let inDeps = false;
  const finish = () => {
    if (descriptors.length && /^\d/.test(version) && !/@(workspace|link|portal|file):/.test(`${descriptors.join()} ${resolution}`)) {
      const name = yarnDescriptorName(berry && resolution ? resolution : descriptors[0]!);
      const id = `${name}@${version}#${headLine}`;
      nodes.set(id, { ...pkg('npm', name, version, false, headLine), edges });
      for (const d of descriptors) byDescriptor.set(d, id);
    }
    descriptors = [];
    version = resolution = '';
    edges = [];
    inDeps = false;
  };
  text.split(/\r?\n/).forEach((line, i) => {
    if (line && !/^[\s#]/.test(line) && line.endsWith(':')) {
      finish();
      if (!line.startsWith('__metadata')) {
        descriptors = line.slice(0, -1).split(/,\s*/).map(unquote);
        headLine = i + 1;
      }
      return;
    }
    const child = inDeps ? /^ {4}("[^"]+"|[^\s:]+):? +(.+)$/.exec(line) : null;
    if (child) {
      edges.push(`${unquote(child[1]!)}@${unquote(child[2]!)}`);
      return;
    }
    if (/^ {2}\S/.test(line)) {
      inDeps = /^ {2}(dependencies|optionalDependencies):\s*$/.test(line);
      const f = /^ {2}(version|resolution):? +"?([^"]*)"?\s*$/.exec(line);
      if (f?.[1] === 'version') version = f[2]!;
      if (f?.[1] === 'resolution') resolution = f[2]!;
    }
  });
  finish();

  let manifest: { dependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; peerDependencies?: Record<string, string>; workspaces?: unknown } = {};
  try {
    manifest = JSON.parse(sibling('package.json') ?? '{}');
  } catch {
    /* no usable package.json: everything stays production */
  }
  const resolveDescriptor = (d: string) => {
    const at = d.indexOf('@', 1);
    return byDescriptor.get(d) ?? (at > 0 ? byDescriptor.get(`${d.slice(0, at)}@npm:${d.slice(at + 1)}`) : undefined);
  };
  const roots = Object.entries({ ...manifest.dependencies, ...manifest.optionalDependencies, ...manifest.peerDependencies }).map(([n, r]) => resolveDescriptor(`${n}@${r}`));
  const stack = roots.filter((r): r is string => Boolean(r));
  if (stack.length && !manifest.workspaces) {
    const production = new Set<string>();
    while (stack.length) {
      const id = stack.pop()!;
      if (production.has(id)) continue;
      production.add(id);
      for (const edge of nodes.get(id)?.edges ?? []) {
        const next = resolveDescriptor(edge);
        if (next) stack.push(next);
      }
    }
    for (const [id, node] of nodes) node.dev = !production.has(id);
  }
  return { packages: [...nodes.values()].map(({ edges: _edges, ...p }) => p), skipped: 0 };
}

/** A dependency's snapshot key. The version may instead be a link, or an alias's real `name@version`. */
function pnpmRef(name: string, version: string): string | null {
  if (version.startsWith('link:') || version.startsWith('workspace:')) return null;
  return /^@?[^@(]+@/.test(version) ? version : `${name}@${version}`;
}

/**
 * Lockfile v9 doesn't mark dev packages, so walk from what each workspace package needs at run
 * time. Returns the `name@version`s reached, or null if this lockfile can't say. A dev package
 * is only left out when we're sure, because leaving one out hides its vulnerabilities.
 */
function pnpmProduction(text: string): Set<string> | null {
  const RUNTIME = new Set(['dependencies', 'optionalDependencies']);
  const roots: string[] = [];
  const edges = new Map<string, string[]>();
  let section = '';
  let group = '';
  let dep = '';
  let snapshot: string[] | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) {
      section = line.replace(/:.*$/, '');
      continue;
    }
    if (section === 'importers') {
      const heading = /^ {4}(\w+):\s*$/.exec(line);
      const name = /^ {6}(\S.*?):\s*$/.exec(line);
      const version = /^ {8}version:\s*(.+)$/.exec(line);
      if (heading) group = heading[1]!;
      else if (name) dep = unquote(name[1]!);
      else if (version && RUNTIME.has(group)) {
        const ref = pnpmRef(dep, unquote(version[1]!));
        if (ref) roots.push(ref);
      }
    } else if (section === 'snapshots') {
      const key = /^ {2}(\S.*?):(?:\s*\{\})?\s*$/.exec(line);
      const heading = /^ {4}(\w+):\s*$/.exec(line);
      const edge = /^ {6}('[^']+'|"[^"]+"|[^\s:]+):\s*(.+)$/.exec(line);
      if (key) {
        snapshot = [];
        edges.set(unquote(key[1]!), snapshot);
      } else if (heading) group = heading[1]!;
      else if (edge && snapshot && RUNTIME.has(group)) {
        const ref = pnpmRef(unquote(edge[1]!), unquote(edge[2]!));
        if (ref) snapshot.push(ref);
      }
    }
  }
  if (!edges.size) return null; // older lockfiles carry their own `dev: true` markers
  if (roots.length && !roots.some((r) => edges.has(r))) return null; // a shape we didn't understand

  const production = new Set<string>();
  const seen = new Set<string>();
  const queue = [...roots];
  while (queue.length) {
    const id = queue.pop()!;
    if (seen.has(id) || !edges.has(id)) continue;
    seen.add(id);
    production.add(withoutPeers(id));
    queue.push(...edges.get(id)!);
  }
  return production;
}

/** Lockfile v6+ keys look like `name@1.2.3(peer@1)`, older ones like `/name/1.2.3_peer@1`. */
function pnpmLock(text: string): Parsed {
  const packages: Locked[] = [];
  let inPackages = false;
  let last: Locked | null = null;
  for (const [i, line] of text.split(/\r?\n/).entries()) {
    if (/^\S/.test(line)) {
      inPackages = line.startsWith('packages:');
      last = null;
      continue;
    }
    if (!inPackages) continue;
    const key = /^ {2}(\S.*):\s*$/.exec(line);
    if (key) {
      const id = withoutPeers(unquote(key[1]!).replace(/^\//, ''));
      const oldStyle = /^(@[^/@]+\/[^/@]+|[^/@]+)\/(\d[^/]*)$/.exec(id);
      const at = id.lastIndexOf('@');
      if (id.includes(':')) last = null; // file:, git and tarball installs
      else if (oldStyle) last = pkg('npm', oldStyle[1]!, oldStyle[2]!.replace(/_.*$/, ''), false, i + 1);
      else if (at > 0) last = pkg('npm', id.slice(0, at), id.slice(at + 1), false, i + 1);
      else last = null;
      if (last) packages.push(last);
    } else if (last && /^ {4}dev: true\s*$/.test(line)) {
      last.dev = true;
    }
  }
  const production = pnpmProduction(text);
  if (production) for (const p of packages) p.dev = !production.has(`${p.name}@${p.version}`);
  return { packages, skipped: 0 };
}

function composerLock(text: string): Parsed {
  const lock = JSON.parse(text) as { packages?: { name: string; version: string }[]; 'packages-dev'?: { name: string; version: string }[] };
  const packages: Locked[] = [];
  let skipped = 0;
  const add = (list: { name: string; version: string }[] | undefined, dev: boolean) => {
    for (const p of list ?? []) {
      // Branch installs (dev-main, 1.x-dev) have no release version to look up.
      if (/^dev-|-dev$/.test(p.version)) skipped++;
      else packages.push(pkg('Packagist', p.name, p.version, dev));
    }
  };
  add(lock.packages, false);
  add(lock['packages-dev'], true);
  return { packages, skipped };
}

const pypiName = (name: string) => name.toLowerCase().replace(/[-_.]+/g, '-');

/** poetry.lock and uv.lock: `[[package]]` tables. uv lists the project itself with an editable or virtual source. */
function tomlPythonLock(text: string): Parsed {
  const packages: Locked[] = [];
  const heads = [...text.matchAll(/^\[\[package\]\]\s*$/gm)];
  heads.forEach((head, i) => {
    const block = text.slice(head.index + head[0].length, heads[i + 1]?.index ?? text.length);
    const table = block.split(/^\[\[?(?!package\.)/m)[0]!;
    const name = /^name\s*=\s*"([^"]+)"/m.exec(table)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(table)?.[1];
    if (!name || !version || /^source\s*=\s*\{\s*(editable|virtual)\b/m.test(table)) return;
    packages.push(pkg('PyPI', pypiName(name), version, /^category\s*=\s*"dev"/m.test(table), lineOf(text, head.index)));
  });
  return { packages, skipped: 0 };
}

function pipfileLock(text: string): Parsed {
  const lock = JSON.parse(text) as { default?: Record<string, { version?: string }>; develop?: Record<string, { version?: string }> };
  const packages: Locked[] = [];
  let skipped = 0;
  const add = (section: Record<string, { version?: string }> | undefined, dev: boolean) => {
    for (const [name, meta] of Object.entries(section ?? {})) {
      if (meta.version?.startsWith('==')) packages.push(pkg('PyPI', pypiName(name), meta.version.slice(2), dev));
      else skipped++;
    }
  };
  add(lock.default, false);
  add(lock.develop, true);
  return { packages, skipped };
}

function requirementsTxt(text: string, file: string): Parsed {
  const dev = /dev|test/i.test(file.slice(file.lastIndexOf('/') + 1));
  const packages: Locked[] = [];
  let skipped = 0;
  for (const [i, raw] of text.split(/\r?\n/).entries()) {
    const line = raw.replace(/\s#.*$/, '').trim();
    // Options, includes, comments and the `--hash` lines that continue a requirement.
    if (!line || line.startsWith('#') || line.startsWith('-') || line.startsWith('\\')) continue;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;,\\]+)\s*(?:[;\\].*)?$/.exec(line);
    if (m) packages.push(pkg('PyPI', pypiName(m[1]!), m[2]!, dev, i + 1));
    else if (/^[A-Za-z0-9]/.test(line) && !line.includes('://')) skipped++;
  }
  return { packages, skipped };
}

/** `group:name:version=compileClasspath,runtimeClasspath`. */
function gradleLock(text: string): Parsed {
  const packages: Locked[] = [];
  for (const [i, line] of text.split(/\r?\n/).entries()) {
    const m = /^([^:#\s]+):([^:\s]+):([^=\s]+)=(.*)$/.exec(line.trim());
    if (!m) continue;
    const dev = m[4]!.split(',').every((conf) => /^test/i.test(conf.trim()));
    packages.push(pkg('Maven', `${m[1]}:${m[2]}`, m[3]!, dev, i + 1));
  }
  return { packages, skipped: 0 };
}

const xmlTag = (block: string, tag: string) => new RegExp(`<${tag}>\\s*([^<]*?)\\s*</${tag}>`).exec(block)?.[1];

/**
 * Direct dependencies only, read without running Maven: a version may come from this file's
 * properties or dependencyManagement. Anything from a parent POM or BOM is counted as skipped.
 */
function pomXml(text: string): Parsed {
  const xml = text.replace(/<!--[\s\S]*?-->/g, '');
  const props = new Map<string, string>();
  for (const block of xml.match(/<properties>[\s\S]*?<\/properties>/g) ?? []) {
    for (const m of block.matchAll(/<([\w.-]+)>\s*([^<]*?)\s*<\/\1>/g)) props.set(m[1]!, m[2]!);
  }
  const resolve = (v: string | undefined) => v?.replace(/\$\{([^}]+)\}/g, (all, k: string) => props.get(k) ?? all);

  const managed = new Map<string, string>();
  for (const block of xml.match(/<dependencyManagement>[\s\S]*?<\/dependencyManagement>/g) ?? []) {
    for (const dep of block.match(/<dependency>[\s\S]*?<\/dependency>/g) ?? []) {
      const version = resolve(xmlTag(dep, 'version'));
      if (version) managed.set(`${xmlTag(dep, 'groupId')}:${xmlTag(dep, 'artifactId')}`, version);
    }
  }

  // Plugin dependencies under <build> never reach the application.
  const used = xml.replace(/<dependencyManagement>[\s\S]*?<\/dependencyManagement>/g, '').replace(/<(build|reporting)>[\s\S]*?<\/\1>/g, '');
  const packages: Locked[] = [];
  let skipped = 0;
  for (const whole of used.match(/<dependency>[\s\S]*?<\/dependency>/g) ?? []) {
    const dep = whole.replace(/<exclusions>[\s\S]*?<\/exclusions>/, '');
    const name = `${resolve(xmlTag(dep, 'groupId'))}:${resolve(xmlTag(dep, 'artifactId'))}`;
    const version = resolve(xmlTag(dep, 'version')) ?? managed.get(name);
    if (!version || /[${[(,]/.test(version) || name.includes('$')) skipped++;
    else packages.push(pkg('Maven', name, version, xmlTag(dep, 'scope') === 'test'));
  }
  return { packages, skipped };
}

function goMod(text: string): Parsed {
  const packages: Locked[] = [];
  let inRequire = false;
  for (const [i, raw] of text.split(/\r?\n/).entries()) {
    const line = raw.replace(/\/\/.*$/, '').trim();
    if (/^require\s*\($/.test(line)) { inRequire = true; continue; }
    if (line === ')') { inRequire = false; continue; }
    const m = (inRequire ? /^(\S+)\s+(v\S+)$/ : /^require\s+(\S+)\s+(v\S+)$/).exec(line);
    if (m) packages.push(pkg('Go', m[1]!, m[2]!.replace(/\+incompatible$/, ''), false, i + 1));
  }
  return { packages, skipped: 0 };
}

function nugetLock(text: string): Parsed {
  const lock = JSON.parse(text) as { dependencies?: Record<string, Record<string, { type?: string; resolved?: string }>> };
  const seen = new Map<string, Locked>();
  for (const framework of Object.values(lock.dependencies ?? {})) {
    for (const [name, meta] of Object.entries(framework)) {
      if (meta.type !== 'Project' && meta.resolved) seen.set(`${name}@${meta.resolved}`, pkg('NuGet', name, meta.resolved));
    }
  }
  return { packages: [...seen.values()], skipped: 0 };
}

/** Top-level gems sit at four spaces under `specs:`; their own requirements are indented further. */
function gemfileLock(text: string): Parsed {
  const packages: Locked[] = [];
  let inGem = false;
  for (const [i, line] of text.split(/\r?\n/).entries()) {
    if (/^\S/.test(line)) inGem = line === 'GEM';
    const m = inGem ? /^ {4}(\S+) \(([^)-]+)(?:-[^)]*)?\)$/.exec(line) : null;
    if (m) packages.push(pkg('RubyGems', m[1]!, m[2]!, false, i + 1));
  }
  return { packages, skipped: 0 };
}

const PURL_TYPES: Record<string, Ecosystem> = {
  npm: 'npm', composer: 'Packagist', pypi: 'PyPI', maven: 'Maven', golang: 'Go', nuget: 'NuGet', gem: 'RubyGems', cargo: 'crates.io',
};

/** A package URL such as pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar. */
export function fromPurl(purl: string, dev = false): Locked | null {
  const m = /^pkg:([^/]+)\/(.+)@([^?#]+)/.exec(purl);
  const ecosystem = m && PURL_TYPES[m[1]!.toLowerCase()];
  if (!m || !ecosystem) return null;
  const path = decodeURIComponent(m[2]!);
  const version = decodeURIComponent(m[3]!);
  if (ecosystem === 'Maven') {
    const slash = path.lastIndexOf('/');
    return slash > 0 ? pkg(ecosystem, `${path.slice(0, slash)}:${path.slice(slash + 1)}`, version, dev) : null;
  }
  return pkg(ecosystem, ecosystem === 'PyPI' ? pypiName(path) : path, version, dev);
}

/** A CycloneDX JSON SBOM: the only format here that covers transitive Maven dependencies. */
export function cycloneDx(text: string): Parsed {
  type Component = { purl?: string; scope?: string; components?: Component[] };
  const bom = JSON.parse(text) as { bomFormat?: string; components?: Component[] };
  if (bom.bomFormat !== 'CycloneDX') throw new Error('not a CycloneDX JSON SBOM');
  const packages: Locked[] = [];
  let skipped = 0;
  const walk = (list: Component[] | undefined) => {
    for (const c of list ?? []) {
      const p = c.purl ? fromPurl(c.purl, c.scope === 'excluded') : null;
      if (p) packages.push(p);
      else skipped++;
      walk(c.components);
    }
  };
  walk(bom.components);
  return { packages, skipped };
}

/** Reads a file next to the lockfile, such as its package.json. */
export type Sibling = (name: string) => string | null;
type Format = { match: RegExp; ecosystem: Ecosystem; parse: (text: string, file: string, sibling: Sibling) => Parsed };

const REQUIREMENTS = /(^|\/)requirements[-_.\w]*\.txt$|(^|\/)requirements\/[-_.\w]+\.txt$/;

const FORMATS: Format[] = [
  { match: /(^|\/)(package-lock|npm-shrinkwrap)\.json$/, ecosystem: 'npm', parse: npmLock },
  { match: /(^|\/)yarn\.lock$/, ecosystem: 'npm', parse: yarnLock },
  { match: /(^|\/)pnpm-lock\.yaml$/, ecosystem: 'npm', parse: pnpmLock },
  { match: /(^|\/)composer\.lock$/, ecosystem: 'Packagist', parse: composerLock },
  { match: /(^|\/)(poetry|uv)\.lock$/, ecosystem: 'PyPI', parse: tomlPythonLock },
  { match: /(^|\/)Pipfile\.lock$/, ecosystem: 'PyPI', parse: pipfileLock },
  { match: REQUIREMENTS, ecosystem: 'PyPI', parse: requirementsTxt },
  { match: /(^|\/)([\w-]+-)?gradle\.lockfile$/, ecosystem: 'Maven', parse: gradleLock },
  { match: /(^|\/)pom\.xml$/, ecosystem: 'Maven', parse: pomXml },
  { match: /(^|\/)go\.mod$/, ecosystem: 'Go', parse: goMod },
  { match: /(^|\/)packages\.lock\.json$/, ecosystem: 'NuGet', parse: nugetLock },
  { match: /(^|\/)Gemfile\.lock$/, ecosystem: 'RubyGems', parse: gemfileLock },
];

export const isPomXml = (path: string) => /(^|\/)pom\.xml$/.test(path);

/** Project files that mean an ecosystem is in use, and how to get a lockfile Fortis can read. */
const MANIFESTS: { match: RegExp; ecosystem: Ecosystem; label: string; hint: string }[] = [
  { match: /(^|\/)package\.json$/, ecosystem: 'npm', label: 'package.json', hint: 'commit package-lock.json, yarn.lock or pnpm-lock.yaml' },
  { match: /(^|\/)composer\.json$/, ecosystem: 'Packagist', label: 'composer.json', hint: 'commit composer.lock' },
  { match: /(^|\/)(pyproject\.toml|Pipfile|setup\.py)$/, ecosystem: 'PyPI', label: 'Python project files', hint: 'commit poetry.lock, uv.lock, Pipfile.lock or a pinned requirements.txt' },
  { match: /(^|\/)build\.gradle(\.kts)?$/, ecosystem: 'Maven', label: 'build.gradle', hint: 'turn on Gradle dependency locking, or pass --sbom' },
  { match: /\.csproj$/, ecosystem: 'NuGet', label: '.csproj files', hint: 'set RestorePackagesWithLockFile, or pass --sbom' },
  { match: /(^|\/)Gemfile$/, ecosystem: 'RubyGems', label: 'Gemfile', hint: 'commit Gemfile.lock' },
];

/** Vendored and generated folders hold other people's manifests, not this project's. */
const VENDORED = /(^|\/)(node_modules|vendor|\.venv|venv|site-packages|target|dist|build|\.gradle)\//;

const relevant = (paths: string[], ignore: string[]) => {
  const ignored = ignore.map(globToRegExp);
  return paths.filter((p) => !VENDORED.test(p) && !TEST_PATH.test(p) && !ignored.some((re) => re.test(p)));
};

export function findLockfiles(paths: string[], ignore: string[] = []): string[] {
  const files = relevant(paths, ignore).filter((p) => FORMATS.some((f) => f.match.test(p)));
  // A real lock describes the same project more completely than a requirements file beside it.
  const projectDir = (p: string) => p.replace(/requirements\/[^/]+$|[^/]+$/, '');
  const pythonLocks = new Set(files.filter((p) => /(^|\/)(poetry\.lock|uv\.lock|Pipfile\.lock)$/.test(p)).map(projectDir));
  return files.filter((p) => !REQUIREMENTS.test(p) || !pythonLocks.has(projectDir(p)));
}

const formatOf = (file: string) => {
  const format = FORMATS.find((f) => f.match.test(file));
  if (!format) throw new Error('unknown format');
  return format;
};

export const parseLockfile = (file: string, text: string, sibling: Sibling = () => null): Parsed => formatOf(file).parse(text, file, sibling);
export const ecosystemOf = (file: string): Ecosystem => formatOf(file).ecosystem;

/** Ecosystems the project plainly uses but gave no versions for, so nothing was checked. */
export function missingLockfiles(paths: string[], ignore: string[], found: ReadonlySet<Ecosystem>): string[] {
  const files = relevant(paths, ignore);
  const bun = files.find((p) => /(^|\/)bun\.lockb?$/.test(p));
  return MANIFESTS.filter((m) => !found.has(m.ecosystem) && files.some((p) => m.match.test(p))).map((m) =>
    m.ecosystem === 'npm' && bun
      ? `${bun.slice(bun.lastIndexOf('/') + 1)} is not supported yet, so those dependencies weren't checked: use npm, pnpm or yarn lockfiles, or pass --sbom.`
      : `${m.label} found but no lockfile, so those dependencies weren't checked: ${m.hint}.`,
  );
}
