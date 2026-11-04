import { globToRegExp } from '../files';
import { TEST_PATH } from './types';

/*
 * Reads the exact package versions a project uses, for any language. Each format gets a small
 * hand-written reader, so the CLI stays one dependency-free file. Ecosystem names are OSV's.
 */

export type Ecosystem = 'npm' | 'Packagist' | 'PyPI' | 'Maven' | 'Go' | 'NuGet' | 'RubyGems' | 'crates.io';
export type Locked = { name: string; version: string; ecosystem: Ecosystem; dev: boolean };
/** `skipped` counts declared packages with no exact version to check. */
export type Parsed = { packages: Locked[]; skipped: number };

const pkg = (ecosystem: Ecosystem, name: string, version: string, dev = false): Locked => ({ name, version, ecosystem, dev });

function npmLock(text: string): Parsed {
  const lock = JSON.parse(text) as {
    packages?: Record<string, { version?: string; dev?: boolean; link?: boolean }>;
    dependencies?: Record<string, { version: string; dev?: boolean }>;
  };
  const packages: Locked[] = [];
  if (lock.packages) {
    for (const [path, meta] of Object.entries(lock.packages)) {
      // Keys without node_modules/ are the project and its workspaces, not installed packages.
      const at = path.lastIndexOf('node_modules/');
      if (at === -1 || !meta.version || meta.link) continue;
      packages.push(pkg('npm', path.slice(at + 'node_modules/'.length), meta.version, Boolean(meta.dev)));
    }
  } else if (lock.dependencies) {
    for (const [name, meta] of Object.entries(lock.dependencies)) packages.push(pkg('npm', name, meta.version, Boolean(meta.dev)));
  }
  return { packages, skipped: 0 };
}

/** Yarn classic and Berry: an unindented `"name@range", "name@range2":` line, then its version. */
function yarnLock(text: string): Parsed {
  const packages: Locked[] = [];
  let name: string | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (line && !/^[\s#]/.test(line) && line.endsWith(':')) {
      const first = line.slice(0, -1).split(',')[0]!.trim().replace(/^"|"$/g, '');
      const at = first.indexOf('@', 1);
      name = at > 0 && !first.includes('@workspace:') ? first.slice(0, at) : null;
      continue;
    }
    const m = name && /^\s+version:?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (m) {
      packages.push(pkg('npm', name!, m[1]!));
      name = null;
    }
  }
  return { packages, skipped: 0 };
}

/** Lockfile v6+ keys look like `name@1.2.3(peer@1)`, older ones like `/name/1.2.3`. v9 has no dev marker here. */
function pnpmLock(text: string): Parsed {
  const packages: Locked[] = [];
  let inPackages = false;
  let last: Locked | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) {
      inPackages = line.startsWith('packages:');
      last = null;
      continue;
    }
    if (!inPackages) continue;
    const key = /^ {2}(\S.*):\s*$/.exec(line);
    if (key) {
      const id = key[1]!.replace(/^['"]|['"]$/g, '').replace(/^\//, '').replace(/\(.*$/, '').replace(/_.*$/, '');
      const at = id.lastIndexOf('@');
      const slash = id.lastIndexOf('/');
      if (id.includes(':')) last = null; // file:, git and tarball installs
      else if (at > 0) last = pkg('npm', id.slice(0, at), id.slice(at + 1));
      else if (slash > 0) last = pkg('npm', id.slice(0, slash), id.slice(slash + 1));
      else last = null;
      if (last) packages.push(last);
    } else if (last && /^ {4}dev: true\s*$/.test(line)) {
      last.dev = true;
    }
  }
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
  for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const table = block.split(/^\[\[?(?!package\.)/m)[0]!;
    const name = /^name\s*=\s*"([^"]+)"/m.exec(table)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(table)?.[1];
    if (!name || !version || /^source\s*=\s*\{\s*(editable|virtual)\b/m.test(table)) continue;
    packages.push(pkg('PyPI', pypiName(name), version, /^category\s*=\s*"dev"/m.test(table)));
  }
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
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s#.*$/, '').trim();
    // Options, includes, comments and the `--hash` lines that continue a requirement.
    if (!line || line.startsWith('#') || line.startsWith('-') || line.startsWith('\\')) continue;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;,\\]+)\s*(?:[;\\].*)?$/.exec(line);
    if (m) packages.push(pkg('PyPI', pypiName(m[1]!), m[2]!, dev));
    else if (/^[A-Za-z0-9]/.test(line) && !line.includes('://')) skipped++;
  }
  return { packages, skipped };
}

/** `group:name:version=compileClasspath,runtimeClasspath`. */
function gradleLock(text: string): Parsed {
  const packages: Locked[] = [];
  for (const line of text.split(/\r?\n/)) {
    const m = /^([^:#\s]+):([^:\s]+):([^=\s]+)=(.*)$/.exec(line.trim());
    if (!m) continue;
    const dev = m[4]!.split(',').every((conf) => /^test/i.test(conf.trim()));
    packages.push(pkg('Maven', `${m[1]}:${m[2]}`, m[3]!, dev));
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
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\/\/.*$/, '').trim();
    if (/^require\s*\($/.test(line)) { inRequire = true; continue; }
    if (line === ')') { inRequire = false; continue; }
    const m = (inRequire ? /^(\S+)\s+(v\S+)$/ : /^require\s+(\S+)\s+(v\S+)$/).exec(line);
    if (m) packages.push(pkg('Go', m[1]!, m[2]!.replace(/\+incompatible$/, '')));
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
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) inGem = line === 'GEM';
    const m = inGem ? /^ {4}(\S+) \(([^)-]+)(?:-[^)]*)?\)$/.exec(line) : null;
    if (m) packages.push(pkg('RubyGems', m[1]!, m[2]!));
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

type Format = { match: RegExp; ecosystem: Ecosystem; parse: (text: string, file: string) => Parsed };

const REQUIREMENTS = /(^|\/)requirements[-_.\w]*\.txt$|(^|\/)requirements\/[-_.\w]+\.txt$/;

const FORMATS: Format[] = [
  { match: /(^|\/)package-lock\.json$/, ecosystem: 'npm', parse: npmLock },
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

export const parseLockfile = (file: string, text: string): Parsed => formatOf(file).parse(text, file);
export const ecosystemOf = (file: string): Ecosystem => formatOf(file).ecosystem;

/** Ecosystems the project plainly uses but gave no versions for, so nothing was checked. */
export function missingLockfiles(paths: string[], ignore: string[], found: ReadonlySet<Ecosystem>): string[] {
  const files = relevant(paths, ignore);
  return MANIFESTS.filter((m) => !found.has(m.ecosystem) && files.some((p) => m.match.test(p))).map((m) => `${m.label} found but no lockfile, so those dependencies weren't checked: ${m.hint}.`);
}
