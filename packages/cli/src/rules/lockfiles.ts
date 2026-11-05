import { globToRegExp } from '../files';
import { parseNpmLock, parsePnpmLock, parseYarnLock, type LockedPackage } from './js-lockfiles';
import { lineOf, TEST_PATH } from './types';

/*
 * Reads the exact package versions a project uses, for any language. Each format gets a small
 * hand-written reader, so the CLI stays one dependency-free file. Ecosystem names are OSV's.
 */

export type Ecosystem = 'npm' | 'Packagist' | 'PyPI' | 'Maven' | 'Go' | 'NuGet' | 'RubyGems' | 'crates.io' | 'Pub';
/** `line`: where the package is in its lockfile (npm-family lockfiles), so findings point at it. */
export type Locked = { name: string; version: string; ecosystem: Ecosystem; dev: boolean; line?: number };
/** `skipped` counts declared packages with no exact version to check. */
export type Parsed = { packages: Locked[]; skipped: number };

const pkg = (ecosystem: Ecosystem, name: string, version: string, dev = false, line = 0): Locked => ({ name, version, ecosystem, dev, line });

/*
 * npm, pnpm and Yarn: the readers in js-lockfiles.ts. They are tested against real lockfiles from
 * npm 10, pnpm 8 and 10 (lockfile v5, v6, v9) and Yarn 1 and 4, record the line each package is on,
 * and work out dev-only packages, from the lockfile's own flag or, for pnpm v9 and Yarn, by walking
 * the dependency graph from package.json's production dependencies.
 */
const fromJs = (list: LockedPackage[]): Parsed => ({ packages: list.map((p) => ({ ...p, ecosystem: 'npm' as const })), skipped: 0 });
const npmLock = (text: string): Parsed => fromJs(parseNpmLock(text));
const pnpmLock = (text: string): Parsed => fromJs(parsePnpmLock(text));
const yarnLock = (text: string, _file: string, manifest?: string): Parsed => {
  let pkgJson = {};
  try {
    pkgJson = manifest ? JSON.parse(manifest) : {};
  } catch {
    /* no readable package.json: every package counts as production */
  }
  return fromJs(parseYarnLock(text, pkgJson));
};

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

/** Cargo.lock: `[[package]]` tables. Workspace crates have no `source`; git and path crates aren't on crates.io. */
function cargoLock(text: string): Parsed {
  const packages: Locked[] = [];
  let skipped = 0;
  const heads = [...text.matchAll(/^\[\[package\]\]\s*$/gm)];
  heads.forEach((head, i) => {
    const table = text.slice(head.index + head[0].length, heads[i + 1]?.index ?? text.length).split(/^\[/m)[0]!;
    const name = /^name\s*=\s*"([^"]+)"/m.exec(table)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(table)?.[1];
    const source = /^source\s*=\s*"([^"]+)"/m.exec(table)?.[1];
    if (!name || !version || !source) return; // the project's own crates
    if (!source.startsWith('registry+')) { skipped++; return; }
    packages.push(pkg('crates.io', name, version, false, lineOf(text, head.index)));
  });
  return { packages, skipped };
}

/** pubspec.lock (Dart and Flutter): one block per package under `packages:`, with its source and version. */
function pubspecLock(text: string): Parsed {
  const packages: Locked[] = [];
  let skipped = 0;
  let inPackages = false;
  let current: { name: string; line: number; dev: boolean; source?: string; version?: string } | null = null;
  const flush = () => {
    if (!current) return;
    if (current.source === 'hosted' && current.version) packages.push(pkg('Pub', current.name, current.version, current.dev, current.line));
    else if (current.source && current.source !== 'sdk') skipped++; // git and path packages
    current = null;
  };
  for (const [i, line] of text.split(/\r?\n/).entries()) {
    if (/^\S/.test(line)) { flush(); inPackages = line.startsWith('packages:'); continue; }
    if (!inPackages) continue;
    const name = /^ {2}("?)([\w.-]+)\1:\s*$/.exec(line);
    if (name) { flush(); current = { name: name[2]!, line: i + 1, dev: false }; continue; }
    if (!current) continue;
    const field = /^ {4}(dependency|source|version):\s*"?([^"]*)"?\s*$/.exec(line);
    if (field?.[1] === 'dependency') current.dev = /dev/.test(field[2]!);
    else if (field?.[1] === 'source') current.source = field[2]!;
    else if (field?.[1] === 'version') current.version = field[2]!;
  }
  flush();
  return { packages, skipped };
}

const PURL_TYPES: Record<string, Ecosystem> = {
  npm: 'npm', composer: 'Packagist', pypi: 'PyPI', maven: 'Maven', golang: 'Go', nuget: 'NuGet', gem: 'RubyGems', cargo: 'crates.io', pub: 'Pub',
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

/** `manifest`: the package.json beside the lockfile, which Yarn needs to tell dev-only packages apart. */
type Format = { match: RegExp; ecosystem: Ecosystem; parse: (text: string, file: string, manifest?: string) => Parsed };

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
  { match: /(^|\/)Cargo\.lock$/, ecosystem: 'crates.io', parse: cargoLock },
  { match: /(^|\/)pubspec\.lock$/, ecosystem: 'Pub', parse: pubspecLock },
];

export const isPomXml = (path: string) => /(^|\/)pom\.xml$/.test(path);

/** Project files that mean an ecosystem is in use, and how to get a lockfile Fortis can read. */
const MANIFESTS: { match: RegExp; ecosystem: Ecosystem; label: string; hint: string }[] = [
  { match: /(^|\/)package\.json$/, ecosystem: 'npm', label: 'package.json', hint: 'commit package-lock.json, yarn.lock or pnpm-lock.yaml (Bun lockfiles are not read yet)' },
  { match: /(^|\/)composer\.json$/, ecosystem: 'Packagist', label: 'composer.json', hint: 'commit composer.lock' },
  { match: /(^|\/)(pyproject\.toml|Pipfile|setup\.py)$/, ecosystem: 'PyPI', label: 'Python project files', hint: 'commit poetry.lock, uv.lock, Pipfile.lock or a pinned requirements.txt' },
  { match: /(^|\/)build\.gradle(\.kts)?$/, ecosystem: 'Maven', label: 'build.gradle', hint: 'turn on Gradle dependency locking, or pass --sbom' },
  { match: /\.csproj$/, ecosystem: 'NuGet', label: '.csproj files', hint: 'set RestorePackagesWithLockFile, or pass --sbom' },
  { match: /(^|\/)Gemfile$/, ecosystem: 'RubyGems', label: 'Gemfile', hint: 'commit Gemfile.lock' },
  { match: /(^|\/)Cargo\.toml$/, ecosystem: 'crates.io', label: 'Cargo.toml', hint: 'commit Cargo.lock' },
  { match: /(^|\/)pubspec\.yaml$/, ecosystem: 'Pub', label: 'pubspec.yaml', hint: 'commit pubspec.lock' },
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

export const parseLockfile = (file: string, text: string, manifest?: string): Parsed => formatOf(file).parse(text, file, manifest);
export const ecosystemOf = (file: string): Ecosystem => formatOf(file).ecosystem;

/** Ecosystems the project plainly uses but gave no versions for, so nothing was checked. */
/** Ecosystems we can't read yet: say so, so a scan of such a project doesn't look like a clean pass. */
const UNSUPPORTED: { match: RegExp; label: string }[] = [
  { match: /(^|\/)(Package\.swift|Package\.resolved)$/, label: 'Swift packages' },
  { match: /(^|\/)Podfile(\.lock)?$/, label: 'CocoaPods' },
  { match: /(^|\/)mix\.(exs|lock)$/, label: 'Elixir (mix)' },
];

export function missingLockfiles(paths: string[], ignore: string[], found: ReadonlySet<Ecosystem>): string[] {
  const files = relevant(paths, ignore);
  const missing = MANIFESTS.filter((m) => !found.has(m.ecosystem) && files.some((p) => m.match.test(p))).map((m) => `${m.label} found but no lockfile, so those dependencies weren't checked: ${m.hint}.`);
  const unsupported = UNSUPPORTED.filter((u) => files.some((p) => u.match.test(p))).map((u) => `${u.label} aren't checked for vulnerabilities yet.`);
  return [...missing, ...unsupported];
}
