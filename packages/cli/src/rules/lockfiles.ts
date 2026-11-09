import { globToRegExp } from '../files';
import { parseNpmLock, parsePnpmLock, parseYarnLock, type LockedPackage } from './js-lockfiles';
import { pipfileLock, pylockToml, pypiName, requirementsTxt, tomlPythonLock } from './python-lockfiles';
import { lineOf, TEST_PATH } from './types';

/*
 * Reads the exact package versions a project uses, for any language. Each format gets a small
 * hand-written reader, so the CLI stays one dependency-free file. Ecosystem names are OSV's.
 */

export type Ecosystem = 'npm' | 'Packagist' | 'PyPI' | 'Maven' | 'Go' | 'NuGet' | 'RubyGems' | 'crates.io' | 'Pub';
/** `line`: where the package is in its lockfile (npm-family lockfiles), so findings point at it. */
export type Locked = { name: string; version: string; ecosystem: Ecosystem; dev: boolean; line?: number; direct?: boolean; via?: string };
/** `skipped` counts declared packages with no exact version to check. `directOnly`: the file doesn't list what those packages need. */
export type Parsed = { packages: Locked[]; skipped: number; directOnly?: boolean; /** Names of the skipped packages, where the format shows them. */ skippedNames?: string[] };

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
  const skippedNames: string[] = [];
  const add = (list: { name: string; version: string }[] | undefined, dev: boolean) => {
    for (const p of list ?? []) {
      // Branch installs (dev-main, 1.x-dev) have no release version to look up.
      if (/^dev-|-dev$/.test(p.version)) skippedNames.push(p.name);
      else packages.push(pkg('Packagist', p.name, p.version, dev));
    }
  };
  add(lock.packages, false);
  add(lock['packages-dev'], true);
  return { packages, skipped: skippedNames.length, skippedNames };
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
 * Direct dependencies only, read without running Maven. A version may come from this file's
 * properties or dependencyManagement, or from parent POMs in the same repository (`parents`, nearest
 * first, as readPackages finds them through <relativePath>). A parent or imported BOM from outside the
 * repository, such as spring-boot-starter-parent, sets the version of its own group's artifacts, which
 * is how Spring Boot's starters get theirs.
 */
function pomXml(text: string, _file?: string, parentsJson?: string): Parsed {
  const blank = (c: string) => c.replace(/[^\n]/g, ' ');
  const strip = (x: string) => x.replace(/<!--[\s\S]*?-->/g, blank);
  const xml = strip(text);
  let parents: string[] = [];
  try {
    parents = parentsJson ? (JSON.parse(parentsJson) as string[]).map(strip) : [];
  } catch {
    parents = [];
  }
  const outside = (x: string) => x.replace(/<(dependencies|dependencyManagement|build|reporting|profiles|modules|parent)>[\s\S]*?<\/\1>/g, '');
  const parentBlock = /<parent>([\s\S]*?)<\/parent>/.exec(xml)?.[1] ?? '';
  const props = new Map<string, string>();
  // Outermost parent first, so nearer files win.
  for (const x of [...parents].reverse().concat(xml)) {
    for (const block of x.match(/<properties>[\s\S]*?<\/properties>/g) ?? []) {
      for (const m of block.matchAll(/<([\w.-]+)>\s*([^<]*?)\s*<\/\1>/g)) props.set(m[1]!, m[2]!);
    }
  }
  const own = outside(xml);
  const version = xmlTag(own, 'version') ?? xmlTag(parentBlock, 'version');
  const groupId = xmlTag(own, 'groupId') ?? xmlTag(parentBlock, 'groupId');
  if (version) props.set('project.version', version).set('version', version).set('pom.version', version);
  if (groupId) props.set('project.groupId', groupId);
  if (xmlTag(parentBlock, 'version')) props.set('project.parent.version', xmlTag(parentBlock, 'version')!).set('parent.version', xmlTag(parentBlock, 'version')!);
  const resolve = (v: string | undefined) => v?.replace(/\$\{([^}]+)\}/g, (all, k: string) => props.get(k) ?? all);

  const managed = new Map<string, string>();
  /** Groups whose version a parent or BOM from outside the repository sets. */
  const byGroup = new Map<string, string>();
  for (const x of [...parents].reverse().concat(xml)) {
    for (const block of x.match(/<dependencyManagement>[\s\S]*?<\/dependencyManagement>/g) ?? []) {
      for (const dep of block.match(/<dependency>[\s\S]*?<\/dependency>/g) ?? []) {
        const v = resolve(xmlTag(dep, 'version'));
        const g = resolve(xmlTag(dep, 'groupId'));
        if (!v) continue;
        if (xmlTag(dep, 'scope') === 'import' && g) byGroup.set(g, v);
        else managed.set(`${g}:${resolve(xmlTag(dep, 'artifactId'))}`, v);
      }
    }
  }
  // The outermost parent that isn't in the repository.
  const outermost = parents.length ? (/<parent>([\s\S]*?)<\/parent>/.exec(parents[parents.length - 1]!)?.[1] ?? '') : parentBlock;
  const externalGroup = resolve(xmlTag(outermost, 'groupId'));
  const externalVersion = resolve(xmlTag(outermost, 'version'));
  if (externalGroup && externalVersion && !byGroup.has(externalGroup)) byGroup.set(externalGroup, externalVersion);

  // Plugin dependencies under <build> never reach the application.
  const used = xml.replace(/<dependencyManagement>[\s\S]*?<\/dependencyManagement>/g, blank).replace(/<(build|reporting)>[\s\S]*?<\/\1>/g, blank);
  const packages: Locked[] = [];
  let skipped = 0;
  for (const m of used.matchAll(/<dependency>[\s\S]*?<\/dependency>/g)) {
    const dep = m[0].replace(/<exclusions>[\s\S]*?<\/exclusions>/, '');
    // `${project.version}`: another module of this same build, not a published package.
    if (/^\$\{(?:project\.|pom\.)?version\}$/.test(xmlTag(dep, 'version') ?? '')) continue;
    const group = resolve(xmlTag(dep, 'groupId'));
    const name = `${group}:${resolve(xmlTag(dep, 'artifactId'))}`;
    const v = resolve(xmlTag(dep, 'version')) ?? managed.get(name) ?? (group ? byGroup.get(group) : undefined);
    if (!v || /[${[(,]/.test(v) || name.includes('$')) skipped++;
    else packages.push(pkg('Maven', name, v, xmlTag(dep, 'scope') === 'test', lineOf(text, m.index!)));
  }
  return { packages, skipped };
}

/** The parent a pom.xml names, and where it says to find it. */
export function pomParent(text: string): { relativePath: string; artifactId?: string } | null {
  const block = /<parent>([\s\S]*?)<\/parent>/.exec(text.replace(/<!--[\s\S]*?-->/g, ''))?.[1];
  if (!block) return null;
  const relativePath = xmlTag(block, 'relativePath');
  // An empty <relativePath/> means "look in the repository, not on disk".
  if (relativePath === '' || /<relativePath\s*\/>/.test(block)) return null;
  return { relativePath: relativePath ?? '../pom.xml', artifactId: xmlTag(block, 'artifactId') };
}

/** Gradle configurations used only for tests. */
const GRADLE_TEST_CONFIG = /^(?:test|androidTest|testFixtures|integrationTest|functionalTest)/;

/**
 * A Gradle version catalog (gradle/libs.versions.toml). `buildFiles` is the project's build scripts,
 * for which libraries are only ever used by test configurations. A library whose version comes from a
 * BOM has none here, so it's counted as skipped.
 */
function versionCatalog(text: string, _file?: string, buildFiles?: string): Parsed {
  const versions = new Map<string, string>();
  const packages: Locked[] = [];
  const skippedNames: string[] = [];
  const uses = new Map<string, Set<string>>();
  for (const m of (buildFiles ?? '').matchAll(/\b(\w+)\s*\(?\s*(?:platform\s*\(\s*)?libs\.([\w.]+)/g)) {
    const accessor = m[2]!.replace(/\.get$/, '');
    if (!uses.has(accessor)) uses.set(accessor, new Set());
    uses.get(accessor)!.add(m[1]!);
  }
  const exact = (v: string | undefined) => (v && /^[\w.+-]+$/.test(v) && /\d/.test(v) && !/[+]$|latest/i.test(v) ? v : null);
  let section = '';
  for (const [i, raw] of text.split(/\r?\n/).entries()) {
    const line = raw.replace(/\s+#.*$/, '').trim();
    const head = /^\[([\w.-]+)\]$/.exec(line);
    if (head) { section = head[1]!; continue; }
    const kv = /^([\w.-]+)\s*=\s*(.+)$/.exec(line);
    if (!kv) continue;
    const [, key, value] = kv as unknown as [string, string, string];
    if (section === 'versions') {
      const plain = /^"([^"]*)"$/.exec(value)?.[1];
      const rich = /\b(?:strictly|require|prefer)\s*=\s*"([^"]*)"/.exec(value)?.[1];
      const v = plain ?? rich;
      if (v) versions.set(key, v);
      continue;
    }
    if (section !== 'libraries') continue;
    let module: string | undefined;
    let version: string | undefined;
    const short = /^"([^":]+):([^":]+)(?::([^"]+))?"$/.exec(value);
    if (short) {
      module = `${short[1]}:${short[2]}`;
      version = short[3];
    } else {
      const field = (f: string) => new RegExp(`\\b${f}\\s*=\\s*"([^"]*)"`).exec(value)?.[1];
      module = field('module') ?? (field('group') && field('name') ? `${field('group')}:${field('name')}` : undefined);
      const ref = /\bversion\.ref\s*=\s*"([^"]*)"/.exec(value)?.[1] ?? /\bversion\s*=\s*\{[^}]*\bref\s*=\s*"([^"]*)"/.exec(value)?.[1];
      version = ref ? versions.get(ref) : (field('version') ?? /\bversion\s*=\s*\{[^}]*\b(?:strictly|require|prefer)\s*=\s*"([^"]*)"/.exec(value)?.[1]);
    }
    if (!module) continue;
    const v = exact(version);
    const accessor = key.replace(/[-_]/g, '.');
    const configs = uses.get(accessor);
    const dev = Boolean(configs?.size) && [...configs!].every((c) => GRADLE_TEST_CONFIG.test(c));
    if (v) packages.push(pkg('Maven', module, v, dev, i + 1));
    else skippedNames.push(module);
  }
  return { packages, skipped: skippedNames.length, skippedNames, directOnly: true };
}

/** build.gradle / build.gradle.kts: dependencies written out in full, `implementation("g:a:1.2.3")`. */
function gradleBuild(text: string): Parsed {
  const packages: Locked[] = [];
  const skippedNames: string[] = [];
  const code = text.replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, ' ')).replace(/\/\/[^\n]*/g, '');
  // The buildscript block holds the build's own plugins, not the app's dependencies.
  const app = code.replace(/\bbuildscript\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}/g, (c) => c.replace(/[^\n]/g, ' '));
  for (const m of app.matchAll(/\b(\w+)\s*\(?\s*(?:platform\s*\(\s*|enforcedPlatform\s*\(\s*)?["']([\w.-]+):([\w.-]+):([^"'@\s]+)(?:@\w+)?["']/g)) {
    const config = m[1]!;
    if (/^(?:classpath|id|kotlin|plugin|apply|maven|url)$/.test(config)) continue;
    const version = m[4]!;
    const name = `${m[2]}:${m[3]}`;
    if (/[$+[(,]|latest/i.test(version)) skippedNames.push(name);
    else packages.push(pkg('Maven', name, version, GRADLE_TEST_CONFIG.test(config), lineOf(text, m.index!)));
  }
  return { packages, skipped: skippedNames.length, skippedNames, directOnly: true };
}

/**
 * build.sbt, and Scala files in project/ (`buildSbt` is then the build.sbt beside the project folder,
 * for scalaVersion). `"org" %% "name" % "1.2.3"` becomes org:name_2.13 as Maven Central has it.
 */
function sbtBuild(text: string, file?: string, buildSbt?: string): Parsed {
  const code = (t: string) => t.replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, ' ')).replace(/\/\/[^\n]*/g, '');
  const own = code(text);
  const scalaVersion = /scalaVersion\s*:=\s*"([^"]+)"/.exec(own)?.[1] ?? /scalaVersion\s*:=\s*"([^"]+)"/.exec(code(buildSbt ?? ''))?.[1];
  const binary = scalaVersion ? (scalaVersion.startsWith('3') ? '3' : scalaVersion.split('.').slice(0, 2).join('.')) : null;
  const vals = new Map<string, string>();
  for (const m of [own, code(buildSbt ?? '')].join('\n').matchAll(/\b(?:val|lazy\s+val|def)\s+(\w+)\s*(?::\s*String\s*)?=\s*"([^"]+)"/g)) vals.set(m[1]!, m[2]!);
  const packages: Locked[] = [];
  const skippedNames: string[] = [];
  for (const m of own.matchAll(/"([\w.-]+)"\s*(%%%|%%|%)\s*"([\w.-]+)"\s*%\s*(?:"([^"]+)"|([\w.]+))(\s*%\s*(?:"[\w-]+"|[\w.]+))?/g)) {
    const [, org, op, artifact, quoted, ident, scope] = m;
    const version = quoted ?? vals.get(ident!.split('.').pop()!);
    const name = op === '%' ? `${org}:${artifact}` : `${org}:${artifact}_${binary ?? '?'}`;
    // %%% is Scala.js or Native, whose artifact names depend on the platform too.
    if (!version || op === '%%%' || (op === '%%' && !binary) || /[+[(,]|latest/i.test(version)) skippedNames.push(name);
    else packages.push(pkg('Maven', name, version, /test|it\b|integrationtest/i.test(scope ?? ''), lineOf(text, m.index!)));
  }
  void file;
  return { packages, skipped: skippedNames.length, skippedNames, directOnly: true };
}

/** build.sbt.lock from sbt-dependency-lock: every dependency, transitive ones included. */
function sbtLock(text: string): Parsed {
  const lock = JSON.parse(text) as { dependencies?: { org?: string; name?: string; version?: string; configurations?: string[] }[] };
  const packages: Locked[] = [];
  for (const d of lock.dependencies ?? []) {
    if (!d.org || !d.name || !d.version) continue;
    const configs = d.configurations ?? [];
    packages.push(pkg('Maven', `${d.org}:${d.name}`, d.version, configs.length > 0 && configs.every((c) => /^test/i.test(c))));
  }
  return { packages, skipped: 0 };
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

/** `manifest`: the file beside the lockfile that lists what production needs (package.json for Yarn, pyproject.toml for Poetry). */
export const VERSION_CATALOG = /(^|\/)gradle\/[\w.-]+\.versions\.toml$/;
export const GRADLE_BUILD = /(^|\/)build\.gradle(\.kts)?$/;
export const SBT_BUILD = /(^|\/)build\.sbt$|(^|\/)project\/[\w-]+\.scala$/;
/** Gradle and sbt build files, which list direct dependencies only. */
export const isJvmBuild = (path: string) => VERSION_CATALOG.test(path) || GRADLE_BUILD.test(path) || SBT_BUILD.test(path);

type Format = { match: RegExp; ecosystem: Ecosystem; parse: (text: string, file: string, manifest?: string) => Parsed };

const REQUIREMENTS = /(^|\/)[-_.\w]*requirements[-_.\w]*\.txt$|(^|\/)requirements\/[-_.\w]+\.txt$|(^|\/)constraints[-_.\w]*\.txt$/;

const FORMATS: Format[] = [
  { match: /(^|\/)(package-lock|npm-shrinkwrap)\.json$/, ecosystem: 'npm', parse: npmLock },
  { match: /(^|\/)yarn\.lock$/, ecosystem: 'npm', parse: yarnLock },
  { match: /(^|\/)pnpm-lock\.yaml$/, ecosystem: 'npm', parse: pnpmLock },
  { match: /(^|\/)composer\.lock$/, ecosystem: 'Packagist', parse: composerLock },
  { match: /(^|\/)(poetry|uv|pdm)\.lock$/, ecosystem: 'PyPI', parse: tomlPythonLock },
  { match: /(^|\/)pylock(\.[-_\w]+)?\.toml$/, ecosystem: 'PyPI', parse: pylockToml },
  { match: /(^|\/)Pipfile\.lock$/, ecosystem: 'PyPI', parse: pipfileLock },
  { match: REQUIREMENTS, ecosystem: 'PyPI', parse: requirementsTxt },
  { match: /(^|\/)([\w-]+-)?gradle\.lockfile$/, ecosystem: 'Maven', parse: gradleLock },
  { match: /(^|\/)pom\.xml$/, ecosystem: 'Maven', parse: pomXml },
  { match: VERSION_CATALOG, ecosystem: 'Maven', parse: versionCatalog },
  { match: GRADLE_BUILD, ecosystem: 'Maven', parse: gradleBuild },
  { match: SBT_BUILD, ecosystem: 'Maven', parse: sbtBuild },
  { match: /(^|\/)build\.sbt\.lock$/, ecosystem: 'Maven', parse: sbtLock },
  { match: /(^|\/)go\.mod$/, ecosystem: 'Go', parse: goMod },
  { match: /(^|\/)packages\.lock\.json$/, ecosystem: 'NuGet', parse: nugetLock },
  { match: /(^|\/)Gemfile\.lock$/, ecosystem: 'RubyGems', parse: gemfileLock },
  { match: /(^|\/)Cargo\.lock$/, ecosystem: 'crates.io', parse: cargoLock },
  { match: /(^|\/)pubspec\.lock$/, ecosystem: 'Pub', parse: pubspecLock },
];

export const isPomXml = (path: string) => /(^|\/)pom\.xml$/.test(path);
export const isRequirements = (path: string) => REQUIREMENTS.test(path);

/** The file beside a lockfile that says what production needs, for formats that can't say themselves. */
export function manifestFor(file: string): string | null {
  if (/(^|\/)yarn\.lock$/.test(file)) return 'package.json';
  if (/(^|\/)poetry\.lock$/.test(file)) return 'pyproject.toml';
  return null;
}

/** Project files that mean an ecosystem is in use, and how to get a lockfile Fortis can read. */
const MANIFESTS: { match: RegExp; ecosystem: Ecosystem; label: string; hint: string }[] = [
  { match: /(^|\/)package\.json$/, ecosystem: 'npm', label: 'package.json', hint: 'commit package-lock.json, yarn.lock or pnpm-lock.yaml (Bun lockfiles are not read yet)' },
  { match: /(^|\/)composer\.json$/, ecosystem: 'Packagist', label: 'composer.json', hint: 'commit composer.lock' },
  { match: /(^|\/)(pyproject\.toml|Pipfile|setup\.py|setup\.cfg)$/, ecosystem: 'PyPI', label: 'Python project files', hint: 'run uv lock, poetry lock or pip-compile and commit the result, or pass --sbom' },
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
  const pythonLocks = new Set(files.filter((p) => /(^|\/)(poetry\.lock|uv\.lock|pdm\.lock|pylock(\.[-_\w]+)?\.toml|Pipfile\.lock)$/.test(p)).map(projectDir));
  // A dependency lock lists transitive dependencies too: Gradle's beside its build, sbt's beside build.sbt.
  const rootOf = (p: string) => p.replace(/(?:gradle\/[^/]+|project\/[^/]+|[^/]+)$/, '');
  const locked = new Set(files.filter((p) => /(^|\/)([\w-]+-)?gradle\.lockfile$|(^|\/)build\.sbt\.lock$/.test(p)).map(rootOf));
  return files.filter((p) => (!REQUIREMENTS.test(p) || !pythonLocks.has(projectDir(p))) && !(isJvmBuild(p) && locked.has(rootOf(p))));
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
