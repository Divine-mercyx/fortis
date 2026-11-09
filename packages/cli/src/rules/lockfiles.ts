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

/** `replace` directives, from go.mod or go.work: what each module (at any version, or one) is swapped for. */
type GoReplace = { from: string; fromVersion?: string; to: string; toVersion?: string };

function goReplaces(text: string): GoReplace[] {
  const out: GoReplace[] = [];
  let inBlock = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\/\/.*$/, '').trim();
    if (/^replace\s*\($/.test(line)) { inBlock = true; continue; }
    if (inBlock && line === ')') { inBlock = false; continue; }
    const body = inBlock ? line : /^replace\s+(.*)$/.exec(line)?.[1];
    const m = body && /^(\S+)(?:\s+(v\S+))?\s*=>\s*(\S+)(?:\s+(v\S+))?$/.exec(body);
    if (m) out.push({ from: m[1]!, fromVersion: m[2], to: m[3]!, toVersion: m[4] });
  }
  return out;
}

const isGoPath = (target: string) => /^(?:\.{1,2}\/|\/|[A-Za-z]:[\\/])/.test(target);
const goVersion = (v: string) => v.replace(/\+incompatible$/, '');

/** A module after replacements: another module at a version, or a local folder (null), or itself. */
function applyReplace(name: string, version: string, replaces: GoReplace[]): { name: string; version: string } | null {
  const r = replaces.find((x) => x.from === name && (!x.fromVersion || x.fromVersion === version));
  if (!r) return { name, version };
  if (isGoPath(r.to)) return null;
  return { name: r.to, version: r.toVersion ?? version };
}

/**
 * go.mod: every `require`, with `replace` directives applied. `workspace` is the go.work that uses
 * this module, whose replacements win over the module's own, as they do for the go command.
 * Pseudo-versions (v0.0.0-20240101120000-abcdef123456) are passed on whole, which is what OSV expects.
 */
function goMod(text: string, _file?: string, workspace?: string): Parsed {
  const replaces = [...(workspace ? goReplaces(workspace) : []), ...goReplaces(text)];
  const packages: Locked[] = [];
  const skippedNames: string[] = [];
  let inRequire = false;
  for (const [i, raw] of text.split(/\r?\n/).entries()) {
    const line = raw.replace(/\/\/.*$/, '').trim();
    if (/^require\s*\($/.test(line)) { inRequire = true; continue; }
    if (line === ')') { inRequire = false; continue; }
    const m = (inRequire ? /^(\S+)\s+(v\S+)$/ : /^require\s+(\S+)\s+(v\S+)$/).exec(line);
    if (!m) continue;
    const swapped = applyReplace(m[1]!, m[2]!, replaces);
    if (swapped) packages.push(pkg('Go', swapped.name, goVersion(swapped.version), false, i + 1));
    else skippedNames.push(`${m[1]} (local folder)`);
  }
  return { packages, skipped: skippedNames.length, skippedNames };
}

/**
 * vendor/modules.txt: the modules `go mod vendor` copied in, which is exactly what gets built.
 * `# module version` lines, with `=> replacement [version]` when go.mod replaced it.
 */
function vendorModules(text: string): Parsed {
  const packages: Locked[] = [];
  const skippedNames: string[] = [];
  for (const [i, line] of text.split(/\r?\n/).entries()) {
    const m = /^# (\S+) (v\S+)(?: => (\S+)(?: (v\S+))?)?\s*$/.exec(line);
    if (!m) continue;
    if (m[3] && isGoPath(m[3])) skippedNames.push(`${m[1]} (local folder)`);
    else packages.push(pkg('Go', m[3] ?? m[1]!, goVersion(m[4] ?? m[2]!), false, i + 1));
  }
  return { packages, skipped: skippedNames.length, skippedNames };
}

/** The module folders a go.work file uses: `use ./api` or a `use ( ... )` block. */
export function goWorkModules(text: string): string[] {
  const out: string[] = [];
  let inBlock = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\/\/.*$/, '').trim();
    if (/^use\s*\($/.test(line)) { inBlock = true; continue; }
    if (inBlock && line === ')') { inBlock = false; continue; }
    const dir = inBlock ? line : /^use\s+(\S+)$/.exec(line)?.[1];
    if (dir) out.push(dir.replace(/^["`]|["`]$/g, ''));
  }
  return out;
}

/** An MSBuild attribute or child element of one item, whatever its case. */
function msbuildValue(item: string, name: string): string | undefined {
  const attr = new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`, 'i').exec(item)?.[1];
  return attr ?? new RegExp(`<${name}>\\s*([^<]*?)\\s*</${name}>`, 'i').exec(item)?.[1];
}

/** `$(Name)` properties from <PropertyGroup> elements. */
function msbuildProperties(...xmls: string[]): Map<string, string> {
  const props = new Map<string, string>();
  for (const xml of xmls) {
    for (const group of xml.match(/<PropertyGroup\b[^>]*>[\s\S]*?<\/PropertyGroup>/gi) ?? []) {
      for (const m of group.matchAll(/<([\w.-]+)(?:\s[^>]*)?>\s*([^<]*?)\s*<\/\1>/g)) props.set(m[1]!.toLowerCase(), m[2]!);
    }
  }
  return props;
}

/**
 * NuGet's version for a reference: `1.2.3`, or `[1.2.3]` pinned. Floating (`1.2.*`) and ranges
 * (`[1.0,2.0)`) are left to restore, so there's no one version to check.
 */
function nugetExact(v: string | undefined): string | null {
  const t = v?.trim().replace(/^\[([^,\]]+)\]$/, '$1');
  return t && /^\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z.-]+)?$/.test(t) ? t : null;
}

/** Each <Tag .../> or <Tag ...>...</Tag> item, with where it starts. */
function msbuildItems(xml: string, tag: string): { text: string; index: number }[] {
  return [...xml.matchAll(new RegExp(`<${tag}\\b[^>]*?(?:/>|>[\\s\\S]*?</${tag}>)`, 'gi'))].map((m) => ({ text: m[0], index: m.index! }));
}

/**
 * .csproj, .fsproj and .vbproj: <PackageReference Include="X" Version="1.2.3" />, with versions from
 * Directory.Packages.props (`central`) for projects that manage them centrally. Only direct
 * references: transitive packages are in packages.lock.json alone.
 */
function dotnetProject(text: string, _file?: string, central?: string): Parsed {
  const blank = (x: string) => x.replace(/<!--[\s\S]*?-->/g, (c) => c.replace(/[^\n]/g, ' '));
  const xml = blank(text);
  const props = msbuildProperties(central ? blank(central) : '', xml);
  const expand = (v: string | undefined) => v?.replace(/\$\(([\w.-]+)\)/g, (all, k: string) => props.get(k.toLowerCase()) ?? all);
  const centrally = new Map<string, string>();
  const packages: Locked[] = [];
  const skippedNames: string[] = [];
  if (central) {
    const c = blank(central);
    for (const item of msbuildItems(c, 'PackageVersion')) {
      const name = msbuildValue(item.text, 'Include') ?? msbuildValue(item.text, 'Update');
      const version = expand(msbuildValue(item.text, 'Version'));
      if (name && version) centrally.set(name.toLowerCase(), version);
    }
  }
  for (const item of msbuildItems(xml, 'PackageReference')) {
    const name = msbuildValue(item.text, 'Include');
    if (!name) continue; // `Update=` items change a reference made elsewhere
    const declared = expand(msbuildValue(item.text, 'VersionOverride') ?? msbuildValue(item.text, 'Version')) ?? centrally.get(name.toLowerCase());
    const version = nugetExact(declared);
    // PrivateAssets="all": analyzers and build tools, which don't ship with the app.
    const dev = /\ball\b/i.test(msbuildValue(item.text, 'PrivateAssets') ?? '');
    if (version) packages.push(pkg('NuGet', name, version, dev, lineOf(text, item.index)));
    else skippedNames.push(name);
  }
  return { packages, skipped: skippedNames.length, skippedNames, directOnly: true };
}

/**
 * Directory.Packages.props: its versions are used through the projects, but a GlobalPackageReference
 * applies to every project under it, so those are reported here, once. They're build tools such
 * as analyzers, so they count as dev-only.
 */
function directoryPackagesProps(text: string): Parsed {
  const xml = text.replace(/<!--[\s\S]*?-->/g, (c) => c.replace(/[^\n]/g, ' '));
  const props = msbuildProperties(xml);
  const packages: Locked[] = [];
  const skippedNames: string[] = [];
  for (const item of msbuildItems(xml, 'GlobalPackageReference')) {
    const name = msbuildValue(item.text, 'Include');
    const version = nugetExact(msbuildValue(item.text, 'Version')?.replace(/\$\(([\w.-]+)\)/g, (all, k: string) => props.get(k.toLowerCase()) ?? all));
    if (!name) continue;
    if (version) packages.push(pkg('NuGet', name, version, true, lineOf(text, item.index)));
    else skippedNames.push(name);
  }
  return { packages, skipped: skippedNames.length, skippedNames };
}

/** packages.config, from before PackageReference: every package, transitive ones included. */
function packagesConfig(text: string): Parsed {
  const xml = text.replace(/<!--[\s\S]*?-->/g, (c) => c.replace(/[^\n]/g, ' '));
  const packages: Locked[] = [];
  const skippedNames: string[] = [];
  for (const item of msbuildItems(xml, 'package')) {
    const name = msbuildValue(item.text, 'id');
    const version = nugetExact(msbuildValue(item.text, 'version'));
    if (!name) continue;
    if (version) packages.push(pkg('NuGet', name, version, msbuildValue(item.text, 'developmentDependency') === 'true', lineOf(text, item.index)));
    else skippedNames.push(name);
  }
  return { packages, skipped: skippedNames.length, skippedNames };
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
/** `manifest`: a file beside the lockfile that it needs, such as package.json, Directory.Packages.props or go.work. */
const VENDOR_MODULES = /(^|\/)vendor\/modules\.txt$/;
export const DOTNET_PROJECT = /\.(?:cs|fs|vb)proj$/i;
export const isDotnetProject = (path: string) => DOTNET_PROJECT.test(path);

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
  { match: /(^|\/)go\.mod$/, ecosystem: 'Go', parse: goMod },
  { match: VENDOR_MODULES, ecosystem: 'Go', parse: vendorModules },
  { match: /(^|\/)packages\.lock\.json$/, ecosystem: 'NuGet', parse: nugetLock },
  { match: DOTNET_PROJECT, ecosystem: 'NuGet', parse: dotnetProject },
  { match: /(^|\/)packages\.config$/i, ecosystem: 'NuGet', parse: packagesConfig },
  { match: /(^|\/)Directory\.Packages\.props$/i, ecosystem: 'NuGet', parse: directoryPackagesProps },
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
  { match: /(^|\/)build\.gradle(\.kts)?$/, ecosystem: 'Maven', label: 'build.gradle', hint: 'turn on Gradle dependency locking, or pass --sbom' },
  { match: /\.(?:cs|fs|vb)proj$/, ecosystem: 'NuGet', label: '.NET project files', hint: 'set RestorePackagesWithLockFile, or pass --sbom' },
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
  // A Go module's own vendor/modules.txt is the one vendored file that describes this project.
  const vendored = paths.filter((p) => VENDOR_MODULES.test(p) && !/(^|\/)vendor\/.*\/vendor\//.test(p) && !/(^|\/)vendor\/.+\/vendor\/modules\.txt$/.test(p));
  const files = [...relevant(paths, ignore), ...relevant(vendored.map((p) => p.replace(/vendor\/modules\.txt$/, 'modules.txt')), ignore).map((p) => p.replace(/modules\.txt$/, 'vendor/modules.txt'))].filter((p) =>
    FORMATS.some((f) => f.match.test(p)),
  );
  // A real lock describes the same project more completely than a requirements file beside it.
  const projectDir = (p: string) => p.replace(/requirements\/[^/]+$|[^/]+$/, '');
  const pythonLocks = new Set(files.filter((p) => /(^|\/)(poetry\.lock|uv\.lock|pdm\.lock|pylock(\.[-_\w]+)?\.toml|Pipfile\.lock)$/.test(p)).map(projectDir));
  // packages.lock.json has transitive packages too; vendor/modules.txt is what's actually built.
  const dirOf = (p: string) => p.replace(/[^/]+$/, '');
  const nugetLocks = new Set(files.filter((p) => /(^|\/)packages\.lock\.json$/.test(p)).map(dirOf));
  const goVendored = new Set(files.filter((p) => VENDOR_MODULES.test(p)).map((p) => p.replace(/vendor\/modules\.txt$/, '')));
  return files.filter(
    (p) =>
      !(REQUIREMENTS.test(p) && pythonLocks.has(projectDir(p))) &&
      !((DOTNET_PROJECT.test(p) || /(^|\/)packages\.config$/i.test(p)) && nugetLocks.has(dirOf(p))) &&
      !(/(^|\/)go\.mod$/.test(p) && goVendored.has(dirOf(p))),
  );
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
