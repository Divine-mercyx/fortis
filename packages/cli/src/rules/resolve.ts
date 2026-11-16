import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { GRADLE_BUILD, isDotnetProject, isPomXml, SBT_BUILD, VERSION_CATALOG, type Locked } from './lockfiles';

/*
 * `fortis scan --resolve` (#94): Java, Kotlin, Scala and .NET projects without a lockfile list only their direct
 * libraries, and most known holes (Log4Shell among them) come in through a library's own libraries. With --resolve,
 * Fortis asks the project's own build tool for the full tree:
 *   Gradle  gradle dependencies --configuration runtimeClasspath   (the project's gradlew if it has one)
 *   Maven   mvn dependency:tree                                      (the project's mvnw if it has one)
 *   sbt     sbt dependencyTree
 *   .NET    dotnet list package --include-transitive --format json
 * Off by default: it runs the build tool, and so the project's build scripts. With --offline the tools are told to
 * use what's already in their local cache. Without the tool, or when it fails, the build files are read as before.
 */

/** Runs a command and gives back its output. Tests replace it. */
export type Runner = (cmd: string, args: string[], opts: { cwd: string; timeoutMs: number }) => Promise<{ code: number | null; stdout: string; stderr: string; missing?: boolean }>;

export type ResolvedTree = {
  /** Every package the tool reported, with `via` naming the direct library an indirect one comes in through. */
  packages: (Locked & { file: string })[];
  /** Build files whose dependencies are all in `packages`, so they needn't be read on their own. */
  covered: Set<string>;
  notes: string[];
};

/** How long one build tool may take. A first Gradle run downloads a lot. */
export const RESOLVE_TIMEOUT_MS = 10 * 60_000;

type Tool = 'Gradle' | 'Maven' | 'sbt' | '.NET';
type Build = { tool: Tool; dir: string; files: string[]; file: string };

/* ------------------------------------------------------------------ parsers */

type Dep = { name: string; version: string; depth: number; dev?: boolean };

/** Turns a tree, in reading order, into packages: depth 0 is direct, anything deeper comes in through its depth-0 ancestor. */
function fromTree(deps: Dep[], file: string): (Locked & { file: string })[] {
  const out = new Map<string, Locked & { file: string }>();
  let top: Dep | null = null;
  for (const d of deps) {
    if (d.depth === 0) top = d;
    const direct = d.depth === 0;
    const key = `${d.name}|${d.version}`;
    const known = out.get(key);
    // A library listed directly anywhere is direct; otherwise keep the first library it was seen under.
    if (known && (known.direct || !direct)) continue;
    out.set(key, { name: d.name, version: d.version, ecosystem: 'Maven', dev: Boolean(d.dev), direct, ...(direct || !top ? {} : { via: top.name }), file });
  }
  return [...out.values()];
}

/**
 * `gradle dependencies` output:
 *   +--- org.springframework.boot:spring-boot-starter-log4j2:2.6.1
 *   |    +--- org.apache.logging.log4j:log4j-core:2.14.1
 *   |    \--- org.slf4j:slf4j-api:1.7.32 -> 1.7.36
 *   +--- project :core
 * `a -> b` means Gradle picked b. (*) repeats a subtree shown earlier, (c) is a constraint and (n) wasn't resolved.
 * A local project's own dependencies count as the build's direct ones.
 */
export function parseGradleTree(text: string, file: string): (Locked & { file: string })[] {
  const deps: Dep[] = [];
  const projectDepths: number[] = [];
  for (const line of text.split(/\r?\n/)) {
    const m = /^([| ]*)[+\\]--- (.+?)\s*$/.exec(line);
    if (!m) continue;
    const depth = Math.round(m[1]!.length / 5);
    while (projectDepths.length && projectDepths[projectDepths.length - 1]! >= depth) projectDepths.pop();
    const entry = m[2]!;
    if (/^project\s/.test(entry)) {
      projectDepths.push(depth);
      continue;
    }
    if (/\((?:c|n)\)$|FAILED$/.test(entry)) continue;
    const coords = entry.replace(/\s*\(\*\)$/, '');
    const [declared, picked] = coords.split(/\s+->\s+/) as [string, string | undefined];
    const parts = declared.split(':');
    if (parts.length < 2) continue;
    const version = (picked ?? parts[2] ?? '').replace(/\s*\(.*\)$/, '').trim();
    if (!version || /[+[(,]/.test(version)) continue;
    deps.push({ name: `${parts[0]}:${parts[1]}`, version, depth: depth - projectDepths.length });
  }
  return fromTree(deps, file);
}

/**
 * `mvn dependency:tree` output, one tree per module:
 *   com.example:bank:jar:1.0.0
 *   +- org.springframework.boot:spring-boot-starter-log4j2:jar:2.6.1:compile
 *   |  \- org.apache.logging.log4j:log4j-core:jar:2.14.1:compile
 * Coordinates are group:artifact:type[:classifier]:version:scope. Test scope is dev-only, as in pom.xml.
 * `fileFor` names the pom.xml a module's tree belongs to, from the module's artifactId.
 */
export function parseMavenTree(text: string, fileFor: (artifactId: string) => string): (Locked & { file: string })[] {
  const out: (Locked & { file: string })[] = [];
  let deps: Dep[] = [];
  let file = fileFor('');
  const flush = () => {
    out.push(...fromTree(deps, file));
    deps = [];
  };
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/^\[INFO\]\s?/, '');
    const child = /^([| ]*)[+\\]- (\S+)/.exec(line);
    if (child) {
      const parts = child[2]!.split(':');
      if (parts.length < 5) continue;
      const [group, artifact] = parts;
      const version = parts.length >= 6 ? parts[4]! : parts[3]!;
      const scope = parts.length >= 6 ? parts[5]! : parts[4]!;
      deps.push({ name: `${group}:${artifact}`, version, depth: Math.round(child[1]!.length / 3), dev: scope === 'test' });
      continue;
    }
    const root = /^([\w.-]+):([\w.-]+):[\w.-]+(?::[\w.-]+)?:[\w.-]+\s*$/.exec(line.trim());
    if (root) {
      flush();
      file = fileFor(root[2]!);
    }
  }
  flush();
  return out;
}

/**
 * `sbt dependencyTree` output, one tree per project:
 *   [info] com.example:bank_2.13:0.1.0 [S]
 *   [info]   +-org.typelevel:cats-core_2.13:2.9.0 [S]
 *   [info]   | +-org.typelevel:cats-kernel_2.13:2.9.0 [S]
 * A version sbt replaced shows `(evicted by: x)`; it isn't on the classpath, so it's left out.
 */
export function parseSbtTree(text: string, file: string): (Locked & { file: string })[] {
  const deps: Dep[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/^\[\w+\]\s?/, '');
    const m = /^(\s*(?:\|\s)*\s*)\+-(\S+)(.*)$/.exec(line);
    if (!m || /evicted by/i.test(m[3]!)) continue;
    const parts = m[2]!.split(':');
    if (parts.length < 3) continue;
    // Two spaces per level, under a project line that sits two spaces in.
    const depth = Math.max(0, Math.round((m[1]!.length - 2) / 2));
    deps.push({ name: `${parts[0]}:${parts[1]}`, version: parts[2]!, depth });
  }
  return fromTree(deps, file);
}

/**
 * `dotnet list package --include-transitive --format json` (SDK 7.0.200 and later). It names each project's top-level
 * and transitive packages, but not which top-level package brought a transitive one in.
 */
export function parseDotnetList(text: string, file: string): (Locked & { file: string })[] {
  type Pkg = { id?: string; resolvedVersion?: string };
  const data = JSON.parse(text.slice(text.indexOf('{'))) as { projects?: { frameworks?: { topLevelPackages?: Pkg[]; transitivePackages?: Pkg[] }[] }[] };
  const out = new Map<string, Locked & { file: string }>();
  for (const project of data.projects ?? []) {
    for (const fw of project.frameworks ?? []) {
      for (const [list, direct] of [[fw.topLevelPackages, true], [fw.transitivePackages, false]] as const) {
        for (const p of list ?? []) {
          if (!p.id || !p.resolvedVersion) continue;
          const key = `${p.id}|${p.resolvedVersion}`;
          if (out.get(key)?.direct) continue;
          out.set(key, { name: p.id, version: p.resolvedVersion, ecosystem: 'NuGet', dev: false, direct, file });
        }
      }
    }
  }
  return [...out.values()];
}

/* ------------------------------------------------------------------ builds */

/** The folder a Gradle build runs from: the nearest one up with a settings file or a wrapper. */
function gradleRoot(root: string, dir: string): string {
  for (let d = dir; ; d = dirname(d)) {
    if (['settings.gradle', 'settings.gradle.kts', 'gradlew'].some((f) => existsSync(join(root, d, f)))) return d;
    if (d === '.' || d === dirname(d)) return dir;
  }
}

/** Groups build files into the builds the tools run: one per Gradle project, Maven reactor, sbt build or .NET project. */
export function findBuilds(root: string, files: string[]): Build[] {
  const builds: Build[] = [];
  const gradle = files.filter((f) => GRADLE_BUILD.test(f));
  for (const f of gradle) builds.push({ tool: 'Gradle', dir: dirname(f), files: [f], file: f });
  // A version catalog belongs to the builds beside it; once they're resolved, so is it.
  for (const c of files.filter((f) => VERSION_CATALOG.test(f))) {
    const owner = builds.find((b) => b.tool === 'Gradle' && gradleRoot(root, b.dir) === dirname(dirname(c)));
    if (owner) owner.files.push(c);
  }
  // Maven runs once from the topmost pom.xml, which covers its modules.
  const poms = files.filter(isPomXml).sort((a, b) => a.split('/').length - b.split('/').length);
  for (const p of poms) {
    const top = builds.find((b) => b.tool === 'Maven' && (b.dir === '.' || p.startsWith(`${b.dir}/`)));
    if (top) top.files.push(p);
    else builds.push({ tool: 'Maven', dir: dirname(p), files: [p], file: p });
  }
  for (const s of files.filter((f) => SBT_BUILD.test(f))) {
    const dir = /(^|\/)project\/[\w-]+\.scala$/.test(s) ? dirname(dirname(s)) : dirname(s);
    const build = builds.find((b) => b.tool === 'sbt' && b.dir === dir);
    if (build) build.files.push(s);
    else builds.push({ tool: 'sbt', dir, files: [s], file: `${dir === '.' ? '' : `${dir}/`}build.sbt` });
  }
  for (const p of files.filter(isDotnetProject)) builds.push({ tool: '.NET', dir: dirname(p), files: [p], file: p });
  return builds;
}

/** The project's own wrapper if it has one, otherwise the tool on PATH. */
function wrapper(root: string, dir: string, names: [string, string], fallback: string, platform: NodeJS.Platform): string {
  const name = platform === 'win32' ? names[1] : names[0];
  for (let d = dir; ; d = dirname(d)) {
    if (existsSync(join(root, d, name))) return join(root, d, name);
    if (d === '.' || d === dirname(d)) return fallback;
  }
}

/** The artifactId a pom.xml declares for itself, not its parent's. */
function artifactIdOf(text: string): string {
  return /<artifactId>\s*([^<\s]+)\s*<\/artifactId>/.exec(text.replace(/<parent>[\s\S]*?<\/parent>/, ''))?.[1] ?? '';
}

const LOCK_TIP: Record<Tool, string> = {
  Gradle: 'turn on Gradle dependency locking (dependencyLocking { lockAllConfigurations() } in build.gradle, then gradle dependencies --write-locks) and commit gradle.lockfile',
  Maven: 'generate a CycloneDX SBOM (mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom) and pass it with --sbom, or let fortis ci init add that step',
  sbt: 'add sbt-dependency-lock and commit its build.sbt.lock',
  '.NET': 'set <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile> and commit packages.lock.json',
};

const lastLine = (s: string) => s.trim().split(/\r?\n/).filter((l) => l.trim()).pop()?.trim().slice(0, 200) ?? '';

/** Asks each build's tool for its full tree. Never throws: a build the tool can't resolve is read as before. */
export async function resolveTrees(root: string, files: string[], opts: { offline?: boolean; run?: Runner; timeoutMs?: number; platform?: NodeJS.Platform } = {}): Promise<ResolvedTree> {
  const run = opts.run ?? runCommand;
  const platform = opts.platform ?? process.platform;
  const timeoutMs = opts.timeoutMs ?? RESOLVE_TIMEOUT_MS;
  const result: ResolvedTree = { packages: [], covered: new Set(), notes: [] };

  for (const build of findBuilds(root, files)) {
    const cwd = join(root, build.dir);
    let cmd: string;
    let args: string[];
    let tmp: string | null = null;
    switch (build.tool) {
      case 'Gradle': {
        const top = gradleRoot(root, build.dir);
        cmd = wrapper(root, top, ['gradlew', 'gradlew.bat'], 'gradle', platform);
        args = ['-q', '--console=plain', '-p', cwd, 'dependencies', '--configuration', 'runtimeClasspath', ...(opts.offline ? ['--offline'] : [])];
        break;
      }
      case 'Maven':
        tmp = mkdtempSync(join(tmpdir(), 'fortis-mvn-'));
        cmd = wrapper(root, build.dir, ['mvnw', 'mvnw.cmd'], 'mvn', platform);
        args = ['-B', '-q', 'dependency:tree', `-DoutputFile=${join(tmp, 'tree.txt')}`, '-DappendOutput=true', ...(opts.offline ? ['-o'] : [])];
        break;
      case 'sbt':
        cmd = 'sbt';
        args = ['-batch', '-no-colors', ...(opts.offline ? ['set ThisBuild / offline := true'] : []), 'dependencyTree'];
        break;
      case '.NET':
        cmd = 'dotnet';
        args = ['list', join(root, build.file), 'package', '--include-transitive', '--format', 'json'];
        break;
    }

    try {
      // dotnet list reads what restore wrote; restore first unless offline (offline, a restored project still works).
      if (build.tool === '.NET' && !opts.offline && !existsSync(join(cwd, 'obj', 'project.assets.json'))) {
        const restored = await run('dotnet', ['restore', join(root, build.file)], { cwd, timeoutMs });
        if (restored.missing) throw Object.assign(new Error('missing'), { missing: true });
      }
      const res = await run(cmd, args, { cwd, timeoutMs });
      if (res.missing) {
        result.notes.push(`--resolve: ${build.tool} isn't installed here${build.tool === 'Gradle' || build.tool === 'Maven' ? ' and the project has no wrapper' : ''}, so ${build.file} was read on its own: only the libraries it declares were checked.`);
        continue;
      }
      if (res.code !== 0) {
        result.notes.push(`--resolve: ${build.tool} couldn't list ${build.file}'s dependencies (exit ${res.code}${lastLine(res.stderr || res.stdout) ? `: ${lastLine(res.stderr || res.stdout)}` : ''}), so only the libraries it declares were checked.${opts.offline ? ' With --offline, the tool can only use what is already in its local cache.' : ''}`);
        continue;
      }
      let packages: (Locked & { file: string })[];
      if (build.tool === 'Gradle') packages = parseGradleTree(res.stdout, build.file);
      else if (build.tool === 'sbt') packages = parseSbtTree(res.stdout, build.file);
      else if (build.tool === '.NET') packages = parseDotnetList(res.stdout, build.file);
      else {
        const byArtifact = new Map(build.files.map((f) => [artifactIdOf(readFileSync(join(root, f), 'utf8')), f]));
        packages = parseMavenTree(readFileSync(join(tmp!, 'tree.txt'), 'utf8'), (a) => byArtifact.get(a) ?? build.file);
      }
      if (!packages.length) {
        result.notes.push(`--resolve: ${build.tool} listed no dependencies for ${build.file}, so it was read on its own.`);
        continue;
      }
      result.packages.push(...packages);
      for (const f of build.files) result.covered.add(f);
      const indirect = packages.filter((p) => !p.direct).length;
      result.notes.push(`--resolve: ${build.tool} listed ${packages.length} packages for ${build.file}, ${indirect} of them indirect. So the next scan needs no flag, ${LOCK_TIP[build.tool]}.`);
    } catch (e) {
      if ((e as { missing?: boolean }).missing) result.notes.push(`--resolve: ${build.tool} isn't installed here, so ${build.file} was read on its own: only the libraries it declares were checked.`);
      else result.notes.push(`--resolve: couldn't read ${build.tool}'s answer for ${build.file} (${(e as Error).message}), so only the libraries it declares were checked.`);
    } finally {
      if (tmp) rmSync(tmp, { recursive: true, force: true });
    }
  }
  return result;
}

/** Runs a build tool. On Windows the tools (and wrappers) are .bat or .cmd files, which only cmd.exe can start. */
export const runCommand: Runner = (cmd, args, { cwd, timeoutMs }) =>
  new Promise((resolveRun) => {
    const win = process.platform === 'win32';
    const quote = (s: string) => (/[\s"&|<>^]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s);
    const child = win
      ? spawn('cmd.exe', ['/d', '/s', '/c', `"${[cmd, ...args].map(quote).join(' ')}"`], { cwd, windowsVerbatimArguments: true, windowsHide: true })
      : spawn(cmd, args, { cwd });
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (d) => (stdout += d));
    child.stderr?.on('data', (d) => (stderr += d));
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);
    child.on('error', (e) => {
      clearTimeout(timer);
      resolveRun({ code: null, stdout, stderr: (e as Error).message, missing: (e as NodeJS.ErrnoException).code === 'ENOENT' });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      // cmd.exe says "is not recognized" (exit 9009) for a command it can't find; a shell says 127.
      const missing = code === 9009 || code === 127 || /is not recognized as an internal or external command/i.test(stderr);
      if (timedOut) stderr += `\ntimed out after ${Math.round(timeoutMs / 60_000)} minutes`;
      resolveRun({ code: timedOut ? null : code, stdout, stderr, missing });
    });
  });
