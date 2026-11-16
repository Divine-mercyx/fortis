import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { scanDependencies } from '../src/rules/dependencies';
import { findBuilds, parseDotnetList, parseGradleTree, parseMavenTree, parseSbtTree, resolveTrees, type Runner } from '../src/rules/resolve';

/*
 * --resolve (#94): the build tool's tree, read into packages that say which direct library brought each indirect one
 * in. The tool outputs below are written out in each tool's own format; tests/resolve-live.test.ts runs the real tools.
 */

const GRADLE_TREE = `
runtimeClasspath - Runtime classpath of source set 'main'.
+--- org.springframework.boot:spring-boot-starter-log4j2:2.6.1
|    +--- org.apache.logging.log4j:log4j-slf4j-impl:2.14.1
|    |    +--- org.slf4j:slf4j-api:1.7.25 -> 1.7.32
|    |    +--- org.apache.logging.log4j:log4j-api:2.14.1
|    |    \\--- org.apache.logging.log4j:log4j-core:2.14.1
|    |         \\--- org.apache.logging.log4j:log4j-api:2.14.1
|    +--- org.apache.logging.log4j:log4j-core:2.14.1 (*)
|    \\--- org.slf4j:jul-to-slf4j:1.7.32
|         \\--- org.slf4j:slf4j-api:1.7.32
+--- com.google.guava:guava:31.0-jre
+--- org.slf4j:slf4j-api:1.7.32 (c)
+--- project :core
|    \\--- com.fasterxml.jackson.core:jackson-databind:2.13.0
\\--- io.netty:netty-bom:4.1.70.Final (n)

(c) - A dependency constraint, not a dependency. The dependency affected by the constraint occurs elsewhere in the tree.
(*) - Indicates repeated occurrences of a transitive dependency subtree.
`;

const MAVEN_TREE = `com.example:bank:pom:1.0.0
com.example:bank-api:jar:1.0.0
+- org.springframework.boot:spring-boot-starter-log4j2:jar:2.6.1:compile
|  +- org.apache.logging.log4j:log4j-slf4j-impl:jar:2.14.1:compile
|  |  \\- org.apache.logging.log4j:log4j-api:jar:2.14.1:compile
|  \\- org.apache.logging.log4j:log4j-core:jar:2.14.1:compile
+- io.netty:netty-tcnative-boringssl-static:jar:linux-x86_64:2.0.46.Final:runtime
\\- junit:junit:jar:4.13.2:test
   \\- org.hamcrest:hamcrest-core:jar:1.3:test
`;

const SBT_TREE = `[info] welcome to sbt 1.9.7
[info] com.example:bank_2.13:0.1.0-SNAPSHOT [S]
[info]   +-org.typelevel:cats-core_2.13:2.9.0 [S]
[info]   | +-org.typelevel:cats-kernel_2.13:2.9.0 [S]
[info]   | +-org.scala-lang:scala-library:2.13.8 (evicted by: 2.13.12)
[info]   | +-org.scala-lang:scala-library:2.13.12 [S]
[info]   +-ch.qos.logback:logback-classic:1.2.3
[info]     +-ch.qos.logback:logback-core:1.2.3
[success] Total time: 1 s
`;

const DOTNET_LIST = JSON.stringify({
  version: 1,
  parameters: '--include-transitive',
  projects: [{
    path: '/src/Bank/Bank.csproj',
    frameworks: [{
      framework: 'net8.0',
      topLevelPackages: [{ id: 'Serilog.AspNetCore', requestedVersion: '6.0.0', resolvedVersion: '6.0.0' }],
      transitivePackages: [{ id: 'System.Text.Json', resolvedVersion: '6.0.0' }, { id: 'Serilog', resolvedVersion: '2.10.0' }],
    }],
  }],
});

const summary = (pkgs: { name: string; version: string; direct?: boolean; via?: string; dev?: boolean }[]) =>
  Object.fromEntries(pkgs.map((p) => [`${p.name}@${p.version}`, p.direct ? 'direct' : `via ${p.via ?? '?'}${p.dev ? ' (dev)' : ''}`]));

describe('reading each build tool’s tree', () => {
  it('Gradle: the picked version, which direct library brought each one in, and local projects', () => {
    expect(summary(parseGradleTree(GRADLE_TREE, 'build.gradle.kts'))).toEqual({
      'org.springframework.boot:spring-boot-starter-log4j2@2.6.1': 'direct',
      'org.apache.logging.log4j:log4j-slf4j-impl@2.14.1': 'via org.springframework.boot:spring-boot-starter-log4j2',
      // 1.7.25 -> 1.7.32: Gradle picked 1.7.32, so that's what ships.
      'org.slf4j:slf4j-api@1.7.32': 'via org.springframework.boot:spring-boot-starter-log4j2',
      'org.apache.logging.log4j:log4j-api@2.14.1': 'via org.springframework.boot:spring-boot-starter-log4j2',
      'org.apache.logging.log4j:log4j-core@2.14.1': 'via org.springframework.boot:spring-boot-starter-log4j2',
      'org.slf4j:jul-to-slf4j@1.7.32': 'via org.springframework.boot:spring-boot-starter-log4j2',
      'com.google.guava:guava@31.0-jre': 'direct',
      // A local project's own libraries are the build's direct ones. Constraints (c) and unresolved (n) aren't packages.
      'com.fasterxml.jackson.core:jackson-databind@2.13.0': 'direct',
    });
  });

  it('Maven: one tree per module, each on its own pom.xml, test scope as dev-only, classifiers understood', () => {
    const files: Record<string, string> = { bank: 'pom.xml', 'bank-api': 'api/pom.xml' };
    const pkgs = parseMavenTree(MAVEN_TREE, (a) => files[a] ?? 'pom.xml');
    expect(summary(pkgs)).toEqual({
      'org.springframework.boot:spring-boot-starter-log4j2@2.6.1': 'direct',
      'org.apache.logging.log4j:log4j-slf4j-impl@2.14.1': 'via org.springframework.boot:spring-boot-starter-log4j2',
      'org.apache.logging.log4j:log4j-api@2.14.1': 'via org.springframework.boot:spring-boot-starter-log4j2',
      'org.apache.logging.log4j:log4j-core@2.14.1': 'via org.springframework.boot:spring-boot-starter-log4j2',
      'io.netty:netty-tcnative-boringssl-static@2.0.46.Final': 'direct',
      'junit:junit@4.13.2': 'direct',
      'org.hamcrest:hamcrest-core@1.3': 'via junit:junit (dev)',
    });
    expect(new Set(pkgs.map((p) => p.file))).toEqual(new Set(['api/pom.xml']));
    expect(pkgs.find((p) => p.name === 'junit:junit')!.dev).toBe(true);
  });

  it('Maven: reads the console format too, with [INFO] in front', () => {
    const console = MAVEN_TREE.split('\n').map((l) => (l ? `[INFO] ${l}` : l)).join('\n');
    expect(summary(parseMavenTree(console, () => 'pom.xml'))).toEqual(summary(parseMavenTree(MAVEN_TREE, () => 'pom.xml')));
  });

  it('sbt: leaves out versions sbt evicted', () => {
    expect(summary(parseSbtTree(SBT_TREE, 'build.sbt'))).toEqual({
      'org.typelevel:cats-core_2.13@2.9.0': 'direct',
      'org.typelevel:cats-kernel_2.13@2.9.0': 'via org.typelevel:cats-core_2.13',
      'org.scala-lang:scala-library@2.13.12': 'via org.typelevel:cats-core_2.13',
      'ch.qos.logback:logback-classic@1.2.3': 'direct',
      'ch.qos.logback:logback-core@1.2.3': 'via ch.qos.logback:logback-classic',
    });
  });

  it('.NET: top-level and transitive packages (dotnet does not say which package brought one in)', () => {
    const pkgs = parseDotnetList(DOTNET_LIST, 'src/Bank/Bank.csproj');
    expect(summary(pkgs)).toEqual({ 'Serilog.AspNetCore@6.0.0': 'direct', 'System.Text.Json@6.0.0': 'via ?', 'Serilog@2.10.0': 'via ?' });
    expect(pkgs.every((p) => p.ecosystem === 'NuGet')).toBe(true);
  });
});

const dirs: string[] = [];
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});
const project = (files: Record<string, string>) => {
  const dir = mkdtempSync(join(tmpdir(), 'fortis-resolve-'));
  dirs.push(dir);
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(join(dir, path, '..'), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  return dir;
};
type Call = { cmd: string; args: string[]; cwd: string };
const runner = (answer: (call: Call) => Awaited<ReturnType<Runner>>, calls: Call[] = []): Runner => async (cmd, args, { cwd }) => {
  calls.push({ cmd, args, cwd });
  return answer({ cmd, args, cwd });
};
const GRADLE_BUILD = 'plugins { java }\nrepositories { mavenCentral() }\ndependencies {\n  implementation("org.springframework.boot:spring-boot-starter-log4j2:2.6.1")\n}\n';

describe('which builds are resolved, and how', () => {
  it('groups build files into the builds their tools run', () => {
    const dir = project({ 'settings.gradle.kts': '', 'app/build.gradle.kts': '', 'gradle/libs.versions.toml': '', 'pom.xml': '', 'api/pom.xml': '', 'build.sbt': '', 'project/Deps.scala': '', 'src/Bank/Bank.csproj': '' });
    const builds = findBuilds(dir, ['app/build.gradle.kts', 'gradle/libs.versions.toml', 'pom.xml', 'api/pom.xml', 'build.sbt', 'project/Deps.scala', 'src/Bank/Bank.csproj']);
    expect(builds.map((b) => [b.tool, b.file, b.files])).toEqual([
      ['Gradle', 'app/build.gradle.kts', ['app/build.gradle.kts', 'gradle/libs.versions.toml']],
      ['Maven', 'pom.xml', ['pom.xml', 'api/pom.xml']],
      ['sbt', 'build.sbt', ['build.sbt', 'project/Deps.scala']],
      ['.NET', 'src/Bank/Bank.csproj', ['src/Bank/Bank.csproj']],
    ]);
  });

  it("uses the project's Gradle wrapper, asks for what ships (runtimeClasspath), and stays offline with --offline", async () => {
    const dir = project({ 'settings.gradle.kts': '', 'build.gradle.kts': GRADLE_BUILD, gradlew: '#!/bin/sh\n' });
    const calls: Call[] = [];
    const r = await resolveTrees(dir, ['build.gradle.kts'], { offline: true, platform: 'linux', run: runner(() => ({ code: 0, stdout: GRADLE_TREE, stderr: '' }), calls) });
    expect(calls[0]!.cmd).toBe(join(dir, 'gradlew'));
    expect(calls[0]!.args).toEqual(['-q', '--console=plain', '-p', join(dir, '.'), 'dependencies', '--configuration', 'runtimeClasspath', '--offline']);
    expect([...r.covered]).toEqual(['build.gradle.kts']);
    expect(r.packages.find((p) => p.name === 'org.apache.logging.log4j:log4j-core')).toMatchObject({ direct: false, via: 'org.springframework.boot:spring-boot-starter-log4j2', file: 'build.gradle.kts' });
    expect(r.notes.join('\n')).toMatch(/Gradle listed 8 packages for build\.gradle\.kts, 5 of them indirect\. .*dependencyLocking/);
  });

  it('falls back to the build file when the tool is missing, and says why', async () => {
    const dir = project({ 'build.gradle.kts': GRADLE_BUILD });
    const r = await resolveTrees(dir, ['build.gradle.kts'], { platform: 'linux', run: runner(() => ({ code: null, stdout: '', stderr: '', missing: true })) });
    expect(r.covered.size).toBe(0);
    expect(r.packages).toEqual([]);
    expect(r.notes).toEqual(["--resolve: Gradle isn't installed here and the project has no wrapper, so build.gradle.kts was read on its own: only the libraries it declares were checked."]);
  });

  it('falls back when the tool fails, with its last line of output', async () => {
    const dir = project({ 'build.gradle.kts': GRADLE_BUILD });
    const r = await resolveTrees(dir, ['build.gradle.kts'], { offline: true, platform: 'linux', run: runner(() => ({ code: 1, stdout: '', stderr: 'FAILURE: Build failed.\nCould not resolve org.springframework.boot:spring-boot-starter-log4j2:2.6.1.\n' })) });
    expect(r.covered.size).toBe(0);
    expect(r.notes[0]).toContain('exit 1: Could not resolve org.springframework.boot:spring-boot-starter-log4j2:2.6.1.');
    expect(r.notes[0]).toContain('With --offline, the tool can only use what is already in its local cache.');
  });

  it('runs Maven once for the whole reactor and puts each module on its own pom.xml', async () => {
    const dir = project({
      'pom.xml': '<project><artifactId>bank</artifactId><modules><module>api</module></modules></project>',
      'api/pom.xml': '<project><parent><artifactId>bank</artifactId></parent><artifactId>bank-api</artifactId></project>',
    });
    const calls: Call[] = [];
    const run = runner(({ args }) => {
      writeFileSync(args.find((a) => a.startsWith('-DoutputFile='))!.slice('-DoutputFile='.length), MAVEN_TREE);
      return { code: 0, stdout: '', stderr: '' };
    }, calls);
    const r = await resolveTrees(dir, ['pom.xml', 'api/pom.xml'], { platform: 'linux', run });
    expect(calls.map((c) => c.cmd)).toEqual(['mvn']);
    expect(calls[0]!.args.slice(0, 3)).toEqual(['-B', '-q', 'dependency:tree']);
    expect([...r.covered].sort()).toEqual(['api/pom.xml', 'pom.xml']);
    expect(r.packages.find((p) => p.name === 'org.apache.logging.log4j:log4j-core')).toMatchObject({ file: 'api/pom.xml', via: 'org.springframework.boot:spring-boot-starter-log4j2' });
  });

  it('restores a .NET project before listing it, unless it is offline', async () => {
    const dir = project({ 'Bank.csproj': '<Project />' });
    const calls: Call[] = [];
    await resolveTrees(dir, ['Bank.csproj'], { platform: 'linux', run: runner(() => ({ code: 0, stdout: DOTNET_LIST, stderr: '' }), calls) });
    expect(calls.map((c) => c.args.slice(0, 1)[0])).toEqual(['restore', 'list']);
    const offline: Call[] = [];
    await resolveTrees(dir, ['Bank.csproj'], { offline: true, platform: 'linux', run: runner(() => ({ code: 0, stdout: DOTNET_LIST, stderr: '' }), offline) });
    expect(offline.map((c) => c.args[0])).toEqual(['list']);
  });
});

/** The Log4Shell advisories that matter here, with the ranges OSV publishes (only the fields the CLI reads). */
const LOG4J = {
  'GHSA-jfh8-c2jp-5v3q': { id: 'GHSA-jfh8-c2jp-5v3q', summary: 'Remote code injection in Log4j', aliases: ['CVE-2021-44228'], database_specific: { severity: 'CRITICAL' }, affected: [{ package: { ecosystem: 'Maven', name: 'org.apache.logging.log4j:log4j-core' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '2.13.0' }, { fixed: '2.15.0' }] }] }] },
  'GHSA-8489-44mv-ggj8': { id: 'GHSA-8489-44mv-ggj8', summary: 'Improper Input Validation and Injection in Apache Log4j2', aliases: ['CVE-2021-44832'], database_specific: { severity: 'MODERATE' }, affected: [{ package: { ecosystem: 'Maven', name: 'org.apache.logging.log4j:log4j-core' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '2.13.0' }, { fixed: '2.17.1' }] }] }] },
} as Record<string, object>;
const osv: typeof fetch = async (url, init) => {
  const u = String(url);
  if (u.endsWith('/v1/querybatch')) {
    const { queries } = JSON.parse(String(init?.body)) as { queries: { package: { name: string } }[] };
    return new Response(JSON.stringify({ results: queries.map((q) => (q.package.name === 'org.apache.logging.log4j:log4j-core' ? { vulns: Object.keys(LOG4J).map((id) => ({ id })) } : {})) }));
  }
  return new Response(JSON.stringify(LOG4J[decodeURIComponent(u.split('/').pop()!)]));
};

describe('the issue’s sample: a Gradle app whose direct library pulls in a vulnerable Log4j', () => {
  it('with --resolve, finds Log4j, names both libraries and the version that fixes it', async () => {
    const dir = project({ 'settings.gradle.kts': 'rootProject.name = "bank"\n', 'build.gradle.kts': GRADLE_BUILD });
    const r = await scanDependencies(dir, ['build.gradle.kts'], { fetchImpl: osv, resolve: { run: runner(() => ({ code: 0, stdout: GRADLE_TREE, stderr: '' })) } });
    const log4j = r.detections.find((d) => d.title.startsWith('org.apache.logging.log4j:log4j-core@2.14.1'));
    expect(log4j).toMatchObject({ severity: 'critical', file: 'build.gradle.kts', fixedVersion: '2.17.1' });
    expect(log4j!.title).toBe('org.apache.logging.log4j:log4j-core@2.14.1: Remote code injection in Log4j (+1 more)');
    expect(log4j!.fix).toBe(
      'Upgrade to 2.17.1: pin it in build.gradle.kts: dependencies { constraints { implementation("org.apache.logging.log4j:log4j-core:2.17.1") } }.'
        + ' org.apache.logging.log4j:log4j-core comes in through org.springframework.boot:spring-boot-starter-log4j2;'
        + " if the command doesn't move it, upgrade org.springframework.boot:spring-boot-starter-log4j2.",
    );
    expect(r.notes.join('\n')).not.toContain('only the dependencies they declare');
  });

  it('without --resolve, checks only the declared library and points to --resolve', async () => {
    const dir = project({ 'settings.gradle.kts': '', 'build.gradle.kts': GRADLE_BUILD });
    const r = await scanDependencies(dir, ['build.gradle.kts'], { fetchImpl: osv });
    expect(r.detections).toEqual([]);
    expect(r.checked).toBe(1);
    expect(r.notes.join('\n')).toContain('Transitive dependencies need --resolve (which asks Gradle or sbt for the full tree)');
  });
});
