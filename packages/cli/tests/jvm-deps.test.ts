import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { writeCi } from '../src/ci';
import { readPackages } from '../src/rules/dependencies';

/*
 * spring-boot-maven  a parent POM (whose own parent is spring-boot-starter-parent, from Maven Central)
 *                    with properties and dependencyManagement, and two modules that use them
 * android-gradle     an Android app with gradle/libs.versions.toml, a dependency written out in the
 *                    build script, and the SBOM the generated CI step writes
 * sbt-project        build.sbt with %% and a val, plus project/Dependencies.scala
 * sbt-locked         build.sbt with build.sbt.lock from sbt-dependency-lock (its own test's format)
 */
const FIXTURES = join(__dirname, 'fixtures', 'lockfiles');
const read = (dir: string, files: string[], sbom?: string) => {
  const r = readPackages(join(FIXTURES, dir), files, { sbom });
  return { packages: r.packages.map((p) => `${p.file}:${p.line ?? 0} ${p.name}@${p.version}${p.dev ? ' (dev)' : ''}`), notes: r.notes.join('\n') };
};
const ANDROID = ['settings.gradle.kts', 'build.gradle.kts', 'gradle/libs.versions.toml', 'app/build.gradle.kts'];

describe('Spring Boot on Maven', () => {
  it('fills in versions from properties, parent POMs in the repository, and the Spring Boot parent', () => {
    const { packages, notes } = read('spring-boot-maven', ['pom.xml', 'api/pom.xml', 'core/pom.xml']);
    expect(packages).toEqual([
      'api/pom.xml:12 org.springframework.boot:spring-boot-starter-web@3.1.0',
      'api/pom.xml:16 io.jsonwebtoken:jjwt-api@0.11.5',
      'api/pom.xml:20 org.postgresql:postgresql@42.5.0',
      'api/pom.xml:34 org.springframework.boot:spring-boot-starter-test@3.1.0 (dev)',
      'core/pom.xml:13 org.springframework.boot:spring-boot-starter-data-jpa@3.1.0',
      'core/pom.xml:17 org.apache.commons:commons-text@1.9',
    ]);
    // payments-core is a module of this build; jackson-databind's version is in Spring Boot's BOM, outside the repository.
    expect(notes).toContain('pom.xml: checked 6 of 7 declared dependencies; the other 1 get their version from a parent POM or BOM.');
    expect(notes).toContain('fortis ci init adds the step');
  });
});

describe('Android on Gradle with a version catalog', () => {
  it('checks the catalog and full coordinates in build scripts, with test-only libraries as dev', () => {
    const { packages, notes } = read('android-gradle', ANDROID);
    expect(packages).toEqual([
      'gradle/libs.versions.toml:10 androidx.core:core-ktx@1.12.0',
      'gradle/libs.versions.toml:11 com.squareup.retrofit2:retrofit@2.9.0',
      'gradle/libs.versions.toml:12 com.squareup.retrofit2:converter-gson@2.9.0',
      'gradle/libs.versions.toml:13 androidx.compose:compose-bom@2024.02.00',
      'gradle/libs.versions.toml:15 co.paystack.android:paystack@3.1.3',
      'gradle/libs.versions.toml:16 junit:junit@4.13.2 (dev)',
      'gradle/libs.versions.toml:17 androidx.test.espresso:espresso-core@3.5.1 (dev)',
      'app/build.gradle.kts:18 com.squareup.okhttp3:okhttp@4.9.0',
    ]);
    // compose-ui gets its version from the BOM, gson from a variable: named, not guessed.
    expect(notes).toContain('gradle/libs.versions.toml: androidx.compose.ui:ui.');
    expect(notes).toContain('app/build.gradle.kts: com.google.code.gson:gson.');
    expect(notes).toContain('Gradle and sbt build files: only the dependencies they declare were checked.');
    expect(notes).not.toContain('found but no lockfile');
  });

  it('reads the SBOM from the generated CI step instead, transitive dependencies included', () => {
    const { packages } = read('android-gradle', ANDROID, 'build/reports/cyclonedx/bom.json');
    expect(packages.map((p) => p.split(' ')[1])).toEqual([
      'com.squareup.retrofit2:retrofit@2.9.0',
      'com.squareup.okhttp3:okhttp@4.9.0',
      'com.squareup.okio:okio@2.8.0',
      'com.google.code.gson:gson@2.8.5',
    ]);
  });
});

describe('sbt', () => {
  it('reads build.sbt and project/*.scala with Scala versions in the artifact names', () => {
    const { packages, notes } = read('sbt-project', ['build.sbt', 'project/Dependencies.scala', 'project/build.properties']);
    expect(packages).toEqual([
      'build.sbt:10 org.typelevel:cats-core_2.13@2.10.0',
      'build.sbt:11 io.circe:circe-core_2.13@0.14.6',
      'build.sbt:12 io.circe:circe-parser_2.13@0.14.6',
      'build.sbt:13 org.postgresql:postgresql@42.5.0',
      'build.sbt:16 org.scalatest:scalatest_2.13@3.2.17 (dev)',
      'project/Dependencies.scala:5 org.http4s:http4s-ember-server_2.13@0.23.24',
    ]);
    // A dynamic version, and a Scala.js artifact whose name depends on the platform.
    expect(notes).toContain('build.sbt: com.typesafe.akka:akka-http_2.13, org.scala-js:scalajs-dom_2.13.');
  });

  it('prefers build.sbt.lock, which has every dependency', () => {
    expect(read('sbt-locked', ['build.sbt', 'build.sbt.lock']).packages).toEqual([
      'build.sbt.lock:0 org.apache.commons:commons-lang3@3.9',
      'build.sbt.lock:0 org.scala-lang:scala-library@2.12.10',
      'build.sbt.lock:0 org.scala-lang.modules:scala-xml_2.12@1.2.0 (dev)',
      'build.sbt.lock:0 org.scalatest:scalatest_2.12@3.0.8 (dev)',
    ]);
  });
});

describe('fortis ci init on a Gradle project', () => {
  const dirs: string[] = [];
  afterAll(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

  it('adds an SBOM step that leaves the build files alone, and passes the SBOM to the scan', () => {
    const root = mkdtempSync(join(tmpdir(), 'fortis-gradle-'));
    dirs.push(root);
    cpSync(join(FIXTURES, 'android-gradle'), root, { recursive: true });
    const github = readFileSync(join(root, writeCi(root, 'github', { stagingBranch: 'staging' }).path), 'utf8');
    expect(github).toContain('org.cyclonedx.bom:org.cyclonedx.bom.gradle.plugin:3.5.1');
    expect(github).toContain('./gradlew -q cyclonedxBom --init-script "$RUNNER_TEMP/fortis-sbom.gradle"');
    expect(github).toContain('--sbom build/reports/cyclonedx/bom.json');
    expect(github).not.toContain('makeAggregateBom');
    const gitlab = readFileSync(join(root, writeCi(root, 'gitlab', { stagingBranch: 'staging', force: true }).path), 'utf8');
    expect(gitlab).toContain('cyclonedxBom --init-script');
  });

  it('leaves the step out when Gradle locking already lists everything', () => {
    const root = mkdtempSync(join(tmpdir(), 'fortis-gradle-'));
    dirs.push(root);
    cpSync(join(FIXTURES, 'android-gradle'), root, { recursive: true });
    writeFileSync(join(root, 'gradle.lockfile'), 'junit:junit:4.13.2=testRuntimeClasspath\n');
    const github = readFileSync(join(root, writeCi(root, 'github', { stagingBranch: 'staging' }).path), 'utf8');
    expect(github).not.toContain('cyclonedxBom');
  });
});
