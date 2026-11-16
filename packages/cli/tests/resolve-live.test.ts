import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { scanDependencies } from '../src/rules/dependencies';

/*
 * `fortis scan --resolve` with the real Gradle and Maven, Maven Central and OSV (#94): an app that declares only
 * spring-boot-starter-log4j2 2.6.1, which brings in log4j-core 2.14.1 (Log4Shell). The finding has to name both
 * libraries and the version that fixes it. Normal test runs stay offline; turn it on with
 *   FORTIS_LIVE_RESOLVE=1 pnpm --filter fortis-watchdog exec vitest run tests/resolve-live.test.ts
 * It needs gradle and mvn on PATH (GitHub's Ubuntu runners have both).
 */
const LIVE = process.env.FORTIS_LIVE_RESOLVE === '1';
const STARTER = 'org.springframework.boot:spring-boot-starter-log4j2';

const SAMPLES: Record<string, Record<string, string>> = {
  Gradle: {
    'settings.gradle.kts': 'rootProject.name = "bank"\n',
    'build.gradle.kts': `plugins { java }\nrepositories { mavenCentral() }\ndependencies {\n  implementation("${STARTER}:2.6.1")\n}\n`,
  },
  Maven: {
    'pom.xml': `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>bank</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-log4j2</artifactId>
      <version>2.6.1</version>
    </dependency>
  </dependencies>
</project>
`,
  },
};

const dirs: string[] = [];
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

/** "2.17.1" → [2, 17, 1], for comparing versions. */
const parts = (v: string) => v.split(/[.-]/).map((p) => Number.parseInt(p, 10) || 0);
const atLeast = (v: string, min: string) => {
  const [a, b] = [parts(v), parts(min)];
  for (let i = 0; i < Math.max(a.length, b.length); i++) if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) > (b[i] ?? 0);
  return true;
};

describe.skipIf(!LIVE)('fortis scan --resolve with the real build tools', () => {
  for (const [tool, files] of Object.entries(SAMPLES)) {
    it(`${tool}: Log4j that comes in through a Spring Boot starter is found, with both libraries named and the fix`, async () => {
      const dir = mkdtempSync(join(tmpdir(), `fortis-resolve-${tool.toLowerCase()}-`));
      dirs.push(dir);
      for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
      const buildFile = Object.keys(files).find((f) => f !== 'settings.gradle.kts')!;

      const r = await scanDependencies(dir, Object.keys(files), { resolve: {} });
      expect(r.notes.join('\n'), 'the build tool should have listed the tree').toMatch(new RegExp(`--resolve: ${tool} listed \\d+ packages for ${buildFile.replace('.', '\\.')}`));

      const log4j = r.detections.find((d) => d.title.startsWith('org.apache.logging.log4j:log4j-core@2.14.1'));
      expect(log4j, r.notes.join('\n')).toBeDefined();
      expect(log4j!.severity).toBe('critical');
      expect(log4j!.file).toBe(buildFile);
      expect(log4j!.fix).toContain(`org.apache.logging.log4j:log4j-core comes in through ${STARTER}`);
      expect(atLeast(log4j!.fixedVersion!, '2.17.1'), `fixed version ${log4j!.fixedVersion}`).toBe(true);
      expect(log4j!.fix).toContain(`Upgrade to ${log4j!.fixedVersion}`);
    }, 600_000);
  }
});
