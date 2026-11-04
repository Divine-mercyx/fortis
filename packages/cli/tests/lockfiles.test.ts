import { describe, expect, it } from 'vitest';

import { cycloneDx, findLockfiles, fromPurl, missingLockfiles, parseLockfile } from '../src/rules/lockfiles';

const names = (file: string, text: string) => parseLockfile(file, text).packages.map((p) => `${p.name}@${p.version}${p.dev ? ' dev' : ''}`);

describe('lockfile formats', () => {
  it('package-lock.json: installed packages only, not the project or its workspaces', () => {
    const text = JSON.stringify({
      packages: {
        '': { version: '1.0.0' },
        'apps/web': { version: '0.1.0' },
        'node_modules/axios': { version: '0.21.1' },
        'node_modules/a/node_modules/b': { version: '2.0.0', dev: true },
        'node_modules/web': { version: '0.1.0', link: true },
      },
    });
    const parsed = parseLockfile('package-lock.json', text);
    expect(parsed.packages.map((p) => `${p.name}@${p.version}${p.dev ? ' dev' : ''}`)).toEqual(['axios@0.21.1', 'b@2.0.0 dev']);
    expect(parsed.packages[0]!.ecosystem).toBe('npm');
  });

  it('yarn.lock: classic and Berry', () => {
    const classic = `# yarn lockfile v1\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.1.2"\n  resolved "https://x"\n\nleft-pad@^1.3.0:\n  version "1.3.0"\n`;
    expect(names('yarn.lock', classic)).toEqual(['@babel/core@7.1.2', 'left-pad@1.3.0']);
    const berry = `__metadata:\n  version: 8\n\n"axios@npm:^1.0.0":\n  version: 1.6.0\n\n"my-app@workspace:.":\n  version: 0.0.0-use.local\n`;
    expect(names('yarn.lock', berry)).toEqual(['axios@1.6.0']);
  });

  it('pnpm-lock.yaml: v9, v6 and old-style keys', () => {
    const v9 = `lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      next:\n        specifier: ^15\n        version: 15.0.0(react@19.0.0)\n      '@babel/core':\n        specifier: ^7\n        version: 7.1.2\n\npackages:\n\n  '@babel/core@7.1.2':\n    resolution: {integrity: x}\n\n  next@15.0.0(react@19.0.0):\n    resolution: {integrity: y}\n\nsnapshots:\n\n  '@babel/core@7.1.2': {}\n\n  next@15.0.0(react@19.0.0): {}\n\n  ignored@9.9.9: {}\n`;
    expect(names('pnpm-lock.yaml', v9)).toEqual(['@babel/core@7.1.2', 'next@15.0.0']);
    const v6 = `packages:\n\n  /axios@1.6.0:\n    resolution: {integrity: x}\n    dev: true\n`;
    expect(names('pnpm-lock.yaml', v6)).toEqual(['axios@1.6.0 dev']);
    const v5 = `packages:\n\n  /@scope/name/1.2.3_peer@1:\n    dev: false\n  /left-pad/1.3.0:\n    dev: false\n`;
    expect(names('pnpm-lock.yaml', v5)).toEqual(['@scope/name@1.2.3', 'left-pad@1.3.0']);
  });

  it('pnpm-lock.yaml: keeps package names with underscores', () => {
    const text = `packages:\n\n  string_decoder@1.3.0:\n    resolution: {integrity: x}\n\n  /safe_buffer/5.2.1_peer@1:\n    resolution: {integrity: y}\n`;
    expect(names('pnpm-lock.yaml', text)).toEqual(['string_decoder@1.3.0', 'safe_buffer@5.2.1']);
  });

  describe('pnpm-lock.yaml v9: working out dev packages from the dependency graph', () => {
    const lock = (importers: string, snapshots: string, packages: string[]) => [
      "lockfileVersion: '9.0'", '', 'importers:', '', importers, '', 'packages:', '',
      ...packages.map((p) => `  ${p}:\n    resolution: {integrity: x}\n`), 'snapshots:', '', snapshots, '',
    ].join('\n');
    const dep = (group: string, name: string, version: string) => `    ${group}:\n      ${name}:\n        specifier: ^1\n        version: ${version}`;
    const devOf = (text: string) => Object.fromEntries(parseLockfile('pnpm-lock.yaml', text).packages.map((p) => [`${p.name}@${p.version}`, p.dev]));

    it('marks what only dev tools need, following chains and peer suffixes', () => {
      const text = lock(
        `  .:\n${dep('dependencies', 'express', '4.0.0(peer@1.0.0)')}\n${dep('devDependencies', 'vitest', '3.0.0')}`,
        [
          '  express@4.0.0(peer@1.0.0):\n    dependencies:\n      qs: 6.0.0\n      \'@scope/deep\': 2.0.0',
          '  qs@6.0.0: {}',
          "  '@scope/deep@2.0.0': {}",
          '  peer@1.0.0: {}',
          '  vitest@3.0.0:\n    dependencies:\n      tinypool: 1.1.1\n      qs: 6.0.0\n    transitivePeerDependencies:\n      - supports-color',
          '  tinypool@1.1.1: {}',
        ].join('\n\n'),
        ['express@4.0.0', 'qs@6.0.0', "'@scope/deep@2.0.0'", 'peer@1.0.0', 'vitest@3.0.0', 'tinypool@1.1.1'],
      );
      expect(devOf(text)).toEqual({
        'express@4.0.0': false, 'qs@6.0.0': false, '@scope/deep@2.0.0': false,
        'vitest@3.0.0': true, 'tinypool@1.1.1': true, 'peer@1.0.0': true,
      });
    });

    it('counts a package as production if any workspace package needs it at run time', () => {
      const text = lock(
        `  apps/api:\n${dep('dependencies', 'zod', '3.0.0')}\n\n  apps/web:\n${dep('devDependencies', 'zod', '3.0.0')}`,
        '  zod@3.0.0: {}',
        ['zod@3.0.0'],
      );
      expect(devOf(text)).toEqual({ 'zod@3.0.0': false });
    });

    it('follows optional dependencies and aliases, and ignores workspace links', () => {
      const text = lock(
        `  .:\n${dep('dependencies', 'alias-name', 'real-name@1.0.0')}\n${dep('dependencies', '\'@fortis/shared\'', 'link:packages/shared')}\n${dep('optionalDependencies', 'fsevents', '2.0.0')}`,
        '  real-name@1.0.0: {}\n\n  fsevents@2.0.0:\n    optionalDependencies:\n      nested-opt: 1.0.0\n\n  nested-opt@1.0.0: {}',
        ['real-name@1.0.0', 'fsevents@2.0.0', 'nested-opt@1.0.0'],
      );
      expect(devOf(text)).toEqual({ 'real-name@1.0.0': false, 'fsevents@2.0.0': false, 'nested-opt@1.0.0': false });
    });

    it('marks everything dev in a project with only dev dependencies', () => {
      const text = lock(`  .:\n${dep('devDependencies', 'vitest', '3.0.0')}`, '  vitest@3.0.0: {}', ['vitest@3.0.0']);
      expect(devOf(text)).toEqual({ 'vitest@3.0.0': true });
    });

    it('checks everything rather than hiding packages when it cannot follow the graph', () => {
      const text = lock(`  .:\n${dep('dependencies', 'express', '4.0.0')}`, '  somethingelse@1.0.0: {}', ['express@4.0.0', 'somethingelse@1.0.0']);
      expect(devOf(text)).toEqual({ 'express@4.0.0': false, 'somethingelse@1.0.0': false });
    });
  });

  it('composer.lock: dev section marked, branch installs skipped', () => {
    const text = JSON.stringify({
      packages: [{ name: 'guzzlehttp/guzzle', version: '7.4.0' }, { name: 'acme/fork', version: 'dev-main' }],
      'packages-dev': [{ name: 'phpunit/phpunit', version: 'v10.0.0' }, { name: 'acme/next', version: '1.x-dev' }],
    });
    const parsed = parseLockfile('composer.lock', text);
    expect(parsed.packages.map((p) => `${p.name} ${p.dev}`)).toEqual(['guzzlehttp/guzzle false', 'phpunit/phpunit true']);
    expect(parsed.packages[0]!.ecosystem).toBe('Packagist');
    expect(parsed.skipped).toBe(2);
  });

  it('poetry.lock and uv.lock: packages, without the project itself', () => {
    const poetry = `[[package]]\nname = "Django"\nversion = "3.2.0"\ndescription = "x"\n\n[package.dependencies]\nsqlparse = ">=0.2"\n\n[[package]]\nname = "pytest_cov"\nversion = "4.0.0"\ncategory = "dev"\n\n[metadata]\nlock-version = "2.0"\n`;
    expect(names('poetry.lock', poetry)).toEqual(['django@3.2.0', 'pytest-cov@4.0.0 dev']);
    const uv = `version = 1\n\n[[package]]\nname = "my-app"\nversion = "0.1.0"\nsource = { virtual = "." }\n\n[[package]]\nname = "flask"\nversion = "2.0.0"\nsource = { registry = "https://pypi.org/simple" }\n`;
    expect(names('apps/api/uv.lock', uv)).toEqual(['flask@2.0.0']);
  });

  it('Pipfile.lock', () => {
    const text = JSON.stringify({ default: { django: { version: '==3.2.0' }, git: {} }, develop: { pytest: { version: '==7.0.0' } } });
    const parsed = parseLockfile('Pipfile.lock', text);
    expect(parsed.packages.map((p) => `${p.name}@${p.version} ${p.dev}`)).toEqual(['django@3.2.0 false', 'pytest@7.0.0 true']);
    expect(parsed.skipped).toBe(1);
  });

  it('requirements.txt: pinned lines only, counting the rest', () => {
    const text = [
      '# comment', '-r base.txt', '--index-url https://pypi.org/simple', 'Django==3.2.0', 'requests[socks]==2.25.0 ; python_version > "3.8"',
      'flask>=2.0', 'gunicorn', 'celery==5.2.0 \\', '    --hash=sha256:abc', 'git+https://github.com/acme/thing.git', '',
    ].join('\n');
    const parsed = parseLockfile('requirements.txt', text);
    expect(parsed.packages.map((p) => `${p.name}@${p.version}`)).toEqual(['django@3.2.0', 'requests@2.25.0', 'celery@5.2.0']);
    expect(parsed.skipped).toBe(2);
    expect(parseLockfile('requirements-dev.txt', 'pytest==7.0.0').packages[0]!.dev).toBe(true);
  });

  it('gradle.lockfile: test-only configurations count as dev', () => {
    const text = `# This is a Gradle generated file\norg.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,runtimeClasspath\norg.junit.jupiter:junit-jupiter:5.9.0=testCompileClasspath,testRuntimeClasspath\nempty=annotationProcessor\n`;
    expect(names('gradle.lockfile', text)).toEqual(['org.apache.logging.log4j:log4j-core@2.14.1', 'org.junit.jupiter:junit-jupiter@5.9.0 dev']);
  });

  it('pom.xml: resolves same-file versions and counts what a parent or BOM decides', () => {
    const text = `<project>
      <parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>3.0.0</version></parent>
      <properties><log4j.version>2.14.1</log4j.version></properties>
      <dependencyManagement><dependencies>
        <dependency><groupId>com.acme</groupId><artifactId>managed</artifactId><version>1.2.3</version></dependency>
        <dependency><groupId>org.springframework.cloud</groupId><artifactId>spring-cloud-dependencies</artifactId><version>2022.0.0</version><type>pom</type><scope>import</scope></dependency>
      </dependencies></dependencyManagement>
      <dependencies>
        <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>\${log4j.version}</version></dependency>
        <dependency><groupId>com.acme</groupId><artifactId>managed</artifactId></dependency>
        <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId><exclusions><exclusion><groupId>x</groupId><artifactId>y</artifactId></exclusion></exclusions></dependency>
        <dependency><groupId>com.acme</groupId><artifactId>sibling</artifactId><version>\${project.version}</version></dependency>
        <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13</version><scope>test</scope></dependency>
        <!-- <dependency><groupId>old</groupId><artifactId>gone</artifactId><version>1.0</version></dependency> -->
      </dependencies>
      <build><plugins><plugin><dependencies><dependency><groupId>plugin</groupId><artifactId>only</artifactId><version>1.0</version></dependency></dependencies></plugin></plugins></build>
    </project>`;
    const parsed = parseLockfile('pom.xml', text);
    expect(parsed.packages.map((p) => `${p.name}@${p.version}${p.dev ? ' dev' : ''}`)).toEqual([
      'org.apache.logging.log4j:log4j-core@2.14.1',
      'com.acme:managed@1.2.3',
      'junit:junit@4.13 dev',
    ]);
    expect(parsed.skipped).toBe(2);
  });

  it('go.mod: single and block requires, without the replace block', () => {
    const text = `module example.com/app\n\ngo 1.22\n\nrequire github.com/acme/one v1.0.0\n\nrequire (\n\tgolang.org/x/text v0.3.5\n\tgithub.com/acme/old v2.0.0+incompatible // indirect\n)\n\nreplace (\n\tgithub.com/x/y v1.0.0 => github.com/z/y v1.1.0\n)\n`;
    expect(names('go.mod', text)).toEqual(['github.com/acme/one@v1.0.0', 'golang.org/x/text@v0.3.5', 'github.com/acme/old@v2.0.0']);
  });

  it('packages.lock.json: one entry per version across frameworks, without project references', () => {
    const text = JSON.stringify({ version: 1, dependencies: { 'net8.0': { 'Newtonsoft.Json': { type: 'Direct', resolved: '12.0.1' }, Shared: { type: 'Project' } }, 'net6.0': { 'Newtonsoft.Json': { type: 'Direct', resolved: '12.0.1' } } } });
    expect(names('packages.lock.json', text)).toEqual(['Newtonsoft.Json@12.0.1']);
  });

  it('Gemfile.lock: top-level gems, without their nested requirements', () => {
    const text = `GIT\n  remote: https://x\n  specs:\n    private-gem (0.1.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.3)\n    nokogiri (1.16.0-x86_64-linux)\n      racc (~> 1.4)\n\nPLATFORMS\n  ruby\n`;
    expect(names('Gemfile.lock', text)).toEqual(['rack@2.2.3', 'nokogiri@1.16.0']);
  });

  it('throws on malformed JSON, so the caller can report it', () => {
    expect(() => parseLockfile('composer.lock', '{ not json')).toThrow();
  });
});

describe('SBOM', () => {
  it('maps package URLs to OSV names', () => {
    expect(fromPurl('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar')).toMatchObject({ name: 'org.apache.logging.log4j:log4j-core', version: '2.14.1', ecosystem: 'Maven' });
    expect(fromPurl('pkg:npm/%40scope/name@1.0.0')).toMatchObject({ name: '@scope/name', ecosystem: 'npm' });
    expect(fromPurl('pkg:composer/guzzlehttp/guzzle@7.4.0')).toMatchObject({ name: 'guzzlehttp/guzzle', ecosystem: 'Packagist' });
    expect(fromPurl('pkg:pypi/Django_Rest@3.0')).toMatchObject({ name: 'django-rest', ecosystem: 'PyPI' });
    expect(fromPurl('pkg:golang/golang.org/x/text@v0.3.5')).toMatchObject({ name: 'golang.org/x/text', ecosystem: 'Go' });
    expect(fromPurl('pkg:generic/thing@1.0')).toBeNull();
  });

  it('reads CycloneDX components, including nested ones', () => {
    const parsed = cycloneDx(JSON.stringify({
      bomFormat: 'CycloneDX',
      components: [
        { purl: 'pkg:maven/a/b@1.0', components: [{ purl: 'pkg:maven/c/d@2.0', scope: 'excluded' }] },
        { name: 'no-purl' },
      ],
    }));
    expect(parsed.packages.map((p) => `${p.name} ${p.dev}`)).toEqual(['a:b false', 'c:d true']);
    expect(parsed.skipped).toBe(1);
  });

  it('rejects files that are not CycloneDX', () => {
    expect(() => cycloneDx('{"spdxVersion":"SPDX-2.3"}')).toThrow(/CycloneDX/);
  });
});

describe('finding lockfiles', () => {
  it('looks in every folder, but not vendored code, tests or ignored paths', () => {
    expect(findLockfiles([
      'package-lock.json', 'apps/api/composer.lock', 'services/pay/pom.xml', 'node_modules/x/package-lock.json', 'vendor/y/composer.lock',
      'tests/fixtures/poetry.lock', 'legacy/go.mod', 'README.md',
    ], ['legacy/**'])).toEqual(['package-lock.json', 'apps/api/composer.lock', 'services/pay/pom.xml']);
  });

  it('prefers a real Python lock over requirements files in the same project', () => {
    expect(findLockfiles(['api/poetry.lock', 'api/requirements.txt', 'api/requirements/dev.txt', 'worker/requirements.txt'])).toEqual(['api/poetry.lock', 'worker/requirements.txt']);
  });

  it('says when a project has no lockfile for an ecosystem it uses', () => {
    const notes = missingLockfiles(['build.gradle', 'composer.json', 'composer.lock', 'tests/package.json'], [], new Set(['Packagist']));
    expect(notes).toHaveLength(1);
    expect(notes[0]).toContain('build.gradle');
  });
});
