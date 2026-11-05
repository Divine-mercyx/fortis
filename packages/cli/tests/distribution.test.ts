import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

// @ts-expect-error a plain script with no type declarations
import { homebrewFormula, parseSums, scoopManifest, wingetManifests, writeManifests } from '../scripts/package-manifests.mjs';
import { assetName, expectedHash, installKind, latestVersion, replaceBinary, selfUpdate, UPDATE_HINT, updateCheckEnabled, updateNotice } from '../src/update';

const dirs: string[] = [];
const temp = () => {
  const d = mkdtempSync(join(tmpdir(), 'fortis-dist-'));
  dirs.push(d);
  return d;
};
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe('how this copy was installed', () => {
  const kind = (execPath: string, exists: (p: string) => boolean = () => false) => installKind({ execPath, isBinary: true, exists });

  it('recognises each package manager, so it never overwrites their files', () => {
    expect(kind('/opt/homebrew/Cellar/fortis/1.0/bin/fortis')).toBe('homebrew');
    expect(kind('/home/linuxbrew/.linuxbrew/bin/fortis')).toBe('homebrew');
    expect(kind('C:\\Users\\a\\scoop\\apps\\fortis\\current\\fortis.exe')).toBe('scoop');
    expect(kind('C:\\Users\\a\\AppData\\Local\\Microsoft\\WinGet\\Packages\\X\\fortis.exe')).toBe('winget');
  });

  it('recognises Python installs', () => {
    expect(kind('/home/a/.local/share/pipx/venvs/fortis-watchdog/bin/fortis')).toBe('pip');
    expect(kind('/home/a/.local/share/uv/tools/fortis-watchdog/bin/fortis')).toBe('pip');
    expect(kind('/repo/.venv/bin/fortis', (p) => p === '/repo/.venv/bin/activate')).toBe('pip');
    expect(kind('C:\\repo\\.venv\\Scripts\\fortis.exe', (p) => p.endsWith('/activate.bat'))).toBe('pip');
    expect(kind('C:\\Python312\\Scripts\\fortis.exe')).toBe('pip');
  });

  it('treats the installers and a downloaded binary as able to update themselves', () => {
    expect(kind('/home/a/.fortis/bin/fortis')).toBe('binary');
    expect(kind('C:\\Users\\a\\.fortis\\bin\\fortis.exe')).toBe('binary');
    expect(kind('/usr/local/bin/fortis')).toBe('binary');
  });

  it('recognises the Docker image, and scripts run by Node', () => {
    expect(kind('/usr/local/bin/fortis', (p) => p === '/.dockerenv')).toBe('docker');
    expect(installKind({ execPath: '/usr/bin/node', isBinary: false })).toBe('npm');
  });

  it('has an update command for everything except a binary', () => {
    for (const k of ['npm', 'pip', 'homebrew', 'scoop', 'winget', 'docker'] as const) expect(UPDATE_HINT[k]).toBeTruthy();
  });
});

describe('finding the right download', () => {
  it('names the asset for each system', () => {
    expect(assetName('linux', 'x64', false)).toBe('fortis-linux-x64.tar.gz');
    expect(assetName('linux', 'arm64', false)).toBe('fortis-linux-arm64.tar.gz');
    expect(assetName('linux', 'x64', true)).toBe('fortis-linux-x64-musl.tar.gz');
    expect(assetName('linux', 'arm64', true)).toBe('fortis-linux-arm64-musl.tar.gz');
    expect(assetName('darwin', 'arm64', false)).toBe('fortis-macos-arm64.tar.gz');
    expect(assetName('win32', 'x64', false)).toBe('fortis-windows-x64.zip');
    expect(assetName('win32', 'arm64', false)).toBeNull();
    expect(assetName('freebsd', 'x64', false)).toBeNull();
  });

  it('reads a checksum listing, in text or binary mode', () => {
    const sums = `${'a'.repeat(64)}  one.tar.gz\n${'B'.repeat(64)} *two.zip\r\n`;
    expect(expectedHash(sums, 'one.tar.gz')).toBe('a'.repeat(64));
    expect(expectedHash(sums, 'two.zip')).toBe('b'.repeat(64));
    expect(expectedHash(sums, 'three')).toBeNull();
    expect(expectedHash(`${'a'.repeat(64)}  one.tar.gz.sig\n`, 'one.tar.gz')).toBeNull();
  });

  it('reads the latest version from where GitHub redirects', async () => {
    const answer = (location?: string) => (async () => new Response(null, { status: 302, headers: location ? { location } : {} })) as unknown as typeof fetch;
    expect(await latestVersion({ fetchImpl: answer('https://github.com/o/r/releases/tag/cli-v1.2.3-beta.4') })).toBe('1.2.3-beta.4');
    expect(await latestVersion({ fetchImpl: answer('https://github.com/o/r/releases') })).toBeNull();
    expect(await latestVersion({ fetchImpl: answer() })).toBeNull();
    expect(await latestVersion({ fetchImpl: (async () => { throw new Error('offline'); }) as typeof fetch })).toBeNull();
  });
});

describe('replacing the binary', () => {
  it('renames over it on macOS and Linux', () => {
    const d = temp();
    writeFileSync(join(d, 'fortis'), 'old');
    writeFileSync(join(d, 'new'), 'fresh');
    replaceBinary(join(d, 'fortis'), join(d, 'new'), 'linux');
    expect(readFileSync(join(d, 'fortis'), 'utf8')).toBe('fresh');
    expect(existsSync(join(d, 'new'))).toBe(false);
  });

  it('moves it aside first on Windows, and clears up an earlier leftover', () => {
    const d = temp();
    writeFileSync(join(d, 'fortis.exe'), 'old');
    writeFileSync(join(d, 'fortis.exe.old'), 'older');
    writeFileSync(join(d, 'new'), 'fresh');
    replaceBinary(join(d, 'fortis.exe'), join(d, 'new'), 'win32');
    expect(readFileSync(join(d, 'fortis.exe'), 'utf8')).toBe('fresh');
  });

  it('puts the old one back on Windows if the new one can not move', () => {
    const d = temp();
    writeFileSync(join(d, 'fortis.exe'), 'old');
    expect(() => replaceBinary(join(d, 'fortis.exe'), join(d, 'missing'), 'win32')).toThrow();
    expect(readFileSync(join(d, 'fortis.exe'), 'utf8')).toBe('old');
  });
});

describe('selfUpdate', () => {
  const opts = { platform: 'linux', arch: 'x64', musl: false, env: {} };
  const latest = (v: string) => new Response(null, { status: 302, headers: { location: `https://github.com/o/r/releases/tag/cli-v${v}` } });

  it('does nothing when already on the latest version, and never goes backwards', async () => {
    const d = temp();
    const target = join(d, 'fortis');
    writeFileSync(target, 'old');
    const fetchImpl = (async () => latest('1.0.0')) as unknown as typeof fetch;
    await expect(selfUpdate({ ...opts, target, current: '1.0.0', fetchImpl })).resolves.toEqual({ status: 'current', from: '1.0.0', to: '1.0.0' });
    await expect(selfUpdate({ ...opts, target, current: '2.0.0', fetchImpl })).resolves.toMatchObject({ status: 'current' });
    expect(readFileSync(target, 'utf8')).toBe('old');
  });

  it('refuses a download that does not match its checksum, leaving the binary alone', async () => {
    const d = temp();
    const target = join(d, 'fortis');
    writeFileSync(target, 'old');
    const fetchImpl = (async (url: string) => {
      if (url.endsWith('/releases/latest')) return latest('2.0.0');
      if (url.endsWith('SHA256SUMS')) return new Response(`${'0'.repeat(64)}  fortis-linux-x64.tar.gz\n`);
      return new Response('tampered');
    }) as unknown as typeof fetch;
    await expect(selfUpdate({ ...opts, target, current: '1.0.0', fetchImpl })).rejects.toThrow(/Checksum mismatch/);
    expect(readFileSync(target, 'utf8')).toBe('old');
  });

  it('refuses an asset missing from the checksums, and reports a failed download', async () => {
    const d = temp();
    const target = join(d, 'fortis');
    writeFileSync(target, 'old');
    const unlisted = (async (url: string) => (url.endsWith('SHA256SUMS') ? new Response('') : url.endsWith('/latest') ? latest('2.0.0') : new Response('x'))) as unknown as typeof fetch;
    await expect(selfUpdate({ ...opts, target, current: '1.0.0', fetchImpl: unlisted })).rejects.toThrow(/isn't listed/);
    const missing = (async (url: string) => (url.endsWith('/latest') ? latest('2.0.0') : new Response('', { status: 404 }))) as unknown as typeof fetch;
    await expect(selfUpdate({ ...opts, target, current: '1.0.0', fetchImpl: missing })).rejects.toThrow(/HTTP 404/);
  });

  it('says so when it can not find the latest version', async () => {
    const fetchImpl = (async () => new Response(null, { status: 500 })) as unknown as typeof fetch;
    await expect(selfUpdate({ ...opts, target: join(temp(), 'fortis'), fetchImpl })).rejects.toThrow(/Could not find the latest version/);
  });

  it('builds the download address from the version', async () => {
    const seen: string[] = [];
    const fetchImpl = (async (url: string) => {
      seen.push(url);
      return new Response('', { status: 404 });
    }) as unknown as typeof fetch;
    await selfUpdate({ ...opts, target: join(temp(), 'fortis'), version: 'cli-v3.0.0', fetchImpl }).catch(() => undefined);
    expect(seen).toContain('https://github.com/Divine-mercyx/fortis/releases/download/cli-v3.0.0/fortis-linux-x64.tar.gz');
  });
});

describe('the once-a-day notice', () => {
  const HOUR = 60 * 60 * 1000;
  const redirect = (v: string) => {
    const calls = { n: 0 };
    const fetchImpl = (async () => {
      calls.n++;
      return new Response(null, { status: 302, headers: { location: `https://github.com/o/r/releases/tag/cli-v${v}` } });
    }) as unknown as typeof fetch;
    return { fetchImpl, calls };
  };
  const base = (stateFile: string) => ({ stateFile, current: '1.0.0', hint: 'fortis update' });

  it('tells you about a newer version once a day, and asks GitHub at most once a day', async () => {
    const stateFile = join(temp(), 'nested', 'state.json');
    const { fetchImpl, calls } = redirect('2.0.0');
    const first = await updateNotice({ ...base(stateFile), now: 1000, fetchImpl });
    expect(first).toContain('1.0.0 → 2.0.0');
    expect(first).toContain('fortis update');
    expect(first).toContain('FORTIS_NO_UPDATE_CHECK=1');
    expect(await updateNotice({ ...base(stateFile), now: 1000 + HOUR, fetchImpl })).toBeNull();
    expect(calls.n).toBe(1);
    expect(await updateNotice({ ...base(stateFile), now: 1000 + 25 * HOUR, fetchImpl })).toContain('2.0.0');
    expect(calls.n).toBe(2);
  });

  it('stays quiet when up to date, or on a newer build than the latest release', async () => {
    const stateFile = join(temp(), 'state.json');
    expect(await updateNotice({ ...base(stateFile), now: 1000, fetchImpl: redirect('1.0.0').fetchImpl })).toBeNull();
    const other = join(temp(), 'state.json');
    expect(await updateNotice({ ...base(other), current: '3.0.0', now: 1000, fetchImpl: redirect('2.0.0').fetchImpl })).toBeNull();
  });

  it('does not retry on every command while offline', async () => {
    const stateFile = join(temp(), 'state.json');
    let calls = 0;
    const fetchImpl = (async () => {
      calls++;
      throw new Error('offline');
    }) as unknown as typeof fetch;
    expect(await updateNotice({ ...base(stateFile), now: 1000, fetchImpl })).toBeNull();
    expect(await updateNotice({ ...base(stateFile), now: 2000, fetchImpl })).toBeNull();
    expect(calls).toBe(1);
  });

  it('copes with a damaged state file', async () => {
    const dir = temp();
    const stateFile = join(dir, 'state.json');
    writeFileSync(stateFile, 'not json');
    expect(await updateNotice({ ...base(stateFile), now: 1000, fetchImpl: redirect('2.0.0').fetchImpl })).toContain('2.0.0');
  });

  it('is off in CI and with FORTIS_NO_UPDATE_CHECK', () => {
    expect(updateCheckEnabled({})).toBe(true);
    for (const env of [{ FORTIS_NO_UPDATE_CHECK: '1' }, { CI: 'true' }, { GITHUB_ACTIONS: 'true' }, { GITLAB_CI: 'true' }, { JENKINS_URL: 'x' }, { TF_BUILD: 'True' }, { BUILDKITE: 'true' }, { CIRCLECI: 'true' }, { BITBUCKET_BUILD_NUMBER: '1' }]) {
      expect(updateCheckEnabled(env), JSON.stringify(env)).toBe(false);
    }
  });

  it('never appears in piped output', () => {
    const dir = temp();
    mkdirSync(join(dir, '.fortis'));
    const cli = join(__dirname, '..', 'src', 'index.ts');
    const tsx = join(__dirname, '..', 'node_modules', 'tsx', 'dist', 'cli.mjs');
    const env = { ...process.env, CI: '', GITHUB_ACTIONS: '', HOME: dir, USERPROFILE: dir };
    const out = execFileSync(process.execPath, [tsx, cli, 'rules'], { encoding: 'utf8', env, stdio: ['ignore', 'pipe', 'pipe'] });
    expect(out).not.toContain('newer Fortis');
    expect(existsSync(join(dir, '.fortis', 'update-check.json'))).toBe(false);
  }, 60_000);
});

describe('package manifests', () => {
  const assets = ['fortis-macos-arm64.tar.gz', 'fortis-macos-x64.tar.gz', 'fortis-linux-arm64.tar.gz', 'fortis-linux-x64.tar.gz', 'fortis-windows-x64.zip'];
  const hash = (name: string) => createHash('sha256').update(name).digest('hex');
  const text = assets.map((a) => `${hash(a)}  ${a}`).join('\n');
  const sums = parseSums(text);
  const V = '0.1.0-beta.12';

  it('gives each platform its own URL and hash in the Homebrew formula', () => {
    const rb = homebrewFormula(V, sums) as string;
    for (const a of assets.filter((x) => x.endsWith('.tar.gz'))) {
      expect(rb).toContain(`url "https://github.com/Divine-mercyx/fortis/releases/download/cli-v${V}/${a}"\n      sha256 "${hash(a)}"`);
    }
    expect(rb).toContain('class Fortis < Formula');
    expect(rb).toContain('bin.install "fortis"');
    expect(rb).toContain(`version "${V}"`);
  });

  it('writes a valid Scoop manifest', () => {
    const json = JSON.parse(scoopManifest(V, sums) as string) as { version: string; bin: string; architecture: { '64bit': { url: string; hash: string } } };
    expect(json.version).toBe(V);
    expect(json.bin).toBe('fortis.exe');
    expect(json.architecture['64bit'].hash).toBe(hash('fortis-windows-x64.zip'));
  });

  it('writes the three winget files with an uppercase hash', () => {
    const files = wingetManifests(V, sums) as Record<string, string>;
    expect(Object.keys(files).sort()).toEqual(['DivineMercyx.Fortis.installer.yaml', 'DivineMercyx.Fortis.locale.en-US.yaml', 'DivineMercyx.Fortis.yaml']);
    const installer = files['DivineMercyx.Fortis.installer.yaml']!;
    expect(installer).toContain(`InstallerSha256: ${hash('fortis-windows-x64.zip').toUpperCase()}`);
    expect(installer).toContain('PortableCommandAlias: fortis');
    for (const body of Object.values(files)) expect(body).toContain(`PackageVersion: ${V}`);
  });

  it('refuses a release missing an asset, rather than publishing a broken manifest', () => {
    expect(() => homebrewFormula(V, parseSums(''))).toThrow(/isn't in SHA256SUMS/);
    expect(() => scoopManifest(V, parseSums(''))).toThrow(/isn't in SHA256SUMS/);
  });

  it('writes each one where its repository expects it', () => {
    const out = temp();
    writeManifests(V, text, out);
    expect(existsSync(join(out, 'homebrew', 'Formula', 'fortis.rb'))).toBe(true);
    expect(existsSync(join(out, 'scoop', 'bucket', 'fortis.json'))).toBe(true);
    expect(existsSync(join(out, 'winget', 'DivineMercyx.Fortis.installer.yaml'))).toBe(true);
  });
});

describe('the install script', () => {
  const script = readFileSync(join(__dirname, '..', 'install', 'install.sh'), 'utf8');

  it('uses the musl build rather than refusing, and says what Alpine needs', () => {
    expect(script).toContain('LIBC="-musl"');
    expect(script).toContain('ASSET="fortis-$OS-$ARCH$LIBC.tar.gz"');
    expect(script).toContain('apk add libstdc++');
    expect(script).not.toContain('this system uses musl');
  });
});
