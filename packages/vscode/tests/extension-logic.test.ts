import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { cliCandidates, commandFor, scanArgs, versionAtLeast } from '../src/cli';
import { advisoryUrl, editorPath, hoverText, ignoreComment, lineIndex, parseScanOutput, upgradeCommand, type Finding } from '../src/findings';
import { ScanQueue, type Work } from '../src/queue';

const has = (...paths: string[]) => (p: string) => paths.includes(p);
const LIVE = ['sk', 'live', 'abcdef0123456789abcdef0123456789abcdef01'].join('_');

describe('finding the CLI', () => {
  const look = { platform: 'linux', env: { PATH: '/usr/bin' }, home: '/home/a', workspace: '/w' };

  it('tries the setting, the project, the PATH, then ~/.fortis/bin, in that order', () => {
    const exists = has('/opt/fortis', '/w/node_modules/fortis-watchdog/dist/fortis.js', '/w/.venv/bin/fortis', '/usr/bin/fortis', '/home/a/.fortis/bin/fortis');
    expect(cliCandidates('/opt/fortis', { ...look, exists }).map((c) => [c.kind, c.path])).toEqual([
      ['executable', '/opt/fortis'],
      ['node-script', '/w/node_modules/fortis-watchdog/dist/fortis.js'],
      ['executable', '/w/.venv/bin/fortis'],
      ['executable', '/usr/bin/fortis'],
      ['executable', '/home/a/.fortis/bin/fortis'],
    ]);
  });

  it('finds Windows executables and npm shims', () => {
    const exists = has('C:\\w\\.venv\\Scripts\\fortis.exe', 'C:\\npm\\fortis.cmd');
    const found = cliCandidates('', { platform: 'win32', env: { Path: 'C:\\npm' }, home: 'C:\\Users\\a', workspace: 'C:\\w', exists });
    expect(found.map((c) => [c.kind, c.path])).toEqual([['executable', 'C:\\w\\.venv\\Scripts\\fortis.exe'], ['windows-shim', 'C:\\npm\\fortis.cmd']]);
  });

  it('finds nothing when none is installed, so the bundled one is used', () => {
    expect(cliCandidates('', { ...look, exists: () => false })).toEqual([]);
  });

  it('declares the path setting machine-only, and refuses untrusted folders', () => {
    const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8')) as {
      capabilities: { untrustedWorkspaces: { supported: boolean } };
      contributes: { configuration: { properties: Record<string, { scope?: string }> } };
    };
    // A cloned repository must not be able to choose what runs on this machine.
    expect(pkg.contributes.configuration.properties['fortis.cliPath']!.scope).toBe('machine');
    expect(pkg.capabilities.untrustedWorkspaces.supported).toBe(false);
  });
});

describe('running the CLI', () => {
  it('uses the editor runtime for scripts, so no Node install is needed', () => {
    expect(commandFor({ label: '', kind: 'node-script', path: '/x/fortis.mjs' }, ['--version'], '/editor')).toEqual({ command: '/editor', args: ['/x/fortis.mjs', '--version'], env: { ELECTRON_RUN_AS_NODE: '1' }, windowsVerbatimArguments: false });
  });

  it('starts a .cmd through cmd.exe with its path quoted', () => {
    const c = commandFor({ label: '', kind: 'windows-shim', path: 'C:\\Program Files\\nodejs\\fortis.cmd' }, ['scan', '--json']);
    expect(c.command).toBe('cmd.exe');
    expect(c.args.at(-1)).toBe('""C:\\Program Files\\nodejs\\fortis.cmd" scan --json"');
    expect(c.windowsVerbatimArguments).toBe(true);
  });

  it('never lets a scan from the editor upload', () => {
    for (const paths of [true, false]) for (const offline of [true, false]) expect(scanArgs({ paths, offline })).toContain('--no-upload');
    expect(scanArgs({ paths: true, offline: true })).toEqual(['scan', '--json', '--no-upload', '--offline', '--paths-from', '-']);
  });

  it('compares versions, including pre-releases', () => {
    expect(versionAtLeast('0.1.0-beta.12', '0.1.0-beta.12')).toBe(true);
    expect(versionAtLeast('0.1.0-beta.13', '0.1.0-beta.12')).toBe(true);
    expect(versionAtLeast('0.1.0-beta.9', '0.1.0-beta.12')).toBe(false);
    expect(versionAtLeast('0.1.0', '0.1.0-beta.12')).toBe(true);
    expect(versionAtLeast('0.0.9', '0.1.0-beta.12')).toBe(false);
    expect(versionAtLeast('1.0.0-rc.1', '0.1.0-beta.12')).toBe(true);
  });
});

describe('showing findings', () => {
  const dep: Finding = {
    ruleId: 'DEP-OSV', severity: 'high', title: 'axios@0.21.1: SSRF', file: 'package-lock.json', line: 0, snippet: 'axios@0.21.1 · CVE-2021-3749',
    fix: 'Upgrade to 1.6.0: npm install axios@1.6.0.', fixedVersion: '1.6.0',
  };
  const own: Finding = { ruleId: 'FX-OWN-001', severity: 'critical', title: 'Money record read without an ownership check', file: 'src/a.py', line: 3 };

  it('hovers with the same text as fortis explain, in the language of the file', () => {
    const text = hoverText(own);
    expect(text).toContain('**FX-OWN-001**');
    expect(text).toContain('**Why it matters**');
    expect(text).toContain('**How to fix it**');
    expect(hoverText({ ...own, file: 'src/a.js' })).not.toEqual(text);
  });

  it('prefers the advice for this finding, and copes with a rule it does not know', () => {
    expect(hoverText(dep)).toContain('npm install axios@1.6.0');
    expect(hoverText({ ...own, ruleId: 'NEW-RULE' })).toContain('**NEW-RULE**');
  });

  it('gets the upgrade command from each kind of advice', () => {
    expect(upgradeCommand(dep)).toBe('npm install axios@1.6.0');
    expect(upgradeCommand({ fix: 'Upgrade to 2.0: pip install "x==2.0". x comes in through y; if the command does not move it, upgrade y.' })).toBe('pip install "x==2.0"');
    expect(upgradeCommand({ fix: 'No fixed version yet for GHSA-1. Upgrading to 1.5.2 (npm install a@1.5.2) clears the rest. Check the advisory.' })).toBe('npm install a@1.5.2');
    expect(upgradeCommand({ fix: 'No fixed version yet for GHSA-1. Check the advisory for a workaround, or replace the package.' })).toBeNull();
    expect(upgradeCommand({})).toBeNull();
  });

  it('links only dependency findings to an advisory', () => {
    expect(advisoryUrl(dep)).toBe('https://osv.dev/vulnerability/CVE-2021-3749');
    expect(advisoryUrl(own)).toBeNull();
    expect(advisoryUrl({ ...dep, snippet: 'axios@1 · <script>' })).toBeNull();
  });

  it('puts a finding with no line on the first one', () => {
    expect(lineIndex({ line: 0 })).toBe(0);
    expect(lineIndex({ line: 5 })).toBe(4);
  });

  it('writes the ignore comment each language needs', () => {
    const c = (lang: string) => ignoreComment(own, lang, '  ', 'staff only');
    expect(c('typescript')).toBe('  // fortis-ignore-next-line: staff only');
    expect(c('python')).toBe('  # fortis-ignore-next-line: staff only');
    expect(c('yaml')).toBe('  # fortis-ignore-next-line: staff only');
    expect(c('sql')).toBe('  -- fortis-ignore-next-line: staff only');
    expect(c('html')).toBe('  <!-- fortis-ignore-next-line: staff only -->');
    expect(c('css')).toBe('  /* fortis-ignore-next-line: staff only */');
  });

  it('offers no ignore where a comment can not go, and keeps a reason from closing it early', () => {
    expect(ignoreComment(own, 'json', '', 'x')).toBeNull();
    expect(ignoreComment(dep, 'typescript', '', 'x')).toBeNull();
    expect(ignoreComment(own, 'html', '', 'a --> b\nc')).toBe('<!-- fortis-ignore-next-line: a b c -->');
  });

  it('rejects output from a CLI too old to use', () => {
    expect(() => parseScanOutput('{"detections":[]}')).toThrow(/up to date/);
    expect(parseScanOutput('{"root":"/r","detections":[]}')).toEqual({ root: '/r', detections: [], notes: [], filesScanned: undefined });
  });
});

describe('the scan queue', () => {
  it('gathers saves into one scan, and runs one at a time', async () => {
    vi.useFakeTimers();
    try {
      const runs: Work[] = [];
      let finish = () => {};
      const queue = new ScanQueue((work) => {
        runs.push(work);
        return new Promise<void>((r) => (finish = r));
      }, 100);
      queue.request(['a']);
      queue.request(['b']);
      queue.request(['a']);
      await vi.advanceTimersByTimeAsync(100);
      expect(runs).toEqual([{ all: false, paths: ['a', 'b'] }]);

      // Saves during a scan wait for it to finish.
      queue.request(['c']);
      queue.request();
      await vi.advanceTimersByTimeAsync(500);
      expect(runs).toHaveLength(1);
      finish();
      await vi.advanceTimersByTimeAsync(0);
      expect(runs[1]).toEqual({ all: true, paths: ['c'] });
      finish();
      queue.dispose();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('with the real CLI', () => {
  const cli = join(__dirname, '..', '..', 'cli', 'src', 'index.ts');
  const tsx = join(__dirname, '..', '..', 'cli', 'node_modules', 'tsx', 'dist', 'cli.mjs');
  let dir: string;
  const g = (...a: string[]) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
  const scan = (cwd: string, args: string[], input = '') => {
    const r = spawnSync(process.execPath, [tsx, cli, ...args], { cwd, input, encoding: 'utf8', env: { ...process.env, FORTIS_KEY: '', HOME: dir, USERPROFILE: dir, NO_COLOR: '1' } });
    return { status: r.status, out: parseScanOutput(r.stdout), raw: r.stdout };
  };

  beforeAll(() => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), 'fortis-vscode-')));
    g('init', '-q');
    g('config', 'user.email', 't@example.com');
    g('config', 'user.name', 'Test');
    mkdirSync(join(dir, 'src'));
    writeFileSync(join(dir, 'src', 'pay.js'), `const PAYSTACK = "${LIVE}";\n`);
    writeFileSync(join(dir, 'src', 'other.js'), `const OTHER = "${LIVE}";\n`);
    g('add', '-A');
    g('commit', '-q', '-m', 'init');
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('scans only the saved file, from any folder, with its secret masked', () => {
    const { status, out, raw } = scan(join(dir, 'src'), scanArgs({ paths: true, offline: true }), `${join(dir, 'src', 'pay.js')}\n`);
    expect(status).toBe(1);
    expect(out.detections.map((d) => [d.ruleId, d.file, d.line])).toEqual([['FX-SEC-001', 'src/pay.js', 1]]);
    expect(raw).not.toContain(LIVE);
    expect(editorPath(join(dir, 'src'), out.root, out.detections[0]!.file)).toBe(join(dir, 'src', 'pay.js'));
  });

  it('ignores paths outside the repository, and finds nothing wrong with an empty list', () => {
    const outside = join(tmpdir(), 'not-in-this-repo.js');
    const { status, out } = scan(dir, scanArgs({ paths: true, offline: true }), `${outside}\n`);
    expect(status).toBe(0);
    expect(out.detections).toEqual([]);
  });

  it('honours the comment the quick fix writes', () => {
    const file = join(dir, 'src', 'ignored.js');
    writeFileSync(file, `${ignoreComment({ ruleId: 'FX-SEC-001' }, 'javascript', '', 'test fixture')}\nconst K = "${LIVE}";\n`);
    expect(scan(dir, scanArgs({ paths: true, offline: true }), file).out.detections).toEqual([]);
    rmSync(file);
  });

  it('marks findings accepted in the baseline', () => {
    expect(spawnSync(process.execPath, [tsx, cli, 'baseline', '--offline'], { cwd: dir, encoding: 'utf8', env: { ...process.env, FORTIS_KEY: '', HOME: dir, USERPROFILE: dir } }).status).toBe(0);
    const { out } = scan(dir, scanArgs({ paths: false, offline: true }));
    expect(out.detections.length).toBeGreaterThan(0);
    expect(out.detections.every((d) => d.baseline === true)).toBe(true);
    rmSync(join(dir, '.fortis-baseline.json'));
  });
});
