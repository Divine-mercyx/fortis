import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const cli = join(__dirname, '..');
const read = (p: string) => readFileSync(join(cli, p), 'utf8').replace(/\r\n/g, '\n');
const git = (cwd: string, ...args: string[]) =>
  execFileSync('git', ['-c', 'user.email=t@example.com', '-c', 'user.name=T', '-c', 'init.defaultBranch=trunk', ...args], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();

const hash = (n: number) => String(n).repeat(64).slice(0, 64);
const SUMS = ['fortis-macos-arm64.tar.gz', 'fortis-macos-x64.tar.gz', 'fortis-linux-arm64.tar.gz', 'fortis-linux-x64.tar.gz', 'fortis-windows-x64.zip']
  .map((a, i) => `${hash(i + 1)}  ${a}`)
  .join('\n');

/** Bare repositories standing in for GitHub, the manifests for 0.1.0, and a way to run the script. */
function setup(repos: { tap?: 'empty' | 'readme'; bucket?: 'empty' | 'readme' }) {
  const root = mkdtempSync(join(tmpdir(), 'fortis-publish-'));
  const remote = join(root, 'remote').replace(/\\/g, '/');
  mkdirSync(remote);
  for (const [name, state] of [['homebrew-tap', repos.tap], ['scoop-bucket', repos.bucket]] as const) {
    if (!state) continue;
    const bare = join(remote, `${name}.git`);
    git(root, 'init', '-q', '--bare', bare);
    if (state === 'readme') {
      const work = join(root, `seed-${name}`);
      git(root, 'clone', '-q', bare, work);
      writeFileSync(join(work, 'README.md'), `# ${name}\n`);
      git(work, 'add', '-A');
      git(work, 'commit', '-qm', 'first');
      git(work, 'push', '-q', 'origin', 'HEAD');
    }
  }
  const out = join(root, 'manifests');
  writeFileSync(join(root, 'SHA256SUMS'), SUMS);
  // Run as the workflow runs it.
  execFileSync(process.execPath, [join(cli, 'scripts', 'package-manifests.mjs'), '--version', 'cli-v0.1.0', '--sums', join(root, 'SHA256SUMS'), '--out', out]);
  const run = () =>
    spawnSync('bash', [join(cli, 'scripts', 'publish-manifests.sh'), out], {
      encoding: 'utf8',
      env: { ...process.env, FORTIS_PACKAGE_REMOTE: remote, PACKAGE_REPOS_TOKEN: 'not-a-real-token', GITHUB_REF_NAME: 'cli-v0.1.0', GIT_CONFIG_GLOBAL: join(root, 'gitconfig') },
    });
  writeFileSync(join(root, 'gitconfig'), '[init]\n\tdefaultBranch = trunk\n');
  const show = (repo: string, what: string) => git(root, `--git-dir=${join(remote, `${repo}.git`)}`, ...what.split(' '));
  return { run, show };
}

describe('publishing the manifests', () => {
  it('commits to a repository with a README, and to an empty one, which gets a main branch', () => {
    const { run, show } = setup({ tap: 'empty', bucket: 'readme' });
    const r = run();
    expect(r.stdout + r.stderr).toContain('updated homebrew-tap');
    expect(r.stdout).toContain('updated scoop-bucket');
    expect(r.status).toBe(0);
    // The runner's git might default to another name (here, trunk); GitHub makes the first pushed branch the default.
    expect(show('homebrew-tap', 'for-each-ref --format=%(refname) refs/heads')).toBe('refs/heads/main');
    expect(show('homebrew-tap', 'ls-tree -r --name-only main')).toBe('Formula/fortis.rb');
    expect(show('homebrew-tap', 'log -1 --format=%s main')).toBe('fortis 0.1.0');
    expect(show('scoop-bucket', 'ls-tree -r --name-only HEAD').split('\n')).toEqual(['README.md', 'bucket/fortis.json']);
  });

  it('does nothing the second time', () => {
    const { run } = setup({ tap: 'readme', bucket: 'readme' });
    expect(run().status).toBe(0);
    const again = run();
    expect(again.status).toBe(0);
    expect(again.stdout).toContain('homebrew-tap is already up to date');
    expect(again.stdout).toContain('scoop-bucket is already up to date');
  });

  it('says which repository is missing, and still updates the other', () => {
    const { run, show } = setup({ bucket: 'readme' });
    const r = run();
    expect(r.status).toBe(1);
    expect(r.stdout).toContain("::error::Couldn't read homebrew-tap. Create it as a public repository, and give PACKAGE_REPOS_TOKEN access to it");
    expect(r.stdout).toContain('updated scoop-bucket');
    expect(show('scoop-bucket', 'log -1 --format=%s')).toBe('fortis 0.1.0');
    expect(r.stdout + r.stderr).not.toContain('not-a-real-token');
  });
});

describe('checking the installs after a release', () => {
  const workflow = readFileSync(join(cli, '..', '..', '.github', 'workflows', 'release-cli.yml'), 'utf8').replace(/\r\n/g, '\n');
  const readme = read('README.md');
  const job = (name: string) => {
    const start = workflow.indexOf(`\n  ${name}:\n`);
    expect(start, name).toBeGreaterThan(-1);
    const next = workflow.slice(start + 1).search(/\n {2}[\w-]+:\n/);
    return workflow.slice(start, next === -1 ? undefined : start + 1 + next);
  };

  it('runs only after the tap and bucket were updated, and uses no secrets', () => {
    const installs = job('package-installs');
    expect(installs).toContain('needs: homebrew-scoop');
    expect(installs).toContain("if: needs.homebrew-scoop.outputs.published == 'true'");
    expect(installs).not.toMatch(/secrets\.|environment:/);
    const publish = job('homebrew-scoop');
    expect(publish).toContain('published: ${{ steps.publish.outputs.published }}');
    expect(publish).toMatch(/id: publish[\s\S]*publish-manifests\.sh[^\n]*\n\s+echo "published=true" >> "\$GITHUB_OUTPUT"/);
  });

  it('installs on macOS, Linux and Windows', () => {
    const installs = job('package-installs');
    expect([...installs.matchAll(/runner: ([\w.-]+), how: (\w+)/g)].map((m) => `${m[1]} ${m[2]}`)).toEqual(['macos-15 brew', 'ubuntu-24.04 brew', 'windows-2025 scoop']);
  });

  it("uses the README's own commands, so they're what gets checked", () => {
    const brew = read('scripts/check-brew-install.sh');
    const scoop = read('scripts/check-scoop-install.ps1');
    for (const command of ['brew install divine-mercyx/tap/fortis']) {
      expect(readme).toContain(command);
      expect(brew).toContain(command);
    }
    for (const command of ['scoop bucket add fortis https://github.com/Divine-mercyx/scoop-bucket', 'scoop install fortis']) {
      expect(readme).toContain(command);
      expect(scoop).toContain(command);
    }
  });

  it('pins and checks the Scoop installer', () => {
    const scoop = read('scripts/check-scoop-install.ps1');
    expect(scoop).toMatch(/ScoopInstaller\/Install\/[0-9a-f]{40}\/install\.ps1/);
    expect(scoop).toMatch(/Get-FileHash \$installer -Algorithm SHA256\)\.Hash -ine '[0-9a-f]{64}'/);
  });
});
