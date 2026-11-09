import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { fingerprintOf, readBaseline, splitByBaseline, writeBaseline } from '../src/baseline';
import { githubWorkflow, gitlabJobs, writeCi } from '../src/ci';
import { zapCommand } from '../src/dast';
import { scanHistory } from '../src/history';
import type { Detection } from '../src/rules/types';
import { githubAnnotations, toSarif } from '../src/sarif';

const LIVE = ['sk', 'live', 'Zq8Xv2Lm4Np6Rt0Ws3Yu5Ab7Cd9Ef1Gh'].join('_');
const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach((d) => rmSync(d, { recursive: true, force: true })));
const tmp = () => {
  const d = mkdtempSync(join(tmpdir(), 'fortis-feat-'));
  dirs.push(d);
  return d;
};

const det = (over: Partial<Detection> = {}): Detection => ({
  ruleId: 'FX-OWN-001', severity: 'critical', title: 'Money record read without an ownership check',
  file: 'src/routes/transfers.ts', line: 41, snippet: 'const t = await Transfer.findById(req.params.id)', ...over,
});

describe('SARIF and annotations', () => {
  it('writes valid SARIF 2.1.0 with rule help, levels, masked snippets and fingerprints', () => {
    const sarif = toSarif([det(), det({ ruleId: 'FX-SEC-001', severity: 'critical', title: 'Live key', file: 'src/config.ts', line: 3, snippet: `const k = '${LIVE}'` })]);
    expect(sarif.version).toBe('2.1.0');
    const run = sarif.runs[0]!;
    expect(run.tool.driver.rules.map((r) => r.id)).toEqual(['FX-OWN-001', 'FX-SEC-001']);
    expect(run.tool.driver.rules[0]!.help.text).toContain('Fix:');
    expect(run.results[0]).toMatchObject({ ruleId: 'FX-OWN-001', level: 'error', ruleIndex: 0 });
    expect(run.results[0]!.locations[0]!.physicalLocation.region.startLine).toBe(41);
    expect(JSON.stringify(sarif)).not.toContain(LIVE);
    expect(run.results[1]!.partialFingerprints.fortis).toHaveLength(40);
  });

  it('emits GitHub annotations with properties escaped', () => {
    const [line] = githubAnnotations([det({ file: 'src/a,b.ts', title: 'x: y' })]);
    expect(line).toMatch(/^::error file=src\/a%2Cb\.ts,line=41,title=Fortis FX-OWN-001%3A x%3A y::/);
  });
});

describe('baseline', () => {
  it('lets known findings through and blocks only new ones, even after the code moves', () => {
    const root = tmp();
    writeBaseline(root, [det()]);
    const baseline = readBaseline(root);
    const moved = det({ line: 90 }); // same code, different line
    const fresh = det({ file: 'src/routes/loans.ts' });
    const split = splitByBaseline([moved, fresh], baseline);
    expect(split.known).toEqual([moved]);
    expect(split.fresh).toEqual([fresh]);
  });

  it('matches the fingerprint the API computes', () => {
    // apps/api ingest: sha256(`${ruleId}|${file}|${masked snippet, whitespace collapsed}`).slice(0, 40)
    const d = det({ snippet: '  const t =   await Transfer.findById(req.params.id)  ' });
    expect(fingerprintOf(d)).toBe(fingerprintOf(det()));
  });
});

describe('git history secrets', () => {
  it('finds a key that was committed and later deleted, at the commit that introduced it', async () => {
    const root = tmp();
    const g = (...a: string[]) => execFileSync('git', a, { cwd: root, encoding: 'utf8' }).trim();
    g('init', '-q', '-b', 'main');
    g('config', 'user.email', 't@example.com');
    g('config', 'user.name', 'T');
    writeFileSync(join(root, 'config.ts'), `export const key = '${LIVE}';\n`);
    g('add', '.');
    g('commit', '-qm', 'add key');
    const sha = g('rev-parse', 'HEAD');
    writeFileSync(join(root, 'config.ts'), 'export const key = process.env.PAYSTACK_SECRET_KEY;\n');
    g('commit', '-qam', 'remove key');
    const res = await scanHistory(root);
    expect(res.commitsScanned).toBe(2);
    expect(res.detections).toHaveLength(1);
    expect(res.detections[0]).toMatchObject({ ruleId: 'FX-SEC-001', severity: 'critical', file: 'config.ts', commit: sha });
    expect(res.detections[0]!.title).toContain('git history');
  });
});

describe('fortis ci init', () => {
  it('writes a GitHub workflow with the scan, SARIF upload and staging test', () => {
    const root = tmp();
    const res = writeCi(root, 'github', { stagingBranch: 'staging' });
    const yml = readFileSync(join(root, res.path), 'utf8');
    expect(res.path).toBe('.github/workflows/fortis.yml');
    expect(yml).toContain('scan --ci --sarif fortis.sarif');
    expect(yml).toContain("github.ref == 'refs/heads/staging'");
    expect(yml).toContain('--wait 600');
    expect(yml).toContain('FORTIS_ZAP_AUTH: ${{ secrets.FORTIS_TEST_TOKEN }}');
    expect(writeCi(root, 'github', { stagingBranch: 'staging' }).written).toBe(false);
  });

  it('needs no Node in GitHub Actions, whatever the project is written in', () => {
    const yml = githubWorkflow({ stagingBranch: 'staging' });
    expect(yml).not.toContain('setup-node');
    expect(yml).not.toContain('npx');
    expect(yml).toContain('releases/download/cli-v');
    expect(yml).not.toMatch(/uses: Divine-mercyx\/fortis@/);
    expect(yml).not.toContain('--sbom');
  });

  it('adds an SBOM step for Maven projects, so transitive dependencies are covered', () => {
    const root = tmp();
    writeFileSync(join(root, 'pom.xml'), '<project/>');
    const github = readFileSync(join(root, writeCi(root, 'github', { stagingBranch: 'staging' }).path), 'utf8');
    expect(github).toContain('makeAggregateBom');
    expect(github).toContain('continue-on-error: true');
    expect(github).toContain('--sbom target/bom.json');
    const gitlab = readFileSync(join(root, writeCi(root, 'gitlab', { stagingBranch: 'staging' }).path), 'utf8');
    expect(gitlab).toContain('makeAggregateBom');
  });

  it('runs the GitLab scan in the Fortis image, with no Node', () => {
    const yml = gitlabJobs({ stagingBranch: 'dev' });
    const scanJob = yml.slice(yml.indexOf('fortis-scan:'), yml.indexOf('fortis-staging:'));
    expect(scanJob).toContain('image: ghcr.io/divine-mercyx/fortis:');
    expect(scanJob).not.toContain('npx');
  });

  const hasPyYaml = (() => {
    try {
      execFileSync('python3', ['-c', 'import yaml'], { stdio: 'ignore' });
      return true;
    } catch {
      return false;
    }
  })();

  it.skipIf(!hasPyYaml)('produces YAML that parses', () => {
    for (const y of [githubWorkflow({ stagingBranch: 'staging' }), gitlabJobs({ stagingBranch: 'dev' })]) {
      const out = execFileSync('python3', ['-c', 'import sys,yaml,json; print(json.dumps(sorted(map(str, yaml.safe_load(sys.stdin).keys()))))'], { input: y, encoding: 'utf8' });
      expect(JSON.parse(out).length).toBeGreaterThan(1);
    }
  });
});

describe('logged-in ZAP', () => {
  it('passes the header by environment name only and pins it to the target host', () => {
    const cmd = zapCommand({ target: 'https://staging.paywave.ng', mode: 'baseline', minutes: 1, name: 'n', local: false, auth: { header: 'Authorization', value: 'Bearer secret-token-123' } });
    expect(cmd).toEqual(expect.arrayContaining(['-e', 'ZAP_AUTH_HEADER=Authorization', '-e', 'ZAP_AUTH_HEADER_VALUE', '-e', 'ZAP_AUTH_HEADER_SITE=staging.paywave.ng']));
    expect(cmd.join(' ')).not.toContain('secret-token-123');
  });
});
