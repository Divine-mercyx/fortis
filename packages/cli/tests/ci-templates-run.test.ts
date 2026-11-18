import { execFile, execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parse } from 'yaml';

import { CI_PROVIDERS, writeCi, type CiProvider } from '../src/ci';
import { ciBranch } from '../src/git';

/*
 * Each `fortis ci init` template, run the way its CI system would run it (#89): the YAML parsed, the scan step's own
 * commands run in a shell with that system's environment, on a detached checkout of a repository with a critical
 * finding. Each must fail the job, leave its report where the template publishes it, and publish it even though the
 * scan failed. GitHub Actions and GitLab also post their comment, here to a stand-in API.
 *
 * What this can't show is the system itself accepting the file and showing the report; that's the run on each real
 * system that issue #89 asks for.
 */

const LIVE = ['sk', 'live', 'abcdef0123456789abcdef0123456789abcdef01'].join('_');
const sh = spawnSync('sh', ['-c', 'true']).status === 0 ? 'sh' : null;
const node = process.execPath.replace(/\\/g, '/');
const tsx = join(__dirname, '..', 'node_modules', 'tsx', 'dist', 'cli.mjs').replace(/\\/g, '/');
const cli = join(__dirname, '..', 'src', 'index.ts').replace(/\\/g, '/');

const dirs: string[] = [];
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

/** A stand-in for the GitHub and GitLab APIs: the diff adds the line with the key, and comments are recorded. */
const posted: { path: string; body: string }[] = [];
let server: Server;
let api = '';
beforeAll(async () => {
  const diff = `@@ -0,0 +1 @@\n+const K = "${LIVE}";`;
  server = createServer((req, res) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => {
      const path = (req.url ?? '').split('?')[0]!;
      const send = (body: unknown) => res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(body));
      if (req.method === 'POST') {
        posted.push({ path, body: (JSON.parse(data) as { body: string }).body });
        return send({ id: 1 });
      }
      if (path.endsWith('/pulls/7/files')) return send([{ filename: 'pay.js', status: 'added', patch: diff }]);
      if (path.endsWith('/merge_requests/3/diffs')) return send([{ new_path: 'pay.js', diff }]);
      if (path.endsWith('/comments') || path.endsWith('/notes')) return send([]);
      res.writeHead(404).end('{}');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  api = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

/** A repository with a live key in it, checked out at a commit rather than a branch, as CI systems do. */
function sampleRepo(provider: CiProvider, free: boolean) {
  const dir = mkdtempSync(join(tmpdir(), `fortis-ci-${provider}-`));
  dirs.push(dir);
  const g = (...a: string[]) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
  g('init', '-q', '-b', 'main');
  g('config', 'user.email', 't@example.com');
  g('config', 'user.name', 'Test');
  writeFileSync(join(dir, 'pay.js'), `const K = "${LIVE}";\n`);
  const written = writeCi(dir, provider, { stagingBranch: 'staging', free });
  g('add', '-A');
  g('commit', '-q', '-m', 'init');
  g('checkout', '-q', '--detach');
  return { dir, template: readFileSync(join(dir, written.path), 'utf8') };
}

/** `fortis` on the PATH and in ~/.fortis/bin, where the install script puts it: this checkout's CLI. */
function home(dir: string) {
  const h = join(dir, '.ci-home');
  const bin = join(h, '.fortis', 'bin');
  mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, 'fortis'), `#!/bin/sh\nexec "${node}" "${tsx}" "${cli}" "$@"\n`);
  chmodSync(join(bin, 'fortis'), 0o755);
  return { h, bin };
}

type Step = {
  /** The scan step's shell commands, as the system would run them. */
  script: string;
  /** Where the template publishes the report, and whether that happens after a failed scan. */
  report: string;
  publishedOnFailure: boolean;
  env: Record<string, string>;
};

type Doc = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

/** Each system's scan step and report, read from the parsed template, and the environment that system sets. */
const SYSTEMS: Record<CiProvider, (text: string) => Step> = {
  github: (text) => {
    const steps = (parse(text) as Doc).jobs.scan.steps as Doc[];
    const scan = steps.find((s) => s.name === 'Fortis scan')!;
    const upload = steps.find((s) => String(s.uses).startsWith('github/codeql-action/upload-sarif'))!;
    return {
      script: scan.run,
      report: upload.with.sarif_file,
      publishedOnFailure: /always\(\)/.test(upload.if),
      env: { GITHUB_ACTIONS: 'true', GITHUB_REPOSITORY: 'o/r', GITHUB_API_URL: api, GITHUB_HEAD_REF: 'feature', GITHUB_TOKEN: 't' },
    };
  },
  gitlab: (text) => {
    const job = (parse(text) as Doc)['fortis-scan'];
    return {
      script: (job.script as string[]).join('\n'),
      report: job.artifacts.reports.junit,
      publishedOnFailure: job.artifacts.when === 'always',
      env: { GITLAB_CI: 'true', CI_MERGE_REQUEST_IID: '3', CI_API_V4_URL: api, CI_PROJECT_ID: '42', FORTIS_GITLAB_TOKEN: 't', CI_MERGE_REQUEST_SOURCE_BRANCH_NAME: 'feature' },
    };
  },
  // Bitbucket reads any XML under a test-results folder, in the step's teardown, which runs whether the script failed or not.
  bitbucket: (text) => {
    const script = ((parse(text) as Doc).pipelines.default[0].step.script as string[]).join('\n');
    return { script, report: /--junit (test-results\/\S+)/.exec(script)![1]!, publishedOnFailure: true, env: { BITBUCKET_BUILD_NUMBER: '1', BITBUCKET_BRANCH: 'feature' } };
  },
  azure: (text) => {
    const steps = (parse(text) as Doc).jobs[0].steps as Doc[];
    const publish = steps.find((s) => s.task === 'PublishTestResults@2')!;
    return {
      script: steps.find((s) => s.displayName === 'Fortis scan')!.script,
      report: publish.inputs.testResultsFiles,
      publishedOnFailure: publish.condition === 'always()',
      env: { TF_BUILD: 'True', BUILD_SOURCEBRANCH: 'refs/heads/feature' },
    };
  },
  jenkins: (text) => {
    const stage = text.slice(text.indexOf("stage('Fortis scan')"), text.indexOf("stage('Fortis staging test')") >>> 0 || undefined);
    return {
      script: /sh '''\n([\s\S]*?)'''/.exec(stage)![1]!,
      report: /junit [^\n]*testResults: '([^']+)'/.exec(stage)![1]!,
      publishedOnFailure: /post \{\s*always \{\s*junit /.test(stage),
      env: { JENKINS_URL: 'http://jenkins', BRANCH_NAME: 'feature' },
    };
  },
  // CircleCI runs store_test_results even after a failed step (its configuration reference), so it needs no `when`.
  circleci: (text) => {
    const steps = (parse(text) as Doc).jobs['fortis-scan'].steps as Doc[];
    const run = steps.find((s) => s.run?.name === 'Fortis scan')!.run;
    const folder = steps.find((s) => s.store_test_results)!.store_test_results.path as string;
    return { script: run.command, report: /--junit (\S+)/.exec(run.command)![1]!, publishedOnFailure: (/--junit (\S+)/.exec(run.command)![1]!).startsWith(`${folder}/`), env: { CIRCLECI: 'true', CIRCLE_BRANCH: 'feature' } };
  },
  // Buildkite fills in $VARS when the pipeline is uploaded, so the template escapes them as $$. Artifacts upload after
  // the command, whatever its exit status.
  buildkite: (text) => {
    const step = ((parse(text) as Doc).steps as Doc[])[0]!;
    return { script: (step.command as string).replace(/\$\$/g, '$'), report: step.artifact_paths, publishedOnFailure: true, env: { BUILDKITE: 'true', BUILDKITE_BRANCH: 'feature' } };
  },
};

/** The template's install line downloads the release binary; here `fortis` is already in place. */
const INSTALL = /^\s*curl -fsSL https:\/\/github\.com\/[^\n]+\/install\.sh \| FORTIS_VERSION=\S+ sh\s*$/m;

const run = (dir: string, script: string, env: Record<string, string>) =>
  new Promise<{ status: number; output: string }>((resolve) => {
    execFile(sh!, ['-e', '-c', script], { cwd: dir, env, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 }, (error, stdout, stderr) =>
      resolve({ status: error ? Number((error as { code?: number }).code ?? 1) : 0, output: stdout + stderr }),
    );
  });

describe('every template parses, for a project with a key and without', () => {
  it.each(CI_PROVIDERS.filter((p) => p !== 'jenkins'))('%s', (provider) => {
    for (const free of [true, false]) {
      const { template } = sampleRepo(provider, free);
      expect(() => parse(template)).not.toThrow();
      expect(SYSTEMS[provider](template).script).toContain('scan --ci');
    }
  });
});

describe.skipIf(!sh)('each template run as its CI system would run it', () => {
  it.each(CI_PROVIDERS)('%s: the scan runs, the critical finding fails the job, and the report is published', async (provider) => {
    const { dir, template } = sampleRepo(provider, true);
    const step = SYSTEMS[provider](template);
    // GitLab and Bitbucket run in the Fortis image; the rest install the release binary, in this step or one before it.
    expect(template).toMatch(provider === 'gitlab' || provider === 'bitbucket' ? /image: ghcr\.io\/divine-mercyx\/fortis:\d/ : INSTALL);
    const { h, bin } = home(dir);
    const event = join(dir, '.event.json');
    writeFileSync(event, JSON.stringify({ pull_request: { number: 7, head: { sha: 'abc' } } }));
    const env: Record<string, string> = {
      PATH: `${bin}${process.platform === 'win32' ? ';' : ':'}${process.env.PATH}`,
      HOME: h, USERPROFILE: h, CI: 'true', FORTIS_KEY: '',
      // Where GitHub Actions and CircleCI collect PATH and environment changes for the next step.
      GITHUB_PATH: join(dir, '.github-path'), BASH_ENV: join(dir, '.bash-env'), GITHUB_EVENT_PATH: event,
      ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
      ...step.env,
    };
    const before = posted.length;
    const result = await run(dir, step.script.replace(INSTALL, ''), env);

    expect(result.status, result.output).toBe(1);
    expect(step.publishedOnFailure).toBe(true);
    const reportPath = join(dir, step.report);
    expect(existsSync(reportPath), `${step.report} after: ${result.output}`).toBe(true);
    const report = readFileSync(reportPath, 'utf8');
    expect(report).toContain('FX-SEC-001');
    expect(report).not.toContain(LIVE);
    if (step.report.endsWith('.xml')) expect(report).toMatch(/failures="[1-9]/);

    const comments = posted.slice(before);
    if (provider === 'github' || provider === 'gitlab') {
      expect(comments.map((c) => c.path)).toEqual([provider === 'github' ? '/repos/o/r/issues/7/comments' : '/projects/42/merge_requests/3/notes']);
      expect(comments[0]!.body).toContain('FX-SEC-001');
      expect(comments[0]!.body).not.toContain(LIVE);
    } else {
      expect(comments).toEqual([]);
    }
    // Nothing the scan writes is left where it would be committed by a later step.
    expect(readdirSync(dir).filter((f) => !f.startsWith('.') && !['pay.js', 'fortis.sarif', 'fortis-junit.xml', 'fortis.gitlab-ci.yml', 'bitbucket-pipelines.yml', 'azure-pipelines-fortis.yml', 'Jenkinsfile', 'test-results'].includes(f))).toEqual([]);
  }, 120_000);
});

describe('the branch a CI system builds, on a detached checkout', () => {
  it.each([
    ['GitHub Actions pull request', { GITHUB_ACTIONS: 'true', GITHUB_HEAD_REF: 'feature', GITHUB_REF_NAME: '7/merge', GITHUB_REF_TYPE: 'branch' }, 'feature'],
    ['GitHub Actions push', { GITHUB_ACTIONS: 'true', GITHUB_HEAD_REF: '', GITHUB_REF_NAME: 'main', GITHUB_REF_TYPE: 'branch' }, 'main'],
    ['GitHub Actions tag', { GITHUB_ACTIONS: 'true', GITHUB_REF_NAME: 'v1.0.0', GITHUB_REF_TYPE: 'tag' }, undefined],
    ['GitLab branch', { GITLAB_CI: 'true', CI_COMMIT_BRANCH: 'main' }, 'main'],
    ['GitLab merge request', { GITLAB_CI: 'true', CI_MERGE_REQUEST_SOURCE_BRANCH_NAME: 'feature' }, 'feature'],
    ['Bitbucket', { BITBUCKET_BUILD_NUMBER: '4', BITBUCKET_BRANCH: 'main' }, 'main'],
    ['Azure push', { TF_BUILD: 'True', BUILD_SOURCEBRANCH: 'refs/heads/release/2.0' }, 'release/2.0'],
    ['Azure pull request', { TF_BUILD: 'True', BUILD_SOURCEBRANCH: 'refs/pull/5/merge', SYSTEM_PULLREQUEST_SOURCEBRANCH: 'refs/heads/feature' }, 'feature'],
    ['Azure tag', { TF_BUILD: 'True', BUILD_SOURCEBRANCH: 'refs/tags/v1' }, undefined],
    ['Jenkins multibranch', { JENKINS_URL: 'http://j', BRANCH_NAME: 'main' }, 'main'],
    ['Jenkins pull request', { JENKINS_URL: 'http://j', BRANCH_NAME: 'PR-12', CHANGE_BRANCH: 'feature' }, 'feature'],
    ['Jenkins plain Pipeline job', { JENKINS_URL: 'http://j', GIT_BRANCH: 'origin/main' }, 'main'],
    ['CircleCI', { CIRCLECI: 'true', CIRCLE_BRANCH: 'main' }, 'main'],
    ['Buildkite', { BUILDKITE: 'true', BUILDKITE_BRANCH: 'main' }, 'main'],
    ['outside CI', {}, undefined],
  ])('%s', (_, env, branch) => {
    expect(ciBranch(env)).toBe(branch);
  });
});
