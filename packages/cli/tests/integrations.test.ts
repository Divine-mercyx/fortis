import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

import { azurePipeline, bitbucketPipeline, buildkitePipeline, circleciConfig, CI_PROVIDERS, detectProvider, githubWorkflow, gitlabJobs, jenkinsfile, writeCi } from '../src/ci';
import { toJunit } from '../src/junit';
import { addedLines, COMMENT_MARKER, commentBody, newFindings, postPrComment, prContext, type PrContext } from '../src/pr-comment';
import type { Detection } from '../src/rules/types';

const dirs: string[] = [];
const temp = () => {
  const d = mkdtempSync(join(tmpdir(), 'fortis-int-'));
  dirs.push(d);
  return d;
};
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const LIVE = ['sk', 'live', 'abcdef0123456789abcdef0123456789abcdef01'].join('_');
const finding = (over: Partial<Detection> = {}): Detection => ({ ruleId: 'FX-SEC-001', severity: 'critical', title: 'Live payment key', file: 'src/pay.js', line: 3, snippet: `const k = "${LIVE}";`, ...over });

describe('fortis ci init for each provider', () => {
  const others = { bitbucket: bitbucketPipeline, azure: azurePipeline, jenkins: jenkinsfile, circleci: circleciConfig, buildkite: buildkitePipeline };
  const opts = { stagingBranch: 'staging' };

  for (const [name, render] of Object.entries(others)) {
    it(`${name}: needs no Node, pins the version, and writes a test report`, () => {
      const text = render(opts);
      expect(text).not.toMatch(/\bnpx\b|\bnpm\b|setup-node|image: node/);
      expect(text).toMatch(/fortis"? scan --ci --junit \S+/);
      expect(text).toMatch(/(cli-v|fortis:)\d+\.\d+\.\d+/);
      expect(text).not.toContain('--pr-comment');
    });

    it(`${name}: adds --history only when asked, with a full clone where that isn't the default`, () => {
      expect(render(opts)).not.toContain('--history');
      expect(render({ ...opts, history: true })).toContain('--history');
    });

    it(`${name}: names the SBOM step for Maven`, () => {
      expect(render({ ...opts, maven: true })).toContain('--sbom target/bom.json');
    });
  }

  it('fetches full history for --history on Bitbucket and Azure', () => {
    expect(bitbucketPipeline({ ...opts, history: true })).toContain('depth: full');
    expect(azurePipeline({ ...opts, history: true })).toContain("fetchDepth: '0'");
  });

  it('leaves ZAP out of Bitbucket, and says why', () => {
    const text = bitbucketPipeline(opts);
    expect(text).not.toContain('fortis test --');
    expect(text).toContain('Bitbucket restricts');
  });

  for (const [name, render] of Object.entries({ azure: azurePipeline, jenkins: jenkinsfile, circleci: circleciConfig, buildkite: buildkitePipeline })) {
    it(`${name}: tests staging on the staging branch only, and uses a fixed target when given`, () => {
      expect(render(opts)).toContain('fortis');
      expect(render({ stagingBranch: 'develop' })).toContain('develop');
      expect(render({ ...opts, target: 'https://staging.x.ng' })).toContain('--target https://staging.x.ng');
      expect(render(opts)).toContain('test --target');
    });
  }

  it('escapes Buildkite variables so the agent fills them in, not the upload', () => {
    const text = buildkitePipeline(opts);
    expect(text).toContain('"$$HOME/.fortis/bin/fortis"');
    expect(text).toContain('"$$FORTIS_STAGING_URL"');
    expect(text.replace(/\$\$/g, '')).not.toMatch(/\$[A-Z]/);
  });

  it('does not send an unset Azure variable as a login token', () => {
    expect(azurePipeline(opts)).toContain('# FORTIS_ZAP_AUTH: $(FORTIS_TEST_TOKEN)');
  });

  it('gives Azure secrets to the step explicitly', () => {
    expect(azurePipeline(opts)).toContain('FORTIS_KEY: $(FORTIS_KEY)');
  });

  it('adds PR comments and JUnit to GitHub and GitLab', () => {
    const github = githubWorkflow(opts);
    expect(github).toContain('--pr-comment');
    expect(github).toContain('pull-requests: write');
    expect(github).toContain('GITHUB_TOKEN: ${{ github.token }}');
    const gitlab = gitlabJobs(opts);
    expect(gitlab).toContain('--junit fortis-junit.xml --pr-comment');
    expect(gitlab).toContain('junit: fortis-junit.xml');
  });

  const hasPyYaml = (() => {
    try {
      execFileSync('python3', ['-c', 'import yaml'], { stdio: 'ignore' });
      return true;
    } catch {
      return false;
    }
  })();

  it.skipIf(!hasPyYaml)('produces YAML that parses for every YAML provider', () => {
    for (const y of [bitbucketPipeline(opts), azurePipeline(opts), circleciConfig(opts), buildkitePipeline(opts), bitbucketPipeline({ ...opts, history: true, maven: true })]) {
      const out = execFileSync('python3', ['-c', 'import sys,yaml,json; print(json.dumps(sorted(map(str, yaml.safe_load(sys.stdin).keys()))))'], { input: y, encoding: 'utf8' });
      expect(JSON.parse(out).length).toBeGreaterThan(0);
    }
  });

  it('writes to the expected file for each provider', () => {
    const expected = { github: '.github/workflows/fortis.yml', gitlab: 'fortis.gitlab-ci.yml', bitbucket: 'bitbucket-pipelines.yml', azure: 'azure-pipelines-fortis.yml', jenkins: 'Jenkinsfile', circleci: '.circleci/config.yml', buildkite: '.buildkite/pipeline.yml' };
    expect(Object.keys(expected).sort()).toEqual([...CI_PROVIDERS].sort());
    for (const provider of CI_PROVIDERS) {
      const root = temp();
      const res = writeCi(root, provider, opts);
      expect(res).toMatchObject({ path: expected[provider], written: true, mergeInto: undefined });
      expect(existsSync(join(root, res.path))).toBe(true);
    }
  });

  it('never overwrites a project pipeline, even with --force, and writes beside it', () => {
    for (const [provider, main, beside] of [
      ['bitbucket', 'bitbucket-pipelines.yml', 'fortis.bitbucket-pipelines.yml'],
      ['jenkins', 'Jenkinsfile', 'Jenkinsfile.fortis'],
      ['circleci', '.circleci/config.yml', '.circleci/fortis.yml'],
      ['buildkite', '.buildkite/pipeline.yml', '.buildkite/pipeline.fortis.yml'],
    ] as const) {
      const root = temp();
      mkdirSync(join(root, '.circleci'));
      mkdirSync(join(root, '.buildkite'));
      writeFileSync(join(root, main), 'my own pipeline\n');
      const res = writeCi(root, provider, { ...opts, force: true });
      expect(res).toEqual({ path: beside, written: true, mergeInto: main });
      expect(readFileSync(join(root, main), 'utf8')).toBe('my own pipeline\n');
      expect(existsSync(join(root, beside))).toBe(true);
    }
  });

  it('can regenerate a file it wrote itself', () => {
    const root = temp();
    writeCi(root, 'jenkins', opts);
    expect(writeCi(root, 'jenkins', opts).written).toBe(false);
    const res = writeCi(root, 'jenkins', { stagingBranch: 'develop', force: true });
    expect(res).toMatchObject({ path: 'Jenkinsfile', written: true, mergeInto: undefined });
    expect(readFileSync(join(root, 'Jenkinsfile'), 'utf8')).toContain("branch 'develop'");
  });

  it('detects the provider from the repository', () => {
    const cases: [string, string][] = [['.gitlab-ci.yml', 'gitlab'], ['bitbucket-pipelines.yml', 'bitbucket'], ['azure-pipelines.yml', 'azure'], ['Jenkinsfile', 'jenkins'], ['.buildkite', 'buildkite']];
    for (const [file, provider] of cases) {
      const root = temp();
      writeFileSync(join(root, file), '');
      expect(detectProvider(root)).toBe(provider);
    }
    const circle = temp();
    mkdirSync(join(circle, '.circleci'));
    writeFileSync(join(circle, '.circleci', 'config.yml'), '');
    expect(detectProvider(circle)).toBe('circleci');
    expect(detectProvider(temp())).toBe('github');
  });
});

describe('JUnit output', () => {
  it('fails blocking findings, skips the rest, and masks secrets', () => {
    const xml = toJunit([finding(), finding({ ruleId: 'DEP-OSV', severity: 'low', title: 'a@1: <b>bad</b> & "worse"', file: 'package-lock.json', line: 0 })], { failOn: 'high', durationMs: 1500 });
    expect(xml).toContain('<testsuite name="Fortis" tests="2" failures="1" errors="0" skipped="1" time="1.500">');
    expect(xml).toContain('<failure message="critical: Live payment key" type="FX-SEC-001">');
    expect(xml).toContain('name="FX-SEC-001 src/pay.js:3"');
    expect(xml).toContain('<skipped message="low: a@1: &lt;b&gt;bad&lt;/b&gt; &amp; &quot;worse&quot;"/>');
    expect(xml).toContain('name="DEP-OSV package-lock.json"');
    expect(xml).not.toContain(LIVE);
    expect(xml).toContain('Fix: ');
  });

  it('is one passing test when clean, because some systems reject an empty report', () => {
    const xml = toJunit([], { failOn: 'critical', durationMs: 0 });
    expect(xml).toContain('tests="1" failures="0"');
    expect(xml).toContain('<testcase classname="fortis" name="Fortis scan" time="0"/>');
  });

  it('drops characters XML cannot hold', () => {
    expect(toJunit([finding({ title: 'a\u0001b', severity: 'critical' })], { failOn: 'critical', durationMs: 0 })).toContain('critical: ab');
  });

  it('is written by the CLI, leaving out baselined findings', () => {
    const dir = temp();
    const g = (...a: string[]) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
    g('init', '-q');
    g('config', 'user.email', 't@example.com');
    g('config', 'user.name', 'Test');
    writeFileSync(join(dir, 'pay.js'), `const K = "${LIVE}";\n`);
    g('add', '-A');
    g('commit', '-q', '-m', 'init');
    const cli = join(__dirname, '..', 'src', 'index.ts');
    const tsx = join(__dirname, '..', 'node_modules', 'tsx', 'dist', 'cli.mjs');
    const env = { ...process.env, FORTIS_KEY: '', HOME: dir, USERPROFILE: dir };
    const run = (...args: string[]) => spawnSync(process.execPath, [tsx, cli, ...args], { cwd: dir, encoding: 'utf8', env });
    expect(run('scan', '--offline', '--no-upload', '--junit', 'r.xml').status).toBe(1);
    const report = readFileSync(join(dir, 'r.xml'), 'utf8');
    expect(report).toContain('type="FX-SEC-001"');
    expect(report).not.toContain(LIVE);
    expect(run('baseline', '--offline').status).toBe(0);
    expect(run('scan', '--offline', '--no-upload', '--junit', 'r.xml').status).toBe(0);
    expect(readFileSync(join(dir, 'r.xml'), 'utf8')).toContain('tests="1" failures="0"');
  }, 60_000);
});

describe('which pull request a CI run is for', () => {
  const event = JSON.stringify({ pull_request: { number: 7, head: { sha: 'abc' } } });
  const read = () => event;

  it('reads GitHub Actions', () => {
    const { context } = prContext({ GITHUB_ACTIONS: 'true', GITHUB_EVENT_PATH: '/e', GITHUB_TOKEN: 't', GITHUB_REPOSITORY: 'o/r', GITHUB_API_URL: 'https://ghe/api/v3', GITHUB_SERVER_URL: 'https://ghe' }, read);
    expect(context).toMatchObject({ kind: 'github', api: 'https://ghe/api/v3', project: 'o/r', number: '7', token: 't' });
    expect(context!.blob('src/a b.js', 3)).toBe('https://ghe/o/r/blob/abc/src/a%20b.js#L3');
  });

  it('reads GitLab CI', () => {
    const { context } = prContext({ GITLAB_CI: 'true', CI_MERGE_REQUEST_IID: '9', FORTIS_GITLAB_TOKEN: 't', CI_API_V4_URL: 'https://gl/api/v4', CI_PROJECT_ID: '42', CI_PROJECT_URL: 'https://gl/o/r', CI_COMMIT_SHA: 'abc' });
    expect(context).toMatchObject({ kind: 'gitlab', api: 'https://gl/api/v4', project: '42', number: '9', token: 't' });
    expect(context!.blob('a.js', 0)).toBe('https://gl/o/r/-/blob/abc/a.js');
  });

  it('does nothing outside a pull request', () => {
    expect(prContext({})).toEqual({ context: null });
    expect(prContext({ GITHUB_ACTIONS: 'true', GITHUB_EVENT_PATH: '/e', GITHUB_TOKEN: 't' }, () => '{"push":{}}')).toEqual({ context: null });
    expect(prContext({ GITLAB_CI: 'true', FORTIS_GITLAB_TOKEN: 't' })).toEqual({ context: null });
  });

  it('says so when a pull request has no token, without using CI_JOB_TOKEN', () => {
    expect(prContext({ GITHUB_ACTIONS: 'true', GITHUB_EVENT_PATH: '/e' }, read).reason).toMatch(/GITHUB_TOKEN/);
    expect(prContext({ GITLAB_CI: 'true', CI_MERGE_REQUEST_IID: '9', CI_JOB_TOKEN: 'j' }).reason).toMatch(/FORTIS_GITLAB_TOKEN/);
  });
});

describe('what counts as new', () => {
  it('reads the added lines of a diff', () => {
    const patch = '@@ -1,3 +1,4 @@\n a\n-b\n+c\n+d\n e\n@@ -20,2 +21,3 @@ function x() {\n f\n+g\n h\n\\ No newline at end of file';
    expect([...addedLines(patch)]).toEqual([2, 3, 22]);
  });

  it('keeps findings on added lines, in changed files with no line, and in files too big to diff', () => {
    const files = new Map<string, Set<number> | null>([['a.js', new Set([3])], ['package-lock.json', new Set([9])], ['big.js', null]]);
    const changed = { files, complete: true };
    const pick = (d: Partial<Detection>) => newFindings([finding(d)], changed).length;
    expect(pick({ file: 'a.js', line: 3 })).toBe(1);
    expect(pick({ file: 'a.js', line: 4 })).toBe(0);
    expect(pick({ file: 'other.js', line: 3 })).toBe(0);
    expect(pick({ file: 'package-lock.json', line: 0 })).toBe(1);
    expect(pick({ file: 'big.js', line: 500 })).toBe(1);
    expect(pick({ file: 'a.js', line: 3, commit: 'abc' })).toBe(0);
  });

  it('shows everything when the API could not list every file', () => {
    expect(newFindings([finding({ file: 'unlisted.js' })], { files: new Map(), complete: false })).toHaveLength(1);
  });
});

describe('the comment', () => {
  const ctx = { kind: 'github' as const, blob: (p: string, l: number) => `https://x/${p}#L${l}` };

  it('never shows the code, and masks secrets in scanned text', () => {
    const body = commentBody([finding({ title: `Key ${LIVE}` })], ctx);
    expect(body.startsWith(COMMENT_MARKER)).toBe(true);
    expect(body).not.toContain(LIVE);
    expect(body).not.toContain('const k');
    expect(body).toContain('1 new finding in this pull request');
  });

  it('keeps scanned text from breaking the table, adding HTML or mentioning anyone', () => {
    const body = commentBody([finding({ title: 'a | b <img src=x> @everyone [x](y)\nnext' })], ctx);
    expect(body).toContain('a \\| b \\<img src=x\\> \\@everyone \\[x\\](y) next');
  });

  it('lists the worst first, and caps the table', () => {
    const many = [finding({ severity: 'low', ruleId: 'LOW' }), ...Array.from({ length: 60 }, (_, i) => finding({ line: i + 1 }))];
    const body = commentBody(many, ctx);
    expect(body).toContain('61 new findings');
    expect(body).toContain('And 11 more');
    expect(body).not.toContain('LOW');
  });

  it('uses GitLab wording', () => {
    expect(commentBody([], { ...ctx, kind: 'gitlab' })).toContain('This merge request adds no security findings');
  });
});

describe('posting the comment', () => {
  type Seen = { method: string; url: string; headers: IncomingMessage['headers']; body: string };
  const servers: Server[] = [];
  afterEach(() => {
    for (const s of servers.splice(0)) s.close();
  });

  async function fakeApi(routes: (req: Seen) => { status?: number; json: unknown }) {
    const seen: Seen[] = [];
    const server = createServer((req, res) => {
      let body = '';
      req.on('data', (d: Buffer) => (body += d.toString()));
      req.on('end', () => {
        const entry = { method: req.method!, url: req.url!, headers: req.headers, body };
        seen.push(entry);
        const { status = 200, json } = routes(entry);
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(json));
      });
    });
    servers.push(server);
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    return { seen, api: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
  }
  const github = (api: string): PrContext => ({ kind: 'github', api, project: 'o/r', number: '7', token: 'secret-token', blob: () => null });
  const gitlab = (api: string): PrContext => ({ kind: 'gitlab', api, project: '42', number: '9', token: 'secret-token', blob: () => null });
  const patch = '@@ -0,0 +1,1 @@\n+const k = 1;';
  const mine = finding({ file: 'a.js', line: 1 });
  const older = finding({ file: 'a.js', line: 40 });

  it('creates one comment on GitHub, with only what the pull request adds', async () => {
    const { seen, api } = await fakeApi((r) => (r.url.includes('/files') ? { json: [{ filename: 'a.js', patch }] } : r.method === 'GET' ? { json: [] } : { status: 201, json: {} }));
    await expect(postPrComment(github(api), [mine, older])).resolves.toEqual({ action: 'created', newCount: 1 });
    const post = seen.find((s) => s.method === 'POST')!;
    expect(post.url).toBe('/repos/o/r/issues/7/comments');
    expect(post.headers.authorization).toBe('Bearer secret-token');
    expect((JSON.parse(post.body) as { body: string }).body).toContain('a.js:1');
    expect(post.body).not.toContain('a.js:40');
  });

  it('updates its own comment in place instead of adding another', async () => {
    const { seen, api } = await fakeApi((r) => {
      if (r.url.includes('/files')) return { json: [{ filename: 'a.js', patch }] };
      if (r.method === 'GET') return { json: [{ id: 1, body: 'someone else' }, { id: 5, body: `${COMMENT_MARKER}\nold` }] };
      return { json: {} };
    });
    await expect(postPrComment(github(api), [mine])).resolves.toEqual({ action: 'updated', newCount: 1 });
    expect(seen.filter((s) => s.method === 'POST')).toEqual([]);
    expect(seen.find((s) => s.method === 'PATCH')!.url).toBe('/repos/o/r/issues/comments/5');
  });

  it('stays quiet with nothing to report, and corrects an earlier comment when findings are fixed', async () => {
    const quiet = await fakeApi((r) => (r.url.includes('/files') ? { json: [{ filename: 'a.js', patch }] } : { json: [] }));
    await expect(postPrComment(github(quiet.api), [older])).resolves.toEqual({ action: 'none', newCount: 0 });
    expect(quiet.seen.every((s) => s.method === 'GET')).toBe(true);

    const fixed = await fakeApi((r) => {
      if (r.url.includes('/files')) return { json: [] };
      if (r.method === 'GET') return { json: [{ id: 5, body: `${COMMENT_MARKER}\nold` }] };
      return { json: {} };
    });
    await expect(postPrComment(github(fixed.api), [])).resolves.toEqual({ action: 'updated', newCount: 0 });
    expect(fixed.seen.find((s) => s.method === 'PATCH')!.body).toContain('no new findings');
  });

  it('does not rewrite a comment that is already right', async () => {
    const body = commentBody([], github(''));
    const { seen, api } = await fakeApi((r) => (r.url.includes('/files') ? { json: [] } : { json: [{ id: 5, body }] }));
    await expect(postPrComment(github(api), [])).resolves.toEqual({ action: 'none', newCount: 0 });
    expect(seen.every((s) => s.method === 'GET')).toBe(true);
  });

  it('reads every page of files', async () => {
    const fullPage = Array.from({ length: 100 }, (_, i) => ({ filename: `f${i}.js`, patch }));
    const { seen, api } = await fakeApi((r) => {
      if (r.url.includes('/files')) return { json: r.url.includes('&page=1') ? fullPage : [{ filename: 'a.js', patch }] };
      return r.method === 'GET' ? { json: [] } : { status: 201, json: {} };
    });
    await expect(postPrComment(github(api), [mine])).resolves.toEqual({ action: 'created', newCount: 1 });
    expect(seen.filter((s) => s.url.includes('/files'))).toHaveLength(2);
  });

  it('works the same on GitLab, with its own token header and routes', async () => {
    const { seen, api } = await fakeApi((r) => (r.url.includes('/diffs') ? { json: [{ new_path: 'a.js', diff: patch }, { new_path: 'gone.js', deleted_file: true, diff: patch }] } : r.method === 'GET' ? { json: [{ id: 3, body: `${COMMENT_MARKER}\nold` }] } : { json: {} }));
    await expect(postPrComment(gitlab(api), [mine, finding({ file: 'gone.js', line: 1 })])).resolves.toEqual({ action: 'updated', newCount: 1 });
    const put = seen.find((s) => s.method === 'PUT')!;
    expect(put.url).toBe('/projects/42/merge_requests/9/notes/3');
    expect(put.headers['private-token']).toBe('secret-token');
    expect(put.headers.authorization).toBeUndefined();
  });

  it('explains a refused token without revealing it', async () => {
    const { api } = await fakeApi(() => ({ status: 403, json: { message: 'no' } }));
    const error = (await postPrComment(github(api), [mine]).catch((e: Error) => e)) as Error;
    expect(error.message).toMatch(/read-only token/);
    expect(error.message).not.toContain('secret-token');
  });
});
