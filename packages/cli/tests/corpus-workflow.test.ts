import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

/**
 * A rule change once passed its pull request and only failed the next night's corpus run (#118). corpus.yml now
 * runs the corpus on any pull request that can change what a scan finds. These tests keep its path list complete
 * and its job the same as the nightly one.
 */

const repo = join(__dirname, '..', '..', '..');
const workflow = (name: string) => parse(readFileSync(join(repo, '.github', 'workflows', name), 'utf8'));
const corpus = workflow('corpus.yml');
const nightly = workflow('nightly.yml');
const paths: string[] = corpus.on.pull_request.paths;

/** Whether a repository path matches one of the workflow's patterns (exact files, or a folder ending in /**). */
const covered = (file: string) => paths.some((p) => (p.endsWith('/**') ? file.startsWith(p.slice(0, -2)) : file === p));

/** Every source file a scan runs, found by following imports from scan.ts. Workspace packages are listed by name. */
function scanSources() {
  const seen = new Set<string>(), packages = new Set<string>();
  const visit = (abs: string) => {
    const rel = relative(repo, abs).replace(/\\/g, '/');
    if (seen.has(rel)) return;
    seen.add(rel);
    for (const m of readFileSync(abs, 'utf8').matchAll(/from '([^']+)'/g)) {
      const spec = m[1]!;
      if (spec.startsWith('@fortis/')) packages.add(spec);
      if (!spec.startsWith('.')) continue;
      const base = resolve(dirname(abs), spec);
      const file = [`${base}.ts`, join(base, 'index.ts'), base].find((f) => existsSync(f) && f.endsWith('.ts'));
      if (file) visit(file);
    }
  };
  visit(join(repo, 'packages', 'cli', 'src', 'scan.ts'));
  return { files: [...seen], packages: [...packages] };
}

describe('the corpus check on pull requests', () => {
  it('runs for every source file a scan depends on', () => {
    const { files } = scanSources();
    expect(files.length).toBeGreaterThan(30);
    expect(files.filter((f) => !covered(f))).toEqual([]);
  });

  it('runs for the workspace packages the scan imports, and for the corpus and its own workflow', () => {
    const { packages } = scanSources();
    expect(packages).toContain('@fortis/shared');
    for (const name of packages) expect(paths).toContain(`packages/${name.replace('@fortis/', '')}/src/**`);
    for (const p of ['packages/cli/bench/corpus.json', 'packages/cli/bench/corpus.ts', '.github/workflows/corpus.yml', 'pnpm-lock.yaml']) expect(paths).toContain(p);
  });

  it('runs the same job as the nightly corpus check', () => {
    const steps = (job: { steps: Record<string, unknown>[] }) => job.steps.map(({ name: _name, ...step }) => step);
    expect(steps(corpus.jobs.corpus)).toEqual(steps(nightly.jobs.corpus));
    expect(corpus.jobs.corpus.env).toEqual(nightly.jobs.corpus.env);
    expect(corpus.permissions).toEqual({ contents: 'read' });
  });

  it('leaves the nightly workflow to the live tests on pull requests, so they run only when those change', () => {
    const nightlyPaths: string[] = nightly.on.pull_request.paths;
    expect(nightlyPaths.filter((p) => p.includes('bench/corpus'))).toEqual([]);
    expect(nightly.on.schedule).toBeTruthy();
  });
});
