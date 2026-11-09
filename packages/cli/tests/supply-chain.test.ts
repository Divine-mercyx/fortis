import { describe, expect, it } from 'vitest';

import { upgradeCommand } from '../src/rules/fix-version';
import { findLockfiles, parseLockfile } from '../src/rules/lockfiles';
import { actionUses, baseImages, endOfLife, isProductionDockerfile, releaseOf, SUPPLY_CHAIN_RULES } from '../src/rules/supply-chain';
import { emptyContext, type SourceFile } from '../src/rules/types';

const file = (path: string, text: string): SourceFile => ({ path, text, lines: text.split('\n') });
const flagged = (path: string, text: string) =>
  SUPPLY_CHAIN_RULES.filter((r) => r.appliesTo.test(path)).flatMap((r) => r.run(file(path, text), emptyContext()).map((d) => `${d.ruleId}:${d.line}`));

describe('reading Dockerfiles', () => {
  it('reads registries, tags and digests, and skips stages, scratch and unknown arguments', () => {
    const images = baseImages(file('Dockerfile', [
      'ARG NODE=22.11',
      'ARG BASE',
      'FROM --platform=$BUILDPLATFORM node:${NODE}-alpine AS build',
      'FROM registry.example.com:5000/team/api:3@sha256:abc',
      'FROM docker.io/library/python',
      'FROM build',
      'FROM scratch',
      'FROM ${BASE}',
      'FROM \\',
      '  ghcr.io/acme/base:1.2',
    ].join('\n')));
    expect(images.map((b) => [b.line, b.registry, b.name, b.tag, b.digest])).toEqual([
      [3, '', 'node', '22.11-alpine', null],
      [4, 'registry.example.com:5000', 'team/api', '3', 'sha256:abc'],
      [5, '', 'python', null, null],
      [9, 'ghcr.io', 'acme/base', '1.2', null],
    ]);
  });

  it('tells production Dockerfiles from dev, test and example ones', () => {
    for (const p of ['Dockerfile', 'api/Dockerfile', 'Dockerfile.prod', 'deploy/payments.dockerfile']) expect(isProductionDockerfile(p), p).toBe(true);
    for (const p of ['Dockerfile.dev', 'docker/test/Dockerfile', '.devcontainer/Dockerfile', 'examples/api/Dockerfile', 'Dockerfile.local']) expect(isProductionDockerfile(p), p).toBe(false);
  });

  it('works out the release an image is built on, including the OS under a language image', () => {
    const of = (ref: string) => releaseOf(baseImages(file('Dockerfile', `FROM ${ref}`))[0]!).map((r) => `${r.product} ${r.cycle}`);
    expect(of('node:18.20.4-bullseye-slim')).toEqual(['nodejs 18', 'debian bullseye']);
    expect(of('python:3.12-alpine3.17')).toEqual(['python 3.12', 'alpine-linux 3.17']);
    expect(of('debian:12.5-slim')).toEqual(['debian 12']);
    expect(of('ubuntu:jammy')).toEqual(['ubuntu jammy']);
    expect(of('mcr.microsoft.com/dotnet/aspnet:6.0')).toEqual(['dotnet 6']);
    expect(of('node:lts')).toEqual([]);
  });

  it('judges end-of-life against the date it runs on', () => {
    expect(endOfLife('nodejs', '16', new Date('2026-01-01'))).toBe('2023-09-11');
    expect(endOfLife('nodejs', '16', new Date('2023-01-01'))).toBeNull();
    expect(endOfLife('debian', 'trixie', new Date('2026-01-01'))).toBeNull();
  });
});

describe('Dockerfile rules', () => {
  it('reports a missing tag, a missing digest and an end-of-life image once each', () => {
    expect(flagged('Dockerfile', 'FROM node\nFROM node:24-alpine\nFROM node:16-alpine@sha256:abc')).toEqual(['SUP-IMG-001:1', 'SUP-IMG-002:2', 'SUP-IMG-003:3']);
  });

  it('honours fortis-ignore-next-line, the only form Docker allows', () => {
    expect(flagged('Dockerfile', '# fortis-ignore-next-line\nFROM node')).toEqual([]);
  });
});

describe('GitHub Actions rules', () => {
  it('reads uses lines, leaving out local actions and Docker images', () => {
    const uses = actionUses(file('.github/workflows/ci.yml', '- uses: ./.github/actions/x\n- uses: docker://alpine:3\n- uses: "pnpm/action-setup@v4" # pinned later\n'));
    expect(uses).toEqual([{ line: 3, action: 'pnpm/action-setup', ref: 'v4', comment: 'pinned later' }]);
  });

  it("flags third-party tags and branches, but not GitHub's own actions or commit pins", () => {
    const text = ['- uses: actions/checkout@v5', '- uses: github/codeql-action/init@v3', '- uses: pnpm/action-setup@v4', `- uses: pnpm/action-setup@${'a'.repeat(40)} # v4.3.0`, '- uses: pypa/gh-action-pypi-publish@release/v1'].join('\n');
    expect(flagged('.github/workflows/ci.yml', text)).toEqual(['SUP-GHA-001:3', 'SUP-GHA-001:5']);
  });

  it('flags pull_request_target only when it checks out the pull request', () => {
    const job = (trigger: string) => `on: ${trigger}\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v5\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}\n`;
    expect(flagged('.github/workflows/a.yml', job('pull_request_target'))).toEqual(['SUP-GHA-002:7']);
    expect(flagged('.github/workflows/a.yml', job('pull_request'))).toEqual([]);
  });
});

describe('actions in OSV', () => {
  it('finds workflows as dependency files and reads exact versions only', () => {
    expect(findLockfiles(['.github/workflows/ci.yml', 'docs/ci.yml'])).toEqual(['.github/workflows/ci.yml']);
    const text = ['- uses: pnpm/action-setup@v4', '- uses: docker/login-action@v3.7.0', `- uses: astral-sh/setup-uv@${'b'.repeat(40)} # v6.8.0`, `- uses: acme/x@${'c'.repeat(40)}`, '- uses: acme/workflows/.github/workflows/deploy.yml@v1.2.3'].join('\n');
    expect(parseLockfile('.github/workflows/ci.yml', text).packages.map((p) => `${p.ecosystem}:${p.name}@${p.version}:${p.line}`)).toEqual([
      'GitHub Actions:docker/login-action@3.7.0:2',
      'GitHub Actions:astral-sh/setup-uv@6.8.0:3',
      'GitHub Actions:acme/workflows@1.2.3:5',
    ]);
    expect(upgradeCommand('.github/workflows/ci.yml', 'GitHub Actions', 'docker/login-action', '3.7.1')).toBe('point uses: docker/login-action in ci.yml at v3.7.1, pinned by its commit SHA');
  });
});

describe('actions checked against OSV', () => {
  it("asks OSV for an action's advisories and keeps those that cover its version", async () => {
    const { mkdtempSync, mkdirSync, writeFileSync, rmSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const { scanDependencies } = await import('../src/rules/dependencies');
    const root = mkdtempSync(join(tmpdir(), 'fortis-gha-'));
    mkdirSync(join(root, '.github/workflows'), { recursive: true });
    writeFileSync(join(root, '.github/workflows/ci.yml'), '- uses: tj-actions/changed-files@v45.0.7\n- uses: tj-actions/changed-files@v46.0.1\n');
    const asked: unknown[] = [];
    const osv: typeof fetch = async (url, init) => {
      if (String(url).endsWith('/v1/querybatch')) {
        const { queries } = JSON.parse(String(init!.body)) as { queries: unknown[] };
        asked.push(...queries);
        return new Response(JSON.stringify({ results: queries.map(() => ({ vulns: [{ id: 'GHSA-mrrh-fwg8-r2c3' }] })) }));
      }
      return new Response(JSON.stringify({
        id: 'GHSA-mrrh-fwg8-r2c3',
        summary: 'changed-files leaks secrets',
        database_specific: { severity: 'HIGH' },
        affected: [{ package: { name: 'tj-actions/changed-files', ecosystem: 'GitHub Actions' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '46.0.1' }] }] }],
      }));
    };
    const r = await scanDependencies(root, ['.github/workflows/ci.yml'], { fetchImpl: osv });
    rmSync(root, { recursive: true, force: true });
    expect(asked).toEqual([{ package: { name: 'tj-actions/changed-files', ecosystem: 'GitHub Actions' } }, { package: { name: 'tj-actions/changed-files', ecosystem: 'GitHub Actions' } }]);
    expect(r.detections.map((d) => [d.ruleId, d.severity, d.line, d.fixedVersion])).toEqual([['DEP-OSV', 'high', 1, '46.0.1']]);
  });
});
