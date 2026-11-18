import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

// @ts-expect-error: a plain .mjs script with no type declarations
import { waitForListing } from '../scripts/check-listing.mjs';

const root = join(__dirname, '..', '..', '..');
const workflow = readFileSync(join(root, '.github', 'workflows', 'release-vscode.yml'), 'utf8').replace(/\r\n/g, '\n');
const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8')) as { publisher: string; name: string; version: string };

type Call = { url: string; body?: string };
const json = (status: number, body: unknown) => ({ ok: status >= 200 && status < 300, status, json: async () => body });

/** A fake fetch that answers each call with the next response in the list (the last one repeats). */
function store(responses: Array<ReturnType<typeof json> | Error>) {
  const calls: Call[] = [];
  const fetch = async (url: string, init?: { body?: string }) => {
    calls.push({ url, body: init?.body });
    const r = responses[Math.min(calls.length - 1, responses.length - 1)]!;
    if (r instanceof Error) throw r;
    return r;
  };
  return { fetch, calls };
}
const marketplace = (...versions: string[]) => json(200, { results: [{ extensions: versions.length ? [{ versions: versions.map((version) => ({ version })) }] : [] }] });
const quiet = { everyMs: 0, log: () => undefined };

describe('waiting for a store to list the release', () => {
  it('Marketplace: asks by ID for checked versions only, and waits until the version appears', async () => {
    const { fetch, calls } = store([marketplace(), marketplace('0.0.9'), marketplace('0.1.0', '0.0.9')]);
    const lines: string[] = [];
    expect(await waitForListing('marketplace', 'acme.fortis-security', '0.1.0', { fetch, tries: 5, everyMs: 0, log: (l: string) => lines.push(l) })).toBe(true);
    expect(calls).toHaveLength(3);
    const body = JSON.parse(calls[0]!.body!);
    expect(body.filters[0].criteria).toEqual([{ filterType: 7, value: 'acme.fortis-security' }]);
    expect(body.flags & 0x20).toBe(0x20); // leaves out versions still being verified
    expect(lines.at(-1)).toBe('acme.fortis-security 0.1.0 is live on the VS Code Marketplace: https://marketplace.visualstudio.com/items?itemName=acme.fortis-security');
  });

  it('Open VSX: asks for the exact version, and treats 404 as not yet', async () => {
    const { fetch, calls } = store([json(404, { error: 'Extension not found' }), json(200, { version: '0.1.0' })]);
    expect(await waitForListing('openvsx', 'acme.fortis-security', '0.1.0', { fetch, tries: 3, ...quiet })).toBe(true);
    expect(calls.map((c) => c.url)).toEqual(['https://open-vsx.org/api/acme/fortis-security/0.1.0', 'https://open-vsx.org/api/acme/fortis-security/0.1.0']);
  });

  it('keeps trying through network errors and server errors', async () => {
    const { fetch, calls } = store([new Error('ECONNRESET'), json(503, {}), json(200, { version: '0.1.0' })]);
    expect(await waitForListing('openvsx', 'acme.fortis-security', '0.1.0', { fetch, tries: 5, ...quiet })).toBe(true);
    expect(calls).toHaveLength(3);
  });

  it('gives up after the last try and says where to look', async () => {
    const { fetch, calls } = store([marketplace('0.0.9')]);
    const lines: string[] = [];
    expect(await waitForListing('marketplace', 'acme.fortis-security', '0.1.0', { fetch, tries: 3, everyMs: 0, log: (l: string) => lines.push(l) })).toBe(false);
    expect(calls).toHaveLength(3);
    expect(lines.at(-1)).toBe("acme.fortis-security 0.1.0 still isn't listed on the VS Code Marketplace. Its page for the publisher says whether the upload failed a check, and why.");
  });

  it('refuses a store it does not know', async () => {
    await expect(waitForListing('chrome', 'a.b', '1.0.0', quiet)).rejects.toThrow(/Unknown store chrome/);
  });
});

describe('the release workflow', () => {
  const publish = workflow.slice(workflow.indexOf('  publish:'));
  const step = (name: string) => {
    const start = publish.indexOf(`- name: ${name}`);
    expect(start, name).toBeGreaterThan(-1);
    const next = publish.indexOf('\n      - ', start + 1);
    return publish.slice(start, next === -1 ? undefined : next);
  };

  it('fails in this repository when a secret is missing, instead of passing without publishing', () => {
    const check = step('Check the publishing secrets');
    expect(check).toContain('VSCE_PAT');
    expect(check).toContain('OVSX_PAT');
    expect(check).toMatch(/GITHUB_REPOSITORY" = "Divine-mercyx\/fortis"[\s\S]*exit 1/);
    expect(publish.indexOf('Check the publishing secrets')).toBeLessThan(publish.indexOf('Publish to the VS Code Marketplace'));
  });

  it('can be re-run: both stores skip a version they already have', () => {
    expect(step('Publish to the VS Code Marketplace')).toContain('--skip-duplicate');
    expect(step('Publish to Open VSX')).toContain('--skip-duplicate');
  });

  it('creates the Open VSX namespace before the first publish, only if it is missing', () => {
    const ns = step("Create the Open VSX namespace if it's missing");
    expect(ns).toMatch(/= 404 \]; then pnpm exec ovsx create-namespace/);
    expect(publish.indexOf('Create the Open VSX namespace')).toBeLessThan(publish.indexOf('- name: Publish to Open VSX'));
  });

  it('passes only once each store it published to lists the version', () => {
    expect(step('Wait for Open VSX to list it')).toMatch(/if: env\.OVSX_PAT != ''[\s\S]*check-listing\.mjs openvsx/);
    expect(step('Wait for the VS Code Marketplace to list it')).toMatch(/if: env\.VSCE_PAT != ''[\s\S]*check-listing\.mjs marketplace/);
    expect(publish.indexOf('Wait for Open VSX')).toBeGreaterThan(publish.indexOf('- name: Publish to Open VSX'));
  });

  it('allows enough time for the waits', () => {
    const minutes = [...publish.matchAll(/check-listing\.mjs \w+ (\d+)/g)].reduce((n, m) => n + Number(m[1]), 0);
    expect(Number(/timeout-minutes: (\d+)/.exec(publish)?.[1])).toBeGreaterThan(minutes);
  });

  it('the listing it waits for is the one package.json publishes', () => {
    expect(pkg.name).toBe('fortis-security');
    expect(pkg.publisher).toMatch(/^[a-z0-9][a-z0-9-]*$/i);
  });
});
