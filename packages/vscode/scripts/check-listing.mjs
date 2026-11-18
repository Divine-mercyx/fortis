#!/usr/bin/env node
// Waits until a store lists this version of the extension, so a release only passes once people can
// install it. Usage: check-listing.mjs marketplace|openvsx [minutes to wait, default 20]
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const MARKETPLACE = 'https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery';
const OPEN_VSX = 'https://open-vsx.org/api';
// 0x1 includes versions; 0x20 leaves out versions the Marketplace hasn't finished checking.
const FLAGS = 0x1 | 0x20;

export const STORES = {
  marketplace: {
    name: 'the VS Code Marketplace',
    page: (id) => `https://marketplace.visualstudio.com/items?itemName=${id}`,
    async versions(id, fetch) {
      const res = await fetch(MARKETPLACE, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json;api-version=3.0-preview.1' },
        body: JSON.stringify({ filters: [{ criteria: [{ filterType: 7, value: id }] }], flags: FLAGS }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const ext = (await res.json()).results?.[0]?.extensions?.[0];
      return ext ? ext.versions.map((v) => v.version) : [];
    },
  },
  openvsx: {
    name: 'Open VSX',
    page: (id) => `https://open-vsx.org/extension/${id.replace('.', '/')}`,
    async versions(id, fetch, version) {
      const [ns, name] = id.split('.');
      const res = await fetch(`${OPEN_VSX}/${ns}/${name}/${version}`);
      if (res.status === 404) return [];
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return [(await res.json()).version];
    },
  },
};

/** Asks the store every `everyMs` until it lists `version`. Network errors count as "not yet". */
export async function waitForListing(store, id, version, { fetch = globalThis.fetch, tries = 40, everyMs = 30_000, log = console.log } = {}) {
  const s = STORES[store];
  if (!s) throw new Error(`Unknown store ${store}. Use one of: ${Object.keys(STORES).join(', ')}`);
  for (let i = 1; i <= tries; i++) {
    let seen = [];
    try {
      seen = await s.versions(id, fetch, version);
    } catch (e) {
      log(`Couldn't ask ${s.name} (${e.message}). Trying again.`);
    }
    if (seen.includes(version)) {
      log(`${id} ${version} is live on ${s.name}: ${s.page(id)}`);
      return true;
    }
    if (i < tries) {
      log(`Not listed on ${s.name} yet (${i}/${tries}).`);
      await new Promise((r) => setTimeout(r, everyMs));
    }
  }
  log(`${id} ${version} still isn't listed on ${s.name}. Its page for the publisher says whether the upload failed a check, and why.`);
  return false;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [store, minutes = '20'] = process.argv.slice(2);
  const pkg = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'package.json'), 'utf8'));
  const tries = Math.max(1, Math.round((Number(minutes) * 60) / 30));
  waitForListing(store, `${pkg.publisher}.${pkg.name}`, pkg.version, { tries }).then(
    (ok) => (process.exitCode = ok ? 0 : 1),
    (e) => {
      console.error(e.message);
      process.exitCode = 2;
    },
  );
}
