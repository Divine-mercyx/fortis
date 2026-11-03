// Bundles the CLI (and the shared package it uses) into one dependency-free file.
import { build } from 'esbuild';
import { readFileSync, chmodSync } from 'node:fs';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));
await build({
  entryPoints: ['src/index.ts'],
  outfile: 'dist/fortis.js',
  bundle: true,
  platform: 'node',
  target: 'node18',
  format: 'esm',
  banner: { js: '#!/usr/bin/env node' },
  define: {
    __FORTIS_VERSION__: JSON.stringify(pkg.version),
    __FORTIS_API_URL__: JSON.stringify(process.env.FORTIS_DEFAULT_API_URL ?? 'https://api.fortis.dev'),
  },
  legalComments: 'none',
});
chmodSync('dist/fortis.js', 0o755);
console.log(`built dist/fortis.js (v${pkg.version})`);
