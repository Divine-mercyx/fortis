// Bundles the CLI (and the shared package it uses) into one dependency-free file.
// With --sea it writes the CommonJS bundle that scripts/build-binary.mjs turns into an executable.
import { build } from 'esbuild';
import { readFileSync, chmodSync } from 'node:fs';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));
const sea = process.argv.includes('--sea');
const outfile = sea ? 'dist-sea/fortis.cjs' : 'dist/fortis.js';
await build({
  entryPoints: ['src/index.ts'],
  outfile,
  bundle: true,
  platform: 'node',
  target: sea ? 'node22' : 'node18',
  format: sea ? 'cjs' : 'esm',
  banner: sea ? {} : { js: '#!/usr/bin/env node' },
  define: {
    __FORTIS_VERSION__: JSON.stringify(pkg.version),
    __FORTIS_API_URL__: JSON.stringify(process.env.FORTIS_DEFAULT_API_URL ?? 'https://fortis-api-prqr.onrender.com'),
  },
  legalComments: 'none',
});
if (!sea) chmodSync(outfile, 0o755);
console.log(`built ${outfile} (v${pkg.version})`);
