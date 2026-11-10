// Bundles the extension into one file, and copies in the CLI it falls back on when none is installed.
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const here = dirname(fileURLToPath(import.meta.url));
const cli = join(here, '..', 'cli');

await build({
  entryPoints: [join(here, 'src', 'extension.ts')],
  outfile: join(here, 'dist', 'extension.js'),
  bundle: true,
  platform: 'node',
  target: 'node18',
  format: 'cjs',
  external: ['vscode'],
  legalComments: 'none',
});

execFileSync(process.execPath, ['build.mjs'], { cwd: cli, stdio: 'inherit' });
mkdirSync(join(here, 'dist', 'cli'), { recursive: true });
// .mjs: the CLI bundle is an ES module, and this package isn't.
copyFileSync(join(cli, 'dist', 'fortis.js'), join(here, 'dist', 'cli', 'fortis.mjs'));
console.log('built dist/extension.js and dist/cli/fortis.mjs');
