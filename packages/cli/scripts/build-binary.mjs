// Builds a standalone `fortis` executable for this machine's OS and architecture: a copy of the
// Node with the CLI injected, as a Node single executable application. Users need no Node.
// FORTIS_NODE_RUNTIME picks which Node: CI points it at the small build from build-node-runtime.sh.
// Otherwise it's the running Node, so a local build works, at about twice the size.
import { execFileSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdirSync, statSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const cli = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(cli, 'dist-sea');
const isWindows = process.platform === 'win32';
const isMac = process.platform === 'darwin';
const binary = join(out, isWindows ? 'fortis.exe' : 'fortis');
const run = (cmd, args) => execFileSync(cmd, args, { cwd: cli, stdio: 'inherit' });
const runtime = process.env.FORTIS_NODE_RUNTIME || process.execPath;

mkdirSync(out, { recursive: true });
run(process.execPath, ['build.mjs', '--sea']);

const blob = join(out, 'sea.blob');
const config = join(out, 'sea-config.json');
writeFileSync(config, JSON.stringify({ main: join(out, 'fortis.cjs'), output: blob, disableExperimentalSEAWarning: true }));
// The blob has to come from the same Node it's injected into.
run(runtime, ['--experimental-sea-config', config]);

copyFileSync(runtime, binary);
chmodSync(binary, 0o755);
if (isMac) run('codesign', ['--remove-signature', binary]);

const postject = createRequire(import.meta.url).resolve('postject/dist/cli.js');
run(process.execPath, [
  postject,
  binary,
  'NODE_SEA_BLOB',
  blob,
  '--sentinel-fuse',
  'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2',
  ...(isMac ? ['--macho-segment-name', 'NODE_SEA'] : []),
]);
// Apple silicon refuses to run an unsigned binary; an ad-hoc signature is enough outside the App Store.
if (isMac) run('codesign', ['--sign', '-', binary]);

console.log(`built ${binary} (${Math.round(statSync(binary).size / 1024 / 1024)} MB)`);
