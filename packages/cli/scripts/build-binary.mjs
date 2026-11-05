// Builds a standalone `fortis` executable for this machine's OS and architecture: a copy of the
// running Node with the CLI injected, as a Node single executable application. Users need no Node.
// Release builds use Node 22 (.nvmrc), the version the tests run on.
import { execFileSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const cli = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(cli, 'dist-sea');
const isWindows = process.platform === 'win32';
const isMac = process.platform === 'darwin';
const binary = join(out, isWindows ? 'fortis.exe' : 'fortis');
const run = (cmd, args) => execFileSync(cmd, args, { cwd: cli, stdio: 'inherit' });

/**
 * Removes the Authenticode signature from a copy of node.exe. Injecting the CLI invalidates it, and
 * signtool can't sign a file that still has the old one (0x800700C1). This is `signtool remove /s`
 * without needing the Windows SDK: clear the PE's certificate entry and cut the table off the end.
 */
function stripWindowsSignature(file) {
  const data = readFileSync(file);
  const pe = data.readUInt32LE(0x3c);
  const optional = pe + 24;
  const isPe32Plus = data.readUInt16LE(optional) === 0x20b;
  const entry = optional + (isPe32Plus ? 112 : 96) + 4 * 8; // data directory 4: the certificate table
  const offset = data.readUInt32LE(entry);
  const size = data.readUInt32LE(entry + 4);
  if (!offset || !size) return;
  data.writeUInt32LE(0, entry);
  data.writeUInt32LE(0, entry + 4);
  writeFileSync(file, offset + size >= data.length ? data.subarray(0, offset) : data);
}

mkdirSync(out, { recursive: true });
run(process.execPath, ['build.mjs', '--sea']);

const blob = join(out, 'sea.blob');
const config = join(out, 'sea-config.json');
writeFileSync(config, JSON.stringify({ main: join(out, 'fortis.cjs'), output: blob, disableExperimentalSEAWarning: true }));
run(process.execPath, ['--experimental-sea-config', config]);

copyFileSync(process.execPath, binary);
chmodSync(binary, 0o755);
if (isMac) run('codesign', ['--remove-signature', binary]);
if (isWindows) stripWindowsSignature(binary);

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
