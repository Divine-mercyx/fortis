#!/usr/bin/env node
// Runs `fortis update` for real: a built binary replaces itself from a local release folder. On
// Windows this exercises replacing a running .exe. Usage: update-check.mjs <binary> <release folder>
import { execFileSync, spawn } from 'node:child_process';
import { copyFileSync, createReadStream, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';

const [binary, release] = process.argv.slice(2);
const home = mkdtempSync(join(tmpdir(), 'fortis-update-'));
const bin = join(home, '.fortis', 'bin');
mkdirSync(bin, { recursive: true });
const installed = join(bin, basename(binary));

// The installed copy has a marker the release's copy doesn't, so a replacement can be seen.
copyFileSync(binary, installed);
writeFileSync(installed, Buffer.concat([readFileSync(installed), Buffer.from('fortis-old-copy')]));

const server = createServer((req, res) => {
  const name = basename(req.url ?? '');
  res.writeHead(200);
  createReadStream(join(release, name))
    .on('error', () => {
      res.statusCode = 404;
      res.end();
    })
    .pipe(res);
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const env = { ...process.env, FORTIS_DOWNLOAD_BASE: base, FORTIS_NO_UPDATE_CHECK: '1', HOME: home, USERPROFILE: home };

const run = (args) =>
  new Promise((resolve) => {
    let out = '';
    const child = spawn(installed, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (out += d));
    child.on('close', (code) => resolve({ code, out }));
  });

try {
  const { code, out } = await run(['update', '99.0.0']);
  console.log(out.trim());
  if (code !== 0) throw new Error(`fortis update exited with ${code}`);
  if (readFileSync(installed).includes('fortis-old-copy')) throw new Error('the binary was not replaced');
  const after = execFileSync(installed, ['--version'], { env, encoding: 'utf8' }).trim();
  console.log(`ok: replaced itself and runs: ${after}`);

  // A second update must clean up what Windows couldn't delete the first time.
  const again = await run(['update', '99.0.0']);
  if (again.code !== 0) throw new Error(`the second update exited with ${again.code}:\n${again.out}`);
  console.log('ok: updates again');

  // A tampered download must be refused, leaving the working copy alone.
  const asset = readFileSync(join(release, 'SHA256SUMS'), 'utf8').replace(/^[0-9a-f]{64}/gim, '0'.repeat(64));
  const badRelease = mkdtempSync(join(tmpdir(), 'fortis-bad-'));
  writeFileSync(join(badRelease, 'SHA256SUMS'), asset);
  await new Promise((resolve) => server.close(resolve));
  const bad = createServer((req, res) => {
    const name = basename(req.url ?? '');
    res.writeHead(200);
    createReadStream(join(name === 'SHA256SUMS' ? badRelease : release, name)).pipe(res);
  });
  await new Promise((resolve) => bad.listen(0, '127.0.0.1', resolve));
  env.FORTIS_DOWNLOAD_BASE = `http://127.0.0.1:${bad.address().port}`;
  const refused = await run(['update', '99.0.0']);
  if (refused.code === 0 || !/checksum mismatch/i.test(refused.out)) throw new Error(`a bad checksum was not refused:\n${refused.out}`);
  execFileSync(installed, ['--version'], { env });
  console.log('ok: refuses a bad checksum, and still runs');
  bad.close();
  rmSync(badRelease, { recursive: true, force: true });
  process.exitCode = 0;
} catch (e) {
  console.error(`FAILED: ${e.message}`);
  process.exitCode = 1;
} finally {
  server.close();
  try {
    rmSync(home, { recursive: true, force: true, maxRetries: 3 });
  } catch {
    /* Windows can hold on to a file that has only just exited */
  }
}
process.exit(process.exitCode);
