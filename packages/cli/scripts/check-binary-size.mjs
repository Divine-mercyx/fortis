#!/usr/bin/env node
// Fails if a binary or its download gets too big. Usage: check-binary-size.mjs <binary> <archive>
import { appendFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const MB = 1024 * 1024;
export const MAX_BINARY = 60 * MB;
export const MAX_DOWNLOAD = 25 * MB;

export function checkSizes(binary, download) {
  const problems = [];
  if (binary > MAX_BINARY) problems.push(`The binary is ${(binary / MB).toFixed(1)} MB. The limit is ${MAX_BINARY / MB} MB.`);
  if (download > MAX_DOWNLOAD) problems.push(`The download is ${(download / MB).toFixed(1)} MB. The limit is ${MAX_DOWNLOAD / MB} MB.`);
  return problems;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [binary, archive] = process.argv.slice(2);
  const binarySize = statSync(binary).size;
  const downloadSize = statSync(archive).size;
  const line = `${archive.split(/[\\/]/).pop()}: binary ${(binarySize / MB).toFixed(1)} MB, download ${(downloadSize / MB).toFixed(1)} MB`;
  console.log(line);
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `### ${line}\n`);
  const problems = checkSizes(binarySize, downloadSize);
  for (const p of problems) console.error(`FAILED: ${p}`);
  process.exit(problems.length ? 1 : 0);
}
