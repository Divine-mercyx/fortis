import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { inflateRawSync } from 'node:zlib';

import { compareVersions, type OsvAffected } from './fix-version';
import type { Ecosystem, Locked } from './lockfiles';

/*
 * Air-gapped dependency checks: OSV publishes every advisory per ecosystem as a zip
 * (https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip). Copy those onto the
 * network and pass --osv-db <dir>: the folder may hold the zips (any names, in subfolders too) or
 * the advisories already unzipped as .json files. Matching follows the OSV schema: a version is
 * affected when it is listed in `versions` or falls inside a range's introduced/fixed/last_affected events.
 */

export type DbAdvisory = {
  id: string;
  summary?: string;
  aliases?: string[];
  withdrawn?: string;
  database_specific?: { severity?: string };
  affected?: (OsvAffected & { versions?: string[] })[];
};

// ---------------------------------------------------------------- zip (with ZIP64), no dependency

const u16 = (b: Buffer, o: number) => b.readUInt16LE(o);
const u32 = (b: Buffer, o: number) => b.readUInt32LE(o);
const u64 = (b: Buffer, o: number) => Number(b.readBigUInt64LE(o));

/** Calls `onEntry` with the name and contents of every file in the archive. */
export function readZip(buf: Buffer, onEntry: (name: string, data: Buffer) => void) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65_557); i--) {
    if (u32(buf, i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd === -1) throw new Error('not a zip file');
  let count = u16(buf, eocd + 10);
  let cdOffset = u32(buf, eocd + 16);
  if (count === 0xffff || cdOffset === 0xffffffff) {
    const loc = eocd - 20;
    if (loc < 0 || u32(buf, loc) !== 0x07064b50) throw new Error('damaged ZIP64 archive');
    const z64 = u64(buf, loc + 8);
    if (u32(buf, z64) !== 0x06064b50) throw new Error('damaged ZIP64 archive');
    count = u64(buf, z64 + 32);
    cdOffset = u64(buf, z64 + 48);
  }
  let p = cdOffset;
  for (let n = 0; n < count; n++) {
    if (u32(buf, p) !== 0x02014b50) throw new Error('damaged zip directory');
    const method = u16(buf, p + 10);
    let compSize = u32(buf, p + 20);
    let size = u32(buf, p + 24);
    const nameLen = u16(buf, p + 28);
    const extraLen = u16(buf, p + 30);
    const commentLen = u16(buf, p + 32);
    let local = u32(buf, p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    // ZIP64 sizes and offset live in extra field 0x0001, in this order, only for fields that overflowed.
    for (let e = p + 46 + nameLen; e < p + 46 + nameLen + extraLen; ) {
      const id = u16(buf, e);
      const len = u16(buf, e + 2);
      if (id === 0x0001) {
        let q = e + 4;
        if (size === 0xffffffff) (size = u64(buf, q)), (q += 8);
        if (compSize === 0xffffffff) (compSize = u64(buf, q)), (q += 8);
        if (local === 0xffffffff) local = u64(buf, q);
      }
      e += 4 + len;
    }
    p += 46 + nameLen + extraLen + commentLen;
    if (name.endsWith('/')) continue;
    if (u32(buf, local) !== 0x04034b50) throw new Error(`damaged zip entry ${name}`);
    const start = local + 30 + u16(buf, local + 26) + u16(buf, local + 28);
    const raw = buf.subarray(start, start + compSize);
    if (method === 0) onEntry(name, raw);
    else if (method === 8) onEntry(name, inflateRawSync(raw));
    else throw new Error(`unsupported zip compression (${method}) in ${name}`);
  }
}

// ---------------------------------------------------------------- matching

const norm = (eco: string, name: string) => (eco === 'PyPI' ? name.toLowerCase().replace(/[-_.]+/g, '-') : eco === 'NuGet' ? name.toLowerCase() : name);

/** Whether `version` is inside one OSV range. */
export function inRange(version: string, events: { introduced?: string; fixed?: string; last_affected?: string }[]): boolean {
  const at = (e: (typeof events)[number]) => e.introduced ?? e.fixed ?? e.last_affected ?? '0';
  const sorted = [...events].sort((a, b) => (at(a) === '0' ? -1 : at(b) === '0' ? 1 : compareVersions(at(a), at(b))));
  let affected = false;
  for (const e of sorted) {
    if (e.introduced !== undefined && (e.introduced === '0' || compareVersions(version, e.introduced) >= 0)) affected = true;
    if (e.fixed !== undefined && compareVersions(version, e.fixed) >= 0) affected = false;
    if (e.last_affected !== undefined && compareVersions(version, e.last_affected) > 0) affected = false;
  }
  return affected;
}

export function affects(adv: DbAdvisory, eco: Ecosystem, name: string, version: string): boolean {
  if (adv.withdrawn) return false;
  return (adv.affected ?? []).some(
    (a) =>
      a.package?.ecosystem?.split(':')[0] === eco &&
      norm(eco, a.package.name ?? '') === norm(eco, name) &&
      ((a.versions ?? []).includes(version) || (a.ranges ?? []).some((r) => r.type !== 'GIT' && inRange(version, r.events ?? []))),
  );
}

function filesIn(dir: string, depth = 3): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory() && depth > 0) out.push(...filesIn(p, depth - 1));
    else if (e.isFile() && /\.(zip|json)$/i.test(e.name)) out.push(p);
  }
  return out;
}

/**
 * Looks the packages up in a local OSV database. Returns the advisory ids per package (keyed like
 * the network lookup) and every matching advisory.
 */
export function lookupLocal(dir: string, pkgs: Locked[], keyOf: (p: Locked) => string): { hits: Map<string, string[]>; details: Map<string, DbAdvisory>; read: number } {
  if (!existsSync(dir) || !statSync(dir).isDirectory()) throw new Error(`--osv-db ${dir} is not a folder`);
  const wanted = new Map<string, Locked[]>();
  for (const p of pkgs) {
    const k = `${p.ecosystem}|${norm(p.ecosystem, p.name)}`;
    wanted.set(k, [...(wanted.get(k) ?? []), p]);
  }
  const hits = new Map<string, string[]>();
  const details = new Map<string, DbAdvisory>();
  let read = 0;
  const consider = (text: string) => {
    let adv: DbAdvisory;
    try {
      adv = JSON.parse(text) as DbAdvisory;
    } catch {
      return;
    }
    if (!adv.id || adv.withdrawn) return;
    read++;
    for (const a of adv.affected ?? []) {
      const eco = a.package?.ecosystem?.split(':')[0];
      if (!eco || !a.package?.name) continue;
      for (const p of wanted.get(`${eco}|${norm(eco, a.package.name)}`) ?? []) {
        if (!affects(adv, p.ecosystem, p.name, p.version)) continue;
        const ids = hits.get(keyOf(p)) ?? [];
        if (!ids.includes(adv.id)) hits.set(keyOf(p), [...ids, adv.id]);
        details.set(adv.id, adv);
      }
    }
  };
  const files = filesIn(dir);
  if (!files.length) throw new Error(`--osv-db ${dir} has no .zip or .json files; download <ECOSYSTEM>/all.zip from osv-vulnerabilities.storage.googleapis.com`);
  for (const f of files) {
    if (/\.zip$/i.test(f)) readZip(readFileSync(f), (name, data) => name.endsWith('.json') && consider(data.toString('utf8')));
    else consider(readFileSync(f, 'utf8'));
  }
  return { hits, details, read };
}
