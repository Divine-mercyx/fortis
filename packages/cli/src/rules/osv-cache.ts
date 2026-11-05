import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

/*
 * OSV answers cached on this machine, so a pre-push check doesn't repeat the same questions and
 * keeps working for a while without a network. Two kinds of entry, both kept for 6 hours:
 *   queries: "ecosystem|name|version" → advisory ids (an empty list means "no known advisories")
 *   vulns:   advisory id → the advisory
 * A broken or unreadable cache is treated as empty; the cache never makes a scan fail.
 */

export const CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const MAX_QUERIES = 50_000;
const MAX_VULNS = 20_000;
const FILE = 'osv-v1.json';

type Entry<T> = { at: number; v: T };
type Data = { queries: Record<string, Entry<string[]>>; vulns: Record<string, Entry<unknown>> };

export function osvCacheDir(env: Record<string, string | undefined> = process.env): string {
  if (env.FORTIS_CACHE_DIR) return env.FORTIS_CACHE_DIR;
  if (process.platform === 'win32' && env.LOCALAPPDATA) return join(env.LOCALAPPDATA, 'fortis', 'cache');
  return join(env.XDG_CACHE_HOME || join(homedir(), '.cache'), 'fortis');
}

export class OsvCache {
  private data: Data = { queries: {}, vulns: {} };
  private dirty = false;

  constructor(
    private readonly dir: string,
    private readonly now: () => number = Date.now,
    private readonly ttl = CACHE_TTL_MS,
  ) {
    try {
      const parsed = JSON.parse(readFileSync(join(dir, FILE), 'utf8')) as Partial<Data>;
      this.data = { queries: parsed.queries ?? {}, vulns: parsed.vulns ?? {} };
    } catch {
      /* first run, or a damaged file: start empty */
    }
  }

  private fresh<T>(e: Entry<T> | undefined): T | undefined {
    return e && this.now() - e.at < this.ttl ? e.v : undefined;
  }

  query(key: string): string[] | undefined {
    return this.fresh(this.data.queries[key]);
  }

  vuln<T>(id: string): T | undefined {
    return this.fresh(this.data.vulns[id]) as T | undefined;
  }

  setQuery(key: string, ids: string[]) {
    this.data.queries[key] = { at: this.now(), v: ids };
    this.dirty = true;
  }

  setVuln(id: string, v: unknown) {
    this.data.vulns[id] = { at: this.now(), v };
    this.dirty = true;
  }

  /** Writes the cache, dropping expired entries and the oldest ones past the size limit. */
  save() {
    if (!this.dirty) return;
    const keep = <T>(rec: Record<string, Entry<T>>, max: number) =>
      Object.fromEntries(
        Object.entries(rec)
          .filter(([, e]) => this.now() - e.at < this.ttl)
          .sort((a, b) => b[1].at - a[1].at)
          .slice(0, max),
      );
    try {
      mkdirSync(this.dir, { recursive: true });
      const tmp = join(this.dir, `${FILE}.${process.pid}.tmp`);
      writeFileSync(tmp, JSON.stringify({ queries: keep(this.data.queries, MAX_QUERIES), vulns: keep(this.data.vulns, MAX_VULNS) }));
      renameSync(tmp, join(this.dir, FILE));
      this.dirty = false;
    } catch {
      /* read-only home, full disk: carry on without caching */
    }
  }
}
