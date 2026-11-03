/**
 * Keeps free-tier hosts (Render sleeps a service after 15 minutes without traffic) awake by
 * requesting health URLs every few minutes during a daily window.
 *
 * Render's free plan has 750 instance hours a month per workspace, shared by every service. Two
 * services awake 24/7 would need about 1,490, so both get suspended mid-month. The default
 * window, 12 hours a day in Lagos time, keeps two services within the limit (2 × 12 × 31 = 744).
 *
 * Env: KEEPALIVE=off to disable · KEEPALIVE_HOURS="8-20" (start-end, 24h; "0-24" = always)
 *      KEEPALIVE_TZ="Africa/Lagos" · KEEPALIVE_URLS="https://a/health,https://b/api/health"
 */

export type KeepAliveOptions = {
  urls: string[];
  hours?: string;
  timeZone?: string;
  intervalMs?: number;
  log?: (msg: string) => void;
  fetchImpl?: typeof fetch;
  now?: () => Date;
};

export function parseHours(spec = '8-20'): [number, number] {
  const m = /^\s*(\d{1,2})\s*-\s*(\d{1,2})\s*$/.exec(spec);
  if (!m) return [8, 20];
  const start = Math.min(24, Number(m[1]));
  const end = Math.min(24, Number(m[2]));
  return [start, end];
}

export function hourIn(timeZone: string, date: Date): number {
  const h = new Intl.DateTimeFormat('en-GB', { hour: 'numeric', hourCycle: 'h23', timeZone }).format(date);
  return Number(h);
}

/** Whether `hour` falls in [start, end), wrapping past midnight (e.g. 20-8). */
export function inWindow(hour: number, [start, end]: [number, number]): boolean {
  if (start === end) return false;
  if (start === 0 && end === 24) return true;
  return start < end ? hour >= start && hour < end : hour >= start || hour < end;
}

/** Starts the timer; returns a stop function. Never throws: a failed ping is only logged. */
export function startKeepAlive(opts: KeepAliveOptions): () => void {
  const urls = [...new Set(opts.urls.map((u) => u.trim()).filter((u) => /^https?:\/\//.test(u)))];
  if (!urls.length) return () => {};
  const window = parseHours(opts.hours);
  const tz = opts.timeZone || 'Africa/Lagos';
  const fetchImpl = opts.fetchImpl ?? fetch;
  const now = opts.now ?? (() => new Date());
  const log = opts.log ?? (() => {});

  const tick = async () => {
    if (!inWindow(hourIn(tz, now()), window)) return;
    await Promise.all(
      urls.map(async (url) => {
        try {
          const res = await fetchImpl(url, { headers: { 'user-agent': 'fortis-keepalive' }, signal: AbortSignal.timeout(30_000) });
          if (!res.ok) log(`keep-alive: ${url} answered ${res.status}`);
        } catch (e) {
          log(`keep-alive: ${url} failed (${(e as Error).message})`);
        }
      }),
    );
  };
  const timer = setInterval(() => void tick(), opts.intervalMs ?? 10 * 60_000);
  // Don't hold the process open just for this.
  (timer as { unref?: () => void }).unref?.();
  void tick();
  return () => clearInterval(timer);
}

/** Reads the KEEPALIVE_* settings; defaults on when running on Render. */
export function keepAliveFromEnv(env: Record<string, string | undefined>, defaults: string[]): KeepAliveOptions | null {
  const flag = (env.KEEPALIVE ?? '').toLowerCase();
  if (flag === 'off' || flag === 'false' || flag === '0') return null;
  if (!env.RENDER && flag !== 'on' && !env.KEEPALIVE_URLS) return null;
  const urls = env.KEEPALIVE_URLS ? env.KEEPALIVE_URLS.split(',') : defaults;
  return { urls, hours: env.KEEPALIVE_HOURS, timeZone: env.KEEPALIVE_TZ };
}
