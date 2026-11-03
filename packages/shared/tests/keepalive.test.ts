import { describe, expect, it } from 'vitest';

import { hourIn, inWindow, keepAliveFromEnv, parseHours, startKeepAlive } from '../src/keepalive';

describe('keep-alive', () => {
  it('works out the hour in Lagos and the window, including across midnight', () => {
    expect(hourIn('Africa/Lagos', new Date('2026-11-03T06:30:00Z'))).toBe(7);
    expect(inWindow(8, parseHours('8-20'))).toBe(true);
    expect(inWindow(20, parseHours('8-20'))).toBe(false);
    expect(inWindow(23, parseHours('20-8'))).toBe(true);
    expect(inWindow(12, parseHours('0-24'))).toBe(true);
    expect(parseHours('nonsense')).toEqual([8, 20]);
  });

  it('only turns on on Render (or when asked) and can be switched off', () => {
    expect(keepAliveFromEnv({}, ['https://a/health'])).toBeNull();
    expect(keepAliveFromEnv({ RENDER: 'true' }, ['https://a/health'])?.urls).toEqual(['https://a/health']);
    expect(keepAliveFromEnv({ RENDER: 'true', KEEPALIVE: 'off' }, ['https://a/health'])).toBeNull();
    expect(keepAliveFromEnv({ KEEPALIVE_URLS: 'https://x/h,https://y/h' }, [])?.urls).toEqual(['https://x/h', 'https://y/h']);
  });

  it('pings inside the window, skips outside it, and never throws on a failure', async () => {
    const hits: string[] = [];
    const fetchImpl = (async (url: string) => {
      hits.push(url);
      if (url.includes('down')) throw new Error('ECONNREFUSED');
      return new Response('ok');
    }) as unknown as typeof fetch;
    const logs: string[] = [];
    const stop = startKeepAlive({ urls: ['https://a/health', 'https://down/health', 'not-a-url'], fetchImpl, log: (m) => logs.push(m), now: () => new Date('2026-11-03T10:00:00Z') });
    await new Promise((r) => setTimeout(r, 20));
    stop();
    expect(hits).toEqual(['https://a/health', 'https://down/health']);
    expect(logs[0]).toMatch(/down.*failed/);

    const quiet: string[] = [];
    const stop2 = startKeepAlive({ urls: ['https://a/health'], fetchImpl: (async (u: string) => { quiet.push(u); return new Response('ok'); }) as unknown as typeof fetch, now: () => new Date('2026-11-03T23:00:00Z') });
    await new Promise((r) => setTimeout(r, 20));
    stop2();
    expect(quiet).toEqual([]);
  });
});
