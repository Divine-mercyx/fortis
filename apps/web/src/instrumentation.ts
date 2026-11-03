/**
 * Runs once when the dashboard server starts. On Render's free plan it keeps this service and
 * the API awake during the day: /api/health on the dashboard passes through to the API.
 * See packages/shared/src/keepalive.ts for the settings and the free-hours budget.
 */
export async function register() {
  if (process.env.NEXT_RUNTIME !== 'nodejs') return;
  const { keepAliveFromEnv, startKeepAlive } = await import('@fortis/shared');
  const self = process.env.RENDER_EXTERNAL_URL?.replace(/\/+$/, '');
  const api = process.env.API_URL?.replace(/\/+$/, '');
  const opts = keepAliveFromEnv(process.env, [self ? `${self}/api/health` : '', api ? `${api}/health` : '']);
  if (!opts) return;
  startKeepAlive({ ...opts, log: (m) => console.warn(m) });
  console.log(`keep-alive on (${opts.hours ?? '8-20'} ${opts.timeZone ?? 'Africa/Lagos'})`);
}
