import { keepAliveFromEnv, startKeepAlive } from '@fortis/shared';

import { buildApp } from './app';
import { env } from './config/env';

const app = await buildApp();
try {
  await app.listen({ port: env.PORT, host: env.HOST });
  // Free Render plans sleep after 15 idle minutes. Ping this API and the dashboard (whose
  // /api/health passes through to this API's /health) so both stay awake during the day.
  const self = process.env.RENDER_EXTERNAL_URL?.replace(/\/+$/, '');
  const keepAlive = keepAliveFromEnv(process.env, [self ? `${self}/health` : '', `${env.WEB_URL.replace(/\/+$/, '')}/api/health`]);
  if (keepAlive) {
    startKeepAlive({ ...keepAlive, log: (m) => app.log.warn(m) });
    app.log.info(`keep-alive on (${keepAlive.hours ?? '9-21'} ${keepAlive.timeZone ?? 'Africa/Lagos'})`);
  }
} catch (err) {
  app.log.error(err);
  process.exit(1);
}

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    app.close().then(() => process.exit(0));
  });
}
