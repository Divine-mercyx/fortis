import cookie from '@fastify/cookie';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyServerOptions } from 'fastify';

import { env } from './config/env';
import { pool } from './db/client';
import { AppError } from './lib/errors';
import { cliRoutes } from './modules/cli.routes';
import { authRoutes } from './modules/auth.routes';
import { findingsRoutes } from './modules/findings.routes';
import { orgRoutes } from './modules/orgs.routes';
import { exposureRoutes } from './modules/exposure.routes';
import { targetRoutes } from './modules/targets.routes';
import { authPlugin } from './plugins/auth';

export async function buildApp(opts: FastifyServerOptions = {}) {
  const app = Fastify({
    logger: env.isTest ? false : { level: env.LOG_LEVEL, redact: ['req.headers.authorization', 'req.headers.cookie'] },
    trustProxy: true,
    bodyLimit: 256 * 1024,
    ...opts,
  });

  // Only JSON bodies: form/text posts (which browsers can send cross-site without a preflight) are refused.
  app.removeContentTypeParser('text/plain');

  await app.register(helmet, { contentSecurityPolicy: false });
  await app.register(cookie);
  await app.register(rateLimit, { global: true, max: 300, timeWindow: '1 minute', enableDraftSpec: true });
  await app.register(authPlugin);

  app.setErrorHandler((err, req, reply) => {
    if (err instanceof AppError) {
      return reply.code(err.statusCode).send({ error: { code: err.code, message: err.message, details: err.details } });
    }
    const e = err as { statusCode?: number; code?: string; message?: string };
    if (e.statusCode && e.statusCode < 500) {
      return reply.code(e.statusCode).send({ error: { code: e.code ?? 'BAD_REQUEST', message: e.message ?? 'Bad request' } });
    }
    req.log.error(err);
    return reply.code(500).send({ error: { code: 'INTERNAL', message: 'Something went wrong on our side.' } });
  });

  app.setNotFoundHandler((_req, reply) => reply.code(404).send({ error: { code: 'NOT_FOUND', message: 'Route not found.' } }));

  app.get('/health', async () => {
    await pool.query('select 1');
    return { ok: true };
  });

  await app.register(authRoutes);
  await app.register(orgRoutes);
  await app.register(cliRoutes);
  await app.register(findingsRoutes);
  await app.register(targetRoutes);
  await app.register(exposureRoutes);
  return app;
}
