import { z } from 'zod';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().default(4000),
  HOST: z.string().default('0.0.0.0'),
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  /** Use TLS for Postgres (DigitalOcean managed databases require it). */
  DATABASE_SSL: z.enum(['true', 'false']).default('false'),
  /** Comma-separated origins allowed to send cookie-authenticated writes. */
  WEB_ORIGINS: z.string().default('http://localhost:3000'),
  /** Public dashboard URL, used in CLI responses. */
  WEB_URL: z.string().default('http://localhost:3000'),
  SESSION_TTL_DAYS: z.coerce.number().int().min(1).max(90).default(14),
  /** Sign-up and login attempts per IP per minute. */
  AUTH_RATE_LIMIT_PER_MIN: z.coerce.number().int().min(1).default(10),
  /** Plan for new workspaces (e.g. core during early access and demos). */
  DEFAULT_PLAN: z.enum(['free', 'core', 'plus', 'enterprise']).default('free'),
  COOKIE_SECURE: z.enum(['true', 'false']).optional(),
  /** Ed25519 private key (PEM) that signs rule packs. Required in production. */
  RULES_SIGNING_PRIVATE_KEY: z.string().optional(),
  RULES_SIGNING_KEY_ID: z.string().default('dev'),
  LOG_LEVEL: z.string().default('info'),
  /** Shared secret for scheduled jobs (POST /v1/internal/exposure/run-due). Unset turns the route off. */
  CRON_SECRET: z.preprocess((v) => (v === '' ? undefined : v), z.string().min(32).optional()),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  console.error('Invalid environment configuration:');
  for (const issue of parsed.error.issues) console.error(`  - ${issue.path.join('.')}: ${issue.message}`);
  process.exit(1);
}

const raw = parsed.data;
if (raw.NODE_ENV === 'production' && !raw.RULES_SIGNING_PRIVATE_KEY) {
  console.error('RULES_SIGNING_PRIVATE_KEY is required in production');
  process.exit(1);
}

export const env = {
  ...raw,
  webOrigins: raw.WEB_ORIGINS.split(',').map((o) => o.trim()).filter(Boolean),
  cookieSecure: raw.COOKIE_SECURE ? raw.COOKIE_SECURE === 'true' : raw.NODE_ENV === 'production',
  isProd: raw.NODE_ENV === 'production',
  isTest: raw.NODE_ENV === 'test',
};
