import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    globalSetup: ['tests/global-setup.ts'],
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 30_000,
    env: {
      NODE_ENV: 'test',
      DATABASE_URL: process.env.TEST_DATABASE_URL ?? 'postgres://postgres:postgres@localhost:5432/fortis_test',
      WEB_ORIGINS: 'http://localhost:3000',
      WEB_URL: 'http://localhost:3000',
      AUTH_RATE_LIMIT_PER_MIN: '1000',
    },
  },
});
