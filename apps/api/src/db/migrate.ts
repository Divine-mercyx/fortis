import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { migrate } from 'drizzle-orm/node-postgres/migrator';

import { db, pool } from './client';

const migrationsFolder = join(dirname(fileURLToPath(import.meta.url)), '../../drizzle');

export async function runMigrations() {
  await migrate(db, { migrationsFolder });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  runMigrations()
    .then(() => {
      console.log('Migrations applied');
      return pool.end();
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
