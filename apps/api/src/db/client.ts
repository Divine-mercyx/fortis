import { drizzle } from 'drizzle-orm/node-postgres';
import pg from 'pg';

import { env } from '../config/env';
import * as schema from './schema';

export const pool = new pg.Pool({
  connectionString: env.DATABASE_URL,
  max: env.isTest ? 4 : 10,
  ssl: env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
});

export const db = drizzle(pool, { schema });
export type Db = typeof db;
/** A database handle or an open transaction. */
export type DbOrTx = Db | Parameters<Parameters<Db['transaction']>[0]>[0];
