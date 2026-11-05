import { Pool } from 'pg';

export const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgres://app:{{GENERIC}}@10.0.3.12:5432/app' }); // @hit
export const buildUrl = (user: string, pass: string, host: string) => `mysql://${user}:${pass}@${host}/core`;
// Example for the README: postgres://USER:PASSWORD@HOST:5432/DB
export const testUrl = 'postgres://postgres:postgres@127.0.0.1:5432/test';
