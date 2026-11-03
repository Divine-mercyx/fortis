import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

import type { Severity } from '@fortis/shared';

/** Per-repository settings, committed as .fortis.json. Never holds the key. */
export type ProjectConfig = {
  apiUrl?: string;
  projectId?: string;
  failOn?: Severity;
  ignore?: string[];
};

export const PROJECT_CONFIG = '.fortis.json';

export function readProjectConfig(root: string): ProjectConfig {
  const p = join(root, PROJECT_CONFIG);
  if (!existsSync(p)) return {};
  try {
    return JSON.parse(readFileSync(p, 'utf8')) as ProjectConfig;
  } catch {
    throw new Error(`${PROJECT_CONFIG} is not valid JSON`);
  }
}

export function writeProjectConfig(root: string, config: ProjectConfig) {
  writeFileSync(join(root, PROJECT_CONFIG), `${JSON.stringify(config, null, 2)}\n`);
}

/* ---------- User credentials (~/.config/fortis/credentials.json, mode 0600) ---------- */

type Credentials = { keys: Record<string, string> };

export function credentialsPath() {
  const base = process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config');
  return join(base, 'fortis', 'credentials.json');
}

function readCredentials(): Credentials {
  try {
    return JSON.parse(readFileSync(credentialsPath(), 'utf8')) as Credentials;
  } catch {
    return { keys: {} };
  }
}

/** The key for an API: FORTIS_KEY wins (CI), then the saved key from `fortis login`. */
export function resolveKey(api: string): string | undefined {
  return process.env.FORTIS_KEY?.trim() || readCredentials().keys[api];
}

export function saveKey(api: string, key: string) {
  const p = credentialsPath();
  mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
  const creds = readCredentials();
  creds.keys[api] = key;
  writeFileSync(p, `${JSON.stringify(creds, null, 2)}\n`, { mode: 0o600 });
  chmodSync(p, 0o600);
}

export function removeKey(api: string) {
  const creds = readCredentials();
  if (!(api in creds.keys)) return false;
  delete creds.keys[api];
  writeFileSync(credentialsPath(), `${JSON.stringify(creds, null, 2)}\n`, { mode: 0o600 });
  return true;
}
