import { lookup } from 'node:dns/promises';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP, Socket } from 'node:net';

/*
 * Exposure checks: which admin and database ports a verified domain answers on, from the internet.
 * This runs on Fortis's servers against hosts the customer has proven they control (a TXT record at
 * _fortis-verify.<host>) and authorised in writing, exactly like running-app tests.
 *
 * What it does, and no more:
 *   - resolves the host and refuses any private, loopback, link-local or reserved address, so a DNS
 *     record can't point Fortis at its own network;
 *   - opens a TCP connection to each port in SERVICES, with a short timeout, and closes it;
 *   - for a few services, sends one harmless read-only request (Redis PING, an HTTP GET of / or
 *     /version) to tell "port open" from "answers anyone without a password". It never logs in,
 *     never sends credentials and never writes.
 */

export type Service = { port: number; name: string; kind: 'admin' | 'database' | 'cache' | 'queue' | 'cluster' | 'search' };

export const SERVICES: readonly Service[] = [
  { port: 22, name: 'SSH', kind: 'admin' },
  { port: 23, name: 'Telnet', kind: 'admin' },
  { port: 3389, name: 'Remote Desktop', kind: 'admin' },
  { port: 5900, name: 'VNC', kind: 'admin' },
  { port: 5985, name: 'WinRM', kind: 'admin' },
  { port: 3306, name: 'MySQL', kind: 'database' },
  { port: 5432, name: 'PostgreSQL', kind: 'database' },
  { port: 1433, name: 'SQL Server', kind: 'database' },
  { port: 1521, name: 'Oracle', kind: 'database' },
  { port: 27017, name: 'MongoDB', kind: 'database' },
  { port: 5984, name: 'CouchDB', kind: 'database' },
  { port: 9042, name: 'Cassandra', kind: 'database' },
  { port: 8086, name: 'InfluxDB', kind: 'database' },
  { port: 6379, name: 'Redis', kind: 'cache' },
  { port: 11211, name: 'Memcached', kind: 'cache' },
  { port: 9200, name: 'Elasticsearch', kind: 'search' },
  { port: 5601, name: 'Kibana', kind: 'search' },
  { port: 5672, name: 'RabbitMQ', kind: 'queue' },
  { port: 15672, name: 'RabbitMQ management', kind: 'queue' },
  { port: 9092, name: 'Kafka', kind: 'queue' },
  { port: 2181, name: 'ZooKeeper', kind: 'cluster' },
  { port: 2375, name: 'Docker API', kind: 'cluster' },
  { port: 2379, name: 'etcd', kind: 'cluster' },
  { port: 6443, name: 'Kubernetes API', kind: 'cluster' },
  { port: 10250, name: 'kubelet', kind: 'cluster' },
  { port: 8500, name: 'Consul', kind: 'cluster' },
];

/* ------------------------------------------------- which addresses may be scanned */

const v4 = (ip: string) => ip.split('.').map(Number) as [number, number, number, number];

/**
 * True only for public unicast addresses. Everything else (private ranges, loopback, link-local,
 * carrier-grade NAT, multicast, documentation and benchmark ranges, IPv6 ULA and link-local,
 * IPv4-mapped private addresses) is refused, so a DNS record can't aim the scanner inward.
 */
export function isPublicAddress(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) {
    const [a, b, c] = v4(ip);
    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 100 && b >= 64 && b <= 127) return false; // carrier-grade NAT
    if (a === 169 && b === 254) return false; // link-local, cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return false; // IETF, TEST-NET-1
    if (a === 198 && (b === 18 || b === 19)) return false; // benchmarking
    if (a === 198 && b === 51 && c === 100) return false; // TEST-NET-2
    if (a === 203 && b === 0 && c === 113) return false; // TEST-NET-3
    if (a >= 224) return false; // multicast and reserved
    return true;
  }
  if (family === 6) {
    const x = ip.toLowerCase();
    if (x === '::' || x === '::1') return false;
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(x);
    if (mapped) return isPublicAddress(mapped[1]!);
    if (/^f[cd]/.test(x)) return false; // unique local
    if (/^fe[89ab]/.test(x)) return false; // link-local
    if (/^ff/.test(x)) return false; // multicast
    if (/^2001:0?db8:/.test(x)) return false; // documentation
    if (/^64:ff9b:/.test(x)) return false; // NAT64 can reach IPv4 private space
    return true;
  }
  return false;
}

/* ------------------------------------------------- probing */

export type PortResult = { ip: string; port: number; service: string; open: boolean; noAuth?: string; banner?: string };

export type ProbeOptions = {
  /** Resolve a host name to addresses. Swappable in tests. */
  resolve?: (hostname: string) => Promise<string[]>;
  /** Tests only: allow loopback so local fake services can stand in for real ones. */
  allowPrivate?: boolean;
  /** Tests only: where a service's port is really listening. */
  dialPort?: (port: number) => number;
  services?: readonly Service[];
  timeoutMs?: number;
  concurrency?: number;
  /** At most this many addresses per host. */
  maxAddresses?: number;
  /** Which page checks to run. Defaults to PAGE_CHECKS; an empty list turns them off. */
  pages?: readonly PageCheck[];
};

const defaultResolve = async (hostname: string) => (await lookup(hostname, { all: true, verbatim: true })).map((a) => a.address);

/** Connect, optionally send one request, and collect what comes back within the timeout. */
function talk(ip: string, port: number, send: string | null, timeoutMs: number): Promise<{ open: boolean; data: string }> {
  return new Promise((resolve) => {
    const socket = new Socket();
    let data = '';
    let open = false;
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve({ open, data: data.slice(0, 2048) });
    };
    socket.setTimeout(timeoutMs, finish);
    socket.once('error', finish);
    socket.once('close', finish);
    socket.on('data', (chunk) => {
      data += chunk.toString('latin1');
      if (data.length > 2048) finish();
    });
    socket.connect({ host: ip, port }, () => {
      open = true;
      if (send) socket.write(send);
      // Many services speak first (SSH, MySQL); give them a moment, then close.
      setTimeout(finish, Math.min(timeoutMs, send ? timeoutMs : 700));
    });
  });
}

const httpGet = (host: string, path: string) => `GET ${path} HTTP/1.0\r\nHost: ${host}\r\nUser-Agent: fortis-exposure-check\r\nConnection: close\r\n\r\n`;

/** One harmless request per service, and how to tell from the answer that no password was needed. */
const NO_AUTH: Record<number, { send: (host: string) => string; answers: RegExp; what: string }> = {
  6379: { send: () => 'PING\r\n', answers: /^\+PONG/m, what: 'Redis answers commands without a password' },
  9200: { send: (h) => httpGet(h, '/'), answers: /"cluster_name"\s*:/, what: 'Elasticsearch answers without authentication' },
  2375: { send: (h) => httpGet(h, '/version'), answers: /"ApiVersion"\s*:/, what: 'Docker API answers without authentication' },
  5984: { send: (h) => httpGet(h, '/_all_dbs'), answers: /^\s*\[\s*(?:"[^"]*"\s*,?\s*)*\]\s*$/m, what: 'CouchDB lists its databases to anyone' },
  11211: { send: () => 'version\r\n', answers: /^VERSION /m, what: 'Memcached answers without authentication' },
  2379: { send: (h) => httpGet(h, '/version'), answers: /"etcdserver"\s*:/, what: 'etcd answers without authentication' },
  10250: { send: (h) => httpGet(h, '/pods'), answers: /"kind"\s*:\s*"PodList"/, what: 'kubelet lists pods without authentication' },
  8500: { send: (h) => httpGet(h, '/v1/agent/self'), answers: /"Config"\s*:/, what: 'Consul answers without an ACL token' },
};

/** Banners worth keeping: the first printable line, with anything password-like dropped. */
const bannerOf = (data: string) => {
  const line = data.replace(/[^\x20-\x7e\n]/g, ' ').split('\n').map((l) => l.trim()).find((l) => l.length >= 3);
  return line ? line.replace(/(pass(word)?|secret|token)\S*/gi, '[removed]').slice(0, 160) : undefined;
};

async function pool<T, R>(items: T[], n: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i]!);
      }
    }),
  );
  return out;
}

export class ExposureError extends Error {
  constructor(message: string, readonly code: string) {
    super(message);
  }
}

/** Resolve a verified host, refuse non-public addresses, and check every service port. */
export async function probeHost(hostname: string, opts: ProbeOptions = {}): Promise<{ addresses: string[]; refused: string[]; results: PortResult[]; pages: PageResult[] }> {
  const resolve = opts.resolve ?? defaultResolve;
  let all: string[];
  try {
    all = [...new Set(await resolve(hostname))];
  } catch (e) {
    throw new ExposureError(`Could not resolve ${hostname}: ${(e as NodeJS.ErrnoException).code ?? (e as Error).message}`, 'EXPOSURE_DNS');
  }
  const refused = all.filter((ip) => !(opts.allowPrivate ? isIP(ip) : isPublicAddress(ip)));
  const addresses = all.filter((ip) => !refused.includes(ip)).slice(0, opts.maxAddresses ?? 4);
  if (!addresses.length) {
    throw new ExposureError(
      all.length ? `${hostname} resolves only to private or reserved addresses (${all.join(', ')}), which Fortis won't scan.` : `${hostname} has no addresses.`,
      'EXPOSURE_NO_PUBLIC_ADDRESS',
    );
  }
  const services = opts.services ?? SERVICES;
  const timeout = opts.timeoutMs ?? 1500;
  const jobs = addresses.flatMap((ip) => services.map((s) => ({ ip, s })));
  const results = await pool(jobs, opts.concurrency ?? 24, async ({ ip, s }) => {
    const port = opts.dialPort ? opts.dialPort(s.port) : s.port;
    const probe = NO_AUTH[s.port];
    const first = await talk(ip, port, null, timeout);
    if (!first.open) return { ip, port: s.port, service: s.name, open: false } satisfies PortResult;
    const result: PortResult = { ip, port: s.port, service: s.name, open: true, banner: bannerOf(first.data) };
    if (probe) {
      const reply = await talk(ip, port, probe.send(hostname), timeout);
      if (probe.answers.test(reply.data)) result.noAuth = probe.what;
    }
    return result;
  });
  // Admin pages and files, on the first address: a load balancer serves the same site on all of them.
  const pages = opts.pages && opts.pages.length === 0 ? [] : await probePages(hostname, addresses[0]!, opts);
  return { addresses, refused, results, pages };
}

/* ------------------------------------------------- admin pages and files over HTTP */

export type PageCheck = {
  path: string;
  /** What the response must contain for it to be the real thing, not a single-page app's catch-all. */
  match: RegExp;
  ruleId: 'EXP-PANEL-001' | 'EXP-FILE-001';
  severity: 'critical' | 'high' | 'medium';
  what: string;
  fix: string;
};

const PANEL_FIX = 'Take it off the public internet: serve it only on the private network or behind your VPN or SSO, or remove it from production builds.';
const FILE_FIX = 'Remove the file from the web root and block dotfiles and dumps in the web server or CDN. Treat everything in it as leaked: rotate the keys and passwords it holds.';

/** Read-only GETs of well-known paths. Each must match a fingerprint of the real page or file. */
export const PAGE_CHECKS: readonly PageCheck[] = [
  { path: '/.env', match: /^\s*(?:export\s+)?(?:APP_KEY|APP_ENV|DB_PASSWORD|DB_HOST|DATABASE_URL|SECRET_KEY|JWT_SECRET|AWS_SECRET_ACCESS_KEY|PAYSTACK_SECRET_KEY|[A-Z][A-Z0-9_]*_(?:SECRET|PASSWORD|KEY))\s*=/m, ruleId: 'EXP-FILE-001', severity: 'critical', what: 'Environment file (.env) is served to anyone', fix: FILE_FIX },
  { path: '/.git/config', match: /^\[core\]/m, ruleId: 'EXP-FILE-001', severity: 'critical', what: 'Git repository (.git) is served to anyone', fix: 'Block /.git in the web server or CDN and deploy build output instead of a checkout. Anyone can download the source and its history, secrets included: rotate any that were ever committed.' },
  { path: '/backup.sql', match: /(?:CREATE TABLE|INSERT INTO)\s/i, ruleId: 'EXP-FILE-001', severity: 'critical', what: 'Database dump (backup.sql) is served to anyone', fix: FILE_FIX },
  { path: '/dump.sql', match: /(?:CREATE TABLE|INSERT INTO)\s/i, ruleId: 'EXP-FILE-001', severity: 'critical', what: 'Database dump (dump.sql) is served to anyone', fix: FILE_FIX },
  { path: '/actuator/env', match: /"(?:activeProfiles|propertySources)"\s*:/, ruleId: 'EXP-PANEL-001', severity: 'critical', what: 'Spring Boot Actuator shows the environment (/actuator/env)', fix: 'Expose only health and info: management.endpoints.web.exposure.include=health,info, on a separate management port that isn\'t public.' },
  { path: '/actuator/heapdump', match: /^JAVA PROFILE/, ruleId: 'EXP-PANEL-001', severity: 'critical', what: 'Spring Boot Actuator serves heap dumps (/actuator/heapdump)', fix: 'Expose only health and info: management.endpoints.web.exposure.include=health,info, on a separate management port that isn\'t public.' },
  { path: '/h2-console/', match: /H2 Console|h2-console/i, ruleId: 'EXP-PANEL-001', severity: 'critical', what: 'H2 database console is open (/h2-console)', fix: 'Turn the H2 console off in production: spring.h2.console.enabled=false.' },
  { path: '/phpmyadmin/', match: /phpMyAdmin/, ruleId: 'EXP-PANEL-001', severity: 'high', what: 'phpMyAdmin is open to the internet', fix: PANEL_FIX },
  { path: '/adminer.php', match: /\bAdminer\b/, ruleId: 'EXP-PANEL-001', severity: 'high', what: 'Adminer database manager is open to the internet', fix: PANEL_FIX },
  { path: '/_ignition/health-check', match: /"can_execute_commands"\s*:/, ruleId: 'EXP-PANEL-001', severity: 'high', what: 'Laravel Ignition (debug mode) is reachable', fix: 'Set APP_DEBUG=false in production and remove facade/ignition from production dependencies.' },
  { path: '/telescope', match: /Laravel Telescope|telescope-app|window\.Telescope/i, ruleId: 'EXP-PANEL-001', severity: 'high', what: 'Laravel Telescope is open to the internet', fix: 'Limit Telescope to local environments, or gate it with the viewTelescope authorisation.' },
  { path: '/horizon', match: /Laravel Horizon|window\.Horizon/i, ruleId: 'EXP-PANEL-001', severity: 'high', what: 'Laravel Horizon is open to the internet', fix: 'Gate Horizon with the viewHorizon authorisation, or serve it only on the private network.' },
  { path: '/__fortis_not_a_page__', match: /You're seeing this error because you have <code>DEBUG = True<\/code>|Werkzeug Debugger|Whoops! There was an error|<title>Exception<\/title>[\s\S]{0,200}stack trace/i, ruleId: 'EXP-PANEL-001', severity: 'high', what: 'Debug mode shows error pages to anyone', fix: 'Turn debug mode off in production (DEBUG = False, APP_DEBUG=false, FLASK_DEBUG=0) and log errors privately instead.' },
  { path: '/server-status', match: /Apache Server Status for/, ruleId: 'EXP-PANEL-001', severity: 'medium', what: 'Apache server-status is public', fix: 'Allow /server-status only from localhost or the private network.' },
  { path: '/jenkins/', match: /Dashboard \[Jenkins\]|X-Jenkins|jenkins-head-icon/, ruleId: 'EXP-PANEL-001', severity: 'high', what: 'Jenkins is open to the internet', fix: PANEL_FIX },
  { path: '/grafana/login', match: /<title>Grafana<\/title>|grafana-app/, ruleId: 'EXP-PANEL-001', severity: 'medium', what: 'Grafana login is open to the internet', fix: PANEL_FIX },
  { path: '/swagger-ui.html', match: /swagger-ui/i, ruleId: 'EXP-PANEL-001', severity: 'medium', what: 'API documentation (Swagger UI) is public', fix: 'Serve API docs only in staging behind SSO, or turn them off in production builds. They map every route for an attacker.' },
  { path: '/swagger.json', match: /"(?:swagger|openapi)"\s*:\s*"\d/, ruleId: 'EXP-PANEL-001', severity: 'medium', what: 'API specification (swagger.json) is public', fix: 'Serve API docs only in staging behind SSO, or turn them off in production builds. They map every route for an attacker.' },
  { path: '/api-docs', match: /"(?:swagger|openapi)"\s*:\s*"\d|swagger-ui/i, ruleId: 'EXP-PANEL-001', severity: 'medium', what: 'API documentation (/api-docs) is public', fix: 'Serve API docs only in staging behind SSO, or turn them off in production builds. They map every route for an attacker.' },
];

export type PageResult = { url: string; check: PageCheck };

/** One GET, pinned to an address we already vetted, with a short timeout and a capped body. */
function fetchPage(scheme: 'http' | 'https', ip: string, port: number, hostname: string, path: string, timeoutMs: number): Promise<{ status: number; body: string; headers: string } | null> {
  return new Promise((resolve) => {
    const req = (scheme === 'https' ? httpsRequest : httpRequest)(
      {
        host: ip,
        port,
        path,
        method: 'GET',
        servername: scheme === 'https' ? hostname : undefined,
        headers: { Host: hostname, 'User-Agent': 'fortis-exposure-check', Accept: '*/*', Connection: 'close' },
        // This checks what's exposed, not the certificate; a self-signed staging host still counts.
        rejectUnauthorized: false,
        timeout: timeoutMs,
      },
      (res) => {
        let body = '';
        res.setEncoding('latin1');
        res.on('data', (c: string) => {
          body += c;
          if (body.length > 65_536) res.destroy();
        });
        const done = () => resolve({ status: res.statusCode ?? 0, body: body.slice(0, 65_536), headers: JSON.stringify(res.headers) });
        res.on('end', done);
        res.on('close', done);
        res.on('error', done);
      },
    );
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(null));
    req.end();
  });
}

/** Check every well-known path over HTTPS and HTTP; report each one once, preferring HTTPS. */
export async function probePages(hostname: string, ip: string, opts: ProbeOptions = {}): Promise<PageResult[]> {
  const checks = opts.pages ?? PAGE_CHECKS;
  const timeout = opts.timeoutMs ?? 4000;
  const origins: { scheme: 'http' | 'https'; port: number }[] = [
    { scheme: 'https', port: 443 },
    { scheme: 'http', port: 80 },
  ];
  // Skip an origin that doesn't answer at all, so a closed port costs one request, not one per path.
  const live: typeof origins = [];
  for (const o of origins) {
    const port = opts.dialPort ? opts.dialPort(o.port) : o.port;
    if (await fetchPage(o.scheme, ip, port, hostname, '/', timeout)) live.push(o);
  }
  const jobs = live.flatMap((o) => checks.map((check) => ({ o, check })));
  const hits = await pool(jobs, opts.concurrency ?? 8, async ({ o, check }) => {
    const port = opts.dialPort ? opts.dialPort(o.port) : o.port;
    const res = await fetchPage(o.scheme, ip, port, hostname, check.path, timeout);
    if (!res || res.status !== 200 || !(check.match.test(res.body) || check.match.test(res.headers))) return null;
    return { url: `${o.scheme}://${hostname}${o.port === (o.scheme === 'https' ? 443 : 80) ? '' : `:${o.port}`}${check.path}`, check };
  });
  const out: PageResult[] = [];
  for (const h of hits) if (h && !out.some((x) => x.check.path === h.check.path)) out.push(h);
  return out;
}

/* ------------------------------------------------- findings */

export type ExposureFinding = { ruleId: 'EXP-PORT-001' | 'EXP-NOAUTH-001' | 'EXP-PANEL-001' | 'EXP-FILE-001'; severity: 'critical' | 'high' | 'medium'; title: string; file: string; snippet: string; detail: string };

const FIX: Record<Service['kind'], string> = {
  admin: 'Close this port to the internet. Reach the machine through a VPN, a bastion host, or your cloud\'s session manager (AWS SSM, Google IAP, Azure Bastion), and allow only those addresses in the firewall or security group.',
  database: 'Take the database off the public internet: private subnets, no public IP, and a firewall that allows only your application servers. Connect for maintenance through a bastion or VPN.',
  cache: 'Bind the cache to the private network only and block the port in the firewall. Caches often hold sessions and OTPs.',
  queue: 'Keep brokers and their management consoles on the private network, behind the firewall, and turn on authentication.',
  cluster: 'Never expose cluster control ports. Restrict them to the cluster\'s private network and require client certificates or tokens.',
  search: 'Keep search clusters and dashboards private, behind the firewall, with authentication on.',
};

/** Turn port results into findings: one per open port, raised to critical when it answered without a password. */
export function exposureFindings(hostname: string, results: PortResult[], pages: PageResult[] = []): ExposureFinding[] {
  const out: ExposureFinding[] = [];
  for (const p of pages) {
    out.push({ ruleId: p.check.ruleId, severity: p.check.severity, title: p.check.what, file: p.url, snippet: `GET ${p.check.path} 200`, detail: `${p.check.what}, at ${p.url}. ${p.check.fix}` });
  }
  for (const r of results.filter((x) => x.open)) {
    const svc = SERVICES.find((s) => s.port === r.port)!;
    const where = `${hostname}:${r.port}`;
    if (r.noAuth) {
      out.push({ ruleId: 'EXP-NOAUTH-001', severity: 'critical', title: `${r.noAuth} (${where})`, file: where, snippet: `${r.ip}:${r.port} ${r.banner ?? ''}`.trim(), detail: `${r.noAuth}, from the internet, at ${r.ip}. ${FIX[svc.kind]} Then turn on authentication.` });
    } else {
      out.push({
        ruleId: 'EXP-PORT-001',
        severity: svc.kind === 'admin' ? 'high' : svc.kind === 'database' || svc.kind === 'cluster' ? 'high' : 'medium',
        title: `${svc.name} open to the internet (${where})`,
        file: where,
        snippet: `${r.ip}:${r.port}${r.banner ? ` ${r.banner}` : ''}`,
        detail: `${svc.name} accepted a connection from the internet at ${r.ip}. ${FIX[svc.kind]}`,
      });
    }
  }
  return out;
}
