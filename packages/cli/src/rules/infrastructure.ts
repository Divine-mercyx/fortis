import type { Detection, FileRule, SourceFile } from './types';
import { isIgnored } from './types';

/*
 * Infrastructure-as-code checks: the Terraform, Kubernetes and Docker Compose files that decide what
 * a company puts on the internet. Each check looks for one door left open: a firewall rule that lets
 * the whole internet reach a database or admin port, a public storage bucket, a database with a public
 * address, a Kubernetes service that exposes a database, a Compose file that publishes one.
 *
 * The parsers are small on purpose. They read literal values only: a value that comes from a
 * variable (var.cidr, ${...}, {{ .Values.x }}) can't be judged from the file and is left alone, so
 * these rules miss some cases rather than guess. Silence a reviewed line with `# fortis-ignore: <why>`.
 */

export const TERRAFORM = /\.tf$/i;
export const COMPOSE = /(?:^|\/)(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml$/i;
/** Kubernetes manifests: any YAML except the ones other tools own (workflows, Compose, lockfiles). */
export const K8S_YAML = /\.ya?ml$/i;
const NOT_K8S = /(?:^|\/)\.github\/|(?:^|\/)(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml$|lock\.ya?ml$|(?:^|\/)\.gitlab-ci\.ya?ml$/i;

/** Ports nothing on the internet should reach directly: remote admin, databases, caches, queues, cluster control. */
export const SENSITIVE_PORTS: ReadonlyMap<number, string> = new Map([
  [22, 'SSH'], [23, 'Telnet'], [3389, 'Remote Desktop'], [5900, 'VNC'],
  [3306, 'MySQL'], [5432, 'PostgreSQL'], [1433, 'SQL Server'], [1521, 'Oracle'], [27017, 'MongoDB'], [27018, 'MongoDB'],
  [6379, 'Redis'], [11211, 'Memcached'], [9200, 'Elasticsearch'], [9300, 'Elasticsearch'], [5601, 'Kibana'],
  [5984, 'CouchDB'], [9042, 'Cassandra'], [8086, 'InfluxDB'], [7474, 'Neo4j'],
  [5672, 'RabbitMQ'], [15672, 'RabbitMQ management'], [9092, 'Kafka'], [2181, 'ZooKeeper'],
  [2375, 'Docker API'], [2376, 'Docker API'], [2379, 'etcd'], [6443, 'Kubernetes API'], [10250, 'kubelet'], [8500, 'Consul'],
]);
/** Databases, caches and queues: what a Compose file or a Kubernetes service shouldn't publish. */
const DATA_PORTS = new Set([3306, 5432, 1433, 1521, 27017, 27018, 6379, 11211, 9200, 9300, 5984, 9042, 8086, 7474, 5672, 15672, 9092, 2181, 2379]);

const OPEN_CIDR = /^(?:0\.0\.0\.0\/0|::\/0|\*|internet|any)$/i;

const hit = (file: SourceFile, line: number, ruleId: string, severity: Detection['severity'], title: string, fix: string): Detection => ({
  ruleId,
  severity,
  title,
  file: file.path,
  line,
  snippet: (file.lines[line - 1] ?? '').trim(),
  fix,
});

/* ------------------------------------------------------------------ Terraform */

/** A block of HCL: its labels, the text between its braces, and the line its body starts on. */
export type HclBlock = { kind: string; labels: string[]; line: number; body: string; bodyLine: number };

/** Blanks out comments, keeping string contents and line breaks so offsets still map to lines. */
function stripHclComments(text: string): string {
  let out = '';
  let quote = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (quote) {
      out += ch;
      if (ch === '\\') { out += text[++i] ?? ''; continue; }
      if (ch === '"') quote = false;
      continue;
    }
    if (ch === '"') { quote = true; out += ch; continue; }
    if (ch === '#' || (ch === '/' && text[i + 1] === '/')) {
      while (i < text.length && text[i] !== '\n') { out += ' '; i++; }
      if (i < text.length) out += '\n';
      continue;
    }
    if (ch === '/' && text[i + 1] === '*') {
      i += 2;
      out += '  ';
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) { out += text[i] === '\n' ? '\n' : ' '; i++; }
      i++;
      out += '  ';
      continue;
    }
    out += ch;
  }
  return out;
}

/** The index of the brace that closes the one at `open`, skipping braces inside strings. */
function closingBrace(text: string, open: number): number {
  let depth = 0;
  let quote = false;
  for (let i = open; i < text.length; i++) {
    const ch = text[i]!;
    if (quote) {
      if (ch === '\\') i++;
      else if (ch === '"') quote = false;
      continue;
    }
    if (ch === '"') quote = true;
    else if (ch === '{') depth++;
    else if (ch === '}' && --depth === 0) return i;
  }
  return text.length;
}

const lineAt = (text: string, offset: number) => text.slice(0, offset).split('\n').length;

/** Top-level blocks of a Terraform file (`resource "type" "name" { ... }`), or the nested blocks of a body. */
export function hclBlocks(text: string, firstLine = 1): HclBlock[] {
  const clean = firstLine === 1 ? stripHclComments(text) : text;
  const out: HclBlock[] = [];
  const head = /(^|\n)[ \t]*([A-Za-z_][\w-]*)((?:[ \t]+"[^"\n]*")*)[ \t]*\{/g;
  let m: RegExpExecArray | null;
  while ((m = head.exec(clean))) {
    const open = m.index + m[0].length - 1;
    const close = closingBrace(clean, open);
    const labels = [...m[3]!.matchAll(/"([^"]*)"/g)].map((x) => x[1]!);
    out.push({
      kind: m[2]!,
      labels,
      line: firstLine + lineAt(clean, m.index + m[1]!.length) - 1,
      body: clean.slice(open + 1, close),
      bodyLine: firstLine + lineAt(clean, open) - 1,
    });
    head.lastIndex = close;
  }
  return out;
}

/** A literal attribute of a block body (not of its nested blocks): a string, number, bool or list of those. */
export function attr(block: HclBlock, name: string): { value: string | string[]; line: number } | null {
  // Only look at the block's own level: blank out nested blocks first.
  let flat = '';
  let depth = 0;
  for (const ch of block.body) {
    if (ch === '{') depth++;
    flat += depth > 0 && ch !== '\n' ? ' ' : ch;
    if (ch === '}') depth--;
  }
  const re = new RegExp(`(^|\\n)[ \\t]*${name}[ \\t]*=[ \\t]*(\\[[^\\]]*\\]|"[^"\\n]*"|[\\w.-]+)`);
  const m = re.exec(flat);
  if (!m) return null;
  const raw = m[2]!;
  const line = block.bodyLine + lineAt(flat, m.index + m[1]!.length) - 1;
  if (raw.startsWith('[')) {
    const items = [...raw.matchAll(/"([^"]*)"|(-?\d+)/g)].map((x) => x[1] ?? x[2]!);
    return { value: items, line };
  }
  return { value: raw.replace(/^"|"$/g, ''), line };
}

const str = (a: ReturnType<typeof attr>) => (a && typeof a.value === 'string' ? a.value : null);
const list = (a: ReturnType<typeof attr>) => (a ? (Array.isArray(a.value) ? a.value : [a.value]) : []);
/** Sensitive ports inside a port range, or every one of them when the rule allows all ports. */
export function sensitiveIn(from: number, to: number): string[] {
  if (Number.isNaN(from) || Number.isNaN(to)) return [];
  const names: string[] = [];
  for (const [port, name] of SENSITIVE_PORTS) if (port >= from && port <= to && !names.includes(name)) names.push(name);
  return names;
}

/** "22", "5432-5433", "*" (all), as used by GCP and Azure rules. */
function portSpec(spec: string): [number, number] | null {
  if (spec === '*' || spec === '') return [0, 65535];
  const r = /^(\d+)(?:-(\d+))?$/.exec(spec.trim());
  if (!r) return null;
  return [Number(r[1]), Number(r[2] ?? r[1])];
}

const describe = (names: string[]) => (names.length > 3 ? `${names.slice(0, 3).join(', ')} and other admin and database ports` : names.join(', '));

const OPEN_PORT_FIX = 'Allow only the addresses that need it (your office or VPN range, a bastion host, or another security group), or put the service on a private network. For admin access, use a bastion, SSM Session Manager, IAP or a VPN instead of an open port.';

type Opening = { line: number; names: string[] };

/** AWS: aws_security_group ingress blocks, aws_security_group_rule and aws_vpc_security_group_ingress_rule. */
function awsOpenings(block: HclBlock): Opening[] {
  const out: Opening[] = [];
  const check = (b: HclBlock, cidrLine: number) => {
    const proto = str(attr(b, 'protocol')) ?? str(attr(b, 'ip_protocol'));
    const all = proto === '-1' || proto === 'all';
    const from = Number(str(attr(b, 'from_port')) ?? (all ? 0 : NaN));
    const to = Number(str(attr(b, 'to_port')) ?? (all ? 65535 : NaN));
    const names = all && from === 0 && (to === 0 || to === 65535) ? sensitiveIn(0, 65535) : sensitiveIn(from, to);
    if (names.length) out.push({ line: cidrLine, names });
  };
  const openCidr = (b: HclBlock) => {
    for (const key of ['cidr_blocks', 'ipv6_cidr_blocks', 'cidr_ipv4', 'cidr_ipv6']) {
      const a = attr(b, key);
      if (a && list(a).some((c) => OPEN_CIDR.test(c))) return a.line;
    }
    return 0;
  };
  const type = block.labels[0];
  if (type === 'aws_security_group') {
    for (const ingress of hclBlocks(block.body, block.bodyLine).filter((b) => b.kind === 'ingress')) {
      const line = openCidr(ingress);
      if (line) check(ingress, line);
    }
  } else if (type === 'aws_security_group_rule') {
    if (str(attr(block, 'type')) !== 'ingress') return out;
    const line = openCidr(block);
    if (line) check(block, line);
  } else if (type === 'aws_vpc_security_group_ingress_rule') {
    const line = openCidr(block);
    if (line) check(block, line);
  }
  return out;
}

/** GCP: google_compute_firewall with source_ranges open to everyone. */
function gcpOpenings(block: HclBlock): Opening[] {
  if (block.labels[0] !== 'google_compute_firewall') return [];
  const direction = str(attr(block, 'direction'));
  if (direction && direction.toUpperCase() !== 'INGRESS') return [];
  const ranges = attr(block, 'source_ranges');
  if (!ranges || !list(ranges).some((c) => OPEN_CIDR.test(c))) return [];
  const names: string[] = [];
  for (const allow of hclBlocks(block.body, block.bodyLine).filter((b) => b.kind === 'allow')) {
    const proto = str(attr(allow, 'protocol'));
    const ports = list(attr(allow, 'ports'));
    const specs = ports.length ? ports : proto === 'all' || proto === 'tcp' || proto === 'udp' ? ['*'] : [];
    for (const s of specs) {
      const r = portSpec(s);
      if (r) for (const n of sensitiveIn(r[0], r[1])) if (!names.includes(n)) names.push(n);
    }
  }
  return names.length ? [{ line: ranges.line, names }] : [];
}

/** Azure: azurerm_network_security_rule, and security_rule blocks inside azurerm_network_security_group. */
function azureOpenings(block: HclBlock): Opening[] {
  const rules = block.labels[0] === 'azurerm_network_security_rule'
    ? [block]
    : block.labels[0] === 'azurerm_network_security_group'
      ? hclBlocks(block.body, block.bodyLine).filter((b) => b.kind === 'security_rule')
      : [];
  const out: Opening[] = [];
  for (const r of rules) {
    if ((str(attr(r, 'direction')) ?? '').toLowerCase() !== 'inbound') continue;
    if ((str(attr(r, 'access')) ?? '').toLowerCase() !== 'allow') continue;
    const src = attr(r, 'source_address_prefix') ?? attr(r, 'source_address_prefixes');
    if (!src || !list(src).some((c) => OPEN_CIDR.test(c))) continue;
    const ports = [...list(attr(r, 'destination_port_range')), ...list(attr(r, 'destination_port_ranges'))];
    const names: string[] = [];
    for (const p of ports) {
      const range = portSpec(p);
      if (range) for (const n of sensitiveIn(range[0], range[1])) if (!names.includes(n)) names.push(n);
    }
    if (names.length) out.push({ line: src.line, names });
  }
  return out;
}

/** INF-NET-001: a firewall rule that lets the whole internet reach an admin or database port. */
export const openPortRule: FileRule = {
  id: 'INF-NET-001',
  pack: 'infrastructure',
  appliesTo: TERRAFORM,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    for (const block of hclBlocks(file.text).filter((b) => b.kind === 'resource')) {
      for (const o of [...awsOpenings(block), ...gcpOpenings(block), ...azureOpenings(block)]) {
        if (isIgnored(file, o.line)) continue;
        out.push(hit(file, o.line, 'INF-NET-001', 'high', `Firewall open to the internet on ${describe(o.names)}`, OPEN_PORT_FIX));
      }
    }
    return out;
  },
};

const PUBLIC_ACL = /^(?:public-read|public-read-write|authenticated-read)$/;
const PUBLIC_MEMBER = /^(?:allUsers|allAuthenticatedUsers)$/;

/** INF-STO-001: a storage bucket or container anyone on the internet can read. */
export const publicStorageRule: FileRule = {
  id: 'INF-STO-001',
  pack: 'infrastructure',
  appliesTo: TERRAFORM,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    const flag = (line: number, what: string, fix: string) => {
      if (!isIgnored(file, line)) out.push(hit(file, line, 'INF-STO-001', 'high', what, fix));
    };
    const S3_FIX = 'Keep the bucket private: remove the public ACL, set all four aws_s3_bucket_public_access_block settings to true, and share files with presigned URLs or through CloudFront with origin access control.';
    for (const b of hclBlocks(file.text).filter((x) => x.kind === 'resource')) {
      const type = b.labels[0];
      if (type === 'aws_s3_bucket' || type === 'aws_s3_bucket_acl' || type === 'aws_s3_object') {
        const acl = attr(b, 'acl');
        if (acl && PUBLIC_ACL.test(str(acl) ?? '')) flag(acl.line, `S3 ${type === 'aws_s3_object' ? 'object' : 'bucket'} is public (${str(acl)})`, S3_FIX);
      } else if (type === 'aws_s3_bucket_public_access_block' || type === 'aws_s3_account_public_access_block') {
        for (const key of ['block_public_acls', 'block_public_policy', 'ignore_public_acls', 'restrict_public_buckets']) {
          const a = attr(b, key);
          if (a && str(a) === 'false') { flag(a.line, `S3 public access block turned off (${key} = false)`, S3_FIX); break; }
        }
      } else if (/^google_storage_bucket_(?:iam_member|iam_binding|access_control|acl)$/.test(type ?? '') || type === 'google_storage_object_access_control') {
        const a = attr(b, 'member') ?? attr(b, 'members') ?? attr(b, 'entity');
        if (a && list(a).some((m) => PUBLIC_MEMBER.test(m))) {
          flag(a.line, 'Cloud Storage bucket is readable by everyone', 'Remove allUsers and allAuthenticatedUsers, turn on public access prevention (public_access_prevention = "enforced"), and share files with signed URLs.');
        }
      } else if (type === 'azurerm_storage_container') {
        const a = attr(b, 'container_access_type');
        const v = str(a);
        if (a && (v === 'blob' || v === 'container')) flag(a.line, `Azure storage container is public (${v})`, 'Set container_access_type = "private" and share files with SAS tokens. Set allow_nested_items_to_be_public = false on the storage account so no container can be made public.');
      } else if (type === 'azurerm_storage_account') {
        const a = attr(b, 'allow_nested_items_to_be_public') ?? attr(b, 'allow_blob_public_access');
        if (a && str(a) === 'true') flag(a.line, 'Azure storage account lets containers be public', 'Set allow_nested_items_to_be_public = false and share files with SAS tokens.');
      }
    }
    return out;
  },
};

/** INF-DB-001: a managed database given a public address. */
export const publicDatabaseRule: FileRule = {
  id: 'INF-DB-001',
  pack: 'infrastructure',
  appliesTo: TERRAFORM,
  skipTests: true,
  run(file) {
    const out: Detection[] = [];
    for (const b of hclBlocks(file.text).filter((x) => x.kind === 'resource')) {
      const type = b.labels[0];
      if (/^aws_(?:db_instance|rds_cluster_instance|redshift_cluster|dms_replication_instance)$/.test(type ?? '')) {
        const a = attr(b, 'publicly_accessible');
        if (a && str(a) === 'true' && !isIgnored(file, a.line)) {
          out.push(hit(file, a.line, 'INF-DB-001', 'high', 'Database has a public address (publicly_accessible = true)', 'Set publicly_accessible = false, keep the database in private subnets, and reach it from your app servers or through a bastion or VPN.'));
        }
      } else if (type === 'google_sql_database_instance') {
        for (const settings of hclBlocks(b.body, b.bodyLine).filter((x) => x.kind === 'settings')) {
          for (const ip of hclBlocks(settings.body, settings.bodyLine).filter((x) => x.kind === 'ip_configuration')) {
            for (const net of hclBlocks(ip.body, ip.bodyLine).filter((x) => x.kind === 'authorized_networks')) {
              const v = attr(net, 'value');
              if (v && OPEN_CIDR.test(str(v) ?? '') && !isIgnored(file, v.line)) {
                out.push(hit(file, v.line, 'INF-DB-001', 'high', 'Cloud SQL accepts connections from anywhere (0.0.0.0/0)', 'Remove the 0.0.0.0/0 authorised network. Use private IP, or the Cloud SQL Auth Proxy, so only your services can connect.'));
              }
            }
          }
        }
      } else if (/^azurerm_(?:postgresql|mysql|mariadb|mssql|sql)(?:_flexible_server|_server)?_firewall_rule$/.test(type ?? '')) {
        const start = attr(b, 'start_ip_address');
        const end = attr(b, 'end_ip_address');
        if (str(start) === '0.0.0.0' && str(end) === '255.255.255.255' && start && !isIgnored(file, start.line)) {
          out.push(hit(file, start.line, 'INF-DB-001', 'high', 'Database firewall allows every address', 'Allow only your application\'s addresses, or use a private endpoint so the database has no public address at all.'));
        }
      }
    }
    return out;
  },
};

/* ----------------------------------------------------------------- Kubernetes */

/** INF-K8S-001: a Service that puts a database or cache on a public load balancer or node port. */
export const k8sExposedServiceRule: FileRule = {
  id: 'INF-K8S-001',
  pack: 'infrastructure',
  appliesTo: K8S_YAML,
  skipTests: true,
  run(file) {
    if (NOT_K8S.test(file.path) || !/^\s*kind:\s*Service\b/m.test(file.text)) return [];
    const out: Detection[] = [];
    // One YAML document at a time.
    let start = 0;
    const docs: [number, number][] = [];
    file.lines.forEach((l, i) => {
      if (/^---/.test(l)) { docs.push([start, i]); start = i + 1; }
    });
    docs.push([start, file.lines.length]);
    for (const [a, b] of docs) {
      const lines = file.lines.slice(a, b).map((l) => l.replace(/\s+#.*$/, ''));
      if (!lines.some((l) => /^kind:\s*Service\s*$/.test(l.trim()))) continue;
      const typeIdx = lines.findIndex((l) => /^\s*type:\s*["']?(LoadBalancer|NodePort)["']?\s*$/.test(l));
      if (typeIdx === -1) continue;
      if (lines.some((l) => /^\s*loadBalancerSourceRanges:/.test(l))) continue;
      // An internal load balancer stays inside the network.
      if (lines.some((l) => /load-balancer-internal|internal-load-balancer|load-balancer-type:\s*["']?internal|networking\.gke\.io\/load-balancer-type:\s*["']?Internal|aws-load-balancer-scheme:\s*["']?internal/i.test(l))) continue;
      const names: string[] = [];
      for (const l of lines) {
        const p = /^\s*-?\s*(?:port|targetPort):\s*["']?(\d+)/.exec(l);
        if (p && DATA_PORTS.has(Number(p[1]))) {
          const n = SENSITIVE_PORTS.get(Number(p[1]))!;
          if (!names.includes(n)) names.push(n);
        }
      }
      const line = a + typeIdx + 1;
      if (names.length && !isIgnored(file, line)) {
        const type = /LoadBalancer/.test(lines[typeIdx]!) ? 'LoadBalancer' : 'NodePort';
        out.push(hit(file, line, 'INF-K8S-001', 'high', `Kubernetes ${type} service exposes ${describe(names)}`, 'Use type: ClusterIP so only pods in the cluster can reach it. If something outside the cluster needs it, use an internal load balancer and set loadBalancerSourceRanges to the addresses that need access.'));
      }
    }
    return out;
  },
};

/* ------------------------------------------------------------- Docker Compose */

const DEV_COMPOSE = /(?:^|[/.\-_])(?:dev|devel|development|test|tests|testing|local|debug|ci|e2e|example|examples|sample|samples|demo|override)(?:[/.\-_]|$)/i;

/** The container port and host address of one Compose `ports:` entry, short or long syntax. */
export function composePort(entry: string): { host: string | null; container: number } | null {
  const v = entry.trim().replace(/^-\s*/, '').replace(/^["']|["']$/g, '').replace(/\/(?:tcp|udp)$/, '');
  if (!/^[\d.:[\]a-f-]+$/i.test(v)) return null;
  // "8080", "8080:80", "127.0.0.1:8080:80", "[::1]:8080:80"
  const ipv6 = /^\[([^\]]+)\]:(.+)$/.exec(v);
  const parts = ipv6 ? [ipv6[1]!, ...ipv6[2]!.split(':')] : v.split(':');
  if (parts.length === 1) return { host: null, container: Number(parts[0]!.split('-')[0]) };
  const container = Number(parts[parts.length - 1]!.split('-')[0]);
  const host = parts.length === 3 ? parts[0]! : null;
  return Number.isNaN(container) ? null : { host, container };
}

const LOOPBACK = /^(?:127\.\d+\.\d+\.\d+|::1|localhost)$/;

/** INF-NET-002: a production Compose file publishes a database or cache port on every network interface. */
export const composeDatabasePortRule: FileRule = {
  id: 'INF-NET-002',
  pack: 'infrastructure',
  appliesTo: COMPOSE,
  skipTests: true,
  run(file) {
    if (DEV_COMPOSE.test(file.path.replace(/(?:docker-)?compose(?=[.-])/i, ''))) return [];
    const out: Detection[] = [];
    let inPorts = -1; // indent of the `ports:` key while inside its list
    let longEntry: { line: number; target?: number; host?: string } | null = null;
    const flush = () => {
      if (longEntry?.target && DATA_PORTS.has(longEntry.target) && !(longEntry.host && LOOPBACK.test(longEntry.host))) report(longEntry.line, longEntry.target);
      longEntry = null;
    };
    const report = (line: number, port: number) => {
      if (isIgnored(file, line)) return;
      const name = SENSITIVE_PORTS.get(port)!;
      out.push(hit(file, line, 'INF-NET-002', 'medium', `Compose publishes ${name} on every network interface`, `Drop the ports entry so only other services in the Compose network can reach ${name}, or bind it to this machine only: "127.0.0.1:${port}:${port}". On a server, a published port is open to anyone who can reach it, and Docker's rules bypass ufw.`));
    };
    file.lines.forEach((raw, i) => {
      const line = raw.replace(/\s+#.*$/, '');
      if (!line.trim()) return;
      const indent = line.length - line.trimStart().length;
      if (/^\s*ports:\s*$/.test(line)) { flush(); inPorts = indent; return; }
      if (inPorts === -1) return;
      if (indent <= inPorts && !/^\s*-/.test(line)) { flush(); inPorts = -1; return; }
      const item = /^\s*-\s*(.*)$/.exec(line);
      if (item) {
        flush();
        const target = /^target:\s*(\d+)/.exec(item[1]!);
        if (target) { longEntry = { line: i + 1, target: Number(target[1]) }; return; }
        if (/^\w+:/.test(item[1]!)) { longEntry = { line: i + 1 }; const t = /^host_ip:\s*["']?([^"'\s]+)/.exec(item[1]!); if (t) longEntry.host = t[1]; return; }
        const p = composePort(item[1]!);
        if (p && DATA_PORTS.has(p.container) && !(p.host && LOOPBACK.test(p.host))) report(i + 1, p.container);
        return;
      }
      if (longEntry) {
        const t = /^\s*target:\s*(\d+)/.exec(line);
        if (t) longEntry.target = Number(t[1]);
        const h = /^\s*host_ip:\s*["']?([^"'\s]+)/.exec(line);
        if (h) longEntry.host = h[1];
      }
    });
    flush();
    return out;
  },
};

export const INFRASTRUCTURE_RULES: FileRule[] = [openPortRule, publicStorageRule, publicDatabaseRule, k8sExposedServiceRule, composeDatabasePortRule];
