import { SENSITIVE_PORTS, sensitiveIn } from './infrastructure';
import type { Detection, FileRule, SourceFile } from './types';
import { isIgnored } from './types';

/*
 * The infrastructure checks for formats other than Terraform: CloudFormation and SAM templates,
 * Pulumi programs (TypeScript, JavaScript, Python), Bicep and ARM templates, and Helm values files.
 * They report under the same rule IDs as the Terraform checks, so a team sees one finding type for
 * "database open to the internet" whatever tool wrote the infrastructure.
 *
 * None of these formats needs a full parser for these questions. Each finding is anchored on the
 * line that opens the door (the open CIDR, the public flag), and the settings that decide whether
 * it matters (ports, direction, resource type) are read from the object around it.
 */

export type InfraId = 'INF-NET-001' | 'INF-STO-001' | 'INF-DB-001' | 'INF-K8S-001';
export type InfraFinding = { id: InfraId; line: number; severity: Detection['severity']; title: string; fix: string };

const OPEN = /^(?:0\.0\.0\.0\/0|::\/0|\*|Internet|Any)$/i;
const DATA_PORTS = new Set([3306, 5432, 1433, 1521, 27017, 27018, 6379, 11211, 9200, 9300, 5984, 9042, 8086, 7474, 5672, 15672, 9092, 2181, 2379]);
const describe = (names: string[]) => (names.length > 3 ? `${names.slice(0, 3).join(', ')} and other admin and database ports` : names.join(', '));

export const FIX = {
  port: 'Allow only the addresses that need it (your office or VPN range, a bastion host, or another security group), or keep the service on a private network. For admin access, use a bastion, SSM Session Manager, IAP or a VPN instead of an open port.',
  s3: 'Keep the bucket private: remove the public ACL or policy, turn every public access block setting on, and share files with presigned URLs or a CDN with origin access control.',
  azureStorage: 'Turn public blob access off on the storage account and keep containers private; share files with SAS tokens.',
  db: 'Turn the public address off and keep the database in private subnets. Connect from your app servers, a bastion or a VPN, or through a private endpoint.',
  k8s: 'Use a ClusterIP service so only pods in the cluster can reach it. If something outside the cluster needs it, use an internal load balancer and set loadBalancerSourceRanges.',
};

const lineAt = (text: string, offset: number) => text.slice(0, offset).split('\n').length;

/** The innermost `{...}` or `(...)` around an offset: the object or call a setting belongs to. */
export function enclosing(text: string, offset: number): { start: number; end: number } {
  let depth = 0;
  let start = 0;
  for (let i = offset; i >= 0; i--) {
    const ch = text[i]!;
    if (ch === '}' || ch === ')') depth++;
    else if (ch === '{' || ch === '(') {
      if (depth === 0) { start = i; break; }
      depth--;
    }
  }
  depth = 0;
  let end = text.length;
  for (let i = start; i < text.length; i++) {
    const ch = text[i]!;
    if (ch === '{' || ch === '(') depth++;
    else if ((ch === '}' || ch === ')') && --depth === 0) { end = i + 1; break; }
  }
  return { start, end };
}

/** A YAML list item or mapping a line belongs to: from its `- ` (or parent key) to the next sibling. */
export function yamlItem(lines: string[], index: number): { start: number; end: number } {
  const ind = (l: string) => /^\s*/.exec(l)![0].length;
  const own = ind(lines[index]!);
  let start = index;
  for (let i = index; i >= 0; i--) {
    const l = lines[i]!;
    if (!l.trim()) continue;
    if (/^\s*-\s/.test(l) && ind(l) < own + (i === index ? 1 : 0)) { start = i; break; }
    if (ind(l) < own && !/^\s*-\s/.test(l)) { start = i; break; }
  }
  const base = ind(lines[start]!);
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    const l = lines[i]!;
    if (!l.trim()) continue;
    if (ind(l) <= base) { end = i; break; }
  }
  return { start, end };
}

const num = (re: RegExp, text: string) => {
  const m = re.exec(text);
  return m ? Number(m[1]) : NaN;
};

/** Sensitive ports named in a region: an explicit range, or every port when the protocol is "all". */
function portsIn(region: string, from: RegExp, to: RegExp, all: RegExp): string[] {
  if (all.test(region)) return sensitiveIn(0, 65535);
  const f = num(from, region);
  const t = num(to, region);
  return sensitiveIn(f, Number.isNaN(t) ? f : t);
}

/* ------------------------------------------------------------- CloudFormation */

export const isCloudFormation = (file: SourceFile) =>
  /\.(?:ya?ml|json|template)$/i.test(file.path) && /AWSTemplateFormatVersion|Type["']?\s*:\s*["']?AWS::/.test(file.text);

/** The CloudFormation resource type a line belongs to: the nearest `Type: AWS::...` above it. */
function cfnTypeAt(lines: string[], index: number): string {
  for (let i = index; i >= 0 && i > index - 120; i--) {
    const m = /["']?Type["']?\s*:\s*["']?(AWS::[\w:]+)/.exec(lines[i]!);
    if (m) return m[1]!;
  }
  return '';
}

export function cloudFormationFindings(file: SourceFile): InfraFinding[] {
  const out: InfraFinding[] = [];
  const json = /\.json$/i.test(file.path) || file.text.trimStart().startsWith('{');
  const region = (i: number): string => {
    if (json) {
      const offset = file.lines.slice(0, i).join('\n').length + 1;
      const r = enclosing(file.text, offset + (file.lines[i]!.indexOf(':') > 0 ? file.lines[i]!.indexOf(':') : 0));
      return file.text.slice(r.start, r.end);
    }
    const r = yamlItem(file.lines, i);
    return file.lines.slice(r.start, r.end).join('\n');
  };
  file.lines.forEach((line, i) => {
    const n = i + 1;
    // Security group ingress open to the world.
    const cidr = /["']?CidrIp(?:v6)?["']?\s*:\s*["']?(0\.0\.0\.0\/0|::\/0)["']?/.exec(line);
    if (cidr) {
      const type = cfnTypeAt(file.lines, i);
      const r = region(i);
      if (/SecurityGroupEgress/.test(type) || /\bSecurityGroupEgress\b/.test(file.lines.slice(Math.max(0, i - 12), i).join('\n')) && !/SecurityGroupIngress/.test(file.lines.slice(Math.max(0, i - 6), i).join('\n'))) return;
      const names = portsIn(r, /["']?FromPort["']?\s*:\s*["']?(-?\d+)/, /["']?ToPort["']?\s*:\s*["']?(-?\d+)/, /["']?IpProtocol["']?\s*:\s*["']?-1\b/);
      if (names.length) out.push({ id: 'INF-NET-001', line: n, severity: 'high', title: `Security group open to the internet on ${describe(names)}`, fix: FIX.port });
    }
    // S3: a public canned ACL, or the public access block turned off.
    const acl = /["']?AccessControl["']?\s*:\s*["']?(PublicRead|PublicReadWrite|AuthenticatedRead)["']?/.exec(line);
    if (acl && /S3::Bucket/.test(cfnTypeAt(file.lines, i))) out.push({ id: 'INF-STO-001', line: n, severity: 'high', title: `S3 bucket is public (${acl[1]})`, fix: FIX.s3 });
    const block = /["']?(BlockPublicAcls|BlockPublicPolicy|IgnorePublicAcls|RestrictPublicBuckets)["']?\s*:\s*["']?false\b/i.exec(line);
    if (block && /S3::Bucket/.test(cfnTypeAt(file.lines, i))) out.push({ id: 'INF-STO-001', line: n, severity: 'high', title: `S3 public access block turned off (${block[1]}: false)`, fix: FIX.s3 });
    // A bucket policy that lets anyone read.
    const principal = /["']?Principal["']?\s*:\s*(?:["']\*["']|\{\s*["']?AWS["']?\s*:\s*["']\*["']\s*\})/.exec(line) ?? (/["']?Principal["']?\s*:\s*$/.test(line) && /^\s*["']?AWS["']?\s*:\s*["']\*["']/.test(file.lines[i + 1] ?? '') ? ['x'] : null);
    if (principal && /S3::BucketPolicy/.test(cfnTypeAt(file.lines, i))) {
      const r = json ? region(i) : file.lines.slice(yamlItem(file.lines, i).start, yamlItem(file.lines, i).end).join('\n');
      if (/["']?Effect["']?\s*:\s*["']?Allow/.test(r) && /s3:Get|s3:\*|s3:List/.test(r) && !/Condition/.test(r)) {
        out.push({ id: 'INF-STO-001', line: n, severity: 'high', title: 'S3 bucket policy lets anyone read', fix: FIX.s3 });
      }
    }
    // Databases with a public address.
    if (/["']?PubliclyAccessible["']?\s*:\s*["']?true\b/i.test(line) && /AWS::(?:RDS::DBInstance|Redshift::Cluster|DMS::ReplicationInstance)/.test(cfnTypeAt(file.lines, i))) {
      out.push({ id: 'INF-DB-001', line: n, severity: 'high', title: 'Database has a public address (PubliclyAccessible: true)', fix: FIX.db });
    }
  });
  return out;
}

/* ------------------------------------------------------------------- Pulumi */

export const isPulumi = (file: SourceFile) =>
  /\.(?:[cm]?[jt]s|py)$/i.test(file.path) && /@pulumi\/(?:aws|gcp|azure|azure-native|kubernetes)|\bpulumi_(?:aws|gcp|azure|azure_native|kubernetes)\b/.test(file.text);

export function pulumiFindings(file: SourceFile): InfraFinding[] {
  const out: InfraFinding[] = [];
  const text = file.text;
  const lineOf = (offset: number) => lineAt(text, offset);
  // Security group rules and GCP firewalls, by the open range.
  for (const m of text.matchAll(/(cidrBlocks|cidr_blocks|ipv6CidrBlocks|ipv6_cidr_blocks|cidrIpv4|cidr_ipv4|cidrIpv6|cidr_ipv6|sourceRanges|source_ranges)\s*[:=]\s*(\[[^\]]*\]|["'][^"']*["'])/g)) {
    if (!/["'](?:0\.0\.0\.0\/0|::\/0)["']/.test(m[2]!)) continue;
    const r = enclosing(text, m.index!);
    const region = text.slice(r.start, r.end);
    const before = text.slice(Math.max(0, r.start - 160), r.start);
    if (/\begress\b/i.test(before.split(/\n/).slice(-2).join('\n')) || /type\s*[:=]\s*["']egress["']/.test(region) || /direction\s*[:=]\s*["']EGRESS["']/i.test(region)) continue;
    let names: string[];
    if (/sourceRanges|source_ranges/.test(m[1]!)) {
      names = [];
      for (const p of region.matchAll(/ports\s*[:=]\s*\[([^\]]*)\]/g)) {
        for (const spec of p[1]!.matchAll(/["'](\d+)(?:-(\d+))?["']/g)) for (const n of sensitiveIn(Number(spec[1]), Number(spec[2] ?? spec[1]))) if (!names.includes(n)) names.push(n);
      }
      if (!names.length && /protocol\s*[:=]\s*["']all["']/.test(region)) names = sensitiveIn(0, 65535);
    } else {
      names = portsIn(region, /(?:fromPort|from_port)\s*[:=]\s*(-?\d+)/, /(?:toPort|to_port)\s*[:=]\s*(-?\d+)/, /(?:protocol|ip_protocol|ipProtocol)\s*[:=]\s*["']-1["']/);
    }
    if (names.length) out.push({ id: 'INF-NET-001', line: lineOf(m.index!), severity: 'high', title: `Firewall open to the internet on ${describe(names)}`, fix: FIX.port });
  }
  // Azure network security rules.
  for (const m of text.matchAll(/(sourceAddressPrefix|source_address_prefix)\s*[:=]\s*["']([^"']*)["']/g)) {
    if (!OPEN.test(m[2]!)) continue;
    const region = text.slice(...Object.values(enclosing(text, m.index!)) as [number, number]);
    if (!/["']Inbound["']/i.test(region) || !/["']Allow["']/i.test(region)) continue;
    const names: string[] = [];
    for (const p of region.matchAll(/destination_?[Pp]ort_?[Rr]anges?\s*[:=]\s*(\[[^\]]*\]|["'][^"']*["'])/g)) {
      for (const spec of p[1]!.matchAll(/["'](\*|\d+)(?:-(\d+))?["']/g)) {
        const found = spec[1] === '*' ? sensitiveIn(0, 65535) : sensitiveIn(Number(spec[1]), Number(spec[2] ?? spec[1]));
        for (const n of found) if (!names.includes(n)) names.push(n);
      }
    }
    if (names.length) out.push({ id: 'INF-NET-001', line: lineOf(m.index!), severity: 'high', title: `Network security rule open to the internet on ${describe(names)}`, fix: FIX.port });
  }
  // Public buckets.
  for (const m of text.matchAll(/\bacl\s*[:=]\s*["'](public-read|public-read-write|authenticated-read)["']/g)) {
    out.push({ id: 'INF-STO-001', line: lineOf(m.index!), severity: 'high', title: `S3 bucket is public (${m[1]})`, fix: FIX.s3 });
  }
  for (const m of text.matchAll(/\b(blockPublicAcls|blockPublicPolicy|ignorePublicAcls|restrictPublicBuckets|block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*[:=]\s*(?:false|False)\b/g)) {
    out.push({ id: 'INF-STO-001', line: lineOf(m.index!), severity: 'high', title: `S3 public access block turned off (${m[1]} = false)`, fix: FIX.s3 });
  }
  for (const m of text.matchAll(/\bmember\s*[:=]\s*["'](allUsers|allAuthenticatedUsers)["']/g)) {
    out.push({ id: 'INF-STO-001', line: lineOf(m.index!), severity: 'high', title: 'Cloud Storage bucket is readable by everyone', fix: FIX.s3 });
  }
  for (const m of text.matchAll(/\b(?:allowBlobPublicAccess|allow_blob_public_access|allowNestedItemsToBePublic|allow_nested_items_to_be_public)\s*[:=]\s*(?:true|True)\b/g)) {
    out.push({ id: 'INF-STO-001', line: lineOf(m.index!), severity: 'high', title: 'Azure storage account lets containers be public', fix: FIX.azureStorage });
  }
  // Databases.
  for (const m of text.matchAll(/\b(?:publiclyAccessible|publicly_accessible)\s*[:=]\s*(?:true|True)\b/g)) {
    out.push({ id: 'INF-DB-001', line: lineOf(m.index!), severity: 'high', title: 'Database has a public address (publiclyAccessible: true)', fix: FIX.db });
  }
  // Kubernetes services from Pulumi's kubernetes provider.
  for (const m of text.matchAll(/\btype\s*[:=]\s*["'](LoadBalancer|NodePort)["']/g)) {
    const r = enclosing(text, m.index!);
    const outer = enclosing(text, Math.max(0, r.start - 1));
    const region = text.slice(outer.start, outer.end);
    if (/loadBalancerSourceRanges|load_balancer_source_ranges|internal/i.test(region)) continue;
    const names: string[] = [];
    for (const p of region.matchAll(/\b(?:port|targetPort|target_port)\s*[:=]\s*(\d+)/g)) {
      const port = Number(p[1]);
      if (DATA_PORTS.has(port) && !names.includes(SENSITIVE_PORTS.get(port)!)) names.push(SENSITIVE_PORTS.get(port)!);
    }
    if (names.length) out.push({ id: 'INF-K8S-001', line: lineOf(m.index!), severity: 'high', title: `Kubernetes ${m[1]} service exposes ${describe(names)}`, fix: FIX.k8s });
  }
  return out;
}

/* ------------------------------------------------------------ Bicep and ARM */

export const isAzureTemplate = (file: SourceFile) =>
  /\.bicep$/i.test(file.path) || (/\.json$/i.test(file.path) && /deploymentTemplate\.json|"Microsoft\.(?:Network|Storage|Sql|DBfor\w+)\//.test(file.text));

export function azureTemplateFindings(file: SourceFile): InfraFinding[] {
  const out: InfraFinding[] = [];
  const text = file.text;
  const q = `["']`;
  for (const m of text.matchAll(new RegExp(`${q}?sourceAddressPrefix${q}?\\s*:\\s*${q}([^"']*)${q}`, 'g'))) {
    if (!OPEN.test(m[1]!)) continue;
    const r = enclosing(text, m.index!);
    const region = text.slice(r.start, r.end);
    if (!new RegExp(`direction${q}?\\s*:\\s*${q}Inbound`, 'i').test(region) || !new RegExp(`access${q}?\\s*:\\s*${q}Allow`, 'i').test(region)) continue;
    const names: string[] = [];
    for (const p of region.matchAll(new RegExp(`destinationPortRanges?${q}?\\s*:\\s*(\\[[^\\]]*\\]|${q}[^"']*${q})`, 'g'))) {
      for (const spec of p[1]!.matchAll(/["'](\*|\d+)(?:-(\d+))?["']/g)) {
        const found = spec[1] === '*' ? sensitiveIn(0, 65535) : sensitiveIn(Number(spec[1]), Number(spec[2] ?? spec[1]));
        for (const n of found) if (!names.includes(n)) names.push(n);
      }
    }
    if (names.length) out.push({ id: 'INF-NET-001', line: lineAt(text, m.index!), severity: 'high', title: `Network security rule open to the internet on ${describe(names)}`, fix: FIX.port });
  }
  for (const m of text.matchAll(new RegExp(`${q}?(allowBlobPublicAccess)${q}?\\s*:\\s*true\\b`, 'g'))) {
    out.push({ id: 'INF-STO-001', line: lineAt(text, m.index!), severity: 'high', title: 'Azure storage account lets containers be public', fix: FIX.azureStorage });
  }
  for (const m of text.matchAll(new RegExp(`${q}?publicAccess${q}?\\s*:\\s*${q}(Blob|Container)${q}`, 'g'))) {
    out.push({ id: 'INF-STO-001', line: lineAt(text, m.index!), severity: 'high', title: `Azure storage container is public (${m[1]})`, fix: FIX.azureStorage });
  }
  for (const m of text.matchAll(new RegExp(`${q}?startIpAddress${q}?\\s*:\\s*${q}0\\.0\\.0\\.0${q}`, 'g'))) {
    const region = text.slice(...Object.values(enclosing(text, m.index!)) as [number, number]);
    if (new RegExp(`endIpAddress${q}?\\s*:\\s*${q}255\\.255\\.255\\.255${q}`).test(region)) {
      out.push({ id: 'INF-DB-001', line: lineAt(text, m.index!), severity: 'high', title: 'Database firewall allows every address', fix: FIX.db });
    }
  }
  return out;
}

/* ---------------------------------------------------------------- Helm values */

export const HELM_VALUES = /(?:^|\/)values(?:[.-][\w.-]+)?\.ya?ml$/i;
const CHART_PORT: Record<string, number> = {
  postgresql: 5432, postgres: 5432, mysql: 3306, mariadb: 3306, redis: 6379, mongodb: 27017, mongo: 27017, elasticsearch: 9200,
  rabbitmq: 5672, kafka: 9092, memcached: 11211, cassandra: 9042, zookeeper: 2181, etcd: 2379, couchdb: 5984, influxdb: 8086, neo4j: 7474, mssql: 1433,
};

export function helmFindings(file: SourceFile): InfraFinding[] {
  if (!HELM_VALUES.test(file.path) || /kind:\s*Service/.test(file.text)) return [];
  const out: InfraFinding[] = [];
  const lines = file.lines.map((l) => l.replace(/\s+#.*$/, ''));
  const ind = (l: string) => /^\s*/.exec(l)![0].length;
  lines.forEach((line, i) => {
    const t = /^\s*type:\s*["']?(LoadBalancer|NodePort)["']?\s*$/.exec(line);
    if (!t) return;
    // The service block: its parent key and everything under it.
    let parent = i;
    for (let k = i - 1; k >= 0; k--) if (lines[k]!.trim() && ind(lines[k]!) < ind(line)) { parent = k; break; }
    let end = lines.length;
    for (let k = parent + 1; k < lines.length; k++) if (lines[k]!.trim() && ind(lines[k]!) <= ind(lines[parent]!)) { end = k; break; }
    const block = lines.slice(parent, end).join('\n');
    if (/loadBalancerSourceRanges:\s*\n\s*-|loadBalancerSourceRanges:\s*\[[^\]\s]/.test(block) || /internal/i.test(block)) return;
    let port = NaN;
    for (const p of block.matchAll(/\b(?:port|ports|[a-z]+Port)\s*:\s*(\d+)/gi)) if (DATA_PORTS.has(Number(p[1]))) { port = Number(p[1]); break; }
    if (Number.isNaN(port)) {
      // No port written: the chart or the section says what the service is (bitnami/postgresql, redis:).
      const ancestors: string[] = [file.path];
      let cur = parent;
      for (let k = parent - 1; k >= 0; k--) if (lines[k]!.trim() && ind(lines[k]!) < ind(lines[cur]!)) { ancestors.push(lines[k]!); cur = k; }
      for (const w of ancestors.join(' ').toLowerCase().split(/[^a-z]+/)) if (CHART_PORT[w]) { port = CHART_PORT[w]!; break; }
    }
    if (Number.isNaN(port)) return;
    out.push({ id: 'INF-K8S-001', line: i + 1, severity: 'high', title: `Helm values put ${SENSITIVE_PORTS.get(port)} on a ${t[1]} service`, fix: FIX.k8s });
  });
  return out;
}

/* -------------------------------------------------------------------- rules */

const ALL_FORMATS = /\.(?:ya?ml|json|template|bicep|[cm]?[jt]s|py)$/i;
const cache = new WeakMap<SourceFile, InfraFinding[]>();

/** Every finding in one file, from whichever format it is. Cached, since four rules ask. */
export function formatFindings(file: SourceFile): InfraFinding[] {
  const hit = cache.get(file);
  if (hit) return hit;
  const out = [
    ...(isCloudFormation(file) ? cloudFormationFindings(file) : []),
    ...(isPulumi(file) ? pulumiFindings(file) : []),
    ...(isAzureTemplate(file) ? azureTemplateFindings(file) : []),
    ...helmFindings(file),
  ].filter((f, i, all) => all.findIndex((g) => g.id === f.id && g.line === f.line) === i);
  cache.set(file, out);
  return out;
}

const formatRule = (id: InfraId): FileRule => ({
  id,
  pack: 'infrastructure',
  appliesTo: ALL_FORMATS,
  skipTests: true,
  run(file) {
    if (!/AWS::|@pulumi|pulumi_|Microsoft\.|\.bicep$|LoadBalancer|NodePort/.test(file.text + file.path)) return [];
    return formatFindings(file)
      .filter((f) => f.id === id && !isIgnored(file, f.line))
      .map((f) => ({ ruleId: f.id, severity: f.severity, title: f.title, file: file.path, line: f.line, snippet: (file.lines[f.line - 1] ?? '').trim(), fix: f.fix }));
  },
});

export const FORMAT_RULES: FileRule[] = (['INF-NET-001', 'INF-STO-001', 'INF-DB-001', 'INF-K8S-001'] as const).map(formatRule);
