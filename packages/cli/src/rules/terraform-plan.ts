import { FIX } from './infrastructure-formats';
import { sensitiveIn, type Unresolved } from './infrastructure';
import type { Detection } from './types';

/*
 * `fortis scan --terraform-plan plan.json` (#93): reads `terraform show -json` output, where every value is final.
 * A database made public by a pipeline variable (TF_VAR_…, -var) or by another repository's module looks harmless in
 * the .tf files and is plain in the plan. The same checks as INF-NET-001, INF-STO-001 and INF-DB-001 run on each
 * planned resource. A value Terraform only learns while applying is listed as not checked, not passed.
 *
 *   terraform plan -out=tfplan && terraform show -json tfplan > plan.json
 *   fortis scan --terraform-plan plan.json
 */

type Values = Record<string, unknown>;
type Planned = { address: string; type: string; values: Values; unknown: Values };

const OPEN = /^(?:0\.0\.0\.0\/0|::\/0|\*|Internet|Any)$/i;
const PUBLIC_ACL = /^(?:public-read|public-read-write|authenticated-read)$/;
const PUBLIC_MEMBER = /^(?:allUsers|allAuthenticatedUsers)$/;

/** Every resource the plan creates, changes or keeps, with its final values and which of them are known only after apply. */
export function plannedResources(plan: unknown): Planned[] {
  const p = plan as { resource_changes?: { address: string; type: string; mode?: string; change?: { actions?: string[]; after?: Values | null; after_unknown?: Values } }[]; planned_values?: { root_module?: Module } };
  type Module = { resources?: { address: string; type: string; mode?: string; values?: Values }[]; child_modules?: Module[] };
  if (Array.isArray(p.resource_changes)) {
    return p.resource_changes
      .filter((r) => r.mode !== 'data' && r.change?.after && !(r.change.actions ?? []).every((a) => a === 'delete'))
      .map((r) => ({ address: r.address, type: r.type, values: r.change!.after!, unknown: r.change!.after_unknown ?? {} }));
  }
  // A plan saved without changes (or state from `terraform show -json` with no plan) has planned_values only.
  const out: Planned[] = [];
  const walk = (m?: Module) => {
    for (const r of m?.resources ?? []) if (r.mode !== 'data') out.push({ address: r.address, type: r.type, values: r.values ?? {}, unknown: {} });
    for (const c of m?.child_modules ?? []) walk(c);
  };
  walk(p.planned_values?.root_module);
  return out;
}

const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v]);
const strings = (v: unknown): string[] => list(v).filter((x): x is string => typeof x === 'string');

/** Sensitive ports in a "22", "5432-5433" or "*" spec. */
function portNames(spec: string): string[] {
  if (spec === '*' || spec === '') return sensitiveIn(0, 65535);
  const r = /^(\d+)(?:-(\d+))?$/.exec(spec.trim());
  return r ? sensitiveIn(Number(r[1]), Number(r[2] ?? r[1])) : [];
}
const describe = (names: string[]) => (names.length > 3 ? `${names.slice(0, 3).join(', ')} and other admin and database ports` : names.join(', '));

/** The ports an AWS ingress rule (a nested ingress block, an aws_security_group_rule or a VPC ingress rule) opens. */
function awsPorts(rule: Values): string[] {
  const proto = String(rule.protocol ?? rule.ip_protocol ?? '');
  const from = Number(rule.from_port ?? NaN);
  const to = Number(rule.to_port ?? NaN);
  if (proto === '-1' || proto === 'all') return sensitiveIn(0, 65535);
  return sensitiveIn(from, to);
}

type Hit = { ruleId: 'INF-NET-001' | 'INF-STO-001' | 'INF-DB-001'; title: string; setting: string; fix: string };

/** What's wrong with one planned resource, and which settings that decide it Terraform doesn't know yet. */
export function checkResource(r: Planned): { hits: Hit[]; unknown: { ruleId: Hit['ruleId']; setting: string }[] } {
  const v = r.values;
  const hits: Hit[] = [];
  const unknown: { ruleId: Hit['ruleId']; setting: string }[] = [];
  const isUnknown = (key: string) => r.unknown[key] === true;
  const watch = (ruleId: Hit['ruleId'], ...keys: string[]) => {
    for (const k of keys) if (isUnknown(k)) unknown.push({ ruleId, setting: k });
  };

  switch (r.type) {
    case 'aws_db_instance':
    case 'aws_rds_cluster_instance':
    case 'aws_redshift_cluster':
    case 'aws_dms_replication_instance':
      if (v.publicly_accessible === true) hits.push({ ruleId: 'INF-DB-001', title: 'Database has a public address (publicly_accessible = true)', setting: 'publicly_accessible = true', fix: FIX.db });
      watch('INF-DB-001', 'publicly_accessible');
      break;
    case 'google_sql_database_instance':
      for (const s of list(v.settings) as Values[]) {
        for (const ip of list(s.ip_configuration) as Values[]) {
          for (const n of list(ip.authorized_networks) as Values[]) {
            if (typeof n.value === 'string' && OPEN.test(n.value)) hits.push({ ruleId: 'INF-DB-001', title: `Cloud SQL accepts connections from anywhere (${n.value})`, setting: `authorized_networks.value = ${n.value}`, fix: 'Remove the open authorised network. Use private IP, or the Cloud SQL Auth Proxy, so only your services can connect.' });
          }
        }
      }
      break;
    case 'aws_security_group':
      for (const rule of list(v.ingress) as Values[]) {
        const open = [...strings(rule.cidr_blocks), ...strings(rule.ipv6_cidr_blocks)].find((c) => OPEN.test(c));
        const names = open ? awsPorts(rule) : [];
        if (names.length) hits.push({ ruleId: 'INF-NET-001', title: `Firewall open to the internet on ${describe(names)}`, setting: `ingress from ${open}`, fix: FIX.port });
      }
      watch('INF-NET-001', 'ingress');
      break;
    case 'aws_security_group_rule':
    case 'aws_vpc_security_group_ingress_rule': {
      if (r.type === 'aws_security_group_rule' && v.type !== 'ingress') break;
      const open = [...strings(v.cidr_blocks), ...strings(v.ipv6_cidr_blocks), ...strings(v.cidr_ipv4), ...strings(v.cidr_ipv6)].find((c) => OPEN.test(c));
      const names = open ? awsPorts(v) : [];
      if (names.length) hits.push({ ruleId: 'INF-NET-001', title: `Firewall open to the internet on ${describe(names)}`, setting: `ingress from ${open}`, fix: FIX.port });
      watch('INF-NET-001', 'cidr_blocks', 'ipv6_cidr_blocks', 'cidr_ipv4', 'cidr_ipv6');
      break;
    }
    case 'google_compute_firewall': {
      if (v.direction && String(v.direction).toUpperCase() !== 'INGRESS') break;
      const open = strings(v.source_ranges).find((c) => OPEN.test(c));
      if (!open) {
        watch('INF-NET-001', 'source_ranges');
        break;
      }
      const names: string[] = [];
      for (const a of list(v.allow) as Values[]) {
        const ports = strings(a.ports);
        const specs = ports.length ? ports : ['all', 'tcp', 'udp'].includes(String(a.protocol)) ? ['*'] : [];
        for (const s of specs) for (const n of portNames(s)) if (!names.includes(n)) names.push(n);
      }
      if (names.length) hits.push({ ruleId: 'INF-NET-001', title: `Firewall open to the internet on ${describe(names)}`, setting: `source_ranges = ${open}`, fix: FIX.port });
      break;
    }
    case 'azurerm_network_security_rule':
    case 'azurerm_network_security_group':
      for (const rule of (r.type === 'azurerm_network_security_rule' ? [v] : list(v.security_rule)) as Values[]) {
        if (String(rule.direction).toLowerCase() !== 'inbound' || String(rule.access).toLowerCase() !== 'allow') continue;
        const open = [...strings(rule.source_address_prefix), ...strings(rule.source_address_prefixes)].find((c) => OPEN.test(c));
        if (!open) continue;
        const names: string[] = [];
        for (const p of [...strings(rule.destination_port_range), ...strings(rule.destination_port_ranges)]) for (const n of portNames(p)) if (!names.includes(n)) names.push(n);
        if (names.length) hits.push({ ruleId: 'INF-NET-001', title: `Firewall open to the internet on ${describe(names)}`, setting: `source_address_prefix = ${open}`, fix: FIX.port });
      }
      break;
    case 'aws_s3_bucket':
    case 'aws_s3_bucket_acl':
      if (typeof v.acl === 'string' && PUBLIC_ACL.test(v.acl)) hits.push({ ruleId: 'INF-STO-001', title: `S3 bucket is public (${v.acl})`, setting: `acl = ${v.acl}`, fix: FIX.s3 });
      watch('INF-STO-001', 'acl');
      break;
    case 'aws_s3_bucket_public_access_block':
    case 'aws_s3_account_public_access_block': {
      const off = ['block_public_acls', 'block_public_policy', 'ignore_public_acls', 'restrict_public_buckets'].find((k) => v[k] === false);
      if (off) hits.push({ ruleId: 'INF-STO-001', title: `S3 public access block turned off (${off} = false)`, setting: `${off} = false`, fix: FIX.s3 });
      break;
    }
    case 'google_storage_bucket_iam_member':
    case 'google_storage_bucket_iam_binding': {
      const who = [...strings(v.member), ...strings(v.members)].find((m) => PUBLIC_MEMBER.test(m));
      if (who) hits.push({ ruleId: 'INF-STO-001', title: 'Cloud Storage bucket is readable by everyone', setting: `member = ${who}`, fix: 'Remove allUsers and allAuthenticatedUsers, turn on public access prevention, and share files with signed URLs.' });
      watch('INF-STO-001', 'member', 'members');
      break;
    }
    case 'azurerm_storage_container':
      if (v.container_access_type === 'blob' || v.container_access_type === 'container') hits.push({ ruleId: 'INF-STO-001', title: `Azure storage container is public (${v.container_access_type})`, setting: `container_access_type = ${v.container_access_type}`, fix: FIX.azureStorage });
      break;
    case 'azurerm_storage_account':
      if (v.allow_nested_items_to_be_public === true || v.allow_blob_public_access === true) hits.push({ ruleId: 'INF-STO-001', title: 'Azure storage account lets containers be public', setting: 'allow_nested_items_to_be_public = true', fix: FIX.azureStorage });
      break;
    case 'azurerm_postgresql_firewall_rule':
    case 'azurerm_postgresql_flexible_server_firewall_rule':
    case 'azurerm_mysql_firewall_rule':
    case 'azurerm_mysql_flexible_server_firewall_rule':
    case 'azurerm_mariadb_firewall_rule':
    case 'azurerm_mssql_firewall_rule':
    case 'azurerm_sql_firewall_rule':
      if (v.start_ip_address === '0.0.0.0' && v.end_ip_address === '255.255.255.255') hits.push({ ruleId: 'INF-DB-001', title: 'Database firewall allows every address', setting: 'start_ip_address = 0.0.0.0, end_ip_address = 255.255.255.255', fix: FIX.db });
      break;
  }
  return { hits, unknown };
}

/** The 1-based line a resource's address first appears on (a plan written by terraform show -json is one line). */
function lineOf(text: string, address: string): number {
  const at = text.indexOf(`"address":"${address}"`) >= 0 ? text.indexOf(`"address":"${address}"`) : text.indexOf(`"${address}"`);
  return at < 0 ? 1 : text.slice(0, at).split('\n').length;
}

/** Findings for a plan file, and the settings whose final value the plan doesn't know. Throws if it isn't a plan. */
export function planFindings(text: string, file: string): { detections: Detection[]; unresolved: Unresolved[]; resources: number } {
  const plan = JSON.parse(text) as Record<string, unknown>;
  if (!plan || typeof plan !== 'object' || !('format_version' in plan) || !('resource_changes' in plan || 'planned_values' in plan)) {
    throw new Error("it isn't terraform show -json output (no format_version and resource_changes)");
  }
  const resources = plannedResources(plan);
  const detections: Detection[] = [];
  const unresolved: Unresolved[] = [];
  for (const r of resources) {
    const { hits, unknown } = checkResource(r);
    const line = lineOf(text, r.address);
    for (const h of hits) {
      detections.push({ ruleId: h.ruleId, severity: 'high', title: `${h.title}: ${r.address}`, file, line, snippet: `${r.address}: ${h.setting}`.slice(0, 300), fix: `${h.fix} The plan's value is final, so change the variable, CI setting or module input that sets it.` });
    }
    for (const u of unknown) unresolved.push({ ruleId: u.ruleId, file, line, setting: `${r.address} ${u.setting}`, value: 'known only after apply' });
  }
  return { detections, unresolved, resources: resources.length };
}
