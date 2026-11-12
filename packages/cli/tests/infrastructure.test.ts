import { describe, expect, it } from 'vitest';

import { attr, composePort, hclBlocks, INFRASTRUCTURE_RULES, sensitiveIn } from '../src/rules/infrastructure';
import { emptyContext, type SourceFile } from '../src/rules/types';

const file = (path: string, text: string): SourceFile => ({ path, text, lines: text.split('\n') });
const flagged = (path: string, text: string) =>
  INFRASTRUCTURE_RULES.filter((r) => r.appliesTo.test(path)).flatMap((r) => r.run(file(path, text), emptyContext()).map((d) => `${d.ruleId}:${d.line}`));
const titles = (path: string, text: string) =>
  INFRASTRUCTURE_RULES.filter((r) => r.appliesTo.test(path)).flatMap((r) => r.run(file(path, text), emptyContext()).map((d) => d.title));

describe('reading Terraform', () => {
  it('finds resource blocks, nested blocks and literal attributes, and ignores comments', () => {
    const text = [
      '# resource "aws_db_instance" "old" { publicly_accessible = true }',
      'resource "aws_security_group" "api" {',
      '  name = "api"  // the API',
      '  ingress {',
      '    from_port   = 22',
      '    to_port     = 22',
      '    cidr_blocks = ["0.0.0.0/0", "10.0.0.0/8"]',
      '  }',
      '}',
    ].join('\n');
    const blocks = hclBlocks(text);
    expect(blocks.map((b) => [b.kind, b.labels, b.line])).toEqual([['resource', ['aws_security_group', 'api'], 2]]);
    expect(attr(blocks[0]!, 'name')).toEqual({ value: 'api', line: 3 });
    // An attribute of a nested block isn't one of the outer block's.
    expect(attr(blocks[0]!, 'from_port')).toBeNull();
    const ingress = hclBlocks(blocks[0]!.body, blocks[0]!.bodyLine)[0]!;
    expect(ingress.kind).toBe('ingress');
    expect(attr(ingress, 'cidr_blocks')).toEqual({ value: ['0.0.0.0/0', '10.0.0.0/8'], line: 7 });
  });

  it('names the sensitive ports inside a range', () => {
    expect(sensitiveIn(22, 22)).toEqual(['SSH']);
    expect(sensitiveIn(80, 443)).toEqual([]);
    expect(sensitiveIn(5000, 6500)).toEqual(['VNC', 'WinRM', 'PostgreSQL', 'Redis', 'Kibana', 'CouchDB', 'RabbitMQ', 'Kubernetes API']);
  });
});

describe('INF-NET-001: firewall open to the internet', () => {
  it('flags AWS security groups, rules and VPC ingress rules open to 0.0.0.0/0 on admin or database ports', () => {
    expect(flagged('infra/sg.tf', [
      'resource "aws_security_group" "db" {',
      '  ingress {',
      '    from_port   = 5432',
      '    to_port     = 5432',
      '    protocol    = "tcp"',
      '    cidr_blocks = ["0.0.0.0/0"]',
      '  }',
      '  ingress {',
      '    from_port   = 443',
      '    to_port     = 443',
      '    protocol    = "tcp"',
      '    cidr_blocks = ["0.0.0.0/0"]',
      '  }',
      '}',
      'resource "aws_security_group_rule" "ssh" {',
      '  type             = "ingress"',
      '  from_port        = 22',
      '  to_port          = 22',
      '  protocol         = "tcp"',
      '  ipv6_cidr_blocks = ["::/0"]',
      '}',
      'resource "aws_vpc_security_group_ingress_rule" "all" {',
      '  cidr_ipv4   = "0.0.0.0/0"',
      '  ip_protocol = "-1"',
      '}',
    ].join('\n'))).toEqual(['INF-NET-001:6', 'INF-NET-001:20', 'INF-NET-001:23']);
  });

  it('leaves private ranges, egress, web ports and values from variables alone', () => {
    expect(flagged('main.tf', [
      'resource "aws_security_group" "db" {',
      '  ingress {',
      '    from_port   = 5432',
      '    to_port     = 5432',
      '    cidr_blocks = ["10.0.0.0/16"]',
      '  }',
      '  ingress {',
      '    from_port   = 22',
      '    to_port     = 22',
      '    cidr_blocks = var.admin_cidrs',
      '  }',
      '  egress {',
      '    from_port   = 0',
      '    to_port     = 0',
      '    protocol    = "-1"',
      '    cidr_blocks = ["0.0.0.0/0"]',
      '  }',
      '}',
      'resource "aws_security_group_rule" "out" {',
      '  type        = "egress"',
      '  from_port   = 22',
      '  to_port     = 22',
      '  cidr_blocks = ["0.0.0.0/0"]',
      '}',
    ].join('\n'))).toEqual([]);
  });

  it('flags GCP firewalls and Azure rules, including port ranges and *', () => {
    expect(flagged('gcp.tf', [
      'resource "google_compute_firewall" "admin" {',
      '  name          = "admin"',
      '  source_ranges = ["0.0.0.0/0"]',
      '  allow {',
      '    protocol = "tcp"',
      '    ports    = ["22", "3389", "8000-9000"]',
      '  }',
      '}',
      'resource "google_compute_firewall" "web" {',
      '  source_ranges = ["0.0.0.0/0"]',
      '  allow {',
      '    protocol = "tcp"',
      '    ports    = ["80", "443"]',
      '  }',
      '}',
    ].join('\n'))).toEqual(['INF-NET-001:3']);
    expect(flagged('azure.tf', [
      'resource "azurerm_network_security_rule" "rdp" {',
      '  direction                  = "Inbound"',
      '  access                     = "Allow"',
      '  source_address_prefix      = "*"',
      '  destination_port_range     = "3389"',
      '}',
      'resource "azurerm_network_security_group" "nsg" {',
      '  security_rule {',
      '    direction              = "Inbound"',
      '    access                 = "Deny"',
      '    source_address_prefix  = "Internet"',
      '    destination_port_range = "*"',
      '  }',
      '}',
    ].join('\n'))).toEqual(['INF-NET-001:4']);
  });

  it('honours fortis-ignore', () => {
    expect(flagged('bastion.tf', [
      'resource "aws_security_group_rule" "bastion" {',
      '  type        = "ingress"',
      '  from_port   = 22',
      '  to_port     = 22',
      '  cidr_blocks = ["0.0.0.0/0"] # fortis-ignore: bastion, key-only SSH',
      '}',
    ].join('\n'))).toEqual([]);
  });
});

describe('INF-STO-001: public storage', () => {
  it('flags public S3 ACLs, a disabled public access block, allUsers on GCS and public Azure containers', () => {
    expect(flagged('storage.tf', [
      'resource "aws_s3_bucket" "kyc" {',
      '  bucket = "kyc-docs"',
      '  acl    = "public-read"',
      '}',
      'resource "aws_s3_bucket_public_access_block" "kyc" {',
      '  bucket                  = aws_s3_bucket.kyc.id',
      '  block_public_acls       = true',
      '  block_public_policy     = false',
      '}',
      'resource "google_storage_bucket_iam_member" "public" {',
      '  bucket = "statements"',
      '  role   = "roles/storage.objectViewer"',
      '  member = "allUsers"',
      '}',
      'resource "azurerm_storage_container" "docs" {',
      '  container_access_type = "blob"',
      '}',
      'resource "aws_s3_bucket" "private" {',
      '  acl = "private"',
      '}',
    ].join('\n'))).toEqual(['INF-STO-001:3', 'INF-STO-001:8', 'INF-STO-001:13', 'INF-STO-001:16']);
  });
});

describe('INF-DB-001: database with a public address', () => {
  it('flags RDS, Cloud SQL and Azure database rules open to everyone', () => {
    expect(flagged('db.tf', [
      'resource "aws_db_instance" "core" {',
      '  engine              = "postgres"',
      '  publicly_accessible = true',
      '}',
      'resource "aws_db_instance" "replica" {',
      '  publicly_accessible = false',
      '}',
      'resource "google_sql_database_instance" "main" {',
      '  settings {',
      '    ip_configuration {',
      '      authorized_networks {',
      '        name  = "office"',
      '        value = "102.89.0.0/16"',
      '      }',
      '      authorized_networks {',
      '        name  = "everyone"',
      '        value = "0.0.0.0/0"',
      '      }',
      '    }',
      '  }',
      '}',
      'resource "azurerm_postgresql_flexible_server_firewall_rule" "all" {',
      '  start_ip_address = "0.0.0.0"',
      '  end_ip_address   = "255.255.255.255"',
      '}',
      'resource "azurerm_postgresql_flexible_server_firewall_rule" "azure" {',
      '  start_ip_address = "0.0.0.0"',
      '  end_ip_address   = "0.0.0.0"',
      '}',
    ].join('\n'))).toEqual(['INF-DB-001:3', 'INF-DB-001:17', 'INF-DB-001:23']);
  });
});

describe('INF-K8S-001: Kubernetes service exposing a database', () => {
  it('flags a public LoadBalancer or NodePort on a database port, one document at a time', () => {
    expect(flagged('k8s/redis.yaml', [
      'apiVersion: v1',
      'kind: Deployment',
      'metadata:',
      '  name: api',
      '---',
      'apiVersion: v1',
      'kind: Service',
      'metadata:',
      '  name: redis',
      'spec:',
      '  type: LoadBalancer',
      '  ports:',
      '    - port: 6379',
      '      targetPort: 6379',
      '---',
      'apiVersion: v1',
      'kind: Service',
      'metadata:',
      '  name: web',
      'spec:',
      '  type: LoadBalancer',
      '  ports:',
      '    - port: 443',
    ].join('\n'))).toEqual(['INF-K8S-001:11']);
    expect(titles('deploy/pg.yml', 'kind: Service\nspec:\n  type: NodePort\n  ports:\n  - port: 5432\n')).toEqual(['Kubernetes NodePort service exposes PostgreSQL']);
  });

  it('leaves ClusterIP, internal load balancers, source ranges and non-Kubernetes YAML alone', () => {
    expect(flagged('k8s/pg.yaml', 'kind: Service\nspec:\n  ports:\n  - port: 5432\n')).toEqual([]);
    expect(flagged('k8s/pg.yaml', 'kind: Service\nmetadata:\n  annotations:\n    networking.gke.io/load-balancer-type: "Internal"\nspec:\n  type: LoadBalancer\n  ports:\n  - port: 5432\n')).toEqual([]);
    expect(flagged('k8s/pg.yaml', 'kind: Service\nspec:\n  type: LoadBalancer\n  loadBalancerSourceRanges:\n  - 10.0.0.0/8\n  ports:\n  - port: 5432\n')).toEqual([]);
    expect(flagged('.github/workflows/ci.yml', 'kind: Service\nspec:\n  type: LoadBalancer\n  ports:\n  - port: 5432\n')).toEqual([]);
  });
});

describe('INF-NET-002: Compose publishing a database', () => {
  it('reads short-syntax port entries', () => {
    expect(composePort('"5432:5432"')).toEqual({ host: null, container: 5432 });
    expect(composePort('127.0.0.1:6379:6379')).toEqual({ host: '127.0.0.1', container: 6379 });
    expect(composePort('[::1]:5432:5432/tcp')).toEqual({ host: '::1', container: 5432 });
    expect(composePort('3000')).toEqual({ host: null, container: 3000 });
    expect(composePort('${PORT}:80')).toBeNull();
  });

  it('flags database ports published on every interface, and not loopback, web ports or dev files', () => {
    const compose = [
      'services:',
      '  db:',
      '    image: postgres:16',
      '    ports:',
      '      - "5432:5432"',
      '  cache:',
      '    image: redis:7',
      '    ports:',
      '      - "127.0.0.1:6379:6379"',
      '  mongo:',
      '    image: mongo:7',
      '    ports:',
      '      - target: 27017',
      '        published: 27017',
      '  api:',
      '    image: api',
      '    ports:',
      '      - "8080:3000"',
      '    environment:',
      '      DB_PORT: 5432',
    ].join('\n');
    expect(flagged('docker-compose.yml', compose)).toEqual(['INF-NET-002:5', 'INF-NET-002:13']);
    expect(flagged('compose.prod.yaml', compose)).toEqual(['INF-NET-002:5', 'INF-NET-002:13']);
    expect(flagged('docker-compose.dev.yml', compose)).toEqual([]);
    expect(flagged('docker-compose.override.yml', compose)).toEqual([]);
  });
});
