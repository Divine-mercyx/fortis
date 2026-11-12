import { describe, expect, it } from 'vitest';

import { INFRASTRUCTURE_RULES, resolveTerraform, terraformValues } from '../src/rules/infrastructure';
import { azureTemplateFindings, cloudFormationFindings, enclosing, FORMAT_RULES, formatFindings, helmFindings, isCloudFormation, isPulumi, pulumiFindings, yamlItem } from '../src/rules/infrastructure-formats';
import { buildContext } from '../src/scan';
import { emptyContext, type SourceFile } from '../src/rules/types';

const file = (path: string, text: string): SourceFile => ({ path, text, lines: text.split('\n') });
const ids = (fs: { id: string; line: number }[]) => fs.map((f) => `${f.id}:${f.line}`);
const all = (path: string, text: string, ctx = emptyContext()) =>
  [...INFRASTRUCTURE_RULES, ...FORMAT_RULES].filter((r) => r.appliesTo.test(path)).flatMap((r) => r.run(file(path, text), ctx).map((d) => `${d.ruleId}:${d.line}`)).sort();

describe('helpers', () => {
  it('finds the object or call around an offset', () => {
    const t = 'new Sg("x", { ingress: [{ fromPort: 22, cidrBlocks: ["0.0.0.0/0"] }] })';
    const r = enclosing(t, t.indexOf('cidrBlocks'));
    expect(t.slice(r.start, r.end)).toBe('{ fromPort: 22, cidrBlocks: ["0.0.0.0/0"] }');
    const py = 'aws.ec2.SecurityGroupIngressArgs(from_port=22, to_port=22, cidr_blocks=["0.0.0.0/0"])';
    expect(py.slice(...Object.values(enclosing(py, py.indexOf('cidr'))) as [number, number])).toBe('(from_port=22, to_port=22, cidr_blocks=["0.0.0.0/0"])');
  });

  it('finds the YAML list item a line belongs to', () => {
    const lines = ['SecurityGroupIngress:', '  - IpProtocol: tcp', '    FromPort: 22', '    ToPort: 22', '    CidrIp: 0.0.0.0/0', '  - IpProtocol: tcp', '    FromPort: 443'];
    const r = yamlItem(lines, 4);
    expect(lines.slice(r.start, r.end)).toEqual(['  - IpProtocol: tcp', '    FromPort: 22', '    ToPort: 22', '    CidrIp: 0.0.0.0/0']);
  });

  it('tells the formats apart', () => {
    expect(isCloudFormation(file('stack.yaml', 'AWSTemplateFormatVersion: "2010-09-09"\nResources: {}'))).toBe(true);
    expect(isCloudFormation(file('k8s/svc.yaml', 'kind: Service'))).toBe(false);
    expect(isPulumi(file('index.ts', 'import * as aws from "@pulumi/aws";'))).toBe(true);
    expect(isPulumi(file('__main__.py', 'import pulumi_aws as aws'))).toBe(true);
    expect(isPulumi(file('index.ts', 'import express from "express";'))).toBe(false);
  });
});

describe('Terraform variables, locals, tfvars and modules', () => {
  const vars = file('infra/variables.tf', [
    'variable "admin_cidrs" {',
    '  type    = list(string)',
    '  default = ["0.0.0.0/0"]',
    '}',
    'variable "db_public" {',
    '  default = false',
    '}',
    'locals {',
    '  open = "0.0.0.0/0"',
    '  ssh  = 22',
    '}',
  ].join('\n'));
  const tfvars = file('infra/terraform.tfvars', 'db_public = true\n# admin_cidrs = ["10.0.0.0/8"]');

  it('collects defaults, locals and tfvars, tfvars winning', () => {
    const v = terraformValues([vars, tfvars]).get('infra')!;
    expect(v.get('var.admin_cidrs')).toBe('["0.0.0.0/0"]');
    expect(v.get('local.open')).toBe('"0.0.0.0/0"');
    expect(v.get('local.ssh')).toBe('22');
    expect(v.get('var.db_public')).toBe('true');
  });

  it('judges values that come from variables and locals', () => {
    const main = file('infra/main.tf', [
      'resource "aws_security_group_rule" "ssh" {',
      '  type        = "ingress"',
      '  from_port   = local.ssh',
      '  to_port     = local.ssh',
      '  cidr_blocks = var.admin_cidrs',
      '}',
      'resource "aws_security_group_rule" "pg" {',
      '  type        = "ingress"',
      '  from_port   = 5432',
      '  to_port     = 5432',
      '  cidr_blocks = [local.open]',
      '}',
      'resource "aws_db_instance" "core" {',
      '  publicly_accessible = var.db_public',
      '}',
      'resource "aws_security_group_rule" "unknown" {',
      '  type        = "ingress"',
      '  from_port   = 22',
      '  to_port     = 22',
      '  cidr_blocks = var.not_defined',
      '}',
    ].join('\n'));
    const ctx = buildContext([vars, tfvars, main]);
    expect(resolveTerraform(main, ctx).split('\n')[4]).toBe('  cidr_blocks = ["0.0.0.0/0"]');
    expect(all('infra/main.tf', main.text, ctx)).toEqual(['INF-DB-001:14', 'INF-NET-001:11', 'INF-NET-001:5']);
    // Without the other files there's nothing to resolve, so nothing is guessed.
    expect(all('infra/main.tf', main.text)).toEqual([]);
  });

  it('leaves interpolations alone', () => {
    const f = file('a/main.tf', 'variable "env" {\n  default = "prod"\n}\nresource "x" "y" {\n  name = "db-${var.env}"\n  tag  = var.env\n}');
    expect(resolveTerraform(f).split('\n').slice(4)).toEqual(['  name = "db-${var.env}"', '  tag  = "prod"', '}']);
  });

  it('reads security-group, S3 and RDS modules', () => {
    expect(all('infra/modules.tf', [
      'module "web_sg" {',
      '  source              = "terraform-aws-modules/security-group/aws"',
      '  ingress_cidr_blocks = ["0.0.0.0/0"]',
      '  ingress_rules       = ["https-443-tcp", "ssh-tcp"]',
      '}',
      'module "db_sg" {',
      '  source = "terraform-aws-modules/security-group/aws"',
      '  ingress_with_cidr_blocks = [',
      '    {',
      '      from_port   = 5432',
      '      to_port     = 5432',
      '      protocol    = "tcp"',
      '      cidr_blocks = "0.0.0.0/0"',
      '    },',
      '    {',
      '      rule        = "https-443-tcp"',
      '      cidr_blocks = "0.0.0.0/0"',
      '    },',
      '  ]',
      '}',
      'module "https_only" {',
      '  source              = "terraform-aws-modules/security-group/aws"',
      '  ingress_cidr_blocks = ["0.0.0.0/0"]',
      '  ingress_rules       = ["https-443-tcp", "http-80-tcp"]',
      '}',
      'module "docs" {',
      '  source = "terraform-aws-modules/s3-bucket/aws"',
      '  acl    = "public-read"',
      '  block_public_policy = false',
      '}',
      'module "db" {',
      '  source              = "terraform-aws-modules/rds/aws"',
      '  publicly_accessible = true',
      '}',
    ].join('\n'))).toEqual(['INF-DB-001:33', 'INF-NET-001:13', 'INF-NET-001:3', 'INF-STO-001:28', 'INF-STO-001:29']);
  });
});

describe('CloudFormation', () => {
  it('flags open security groups, public buckets and public databases in YAML', () => {
    const text = [
      'AWSTemplateFormatVersion: "2010-09-09"',
      'Resources:',
      '  DbSecurityGroup:',
      '    Type: AWS::EC2::SecurityGroup',
      '    Properties:',
      '      GroupDescription: db',
      '      SecurityGroupIngress:',
      '        - IpProtocol: tcp',
      '          FromPort: 5432',
      '          ToPort: 5432',
      '          CidrIp: 0.0.0.0/0',
      '        - IpProtocol: tcp',
      '          FromPort: 443',
      '          ToPort: 443',
      '          CidrIp: 0.0.0.0/0',
      '        - IpProtocol: tcp',
      '          FromPort: 22',
      '          ToPort: 22',
      '          CidrIp: 10.0.0.0/8',
      '  SshIngress:',
      '    Type: AWS::EC2::SecurityGroupIngress',
      '    Properties:',
      '      IpProtocol: "-1"',
      '      CidrIpv6: ::/0',
      '  Docs:',
      '    Type: AWS::S3::Bucket',
      '    Properties:',
      '      AccessControl: PublicRead',
      '      PublicAccessBlockConfiguration:',
      '        BlockPublicAcls: false',
      '  Db:',
      '    Type: AWS::RDS::DBInstance',
      '    Properties:',
      '      PubliclyAccessible: true',
      '  Replica:',
      '    Type: AWS::RDS::DBInstance',
      '    Properties:',
      '      PubliclyAccessible: false',
    ].join('\n');
    expect(ids(cloudFormationFindings(file('stack.yaml', text)))).toEqual(['INF-NET-001:11', 'INF-NET-001:24', 'INF-STO-001:28', 'INF-STO-001:30', 'INF-DB-001:34']);
  });

  it('reads JSON templates and public bucket policies', () => {
    const text = JSON.stringify({
      AWSTemplateFormatVersion: '2010-09-09',
      Resources: {
        Sg: { Type: 'AWS::EC2::SecurityGroup', Properties: { SecurityGroupIngress: [{ IpProtocol: 'tcp', FromPort: 3389, ToPort: 3389, CidrIp: '0.0.0.0/0' }, { IpProtocol: 'tcp', FromPort: 80, ToPort: 80, CidrIp: '0.0.0.0/0' }] } },
        Policy: { Type: 'AWS::S3::BucketPolicy', Properties: { PolicyDocument: { Statement: [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::docs/*' }] } } },
        Db: { Type: 'AWS::RDS::DBInstance', Properties: { PubliclyAccessible: true } },
      },
    }, null, 2);
    const f = cloudFormationFindings(file('template.json', text));
    expect(f.map((x) => x.id)).toEqual(['INF-NET-001', 'INF-STO-001', 'INF-DB-001']);
    expect(f[0]!.title).toContain('Remote Desktop');
  });

  it('leaves egress rules and private policies alone', () => {
    expect(cloudFormationFindings(file('stack.yaml', [
      'Resources:',
      '  Sg:',
      '    Type: AWS::EC2::SecurityGroup',
      '    Properties:',
      '      SecurityGroupEgress:',
      '        - IpProtocol: "-1"',
      '          CidrIp: 0.0.0.0/0',
      '  Policy:',
      '    Type: AWS::S3::BucketPolicy',
      '    Properties:',
      '      PolicyDocument:',
      '        Statement:',
      '          - Effect: Allow',
      '            Principal:',
      '              Service: cloudfront.amazonaws.com',
      '            Action: s3:GetObject',
    ].join('\n')))).toEqual([]);
  });
});

describe('Pulumi', () => {
  it('reads TypeScript programs', () => {
    const text = [
      'import * as aws from "@pulumi/aws";',
      'const sg = new aws.ec2.SecurityGroup("db", {',
      '  ingress: [',
      '    { protocol: "tcp", fromPort: 5432, toPort: 5432, cidrBlocks: ["0.0.0.0/0"] },',
      '    { protocol: "tcp", fromPort: 443, toPort: 443, cidrBlocks: ["0.0.0.0/0"] },',
      '  ],',
      '  egress: [{ protocol: "-1", fromPort: 0, toPort: 0, cidrBlocks: ["0.0.0.0/0"] }],',
      '});',
      'const db = new aws.rds.Instance("core", { engine: "postgres", publiclyAccessible: true });',
      'const docs = new aws.s3.BucketAclV2("docs", { bucket: b.id, acl: "public-read" });',
      'const pab = new aws.s3.BucketPublicAccessBlock("pab", { bucket: b.id, blockPublicAcls: false });',
    ].join('\n');
    expect(ids(pulumiFindings(file('index.ts', text)))).toEqual(['INF-NET-001:4', 'INF-STO-001:10', 'INF-STO-001:11', 'INF-DB-001:9']);
  });

  it('reads Python programs', () => {
    const text = [
      'import pulumi_aws as aws',
      'import pulumi_gcp as gcp',
      'sg = aws.ec2.SecurityGroup("ssh", ingress=[aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=22, to_port=22, cidr_blocks=["0.0.0.0/0"])])',
      'fw = gcp.compute.Firewall("redis", network=net.id, source_ranges=["0.0.0.0/0"], allows=[gcp.compute.FirewallAllowArgs(protocol="tcp", ports=["6379"])])',
      'db = aws.rds.Instance("core", engine="postgres", publicly_accessible=True)',
      'web = gcp.compute.Firewall("web", network=net.id, source_ranges=["0.0.0.0/0"], allows=[gcp.compute.FirewallAllowArgs(protocol="tcp", ports=["443"])])',
    ].join('\n');
    expect(ids(pulumiFindings(file('__main__.py', text)))).toEqual(['INF-NET-001:3', 'INF-NET-001:4', 'INF-DB-001:5']);
  });

  it('reads Kubernetes services and Azure rules', () => {
    const text = [
      'import * as k8s from "@pulumi/kubernetes";',
      'import * as network from "@pulumi/azure-native/network";',
      'new k8s.core.v1.Service("pg", { spec: { type: "LoadBalancer", ports: [{ port: 5432 }] } });',
      'new k8s.core.v1.Service("web", { spec: { type: "LoadBalancer", ports: [{ port: 443 }] } });',
      'new network.SecurityRule("rdp", { direction: "Inbound", access: "Allow", sourceAddressPrefix: "*", destinationPortRange: "3389" });',
    ].join('\n');
    expect(ids(pulumiFindings(file('index.ts', text)))).toEqual(['INF-NET-001:5', 'INF-K8S-001:3']);
  });
});

describe('Bicep and ARM', () => {
  it('reads Bicep', () => {
    const text = [
      "resource nsg 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {",
      "  name: 'app'",
      '  properties: {',
      '    securityRules: [',
      '      {',
      "        name: 'ssh'",
      '        properties: {',
      "          direction: 'Inbound'",
      "          access: 'Allow'",
      "          protocol: 'Tcp'",
      "          sourceAddressPrefix: '*'",
      "          destinationPortRange: '22'",
      '        }',
      '      }',
      '      {',
      "        name: 'https'",
      '        properties: {',
      "          direction: 'Inbound'",
      "          access: 'Allow'",
      "          sourceAddressPrefix: 'Internet'",
      "          destinationPortRange: '443'",
      '        }',
      '      }',
      '    ]',
      '  }',
      '}',
      "resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {",
      '  properties: { allowBlobPublicAccess: true }',
      '}',
      "resource c 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {",
      "  properties: { publicAccess: 'Container' }",
      '}',
      "resource fw 'Microsoft.Sql/servers/firewallRules@2023-05-01' = {",
      "  properties: { startIpAddress: '0.0.0.0', endIpAddress: '255.255.255.255' }",
      '}',
      "resource azure 'Microsoft.Sql/servers/firewallRules@2023-05-01' = {",
      "  properties: { startIpAddress: '0.0.0.0', endIpAddress: '0.0.0.0' }",
      '}',
    ].join('\n');
    expect(ids(azureTemplateFindings(file('main.bicep', text)))).toEqual(['INF-NET-001:11', 'INF-STO-001:28', 'INF-STO-001:31', 'INF-DB-001:34']);
  });

  it('reads ARM JSON', () => {
    const text = JSON.stringify({
      $schema: 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
      resources: [{ type: 'Microsoft.Network/networkSecurityGroups', properties: { securityRules: [{ name: 'pg', properties: { direction: 'Inbound', access: 'Allow', sourceAddressPrefix: '0.0.0.0/0', destinationPortRanges: ['5432', '443'] } }] } }],
    }, null, 2);
    expect(azureTemplateFindings(file('azuredeploy.json', text)).map((f) => f.title)).toEqual(['Network security rule open to the internet on PostgreSQL']);
  });
});

describe('Helm values', () => {
  it('flags data services on public load balancers, by port or by chart', () => {
    expect(ids(helmFindings(file('charts/api/values.yaml', [
      'postgresql:',
      '  primary:',
      '    service:',
      '      type: LoadBalancer',
      'redis:',
      '  master:',
      '    service:',
      '      type: NodePort',
      '      ports:',
      '        redis: 6379',
      'web:',
      '  service:',
      '    type: LoadBalancer',
      '    port: 443',
      'cache:',
      '  service:',
      '    type: LoadBalancer',
      '    loadBalancerSourceRanges:',
      '      - 10.0.0.0/8',
      '    port: 6379',
    ].join('\n'))))).toEqual(['INF-K8S-001:4', 'INF-K8S-001:8']);
    expect(ids(helmFindings(file('deploy/postgresql/values-prod.yaml', 'service:\n  type: LoadBalancer\n')))).toEqual(['INF-K8S-001:2']);
    expect(helmFindings(file('deploy/api/values.yaml', 'service:\n  type: ClusterIP\n  port: 5432\n'))).toEqual([]);
    expect(helmFindings(file('k8s/other.yaml', 'service:\n  type: LoadBalancer\n  port: 5432\n'))).toEqual([]);
  });
});

describe('the format rules', () => {
  it('report each finding once, under the right rule, and honour fortis-ignore', () => {
    const text = 'import * as aws from "@pulumi/aws";\nnew aws.rds.Instance("a", { publiclyAccessible: true }); // fortis-ignore: read replica for BI, IP-allowlisted\nnew aws.rds.Instance("b", { publiclyAccessible: true });';
    expect(all('infra/index.ts', text)).toEqual(['INF-DB-001:3']);
    expect(formatFindings(file('infra/index.ts', text)).length).toBe(2);
  });

  it('skip ordinary source files quickly', () => {
    expect(all('src/app.ts', 'export const x = { cidrBlocks: ["0.0.0.0/0"], fromPort: 22 };')).toEqual([]);
    expect(all('config/app.json', '{ "PubliclyAccessible": true }')).toEqual([]);
  });
});
