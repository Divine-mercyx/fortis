import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { renderedFiles, type HelmRunner } from '../src/rules/helm';
import { ciTerraformVars } from '../src/rules/infrastructure';
import { cfnParameterDefaults } from '../src/rules/infrastructure-formats';
import { planFindings } from '../src/rules/terraform-plan';
import { runScan } from '../src/scan';

/*
 * Infrastructure values that come from outside the repository (#93): pipeline variables, CloudFormation parameters,
 * Helm templates, and Terraform plans where every value is final. What still can't be resolved is listed as not checked.
 */

const dirs: string[] = [];
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});
function repo(files: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), 'fortis-infra-'));
  dirs.push(dir);
  const g = (...a: string[]) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
  g('init', '-q', '-b', 'main');
  g('config', 'user.email', 't@example.com');
  g('config', 'user.name', 'Test');
  for (const [p, text] of Object.entries(files)) {
    mkdirSync(join(dir, p, '..'), { recursive: true });
    writeFileSync(join(dir, p), text);
  }
  g('add', '-A');
  g('commit', '-q', '-m', 'init');
  return dir;
}
const scan = (root: string, extra: Partial<Parameters<typeof runScan>[0]> = {}) => runScan({ root, scope: 'full', packs: ['infrastructure'], offline: true, ...extra });
const found = (r: Awaited<ReturnType<typeof runScan>>) => r.detections.map((d) => `${d.ruleId}@${d.file}:${d.line}`);
const notChecked = (r: Awaited<ReturnType<typeof runScan>>) => r.notes.find((n) => n.startsWith('Not checked:')) ?? '';

/** A database whose public address is set from a pipeline variable: the .tf file can't say. */
const MAIN_TF = `variable "db_public" {
  type = bool
}

resource "aws_db_instance" "main" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = var.db_public
}
`;

/** What `terraform show -json` writes for it once the pipeline sets TF_VAR_db_public=true: one line, every value final. */
const PLAN = JSON.stringify({
  format_version: '1.2',
  terraform_version: '1.9.0',
  resource_changes: [
    { address: 'aws_db_instance.main', mode: 'managed', type: 'aws_db_instance', name: 'main', change: { actions: ['create'], after: { engine: 'postgres', publicly_accessible: true }, after_unknown: { id: true, address: true } } },
    { address: 'aws_db_instance.reports', mode: 'managed', type: 'aws_db_instance', name: 'reports', change: { actions: ['create'], after: { engine: 'mysql' }, after_unknown: { publicly_accessible: true } } },
    { address: 'module.network.aws_security_group.db', mode: 'managed', type: 'aws_security_group', name: 'db', change: { actions: ['update'], after: { ingress: [{ cidr_blocks: ['0.0.0.0/0'], from_port: 5432, to_port: 5432, protocol: 'tcp' }, { cidr_blocks: ['0.0.0.0/0'], from_port: 443, to_port: 443, protocol: 'tcp' }] }, after_unknown: {} } },
    { address: 'aws_s3_bucket_acl.exports', mode: 'managed', type: 'aws_s3_bucket_acl', name: 'exports', change: { actions: ['no-op'], after: { acl: 'public-read' }, after_unknown: {} } },
    { address: 'aws_db_instance.old', mode: 'managed', type: 'aws_db_instance', name: 'old', change: { actions: ['delete'], after: null, after_unknown: {} } },
    { address: 'data.aws_db_instance.legacy', mode: 'data', type: 'aws_db_instance', name: 'legacy', change: { actions: ['read'], after: { publicly_accessible: true }, after_unknown: {} } },
  ],
});

describe('--terraform-plan: the plan, where every value is final', () => {
  it('finds what the .tf files leave to variables, and names each resource', () => {
    const r = planFindings(PLAN, 'plan.json');
    expect(r.detections.map((d) => [d.ruleId, d.title, d.snippet])).toEqual([
      ['INF-DB-001', 'Database has a public address (publicly_accessible = true): aws_db_instance.main', 'aws_db_instance.main: publicly_accessible = true'],
      ['INF-NET-001', 'Firewall open to the internet on PostgreSQL: module.network.aws_security_group.db', 'module.network.aws_security_group.db: ingress from 0.0.0.0/0'],
      ['INF-STO-001', 'S3 bucket is public (public-read): aws_s3_bucket_acl.exports', 'aws_s3_bucket_acl.exports: acl = public-read'],
    ]);
    // Deleted resources and data sources aren't checked.
    expect(r.resources).toBe(4);
    expect(r.detections[0]!.fix).toContain('change the variable, CI setting or module input that sets it');
  });

  it("lists what Terraform only learns while applying as not checked", () => {
    expect(planFindings(PLAN, 'plan.json').unresolved).toEqual([
      { ruleId: 'INF-DB-001', file: 'plan.json', line: 1, setting: 'aws_db_instance.reports publicly_accessible', value: 'known only after apply' },
    ]);
  });

  it("refuses JSON that isn't a plan", () => {
    expect(() => planFindings('{"resources": []}', 'state.json')).toThrow("isn't terraform show -json output");
  });

  it('the issue’s case: a public database set from a pipeline variable is caught through --terraform-plan, and listed as not checked without it', async () => {
    const dir = repo({
      'infra/main.tf': MAIN_TF,
      // The pipeline sets the variable from its own settings, so the value isn't written down anywhere.
      '.github/workflows/deploy.yml': 'jobs:\n  deploy:\n    env:\n      TF_VAR_db_public: ${{ vars.DB_PUBLIC }}\n    steps:\n      - run: terraform apply -auto-approve\n',
      'plan.json': PLAN,
    });
    const without = await scan(dir);
    expect(found(without)).toEqual([]);
    expect(notChecked(without)).toContain('Not checked: 1 infrastructure setting gets its value from outside the repository');
    expect(notChecked(without)).toContain('infra/main.tf:8 publicly_accessible = var.db_public (INF-DB-001)');
    expect(notChecked(without)).toContain('--terraform-plan');

    const withPlan = await scan(dir, { terraformPlan: 'plan.json' });
    expect(found(withPlan)).toEqual(['INF-DB-001@plan.json:1', 'INF-NET-001@plan.json:1', 'INF-STO-001@plan.json:1']);
    expect(withPlan.notes).toContain('Terraform plan plan.json: checked 4 planned resources.');
    expect(notChecked(withPlan)).toContain('plan.json:1 aws_db_instance.reports publicly_accessible = known only after apply');
  });

  it('says so when the plan file is missing or wrong', async () => {
    const dir = repo({ 'main.tf': MAIN_TF, 'state.json': '{"resources": []}' });
    expect((await scan(dir, { terraformPlan: 'missing.json' })).notes.join('\n')).toContain("Couldn't read the Terraform plan missing.json");
    expect((await scan(dir, { terraformPlan: 'state.json' })).notes.join('\n')).toContain("Couldn't read the Terraform plan state.json: it isn't terraform show -json output");
  });
});

describe('TF_VAR_ and -var values written in CI files', () => {
  it('reads environment and command-line values, and leaves the CI system’s own variables alone', () => {
    const { env, cli } = ciTerraformVars([
      'env:',
      '  TF_VAR_db_public: "true"',
      '  TF_VAR_admin_cidr: 0.0.0.0/0',
      '  TF_VAR_password: ${{ secrets.DB_PASSWORD }}',
      'script:',
      '  - export TF_VAR_region=eu-west-1',
      "  - terraform apply -var 'instance_count=3' -var=\"env=prod\" -var tier=$TIER",
    ].join('\n'));
    expect(Object.fromEntries(env)).toEqual({ db_public: 'true', admin_cidr: '"0.0.0.0/0"', region: '"eu-west-1"' });
    expect(Object.fromEntries(cli)).toEqual({ instance_count: '3', env: '"prod"' });
  });

  it('judges a setting by the TF_VAR_ the pipeline sets', async () => {
    const dir = repo({ 'infra/main.tf': MAIN_TF, '.gitlab-ci.yml': 'deploy:\n  variables:\n    TF_VAR_db_public: "true"\n  script:\n    - terraform apply\n' });
    const r = await scan(dir);
    expect(found(r)).toEqual(['INF-DB-001@infra/main.tf:8']);
    expect(notChecked(r)).toBe('');
  });

  it("follows Terraform's order: TF_VAR_ under .tfvars, -var over both", async () => {
    const tfvarsWins = repo({ 'main.tf': MAIN_TF, 'terraform.tfvars': 'db_public = false\n', 'Jenkinsfile': "environment {\n  TF_VAR_db_public = 'true'\n}\n" });
    expect(found(await scan(tfvarsWins))).toEqual([]);
    const cliWins = repo({ 'main.tf': MAIN_TF, 'terraform.tfvars': 'db_public = false\n', 'azure-pipelines.yml': "steps:\n  - script: terraform apply -var 'db_public=true'\n" });
    expect(found(await scan(cliWins))).toEqual(['INF-DB-001@main.tf:8']);
  });
});

describe('settings that stay unresolved are listed, not passed', () => {
  it('lists a firewall rule whose source comes from a variable when its port is an admin port, but not a web port', async () => {
    const dir = repo({
      'main.tf': [
        'resource "aws_security_group_rule" "ssh" {',
        '  type        = "ingress"',
        '  from_port   = 22',
        '  to_port     = 22',
        '  protocol    = "tcp"',
        '  cidr_blocks = var.admin_cidrs',
        '}',
        'resource "aws_security_group_rule" "web" {',
        '  type        = "ingress"',
        '  from_port   = 443',
        '  to_port     = 443',
        '  protocol    = "tcp"',
        '  cidr_blocks = var.web_cidrs',
        '}',
        'resource "aws_s3_bucket_acl" "files" {',
        '  acl = local.files_acl',
        '}',
      ].join('\n'),
    });
    const note = notChecked(await scan(dir));
    expect(note).toContain('Not checked: 2 infrastructure settings get their value from outside the repository');
    expect(note).toContain('main.tf:6 cidr_blocks = var.admin_cidrs (INF-NET-001)');
    expect(note).toContain('main.tf:16 acl = local.files_acl (INF-STO-001)');
    expect(note).not.toContain('web_cidrs');
  });

  it('says nothing when every value is written down', async () => {
    const dir = repo({ 'main.tf': MAIN_TF.replace('type = bool', 'type    = bool\n  default = false') });
    const r = await scan(dir);
    expect(found(r)).toEqual([]);
    expect(notChecked(r)).toBe('');
  });
});

describe('CloudFormation parameters', () => {
  const template = (defaultLine: string) => `AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  PublicDb:
    Type: String
${defaultLine}
Resources:
  Db:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: postgres
      PubliclyAccessible: !Ref PublicDb
`;

  it('reads parameter defaults, in YAML and JSON', () => {
    const yaml = { path: 'stack.yaml', text: template("    Default: 'true'"), lines: template("    Default: 'true'").split('\n') };
    expect(Object.fromEntries(cfnParameterDefaults(yaml))).toEqual({ PublicDb: 'true' });
    const json = JSON.stringify({ AWSTemplateFormatVersion: '2010-09-09', Parameters: { PublicDb: { Type: 'String', Default: true }, Name: { Type: 'String' } } });
    expect(Object.fromEntries(cfnParameterDefaults({ path: 'stack.json', text: json, lines: [json] }))).toEqual({ PublicDb: 'true' });
  });

  it('judges !Ref by the parameter’s default', async () => {
    const r = await scan(repo({ 'stack.yaml': template("    Default: 'true'") }));
    expect(found(r)).toEqual(['INF-DB-001@stack.yaml:11']);
  });

  it('judges {"Ref": …} in a JSON template the same way', async () => {
    const json = JSON.stringify({
      AWSTemplateFormatVersion: '2010-09-09',
      Parameters: { PublicDb: { Type: 'String', Default: 'true' } },
      Resources: { Db: { Type: 'AWS::RDS::DBInstance', Properties: { Engine: 'postgres', PubliclyAccessible: { Ref: 'PublicDb' } } } },
    }, null, 2);
    const r = await scan(repo({ 'stack.json': json }));
    expect(r.detections.map((d) => d.ruleId)).toEqual(['INF-DB-001']);
  });

  it('lists a parameter with no default as not checked', async () => {
    const r = await scan(repo({ 'stack.yaml': template('    Description: set by the pipeline') }));
    expect(found(r)).toEqual([]);
    expect(notChecked(r)).toContain('stack.yaml:11 PubliclyAccessible = !Ref PublicDb (INF-DB-001)');
  });
});

describe('Helm charts, rendered with helm template', () => {
  const CHART = {
    'charts/db/Chart.yaml': 'apiVersion: v2\nname: db\nversion: 0.1.0\n',
    'charts/db/values.yaml': 'service:\n  exposed: true\n',
    'charts/db/templates/service.yaml': 'apiVersion: v1\nkind: Service\nmetadata:\n  name: {{ .Release.Name }}-db\nspec:\n  type: {{ if .Values.service.exposed }}LoadBalancer{{ else }}ClusterIP{{ end }}\n  ports:\n    - port: 5432\n',
  };
  const RENDERED = '---\n# Source: db/templates/service.yaml\napiVersion: v1\nkind: Service\nmetadata:\n  name: fortis-scan-db\nspec:\n  type: LoadBalancer\n  ports:\n    - port: 5432\n';

  it('splits helm template output by the template it came from', () => {
    expect(renderedFiles(RENDERED, 'charts/db').map((f) => f.path)).toEqual(['charts/db/templates/service.yaml']);
  });

  it('finds a database Service the template only makes public through values', async () => {
    const calls: string[][] = [];
    const helm: HelmRunner = async (args) => {
      calls.push(args);
      return { code: 0, stdout: RENDERED, stderr: '' };
    };
    const r = await scan(repo(CHART), { helmRunner: helm });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.slice(0, 2)).toEqual(['template', 'fortis-scan']);
    expect(r.detections.map((d) => [d.ruleId, d.file, d.line])).toEqual([['INF-K8S-001', 'charts/db/templates/service.yaml', 0]]);
    expect(r.detections[0]!.title).toMatch(/\(as rendered by helm template\)$/);
  });

  it('says the charts were not rendered when Helm is missing', async () => {
    const r = await scan(repo(CHART), { helmRunner: async () => ({ code: null, stdout: '', stderr: '', missing: true }) });
    expect(r.detections).toEqual([]);
    expect(r.notes.join('\n')).toContain("Helm isn't installed, so the chart in charts/db wasn't rendered");
  });

  it('says which chart failed to render', async () => {
    const r = await scan(repo(CHART), { helmRunner: async () => ({ code: 1, stdout: '', stderr: 'Error: found in Chart.yaml, but missing in charts/ directory: postgresql' }) });
    expect(r.notes.join('\n')).toContain("helm template couldn't render a chart");
    expect(r.notes.join('\n')).toContain('charts/db (Error: found in Chart.yaml, but missing in charts/ directory: postgresql)');
  });
});
