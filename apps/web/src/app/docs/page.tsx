'use client';

import { useEffect, useMemo, useState, type ReactNode } from 'react';

import { controlsFor, FRAMEWORKS, RULE_CATALOG, TARGET_AUTHORIZATION_TEXT, type RulePack } from '@fortis/shared';

import { Search } from '@/components/icons';
import { CodeLine, CopyButton, SeverityPill } from '@/components/ui';
import { API_BASE, CLI_COMMAND, CLI_INSTALL_URL, CLI_PACKAGE, CLI_VERSION } from '@/lib/cli';

/* ---------- Stack and CI choices: every command on the page follows them ---------- */

type StackId = 'npm' | 'pnpm' | 'yarn' | 'bun' | 'other';
type CiId = 'github' | 'gitlab';

const STACKS: Record<StackId, { label: string; install: string; run: string; note?: string }> = {
  npm: { label: 'Node.js · npm', install: `npm i -D ${CLI_PACKAGE}`, run: `npx ${CLI_COMMAND}` },
  pnpm: {
    label: 'Node.js · pnpm',
    install: `pnpm add -D ${CLI_PACKAGE}`,
    run: `pnpm exec ${CLI_COMMAND}`,
    note: 'Every check works, including the dependency check on pnpm-lock.yaml (lockfile v5, v6 and v9, workspaces included).',
  },
  yarn: {
    label: 'Node.js · Yarn',
    install: `yarn add -D ${CLI_PACKAGE}`,
    run: `yarn ${CLI_COMMAND}`,
    note: 'Every check works, including the dependency check on yarn.lock (Yarn 1 and Yarn 2+). Yarn Plug’n’Play works too: the git hook runs the CLI through yarn.',
  },
  bun: {
    label: 'Node.js · Bun',
    install: `bun add -d ${CLI_PACKAGE}`,
    run: `bunx ${CLI_COMMAND}`,
    note: 'The dependency check reads npm, pnpm and yarn lockfiles, so it does not run on bun.lock / bun.lockb yet. Every other check works.',
  },
  other: {
    label: 'Other languages (Python, Go, Java, PHP…)',
    install: `curl -fsSL ${CLI_INSTALL_URL}/install.sh | sh`,
    run: CLI_COMMAND,
    note: `A standalone binary: no Node.js needed. On Windows, in PowerShell: irm ${CLI_INSTALL_URL}/install.ps1 | iex. Secrets, dependencies, staging tests (ZAP) and access checks work for your language. The fintech code rules read JavaScript and TypeScript so far, and the scan tells you which files they skipped.`,
  },
};

const NAV: { id: string; title: string; group: string }[] = [
  { id: 'introduction', title: 'Introduction', group: 'Get started' },
  { id: 'requirements', title: 'Requirements', group: 'Get started' },
  { id: 'install', title: 'Install', group: 'Get started' },
  { id: 'quick-start', title: 'Quick start', group: 'Get started' },
  { id: 'authentication', title: 'Keys and sign-in', group: 'Get started' },
  { id: 'cmd-init', title: 'fortis init', group: 'Commands' },
  { id: 'cmd-scan', title: 'fortis scan', group: 'Commands' },
  { id: 'cmd-test', title: 'fortis test', group: 'Commands' },
  { id: 'cmd-access', title: 'fortis access', group: 'Commands' },
  { id: 'cmd-baseline', title: 'fortis baseline', group: 'Commands' },
  { id: 'cmd-ci', title: 'fortis ci init', group: 'Commands' },
  { id: 'cmd-account', title: 'login, logout, whoami', group: 'Commands' },
  { id: 'cmd-rules', title: 'explain and rules', group: 'Commands' },
  { id: 'pre-push', title: 'Pre-push hook', group: 'Guides' },
  { id: 'ci', title: 'CI pipelines', group: 'Guides' },
  { id: 'staging', title: 'Staging targets', group: 'Guides' },
  { id: 'access-checks', title: 'Access checks', group: 'Guides' },
  { id: 'ignoring', title: 'Ignoring a finding', group: 'Guides' },
  { id: 'config', title: 'Configuration files', group: 'Reference' },
  { id: 'env', title: 'Environment variables', group: 'Reference' },
  { id: 'exit-codes', title: 'Exit codes', group: 'Reference' },
  { id: 'rules', title: 'Rules', group: 'Reference' },
  { id: 'http-api', title: 'HTTP API', group: 'Reference' },
  { id: 'privacy', title: 'What leaves your machine', group: 'Reference' },
  { id: 'troubleshooting', title: 'Troubleshooting', group: 'Reference' },
  { id: 'changelog', title: 'Changelog', group: 'Reference' },
];

/* ---------- Small building blocks ---------- */

function Block({ code, lang }: { code: string; lang?: string }) {
  return (
    <div className="doc-block">
      <div className="doc-block-head">
        <span>{lang ?? 'shell'}</span>
        <CopyButton text={code} />
      </div>
      <pre><code>{code}</code></pre>
    </div>
  );
}

function Section({ id, title, children, eyebrow }: { id: string; title: string; children: ReactNode; eyebrow?: string }) {
  return (
    <section id={id} className="doc-section">
      {eyebrow ? <span className="eyebrow">{eyebrow}</span> : null}
      <h2>
        <a href={`#${id}`} className="doc-anchor">{title}</a>
      </h2>
      {children}
    </section>
  );
}

function Options({ rows }: { rows: [string, string][] }) {
  return (
    <div className="table-wrap doc-table">
      <table className="table">
        <thead><tr><th>Option</th><th>What it does</th></tr></thead>
        <tbody>
          {rows.map(([o, d]) => (
            <tr key={o}><td className="mono nowrap">{o}</td><td>{d}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Note({ children, tone = 'info' }: { children: ReactNode; tone?: 'info' | 'warn' }) {
  return <div className={`doc-note ${tone}`}>{children}</div>;
}

const C = ({ children }: { children: ReactNode }) => <code className="doc-inline">{children}</code>;

/* ---------- CI templates (match what `fortis ci init` writes) ---------- */

const pkg = `${CLI_PACKAGE}@${CLI_VERSION}`;

const GITHUB_YML = `# .github/workflows/fortis.yml  (written by: fortis ci init)
name: Fortis

on:
  pull_request:
  push:
    branches: [main, master, dev, staging]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    name: Code scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Fortis
        uses: Divine-mercyx/fortis@cli-v${CLI_VERSION}
        with:
          version: ${CLI_VERSION}
      - name: Fortis scan
        run: fortis scan --ci --sarif fortis.sarif
        env:
          FORTIS_KEY: \${{ secrets.FORTIS_KEY }}
      - name: Upload to GitHub code scanning
        if: always() && hashFiles('fortis.sarif') != ''
        continue-on-error: true   # free on public repos; needs Advanced Security on private ones
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: fortis.sarif
          category: fortis

  staging:
    name: Staging test (ZAP)
    needs: scan
    if: github.event_name == 'workflow_dispatch' || (github.event_name == 'push' && github.ref == 'refs/heads/staging')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Fortis
        uses: Divine-mercyx/fortis@cli-v${CLI_VERSION}
        with:
          version: ${CLI_VERSION}
      - name: Fortis test
        run: fortis test --target \${{ vars.FORTIS_STAGING_URL }} --wait 600
        env:
          FORTIS_KEY: \${{ secrets.FORTIS_KEY }}
          FORTIS_ZAP_AUTH: \${{ secrets.FORTIS_TEST_TOKEN }}`;

const GITLAB_YML = `# fortis.gitlab-ci.yml  (written by: fortis ci init --provider gitlab)
# In .gitlab-ci.yml:  include: [{ local: fortis.gitlab-ci.yml }]

fortis-scan:
  stage: test
  image: ghcr.io/divine-mercyx/fortis:${CLI_VERSION}
  script:
    - fortis scan --ci --sarif fortis.sarif
  artifacts:
    when: always
    paths: [fortis.sarif]
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH

fortis-staging:
  stage: test
  needs: [fortis-scan]
  image: node:22
  services:
    - docker:27-dind
  variables:
    DOCKER_HOST: tcp://docker:2375
    DOCKER_TLS_CERTDIR: ""
    FORTIS_ZAP_AUTH: $FORTIS_TEST_TOKEN
  before_script:
    - apt-get update -qq && apt-get install -y -qq docker.io > /dev/null
  script:
    - npx --yes ${pkg} test --target $FORTIS_STAGING_URL --wait 600
  rules:
    - if: $CI_COMMIT_BRANCH == "staging"`;

const ACCESS_JSON = `{
  "target": "https://staging.yourapp.com",
  "header": "Authorization",
  "users": {
    "a": { "tokenEnv": "FORTIS_USER_A_TOKEN" },
    "b": { "tokenEnv": "FORTIS_USER_B_TOKEN" }
  },
  "checks": [
    { "name": "Loan",     "list": "/api/loans",     "get": "/api/loans/{id}" },
    { "name": "Wallet",   "list": "/api/wallets",   "get": "/api/wallets/{id}", "idField": "walletId" },
    { "name": "Transfer", "get": "/api/transfers/{id}", "ids": ["trf_01J9ZQ3"] }
  ]
}`;

const PACK_LABEL: Record<RulePack, string> = { fintech: 'Fintech', secrets: 'Secrets', dependencies: 'Dependencies' };
const RULE_LANG: Record<string, string> = {
  'FX-SEC-001': 'Any file', 'SEC-GEN-001': 'Any file', 'DEP-OSV': 'Lockfiles for JavaScript, PHP, Python, Java, Go, .NET and Ruby',
  'FX-BOLA-001': 'Any language (running app)', 'FX-AUTH-001': 'Any language (running app)',
};

/* ---------- Page ---------- */

export default function DocsPage() {
  const [stack, setStack] = useState<StackId>('npm');
  const [ci, setCi] = useState<CiId>('github');
  const [q, setQ] = useState('');
  const [active, setActive] = useState('introduction');
  const [pack, setPack] = useState<'all' | RulePack>('all');

  // Remember the reader's stack (URL first, then this browser).
  useEffect(() => {
    const p = new URLSearchParams(window.location.search);
    const fromUrl = p.get('stack') as StackId | null;
    let saved: string | null = null;
    try {
      saved = window.localStorage.getItem('fortis.docs.stack');
    } catch {
      /* storage blocked */
    }
    const s = (fromUrl && fromUrl in STACKS ? fromUrl : saved && saved in STACKS ? saved : null) as StackId | null;
    if (s) setStack(s);
    const c = p.get('ci');
    if (c === 'gitlab' || c === 'github') setCi(c);
  }, []);
  useEffect(() => {
    try {
      window.localStorage.setItem('fortis.docs.stack', stack);
    } catch {
      /* storage blocked */
    }
    const url = new URL(window.location.href);
    url.searchParams.set('stack', stack);
    url.searchParams.set('ci', ci);
    window.history.replaceState(null, '', url.toString());
  }, [stack, ci]);

  // Highlight the section being read.
  useEffect(() => {
    const els = NAV.map((n) => document.getElementById(n.id)).filter(Boolean) as HTMLElement[];
    const io = new IntersectionObserver(
      (entries) => {
        const visible = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]) setActive(visible[0].target.id);
      },
      { rootMargin: '-80px 0px -65% 0px' },
    );
    els.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, []);

  const s = STACKS[stack];
  const run = (args: string) => `${s.run} ${args}`;
  const filteredNav = NAV.filter((n) => !q.trim() || `${n.title} ${n.group}`.toLowerCase().includes(q.trim().toLowerCase()));
  const groups = [...new Set(filteredNav.map((n) => n.group))];
  const rules = useMemo(() => RULE_CATALOG.filter((r) => pack === 'all' || r.pack === pack), [pack]);

  return (
    <div className="docs-body">
      <aside className="docs-nav">
        <label className="search docs-search">
          <Search />
          <input
            className="input"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && filteredNav[0]) document.getElementById(filteredNav[0].id)?.scrollIntoView({ behavior: 'smooth' });
            }}
            placeholder="Search the docs"
            aria-label="Search the docs"
          />
        </label>
        {groups.map((g) => (
          <div key={g} className="docs-nav-group">
            <span className="docs-nav-label">{g}</span>
            {filteredNav.filter((n) => n.group === g).map((n) => (
              <a key={n.id} href={`#${n.id}`} className={active === n.id ? 'cur' : ''}>{n.title}</a>
            ))}
          </div>
        ))}
        {!filteredNav.length ? <p className="small">Nothing matches “{q}”.</p> : null}
      </aside>

      <main className="docs-main">
        <div className="docs-hero">
          <span className="eyebrow">Fortis Guard · {CLI_PACKAGE} v{CLI_VERSION}</span>
          <h1 className="display">Security checks on <span className="it accent">every release.</span></h1>
          <p className="lead">
            Install the CLI, connect it to your project, and every push, CI run and staging deploy is checked for leaked keys,
            vulnerable packages, fintech-specific flaws and customers who can see each other&apos;s data.
          </p>
          <div className="docs-pickers">
            <label>
              <span>Your stack</span>
              <select className="select" value={stack} onChange={(e) => setStack(e.target.value as StackId)}>
                {(Object.keys(STACKS) as StackId[]).map((k) => <option key={k} value={k}>{STACKS[k].label}</option>)}
              </select>
            </label>
            <label>
              <span>CI</span>
              <select className="select" value={ci} onChange={(e) => setCi(e.target.value as CiId)}>
                <option value="github">GitHub Actions</option>
                <option value="gitlab">GitLab CI</option>
              </select>
            </label>
          </div>
          {s.note ? <Note>{s.note}</Note> : null}
        </div>

        {/* ---------------- Get started ---------------- */}

        <Section id="introduction" title="Introduction" eyebrow="Get started">
          <p>Fortis Guard is the command-line tool behind Fortis. It runs on your machine and in CI, and checks three layers of a release:</p>
          <div className="doc-cards">
            <div><b>Code</b><p>On every push and CI run: payment keys and secrets, known-vulnerable packages, and fintech rules such as money records read without an ownership check, unsigned webhooks, balance races, BVNs in logs and weak OTPs.</p></div>
            <div><b>Running app</b><p>After a staging deploy: an OWASP ZAP scan of the live app, as a visitor or logged in as a test user. Baseline mode only watches; full mode simulates attacks.</p></div>
            <div><b>Access</b><p>With two test customers: can customer B read customer A&apos;s loans, wallets or transfers? This finds broken access control, the most common way fintech data leaks.</p></div>
          </div>
          <p>Results appear in your terminal straight away. On a paid plan they also sync to the dashboard, where fixes close findings automatically and every change is kept as evidence for auditors.</p>
        </Section>

        <Section id="requirements" title="Requirements">
          <ul className="doc-list">
            <li><b>Node.js 18.17 or newer</b> if you install from npm. The standalone binary needs no Node.</li>
            <li><b>git</b>, for the pre-push hook and changed-file scans.</li>
            <li><b>Docker</b>, only for <C>fortis test</C> (ZAP runs in the official <C>zaproxy/zap-stable</C> image).</li>
            <li>A <b>Fortis key</b> for the fintech rules, dashboard sync, staging tests and access checks. Secrets and dependency checks run without one.</li>
          </ul>
          <div className="table-wrap doc-table">
            <table className="table">
              <thead><tr><th>Plan</th><th>Code checks</th><th>Dashboard</th><th>ZAP</th><th>Access checks</th><th>Evidence pack</th></tr></thead>
              <tbody>
                <tr><td>Free</td><td>Secrets (including Paystack, Flutterwave and Monnify keys), dependencies</td><td>Local only</td><td>—</td><td>—</td><td>—</td></tr>
                <tr><td>Core</td><td>+ fintech rules</td><td>Yes</td><td>Baseline, 2 targets</td><td>—</td><td>Summary</td></tr>
                <tr><td>Plus</td><td>+ fintech rules</td><td>Yes</td><td>Baseline and full, 10 targets</td><td>Yes</td><td>Full</td></tr>
                <tr><td>Enterprise</td><td>+ fintech rules</td><td>Yes</td><td>Unlimited targets</td><td>Yes</td><td>Full</td></tr>
              </tbody>
            </table>
          </div>
        </Section>

        <Section id="install" title="Install">
          <p>Add the CLI to your project{stack === 'other' ? ' (or once per machine)' : ' as a development dependency'}:</p>
          <CodeLine cmd={s.install} />
          <p>Check it works:</p>
          <CodeLine cmd={run('--version')} />
          {stack !== 'other' ? (
            <p className="small">You can also run it without installing: <C>npx {CLI_PACKAGE}@{CLI_VERSION} scan</C>.</p>
          ) : null}
        </Section>

        <Section id="quick-start" title="Quick start">
          <ol className="doc-steps">
            <li>
              <b>Create a project and a key.</b> In the dashboard, open <C>Projects</C>, create one for this repository, then <C>New CLI key</C>. Copy the key (it starts with <C>fts_</C>); it is shown once.
            </li>
            <li>
              <b>Connect the repository.</b> From the repository root:
              <CodeLine cmd={run('init --key fts_your_key_here')} />
              This saves the key on your machine (not in the repo), writes <C>.fortis.json</C>, installs the pre-push hook and adds a <C>security:scan</C> script to package.json if you have one.
            </li>
            <li>
              <b>Run your first scan.</b>
              <CodeLine cmd={run('scan')} />
            </li>
            <li>
              <b>Push as usual.</b> The hook checks the files in your push and blocks it if anything critical is found, with the fix next to each finding.
            </li>
            <li>
              <b>Add CI.</b>
              <CodeLine cmd={run(`ci init${ci === 'gitlab' ? ' --provider gitlab' : ''}`)} />
              Then set <C>FORTIS_KEY</C> as a {ci === 'github' ? 'repository secret' : 'masked CI/CD variable'}. See <a href="#ci">CI pipelines</a>.
            </li>
          </ol>
          <Note>Already have lots of findings? Run <C>{run('baseline')}</C> once and commit the file: from then on only new findings block. See <a href="#cmd-baseline">fortis baseline</a>.</Note>
        </Section>

        <Section id="authentication" title="Keys and sign-in">
          <p>A key belongs to one project. Create one per developer machine or CI system so you can revoke them separately in the dashboard. Fortis stores only a hash of each key.</p>
          <p>The CLI looks for a key in this order:</p>
          <ol className="doc-list">
            <li>The <C>FORTIS_KEY</C> environment variable (use this in CI).</li>
            <li>The key saved by <C>{run('login')}</C> or <C>{run('init --key')}</C>, in <C>~/.config/fortis/credentials.json</C> (file mode 600).</li>
          </ol>
          <p>Rule packs from the API are signed with Ed25519. The CLI pins the signing key the first time it connects and refuses a pack whose signature doesn&apos;t match. In CI you can pin it explicitly with <C>FORTIS_RULES_PUBLIC_KEY</C>.</p>
        </Section>

        {/* ---------------- Commands ---------------- */}

        <Section id="cmd-init" title="fortis init" eyebrow="Commands">
          <p>Sets up the current repository.</p>
          <CodeLine cmd={run('init [--key fts_…] [--api URL] [--no-hook]')} />
          <Options rows={[
            ['--key <fts_…>', 'Save this key on your machine and connect the repository to its project.'],
            ['--api <url>', `Use a different Fortis API (default ${API_BASE}).`],
            ['--no-hook', 'Don’t install the pre-push hook.'],
          ]} />
          <p>It writes <C>.fortis.json</C> (commit it; it never holds the key), installs <C>.git/hooks/pre-push</C> (keeping any hook you already have), and adds <C>{'"security:scan": "fortis scan --ci"'}</C> to package.json when there is one.</p>
        </Section>

        <Section id="cmd-scan" title="fortis scan">
          <p>Scans the repository and reports findings, with the fix for each. On a plan with the dashboard it also uploads the masked results.</p>
          <CodeLine cmd={run('scan [options]')} />
          <Options rows={[
            ['--pre-push', 'Only the files in the commits being pushed, plus uncommitted changes. The git hook uses this.'],
            ['--ci', 'Full scan for CI. A full scan also closes dashboard findings it no longer sees. Turned on automatically when CI is set.'],
            ['--fail-on <severity>', 'Exit with code 1 at this severity or above: critical (default), high, medium, low or info.'],
            ['--history', 'Also search every commit on every branch for secrets. A deleted key is still readable in history and must be rotated.'],
            ['--since <rev>', 'With --history, only search commits after this revision.'],
            ['--sarif <file>', 'Write SARIF 2.1.0 for GitHub code scanning, GitLab and IDEs.'],
            ['--json', 'Print machine-readable results instead of the report. Secrets in flagged lines are masked, as everywhere else.'],
            ['--no-upload', 'Keep results on this machine.'],
            ['--no-baseline', 'Report and block on every finding, ignoring .fortis-baseline.json.'],
            ['--offline', 'No network: skips the dependency check and the upload, and uses the free rule packs.'],
            ['--api <url>', 'Use a different Fortis API.'],
          ]} />
          <p>Examples:</p>
          <Block code={`${run('scan')}                      # everything, report only\n${run('scan --fail-on high')}       # stricter: block on high too\n${run('scan --history')}           # include secrets anywhere in git history\n${run('scan --ci --sarif fortis.sarif')}`} />
          <p>Inside GitHub Actions, new findings are also printed as annotations, so they appear on the pull request&apos;s changed lines.</p>
        </Section>

        <Section id="cmd-test" title="fortis test">
          <p>Tests a running app with OWASP ZAP in Docker. Anything that isn&apos;t your own machine must be a verified, authorised <a href="#staging">staging target</a> on the project.</p>
          <CodeLine cmd={run('test --target https://staging.yourapp.com [options]')} />
          <Options rows={[
            ['--target <url>', 'The app to test. Or set "target" once in .fortis.json.'],
            ['--mode baseline|full', 'baseline (default): crawls and inspects responses, sends no attacks. full: adds attack simulation (Fortis Plus, never on production).'],
            ['--openapi <url>', 'Test every operation in an OpenAPI spec, including ones a crawler can’t find. Counts as full.'],
            ['--minutes <n>', 'How long to crawl (default 2, up to 60).'],
            ['--wait <seconds>', 'Wait for the target to come up first. Useful straight after a deploy.'],
            ['--local', 'Test localhost on this machine without registering it. Results stay local.'],
            ['--zap-report <file>', 'Import a ZAP JSON report you ran yourself instead of running Docker.'],
            ['--fail-on <severity>', 'Exit 1 at this severity or above (default high).'],
            ['--json, --no-upload', 'As for scan.'],
          ]} />
          <p><b>Testing behind login.</b> Put a staging test user&apos;s token in <C>FORTIS_ZAP_AUTH</C>. It is sent as <C>Authorization: Bearer …</C> to the target host only, passed to Docker through the environment rather than the command line, and removed from all output and uploads. Use <C>FORTIS_ZAP_AUTH_HEADER=Cookie</C> for cookie sessions.</p>
          <Block code={`FORTIS_ZAP_AUTH=eyJhbGciOi… ${run('test --target https://staging.yourapp.com')}`} />
          <p>Pausing the target in the dashboard stops a running test within about 20 seconds; nothing is uploaded.</p>
        </Section>

        <Section id="cmd-access" title="fortis access">
          <p>Checks whether one customer can read another&apos;s records. See <a href="#access-checks">Access checks</a> for the full guide.</p>
          <CodeLine cmd={run('access init [--openapi URL] [--target URL] [--force]')} />
          <CodeLine cmd={run('access --target https://staging.yourapp.com [options]')} />
          <Options rows={[
            ['init', 'Write .fortis-access.json. With --openapi, resources are found from your spec (GET /things and GET /things/{id}).'],
            ['--target <url>', 'The staging app (or "target" in the config file).'],
            ['--config <file>', 'Use another config file instead of .fortis-access.json.'],
            ['--local', 'Test localhost without registering it. Results stay local.'],
            ['--fail-on <severity>', 'Exit 1 at this severity or above (default high).'],
            ['--json, --no-upload', 'As for scan.'],
          ]} />
        </Section>

        <Section id="cmd-baseline" title="fortis baseline">
          <p>Records today&apos;s findings in <C>.fortis-baseline.json</C>. Commit it: from then on, only new findings block pushes and CI, while the known ones stay visible in the dashboard to fix over time.</p>
          <CodeLine cmd={run('baseline')} />
          <p>Findings are matched by rule, file and the (masked) line of code, not the line number, so moving code around doesn&apos;t make old findings look new. Re-run it whenever you want to accept the current state again.</p>
        </Section>

        <Section id="cmd-ci" title="fortis ci init">
          <p>Writes a ready-to-use pipeline: a scan on every pull request and push, and a ZAP test after each push to your staging branch.</p>
          <CodeLine cmd={run(`ci init${ci === 'gitlab' ? ' --provider gitlab' : ''} [--staging-branch staging] [--target URL] [--force]`)} />
          <Options rows={[
            ['--provider github|gitlab', 'Which CI to write for. Detected from .gitlab-ci.yml when not given.'],
            ['--staging-branch <name>', 'The branch that deploys to staging (default staging).'],
            ['--target <url>', 'Write the staging URL into the file instead of reading it from a CI variable.'],
            ['--force', 'Overwrite an existing file.'],
          ]} />
        </Section>

        <Section id="cmd-account" title="login, logout, whoami">
          <Block code={`${run('login fts_your_key_here')}   # save a key on this machine\n${run('whoami')}                    # project, workspace, plan and rule packs for the key\n${run('logout')}                    # remove the saved key`} />
        </Section>

        <Section id="cmd-rules" title="explain and rules">
          <Block code={`${run('rules')}                 # every rule with its severity and pack\n${run('explain FX-OWN-001')}    # why a rule matters and how to fix it`} />
          <p>Also: <C>{run('--version')}</C> and <C>{run('help')}</C>.</p>
        </Section>

        {/* ---------------- Guides ---------------- */}

        <Section id="pre-push" title="Pre-push hook" eyebrow="Guides">
          <p><C>fortis init</C> installs a git pre-push hook. It finds the CLI in your project (npm, pnpm, Yarn, including Plug’n’Play, or Bun) or on your PATH (a global install), then runs <C>fortis scan --pre-push</C> on the files changed by the commits you are pushing. On the first push of a new repository or branch, that is every commit the remote doesn&apos;t have yet.</p>
          <ul className="doc-list">
            <li>A critical finding blocks the push; everything else is shown but lets it through. Change the threshold with <C>{'"failOn"'}</C> in <C>.fortis.json</C>.</li>
            <li>An existing hook is kept, and Fortis runs after it.</li>
            <li>After upgrading the CLI, run <C>{run('init')}</C> again to update the hook. Your own lines in it are kept.</li>
            <li>In an emergency, skip it once with <C>git push --no-verify</C>. CI still scans.</li>
          </ul>
        </Section>

        <Section id="ci" title="CI pipelines">
          <p>{ci === 'github' ? 'GitHub Actions' : 'GitLab CI'}: generate the file with <C>{run(`ci init${ci === 'gitlab' ? ' --provider gitlab' : ''}`)}</C>, or copy it from here.</p>
          <Block lang="yaml" code={ci === 'github' ? GITHUB_YML : GITLAB_YML} />
          <div className="table-wrap doc-table">
            <table className="table">
              <thead><tr><th>Name</th><th>Kind</th><th>Value</th></tr></thead>
              <tbody>
                <tr><td className="mono">FORTIS_KEY</td><td>{ci === 'github' ? 'Secret' : 'Masked variable'}</td><td>A CLI key from the dashboard (one just for CI).</td></tr>
                <tr><td className="mono">FORTIS_STAGING_URL</td><td>{ci === 'github' ? 'Variable' : 'Variable'}</td><td>The staging URL, verified and authorised in the dashboard.</td></tr>
                <tr><td className="mono">FORTIS_TEST_TOKEN</td><td>{ci === 'github' ? 'Secret (optional)' : 'Masked variable (optional)'}</td><td>A staging test user&apos;s token, to test behind login.</td></tr>
              </tbody>
            </table>
          </div>
          {ci === 'github' ? (
            <p>Findings show as annotations on pull requests on every plan. SARIF upload to the Security tab is free on public repositories and needs GitHub Advanced Security on private ones; the step is allowed to fail without failing the build.</p>
          ) : (
            <p>The ZAP job uses Docker-in-Docker, so the runner must allow privileged services. The SARIF file is saved as a job artifact.</p>
          )}
        </Section>

        <Section id="staging" title="Staging targets">
          <ol className="doc-steps">
            <li><b>Add the URL.</b> Project → Staging targets → Add target. Fortis keeps the origin only (scheme, host and port).</li>
            <li>
              <b>Prove you control the domain.</b> Add the TXT record Fortis shows you, then press Check DNS record:
              <Block lang="dns" code={`_fortis-verify.staging.yourapp.com.  TXT  "fortis-verify=<your token>"`} />
            </li>
            <li><b>Authorise testing.</b> An admin signs this statement with their name; it&apos;s kept in the audit log with the time and wording version:<blockquote className="doc-quote">{TARGET_AUTHORIZATION_TEXT}</blockquote></li>
            <li><b>Run tests</b> with <C>{run('test --target …')}</C>, or let CI do it after each deploy.</li>
          </ol>
          <ul className="doc-list">
            <li>IP addresses and localhost can&apos;t be verified; use <C>--local</C> for those.</li>
            <li>Full (active) scans and access checks are never allowed on targets marked production.</li>
            <li>Private network? Pass Docker flags with <C>FORTIS_ZAP_DOCKER_ARGS</C>, for example <C>--add-host staging.internal:10.0.0.5</C>.</li>
            <li>Pause a target to stop all tests at once; only admins can resume it.</li>
          </ul>
        </Section>

        <Section id="access-checks" title="Access checks">
          <p>For each resource you list, Fortis finds records that belong to test customer A, then requests each one as test customer B and with no login at all. If either gets A&apos;s record back, that&apos;s a finding:</p>
          <ul className="doc-list">
            <li><b>FX-BOLA-001</b>: customer B can read customer A&apos;s record.</li>
            <li><b>FX-AUTH-001</b>: the record is readable without logging in.</li>
          </ul>
          <p><b>Set it up</b></p>
          <ol className="doc-steps">
            <li>Create two ordinary customers on staging, and give customer A at least one loan, wallet or transfer.</li>
            <li>Write the config: <CodeLine cmd={run('access init --openapi https://staging.yourapp.com/openapi.json')} /></li>
            <li>Check the paths, then run it with the two tokens: <CodeLine cmd={`FORTIS_USER_A_TOKEN=… FORTIS_USER_B_TOKEN=… ${run('access --target https://staging.yourapp.com')}`} /></li>
          </ol>
          <Block lang=".fortis-access.json" code={ACCESS_JSON} />
          <ul className="doc-list">
            <li>Each check needs a <C>get</C> path containing <C>{'{id}'}</C>, plus either a <C>list</C> path (IDs are read from the first array of objects in the response, using <C>idField</C>, default <C>id</C>) or explicit <C>ids</C> that belong to user A.</li>
            <li>Only GET requests are sent: nothing is created, changed or deleted. There is a short pause between requests and a cap of 200 per run.</li>
            <li>A 404 that echoes the ID back (“loan 123 not found”) is correctly treated as protected.</li>
            <li>Tokens come from the environment only and are removed from all results. Never put them in the config file.</li>
          </ul>
        </Section>

        <Section id="ignoring" title="Ignoring a finding">
          <p>When you have reviewed a line and it is safe, add a comment on it or on the line above:</p>
          <Block lang="ts" code={`const key = loadFromVault('paystack'); // fortis-ignore\n\n// fortis-ignore-next-line: staff-only route, checked by requirePermission\nconst loan = await Loan.findById(req.params.id);`} />
          <p>Leave a reason after the comment so reviewers know why. To skip whole paths, add globs to <C>{'"ignore"'}</C> in <C>.fortis.json</C>. In the dashboard you can also mark a finding as an accepted risk or a false positive with a reason; that decision goes into the evidence pack.</p>
        </Section>

        {/* ---------------- Reference ---------------- */}

        <Section id="config" title="Configuration files" eyebrow="Reference">
          <p><b>.fortis.json</b>: commit it; it never contains a key.</p>
          <Block lang=".fortis.json (comments are explanation only)" code={`{\n  "projectId": "c1b5…",              // written by fortis init\n  "apiUrl": "${API_BASE}",\n  "failOn": "critical",              // pre-push and scan threshold\n  "ignore": ["legacy/**", "**/*.generated.ts"],\n  "target": "https://staging.yourapp.com"   // default for fortis test\n}`} />
          <p><b>.fortis-baseline.json</b>: written by <C>fortis baseline</C>; holds fingerprints of accepted findings, never code. <b>.fortis-access.json</b>: the resources for <a href="#access-checks">access checks</a>.</p>
          <p>Always skipped: <C>node_modules</C>, <C>dist</C>, <C>build</C>, <C>.next</C>, <C>coverage</C>, <C>vendor</C>, minified files, source maps, lockfiles (except for the dependency check), binaries and files over 1 MB. Fintech rules also skip tests, fixtures and mocks; secret checks don&apos;t.</p>
        </Section>

        <Section id="env" title="Environment variables">
          <div className="table-wrap doc-table">
            <table className="table">
              <thead><tr><th>Variable</th><th>Used by</th><th>What it does</th></tr></thead>
              <tbody>
                {[
                  ['FORTIS_KEY', 'all', 'The CLI key. Takes priority over a saved key.'],
                  ['FORTIS_API_URL', 'all', `API address (default ${API_BASE}).`],
                  ['FORTIS_RULES_PUBLIC_KEY', 'scan', 'Pin the rule-pack signing key (PEM) instead of trusting it on first use.'],
                  ['FORTIS_ZAP_AUTH', 'test', 'A test user’s token for logged-in testing. “Bearer ” is added for the Authorization header.'],
                  ['FORTIS_ZAP_AUTH_HEADER', 'test', 'Header for FORTIS_ZAP_AUTH (default Authorization; e.g. Cookie).'],
                  ['FORTIS_ZAP_IMAGE', 'test', 'ZAP Docker image (default zaproxy/zap-stable).'],
                  ['FORTIS_ZAP_DOCKER_ARGS', 'test', 'Extra docker run flags, e.g. --add-host or --network.'],
                  ['FORTIS_USER_A_TOKEN / FORTIS_USER_B_TOKEN', 'access', 'The two test customers’ tokens (names can be changed in the config).'],
                  ['CI', 'scan', 'Set by CI providers; turns on full-scan mode.'],
                  ['NO_COLOR / FORCE_COLOR', 'all', 'Turn terminal colours off or on.'],
                ].map(([k, u, d]) => <tr key={k}><td className="mono">{k}</td><td>{u}</td><td>{d}</td></tr>)}
              </tbody>
            </table>
          </div>
        </Section>

        <Section id="exit-codes" title="Exit codes">
          <div className="table-wrap doc-table">
            <table className="table">
              <thead><tr><th>Code</th><th>Meaning</th></tr></thead>
              <tbody>
                <tr><td className="mono">0</td><td>Passed: nothing at or above the threshold.</td></tr>
                <tr><td className="mono">1</td><td>Findings at or above the threshold (the push or build should stop).</td></tr>
                <tr><td className="mono">2</td><td>Could not run: bad options, invalid key, target not ready, Docker missing, or a network error.</td></tr>
              </tbody>
            </table>
          </div>
        </Section>

        <Section id="rules" title="Rules">
          <div className="docs-pickers" style={{ marginTop: 0 }}>
            <label>
              <span>Pack</span>
              <select className="select" value={pack} onChange={(e) => setPack(e.target.value as 'all' | RulePack)}>
                <option value="all">All rules</option>
                <option value="fintech">Fintech</option>
                <option value="secrets">Secrets</option>
                <option value="dependencies">Dependencies</option>
              </select>
            </label>
          </div>
          <div className="table-wrap doc-table">
            <table className="table">
              <thead><tr><th>Rule</th><th>Severity</th><th>What it finds</th><th>Works on</th><th>Controls</th></tr></thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.id}>
                    <td className="mono nowrap">{r.id}<span className="small" style={{ display: 'block' }}>{PACK_LABEL[r.pack]}</span></td>
                    <td><SeverityPill severity={r.severity} /></td>
                    <td><b>{r.title}</b><span className="small" style={{ display: 'block', marginTop: 4 }}>{r.summary}</span><span className="small doc-fix">Fix: {r.fix}</span></td>
                    <td className="small">{RULE_LANG[r.id] ?? 'JavaScript, TypeScript'}</td>
                    <td className="small">{[...new Set(controlsFor(r.id).filter((c) => c.framework !== 'cbn').map((c) => `${FRAMEWORKS[c.framework].short} ${c.ref}`))].join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="small">ZAP alerts appear as <C>ZAP-&lt;alert id&gt;</C> with ZAP&apos;s own description and fix. Every rule is measured against a labelled benchmark, and a release can&apos;t make a rule less accurate.</p>
        </Section>

        <Section id="http-api" title="HTTP API">
          <p>The CLI talks to these endpoints, and you can call them from your own tooling. Authenticate with a project key; all bodies are JSON.</p>
          <Block code={`curl ${API_BASE}/v1/cli/whoami \\\n  -H "Authorization: Bearer $FORTIS_KEY"`} />
          <div className="table-wrap doc-table">
            <table className="table">
              <thead><tr><th>Endpoint</th><th>What it does</th></tr></thead>
              <tbody>
                <tr><td className="mono nowrap">GET /v1/cli/whoami</td><td>The key&apos;s project, workspace, plan and entitlements (rule packs, uploads, DAST mode, access checks).</td></tr>
                <tr><td className="mono nowrap">GET /v1/cli/rules</td><td>The signed rule pack for the plan: <C>{'{ keyId, algorithm: "ed25519", payload, signature }'}</C>. Valid for 7 days.</td></tr>
                <tr><td className="mono nowrap">GET /v1/cli/rules/public-key</td><td>The public key that signs rule packs (no auth).</td></tr>
                <tr><td className="mono nowrap">GET /v1/cli/targets</td><td>The project&apos;s staging targets and why each can or can&apos;t be tested. Query: <C>url</C>, <C>mode=baseline|full|access</C>.</td></tr>
                <tr><td className="mono nowrap">POST /v1/cli/scans</td><td>Upload one run&apos;s findings. Safe to retry with the same <C>scanId</C>.</td></tr>
              </tbody>
            </table>
          </div>
          <p><b>POST /v1/cli/scans</b> request:</p>
          <Block lang="json" code={`{
  "scanId": "4f0c6a3e-5b7d-4d8e-9a1b-2c3d4e5f6a7b",   // your UUID; retries reuse it
  "trigger": "ci",                                    // pre-push | ci | manual
  "kind": "code",                                     // code | dast | access
  "scope": "full",                                    // full closes findings it no longer sees
  "commit": "9fceb02", "branch": "main",
  "cliVersion": "${CLI_VERSION}",
  "findings": [
    {
      "ruleId": "FX-OWN-001",
      "severity": "critical",
      "title": "Money record read without an ownership check",
      "file": "src/routes/transfers.ts",
      "line": 41,
      "snippet": "const t = await Transfer.${'findById'}(req.params.id)"
    }
  ]
}`} />
          <p>For <C>dast</C> and <C>access</C> runs, also send <C>targetId</C> (and <C>dastMode</C> for ZAP); the target must be verified, authorised and not paused. Limits: 2,000 findings per upload, a 300-character snippet (masked again on the server), 2 MB per request.</p>
          <p>Response (201, or 200 for a retried <C>scanId</C>):</p>
          <Block lang="json" code={`{
  "scanId": "b17123b2-…",
  "duplicate": false,
  "findingsCount": 1, "newCount": 1, "reopenedCount": 0, "fixedCount": 0,
  "findings": [{ "fingerprint": "8c1e…", "findingId": "e3a9…", "status": "open", "isNew": true }],
  "dashboardUrl": "https://fortis-web.onrender.com/projects/…?scan=b17123b2-…"
}`} />
          <p>Errors use one shape, with an HTTP status: 400 invalid, 401 bad key, 402 not in your plan, 403 target not ready, 404 not found, 429 rate limited (120 requests a minute per key).</p>
          <Block lang="json" code={`{ "error": { "code": "TARGET_NOT_READY", "message": "Verify the domain with its DNS TXT record in the dashboard first." } }`} />
        </Section>

        <Section id="privacy" title="What leaves your machine">
          <ul className="doc-list">
            <li><b>Never:</b> your source code or files. Rules run locally.</li>
            <li><b>Uploaded (paid plans):</b> rule ID, severity, file path, line number and the flagged line with secrets masked (for example <C>sk_live_••••••••3f9a</C>), plus commit, branch and timings.</li>
            <li><b>Dependency check:</b> package names and versions are sent to the public OSV database (osv.dev).</li>
            <li><b>ZAP and access checks:</b> run from your machine or CI; Fortis receives the alerts, never response bodies or tokens.</li>
            <li>Use <C>--no-upload</C> or <C>--offline</C> to keep everything local.</li>
          </ul>
        </Section>

        <Section id="troubleshooting" title="Troubleshooting">
          <dl className="doc-faq">
            <dt>“No Fortis key found, so only the free checks ran”</dt>
            <dd>Run <C>{run('login fts_…')}</C>, or set <C>FORTIS_KEY</C>. Check with <C>{run('whoami')}</C>.</dd>
            <dt>“found but no lockfile, so those dependencies weren&apos;t checked”</dt>
            <dd>Fortis needs exact versions. Commit the lockfile the message names, in any folder of the repository. Bun lockfiles are not read yet; pass <C>--sbom</C> with a CycloneDX file instead.</dd>
            <dt>“pom.xml: checked 3 of 28 declared dependencies”</dt>
            <dd><C>pom.xml</C> lists only direct dependencies, and a parent POM or BOM often sets their versions. Generate a CycloneDX SBOM with Maven and pass <C>--sbom target/bom.json</C> to check them all, including transitive ones. <C>{CLI_COMMAND} ci init</C> adds this step on GitHub Actions.</dd>
            <dt>“Dependency check skipped: could not reach api.osv.dev”</dt>
            <dd>The machine or CI runner can&apos;t reach the OSV database. Allow <C>https://api.osv.dev</C> through your proxy or firewall. The scan then shows “Nothing found · the dependency check did not run” rather than a full pass.</dd>
            <dt>“Docker is installed but not running”</dt>
            <dd>Start Docker Desktop (or the docker service), or run ZAP yourself and pass <C>--zap-report report.json</C>.</dd>
            <dt>“… is not a target on this project” / “Verify the domain…”</dt>
            <dd>Add the URL under Project → Staging targets, add the TXT record, check it, and have an admin authorise testing.</dd>
            <dt>“Fortis: the CLI isn&apos;t installed in this repo”</dt>
            <dd>The git hook couldn&apos;t find the CLI. Install it in the project (see Install) or globally with <C>npm i -g {CLI_PACKAGE}</C>. To push once without the check: <C>git push --no-verify</C>.</dd>
            <dt>The hook didn&apos;t run</dt>
            <dd>Re-run <C>{run('init')}</C>. If you use a custom <C>core.hooksPath</C> (Husky), Fortis installs into that folder.</dd>
            <dt>A finding is wrong</dt>
            <dd>Mark it as a false positive in the dashboard with a reason. That feeds each rule&apos;s false-positive rate, which is how we decide what to tune next.</dd>
          </dl>
        </Section>

        <Section id="changelog" title="Changelog">
          <dl className="doc-faq">
            <dt>0.1.0-beta.9</dt>
            <dd>The dependency check now covers PHP, Python, Java, Go, .NET and Ruby as well as JavaScript, in any folder, and reads CycloneDX SBOMs with <C>--sbom</C>. Standalone binaries, a Docker image and a GitHub Action mean non-JavaScript teams don&apos;t need Node. More secrets are caught in non-JavaScript code and config files. When the dependency check can&apos;t finish, its open findings stay open instead of being marked fixed.</dd>
            <dt>0.1.0-beta.8</dt>
            <dd>The dependency check reads PHP, Python, Java, Go, .NET and Ruby lockfiles (and a CycloneDX SBOM with <C>--sbom</C>) as well as npm, pnpm and Yarn, and secret scanning understands those languages&apos; config files. A scan that couldn&apos;t run the dependency check no longer closes its findings. The first push of a new repository or branch checks every commit being pushed, not only the last one (a key leaked in an earlier commit used to get through). The git hook works with Yarn Plug’n’Play and says clearly when the CLI isn&apos;t installed. Run <C>{run('init')}</C> again to upgrade an existing hook.</dd>
            <dt>0.1.0-beta.7</dt>
            <dd>The dependency check reads <C>pnpm-lock.yaml</C> (v5, v6 and v9, workspaces included) and <C>yarn.lock</C> (Yarn 1 and Yarn 2+), as well as <C>package-lock.json</C>. Findings point at the lockfile line. When the dependency check can&apos;t run, the scan says so instead of “All checks passed”.</dd>
            <dt>0.1.0-beta.6</dt>
            <dd>Paystack, Flutterwave and Monnify secret keys are caught on the free plan. <C>--json</C> output masks secrets. A scan with no lockfile says the dependency check was skipped.</dd>
            <dt>0.1.0-beta.5</dt>
            <dd>Reports itself as 0.1.0-beta.4 (published from a stale build). Upgrade to beta.6 or later.</dd>
          </dl>
        </Section>
      </main>
    </div>
  );
}
