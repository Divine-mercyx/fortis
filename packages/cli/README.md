# fortis-watchdog

Fintech security checks on every push, from [Fortis](https://fortis.dev).

## Install

**JavaScript or TypeScript project:**

```bash
npm i -D fortis-watchdog
npx fortis init --key fts_…   # from the Fortis dashboard → Projects → New CLI key
git push                       # the pre-push hook checks what you're pushing
```

**Any other language.** This is a standalone binary and needs no Node:

```bash
curl -fsSL https://github.com/Divine-mercyx/fortis/releases/latest/download/install.sh | sh
```

```powershell
irm https://github.com/Divine-mercyx/fortis/releases/latest/download/install.ps1 | iex
```

Then run `fortis init --key fts_…` in your repository.

The scripts check the download against the release's `SHA256SUMS`. `FORTIS_VERSION` pins a version, and `FORTIS_INSTALL_DIR` changes the folder (default `~/.fortis/bin`). Builds exist for Linux (x64, arm64, glibc only), macOS (arm64, x64) and Windows (x64). On Alpine, use npm or the Docker image:

```bash
docker run --rm -v "$PWD:/src" -w /src -e FORTIS_KEY ghcr.io/divine-mercyx/fortis fortis scan --ci
```

To verify where a binary came from, run `gh attestation verify fortis-linux-x64.tar.gz --repo Divine-mercyx/fortis`.

## What it checks

| Pack | Rules | Plan |
|---|---|---|
| Secrets | Private keys, AWS, GitHub, Slack, Google and Fortis keys; random-looking hard-coded secrets | Free |
| Dependencies | Known vulnerabilities in `package-lock.json`, `pnpm-lock.yaml` or `yarn.lock`, from [OSV](https://osv.dev) | Free |
| Fintech | Paystack / Flutterwave / Monnify secret keys; money records read without an ownership check; webhooks without a signature check; balance updates outside a transaction; BVN/NIN in logs; weak or leaked OTPs; transfers without an idempotency key | Core and above |

Run `fortis rules` for the list and `fortis explain FX-OWN-001` for why a rule matters and how to fix it.

### Dependency files it reads

| Language | Files |
|---|---|
| JavaScript | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| PHP | `composer.lock` |
| Python | `poetry.lock`, `uv.lock`, `Pipfile.lock`, or a pinned `requirements.txt` |
| Java / Kotlin | `gradle.lockfile`, `pom.xml`, or an SBOM |
| Go | `go.mod` |
| .NET | `packages.lock.json` |
| Ruby | `Gemfile.lock` |

Files are found in any folder of the repository. Dev and test dependencies are left out where the file marks them (`yarn.lock`, recent `pnpm-lock.yaml` and `uv.lock` don't, so those are checked too). If a project has no lockfile, the scan says so.

**Maven needs an SBOM for full coverage.** `pom.xml` lists only direct dependencies, and a parent POM or BOM often decides their versions, so Fortis reports how many it could check. To cover everything, including transitive dependencies, have Maven list them and pass the result to Fortis. `fortis ci init` adds this step for you on GitHub Actions.

```bash
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom -DoutputFormat=json -DoutputName=bom
fortis scan --sbom target/bom.json
```

`--sbom` reads any CycloneDX JSON file, so it works for other languages too.

## Commands

| Command | What it does |
|---|---|
| `fortis init [--key fts_…] [--no-hook]` | Writes `.fortis.json`, installs the pre-push hook, adds an npm `security:scan` script |
| `fortis scan --pre-push` | Checks only the files in the commits being pushed (the hook runs this) |
| `fortis scan --ci` | Full scan for CI; findings it no longer sees are closed as fixed in the dashboard |
| `fortis scan --fail-on high` | Block at high or above (default: critical) |
| `fortis scan --json` / `--no-upload` / `--offline` | Machine output, keep results local, or skip the network |
| `fortis scan --sbom bom.json` | Also check a CycloneDX JSON SBOM |
| `fortis login <key>` / `fortis logout` | Save or remove the key for this machine |
| `fortis whoami` | Project, workspace and plan for the key |

Exit codes: `0` passed, `1` findings at or above the threshold, `2` usage or configuration error, including a full scan that found no files.

If the dependency check can't finish (OSV is down, or a lockfile can't be read), the scan says so, and its open dependency findings stay open. "Couldn't check" isn't recorded as "fixed".

## In CI

```yaml
- uses: Divine-mercyx/fortis@cli-v0.1.0-beta.6
  with:
    version: 0.1.0-beta.6
- run: fortis scan --ci
  env:
    FORTIS_KEY: ${{ secrets.FORTIS_KEY }}
```

`fortis ci init` writes this for you. On other CI systems, use the install script or the Docker image.

## Testing a running app (OWASP ZAP)

`fortis test` runs [OWASP ZAP](https://www.zaproxy.org/) in Docker against a staging URL and syncs the alerts to the dashboard.

```bash
npx fortis test --target https://staging.yourapp.com            # baseline: passive, sends no attacks
npx fortis test --target https://staging.yourapp.com --mode full # active scan (Fortis Plus)
npx fortis test --target https://staging.yourapp.com --openapi https://staging.yourapp.com/openapi.json
npx fortis test --target http://localhost:3000 --local          # your own machine, results stay local
```

Before Fortis will test a URL, an admin adds it under **Project → Staging targets**, proves control of the domain with a DNS TXT record (`_fortis-verify.<host>`), and signs the testing authorisation. Active scans are never allowed against production targets. Pausing a target in the dashboard stops a running test within about 20 seconds.

Needs Docker (image `zaproxy/zap-stable`, override with `FORTIS_ZAP_IMAGE`). For staging on a private network pass extra docker flags with `FORTIS_ZAP_DOCKER_ARGS`, for example `--add-host staging.internal:10.0.0.5`. Without Docker, run ZAP yourself and import its JSON report with `--zap-report report.json`. The default `--fail-on` for tests is `high`.

## CI in one command

```bash
fortis ci init                    # GitHub Actions (or --provider gitlab)
```

This writes `.github/workflows/fortis.yml`, which needs no Node in your project:

- **Every pull request and push** gets a full scan.
  - Findings appear as annotations on the pull request.
  - A SARIF file goes to GitHub code scanning (free on public repositories).
- **Every push to `staging`** (change it with `--staging-branch`) also gets a ZAP test, once the new deploy is answering.
- **Maven projects** also get a step that lists every dependency as an SBOM.

Set the `FORTIS_KEY` secret and the `FORTIS_STAGING_URL` variable in the repository settings. Add `--sarif fortis.sarif` to any scan to write SARIF yourself.

## Adopting Fortis in an existing codebase

```bash
npx fortis baseline                   # records today's findings in .fortis-baseline.json
```

Commit the file. From then on, only **new** findings block pushes and CI. The known ones stay in the dashboard so you can work through them. Pass `--no-baseline` to see everything.

## Secrets in git history

```bash
npx fortis scan --history
```

This searches every commit on every branch. A key that was committed and later deleted can still be read by anyone who can clone the repository, so it must be rotated. Each secret is reported once, at the commit that introduced it.

## Testing behind login

Set `FORTIS_ZAP_AUTH` to a staging test user's token before `fortis test`, and ZAP will crawl and test the pages and APIs behind login. Without it, ZAP only sees what an anonymous visitor sees. `FORTIS_ZAP_AUTH_HEADER` changes the header, for example to `Cookie`. The token:

- is sent to the target host only;
- is passed to Docker through the environment, never on the command line;
- is scrubbed from all output.

## Access checks: can one customer see another's data?

```bash
npx fortis access init --openapi https://staging.yourapp.com/openapi.json   # or edit the example
FORTIS_USER_A_TOKEN=… FORTIS_USER_B_TOKEN=… npx fortis access --target https://staging.yourapp.com
```

Set it up with two ordinary test customers on staging, and give customer A at least one loan, wallet or transfer. For each resource, Fortis then:

1. finds A's records;
2. requests each one as customer B, and again with no login at all.

If either request gets A's record back, that's **FX-BOLA-001** or **FX-AUTH-001**: broken access control, the most common way fintech data leaks. Only GET requests are sent, so nothing is created or changed. Access checks need Fortis Plus and a verified, authorised, non-production target.

## Accuracy

Every rule is measured against a labelled benchmark in `bench/cases`. A line marked `@hit` must be flagged, and a flag on any other line is a false positive. `pnpm bench` prints precision and recall per rule. The test suite fails if any rule drops below its recorded floor. When a rule is wrong on real code, we add that code to the benchmark first, then fix the rule.

## What leaves your machine

Rules run locally. When your plan syncs findings, the CLI sends the rule ID, severity, file path,
line number and a masked copy of the line (secrets and BVN/NIN reduced to their last four characters).
It never sends your source files. `--no-upload` keeps everything local.

Rule packs are signed by the Fortis API with Ed25519 and verified before use. The signing key is pinned
on first use; set `FORTIS_RULES_PUBLIC_KEY` to pin it explicitly in CI.

## Silencing a reviewed line

```js
const testKey = 'sk_test_…'; // fortis-ignore
// fortis-ignore-next-line
const t = await Transfer.findById(req.params.id);
```

Any comment style works, for example `# fortis-ignore` in Python or YAML.

Or exclude paths in `.fortis.json`: `{ "ignore": ["fixtures/**"] }`.

The git hook can be skipped once with `git push --no-verify`.

## Releasing (maintainers)

First release, from a maintainer's machine (npm asks for a 2FA code):

```bash
pnpm install && pnpm --filter fortis-watchdog build
cd packages/cli && pnpm publish --access public --tag beta
```

Then on npmjs.com: package → Settings → Trusted publishing → GitHub Actions, repository
`Divine-mercyx/fortis`, workflow `release-cli.yml`. After that, bump `version` in
`packages/cli/package.json` and push a matching tag (for example `cli-v0.1.0`). GitHub Actions then:

- tests, and builds and smoke-tests a binary on each platform;
- publishes a GitHub Release with the binaries, install scripts, checksums and build attestations;
- pushes the Docker image to `ghcr.io`;
- publishes to npm with provenance. Versions with a pre-release suffix go to the `beta` tag.

To build a binary for your own machine, run `pnpm --filter fortis-watchdog build:binary`. The result goes in `dist-sea/`. A tag on a fork runs everything except npm, which makes a safe dry run; set `FORTIS_REPO` to install from it.

## Configuration

`.fortis.json` (committed; never contains the key):

```json
{ "projectId": "…", "failOn": "critical", "ignore": ["fixtures/**"], "apiUrl": "https://fortis-api-prqr.onrender.com" }
```

Keys are read from `FORTIS_KEY`, then from `~/.config/fortis/credentials.json` (written by `fortis login`, mode 0600).
