# fortis-watchdog

Fintech security checks on every push, from [Fortis](https://fortis.dev).

## Install

**JavaScript or TypeScript project:**

```bash
npm i -D fortis-watchdog
npx fortis init --key fts_…   # from the Fortis dashboard → Projects → New CLI key
git push                       # the pre-push hook checks what you're pushing
```

**Python project:** this needs no Node.

```bash
pip install fortis-watchdog      # or: pipx install fortis-watchdog, uv tool install fortis-watchdog
fortis init --key fts_…
```

Install it in your project's `.venv` or `venv`, or globally. The hook finds it either way, even when the virtual environment isn't active. It also finds it through `uv run` and `poetry run`. If you use [pre-commit](https://pre-commit.com), `fortis init` prints the config to add.

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

| Pack | Rules | Languages | Plan |
|---|---|---|---|
| Secrets | Paystack / Flutterwave / Monnify secret keys; private keys, AWS, GitHub, Slack, Google and Fortis keys; database passwords, SaaS and registry tokens (SendGrid, Slack, OpenAI, Anthropic, npm, PyPI…) in connection URLs, JDBC URLs and .NET connection strings; random-looking hard-coded secrets, including unquoted values in `.env`, `.properties` and YAML files | Any | Free |
| Dependencies | Known vulnerabilities, from [OSV](https://osv.dev) | See below | Free |
| Fintech | Money records read without an ownership check; webhooks without a signature check; balance updates outside a transaction; BVN/NIN in logs; weak or leaked OTPs; transfers without an idempotency key | JavaScript, TypeScript and Python (Django, Django REST, Flask, FastAPI) | Core and above |

`fortis test` and `fortis access` test a running app over HTTP, so they work whatever the backend is written in.

Run `fortis rules` for the list and `fortis explain FX-OWN-001` for why a rule matters and how to fix it.

### Dependency files it reads

| Language | Files |
|---|---|
| JavaScript | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` |
| PHP | `composer.lock` |
| Python | `uv.lock`, `poetry.lock`, `pdm.lock`, `pylock.toml`, `Pipfile.lock`, or pinned requirements files |
| Java / Kotlin | `gradle.lockfile`, `pom.xml`, or an SBOM |
| Go | `go.mod` |
| .NET | `packages.lock.json` |
| Ruby | `Gemfile.lock` |
| Rust | `Cargo.lock` |
| Dart / Flutter | `pubspec.lock` |

Files are found in any folder of the repository. Dev and test dependencies are left out wherever they can be told apart (yarn workspaces can't, so those are all checked). Findings point at the package's line in the file. If a project has no lockfile, the scan says so.

**A hand-written `requirements.txt` lists only direct dependencies,** so the scan says what it couldn't cover. Use a lockfile, compile it with `pip-compile` or `uv pip compile`, or pass an SBOM from [`cyclonedx-py`](https://github.com/CycloneDX/cyclonedx-python). `fortis ci init` adds that step for you on GitHub Actions.

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
| `fortis scan --json` / `--no-upload` / `--offline` | Machine output (secrets masked, like every other output), keep results local, or skip the network |
| `fortis scan --sbom bom.json` | Also check a CycloneDX JSON SBOM |
| `fortis login <key>` / `fortis logout` | Save or remove the key for this machine |
| `fortis whoami` | Project, workspace and plan for the key |

Exit codes: `0` passed, `1` findings at or above the threshold, `2` usage or configuration error, including a full scan that found no files.

If the dependency check can't finish (OSV is down, or a lockfile can't be read), the scan says so, and its open dependency findings stay open. "Couldn't check" isn't recorded as "fixed".

## In CI

```yaml
- uses: Divine-mercyx/fortis@cli-v0.1.0-beta.11
  with:
    version: 0.1.0-beta.11
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
- **Maven projects, and Python projects with a hand-written `requirements.txt`,** also get a step that lists every dependency as an SBOM.

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

Django session logins work too: set `"header": "Cookie"` in `.fortis-access.json` and use `sessionid=…` as each user's token. If either request gets A's record back, that's **FX-BOLA-001** or **FX-AUTH-001**: broken access control, the most common way fintech data leaks. Only GET requests are sent, so nothing is created or changed. Access checks need Fortis Plus and a verified, authorised, non-production target.

## Accuracy

Every rule is measured against a labelled benchmark in `bench/cases`. A line marked `@hit` must be flagged, and a flag on any other line is a false positive. `pnpm bench` prints precision and recall per rule. The test suite fails if any rule drops below its recorded floor. When a rule is wrong on real code, we add that code to the benchmark first, then fix the rule.

## Git checkouts in CI and large repositories

- **Shallow clones** (CI's default `fetch-depth: 1`): a full scan with `--ci` needs only the latest commit. `--history` and branch comparisons say when they could only see part of the history. `fortis ci init --history` adds `--history` together with `fetch-depth: 0` (GitLab: `GIT_DEPTH: 0`).
- **Submodules** are separate repositories, so they're skipped with a note. Pass `--submodules` to scan them too.
- **Worktrees, detached HEAD and sparse checkouts** work. In a sparse checkout, files that aren't on disk are counted in a note. Their findings stay open, since a scan that didn't read them can't say they're fixed.
- **Large repositories:** files are read and checked one at a time, so memory stays flat. A full scan of 100,000 files takes about 11 seconds, and CI checks that it stays under 30. A scan stops after 10 minutes (`FORTIS_SCAN_BUDGET_SECONDS` to change it) with a note, and is then treated as partial. Ignore generated folders in `.fortis.json` to keep scans quick.

## Windows

The pre-push hook is run by Git's own `sh`, whichever shell or app starts the push, so it behaves the same in Git Bash, PowerShell, cmd and WSL.

- **Finding the CLI:** the hook looks in `node_modules/.bin` (npm, pnpm and Yarn shims, Bun's `fortis.exe`), Yarn Plug'n'Play, your PATH, then `%USERPROFILE%\.fortis\bin` where `install.ps1` puts it. That last step is for apps that don't load your shell's PATH.
- **GitHub Desktop, VS Code and Visual Studio:** a blocked push fails with the Fortis report as the error. GitHub Desktop shows it in the error dialog, VS Code under *Git: Show Git Output*, and Visual Studio in the Git output pane. Fix the finding and push again. Skipping once needs a terminal: `git push --no-verify`.
- **Line endings and paths:** CRLF files give the same line numbers and snippets as LF ones. `ignore` globs can use `\` or `/`, `.fortis.json` may be saved with a byte-order mark, and a baseline written on Windows is identical to one written on a Mac or Linux for the same repository.

## Behind a proxy

Fortis reads the same variables as curl, upper or lower case:

```bash
export HTTPS_PROXY=http://proxy.bank.local:8080      # or http://user:password@proxy:8080
export NO_PROXY=.bank.local,10.0.0.0/8               # hosts that skip the proxy
```

- `localhost`, `127.0.0.1` and `::1` never go through the proxy, so `fortis test --local` and access checks against a local app keep working.
- If the proxy inspects TLS with its own certificate, give Fortis the CA: `NODE_EXTRA_CA_CERTS=/path/ca.pem`, `FORTIS_CA_FILE=/path/ca.pem` or `--ca /path/ca.pem`.
- `fortis scan --verbose` prints the proxy in use, with any password hidden.
- Dependency answers from OSV are cached for 6 hours in `~/.cache/fortis` (`FORTIS_CACHE_DIR` to move it, `--no-cache` to skip it). So a pre-push check doesn't repeat the same questions, and keeps working for a while if the network drops.

### No internet at all (air-gapped)

Download OSV's exports for the ecosystems you use, copy them across, and point Fortis at the folder:

```bash
curl -O https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip   # also PyPI, Maven, Go, crates.io, Packagist, NuGet, RubyGems, Pub
fortis scan --offline --osv-db ./osv
```

The folder can hold the zips (in subfolders too) or the advisories already unzipped as `.json` files. Refresh it as often as you'd like new advisories, for example weekly.

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

One-time setup, by the package owner on each registry:

- **npm:** on npmjs.com, package → Settings → Trusted publishing → GitHub Actions, repository `Divine-mercyx/fortis`, workflow `release-cli.yml`. Until then the npm step fails with a 404, because no token is stored in GitHub.
- **PyPI:** on pypi.org, add a pending publisher for `fortis-watchdog`, with repository `Divine-mercyx/fortis`, workflow `release-cli.yml`, environment `pypi`.

To release, bump `version` in `packages/cli/package.json` and push a matching tag (for example `cli-v0.1.0`). GitHub Actions then:

- tests, and builds and smoke-tests a binary on each platform;
- runs the install-and-push check (`scripts/e2e.sh`) for npm, pnpm, Yarn 1, Yarn 4 Plug'n'Play, Bun, a global install, the binary, the install script and the Docker image, on Linux, macOS (arm64 and x64) and Windows. Nothing is published unless all of them pass. Run one locally with `bash scripts/e2e.sh npm fortis-watchdog-<version>.tgz`;
- publishes a GitHub Release with the binaries, install scripts, checksums and build attestations;
- pushes the Docker image to `ghcr.io`;
- publishes to npm with provenance. Versions with a pre-release suffix go to the `beta` tag. A version that's already on npm (published by hand) is skipped, not treated as a failure;
- uses this version's changelog section below as the release notes. Before tagging, change its heading from "(unreleased)" to the release date;
- builds, tests and publishes the wheels to PyPI (TestPyPI on a fork). `packages/python/build_wheel.py` makes one by hand.

Workflow actions are pinned to commit SHAs, and runners to image versions, so a release can't change because an action moved its tag. Dependabot proposes updates to the pins.

To build a binary for your own machine, run `pnpm --filter fortis-watchdog build:binary`. The result goes in `dist-sea/`. A tag on a fork runs everything except npm, which makes a safe dry run; set `FORTIS_REPO` to install from it.

Publishing a tarball by hand: `npm pack` rebuilds `dist/` first, so the packed CLI always reports
the version in `package.json`. Publish it with `npm publish fortis-watchdog-<version>.tgz --tag beta`.

## Configuration

`.fortis.json` (committed; never contains the key):

```json
{ "projectId": "…", "failOn": "critical", "ignore": ["fixtures/**"], "apiUrl": "https://fortis-api-prqr.onrender.com" }
```

Keys are read from `FORTIS_KEY`, then from `~/.config/fortis/credentials.json` (written by `fortis login`, mode 0600).

## Changelog

**0.1.0-beta.12** (unreleased)
- `fortis ci init` writes current major versions of GitHub's actions, so your workflow gets no Node.js 20 deprecation warnings.
- Python is fully supported: `pip install fortis-watchdog`, the fintech rules for Django, Django REST, Flask and FastAPI, and dev packages told apart in uv and Poetry lockfiles.
- `pip install` needs no Node, and the git hook finds the CLI in `.venv` or `venv` even when it isn't active, and through `uv run` and `poetry run`.
- More secrets are caught in Python: real-looking defaults such as `os.getenv("KEY", "…")`, SQLAlchemy connection URLs, tokens in URLs, PyPI tokens and notebooks.
- Works behind company proxies (`HTTPS_PROXY`, `NO_PROXY`, extra CA with `--ca`), caches OSV answers for 6 hours, and checks dependencies with no internet using `--osv-db`. See "Behind a proxy".
- Dependency findings name the version that fixes every advisory and the exact upgrade command for your package manager; for an indirect npm, pnpm or Yarn dependency, the direct one that pulls it in. Also in `--json`, SARIF and the dashboard.
- Database passwords in connection URLs, JDBC URLs and .NET connection strings are reported as critical.
- Stripe keys are named as Stripe (and Paystack as Paystack), with restricted keys and webhook secrets.
- New token formats: SendGrid, Mailgun, Resend, Slack and Discord webhooks, Telegram, OpenAI, Anthropic, Azure Storage, DigitalOcean, Render, npm, PyPI, RubyGems, NuGet, Docker Hub, `.npmrc` tokens, Supabase `service_role` keys, Twilio auth tokens and Google service-account keys. `.npmrc`, `.pypirc`, `.netrc` and `.yarnrc` are now scanned.
- SeerBit, OPay and Squad sandbox secret keys are named.
- A repository with only lockfiles now shows why the dependency check failed, instead of "Found no files to scan".
- Windows: the hook finds the CLI from GitHub Desktop, VS Code and other apps, and CRLF files, BOMs and backslash paths are handled. A Windows baseline matches a Mac or Linux one.
- Shallow CI clones, submodules (`--submodules`), worktrees, detached HEAD and sparse checkouts are handled. Large repositories are read one file at a time, with a time budget.
- Python: the fintech rules cover Django, Flask and FastAPI. More lockfiles are read (`pdm.lock`, `pylock.toml`), and packages without an exact version are named, with how to pin them. Install with pip, pipx or uv, or use the pre-commit hook.
- Every install method is tested end to end on Linux, macOS and Windows before a release.

**0.1.0-beta.11**
- The dependency check reads Rust (`Cargo.lock`) and Dart/Flutter (`pubspec.lock`). A Rust or Flutter project without its lockfile, and Swift, CocoaPods or Elixir projects (not read yet), are now reported instead of passing as clean.
- Hard-coded values in tests that spell themselves out as fake (`nova_abc12345_secret`, `fake-token-1`) are no longer reported. Real-looking secrets in tests still are. Python's `test_*.py` and Go's `*_test.go` count as tests.

**0.1.0-beta.10**
- The installer shows a progress bar while it downloads (about 40 MB), retries dropped connections, and stops with a clear message if the download stalls, instead of looking stuck.
- On an Apple-silicon Mac whose Terminal runs under Rosetta, the installer now picks the native Apple-silicon build.

**0.1.0-beta.9** (beta.8 was not published; its changes are here)
- Any language: the dependency check reads PHP, Python, Java (Gradle, `pom.xml`, or a CycloneDX SBOM with `--sbom`), Go, .NET and Ruby lockfiles as well as npm, pnpm and Yarn, in any folder of the repository, and says which projects have no lockfile.
- More secrets are caught in non-JavaScript code and config files, including PHP, Go and Java/Spring styles and unquoted values in `.env`, `.properties` and YAML.
- Standalone binaries, install scripts, a Docker image and a GitHub Action, so non-JavaScript teams don't need Node. `fortis ci init` uses them.
- The first push of a new repository or branch checks every commit being pushed, not only the last one. Before this, a key leaked in an earlier commit got through on a first push.
- The git hook works with Yarn Plug'n'Play and without Node, and says clearly what to install when the CLI is missing. `fortis init` upgrades a hook from an earlier version and keeps your own lines in it.
- When the dependency check can't finish, its open findings stay open instead of being marked fixed. A full scan that finds no files fails instead of passing.
- `fortis rules | head` and similar pipes no longer crash the CLI.

**0.1.0-beta.7**
- The dependency check reads `pnpm-lock.yaml` (v5, v6 and v9, workspaces included) and `yarn.lock` (Yarn 1 and Yarn 2+), as well as `package-lock.json`. Dev-only packages are still skipped by default.
- Dependency findings point at the lockfile and line where the package appears.
- A scan where the dependency check could not run says "Nothing found · the dependency check did not run" instead of "All checks passed", and an unreachable OSV is reported as "could not reach api.osv.dev".

**0.1.0-beta.6**
- Paystack, Flutterwave and Monnify secret keys are caught on the free plan. Before this they were only reported on paid plans.
- `fortis scan --json` masks secrets in flagged lines, like every other output.
- A full scan with no lockfile says the dependency check was skipped instead of reporting a clean result.

**0.1.0-beta.5**
- Published from a stale build, so it reports itself as `0.1.0-beta.4`. Upgrade to beta.6 or later.
