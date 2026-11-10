# Roadmap

This is the status of the CLI roadmap tracked in [issue #4](https://github.com/Divine-mercyx/fortis/issues/4): every common language and package manager, accurate results, and stable installs on every platform.

**Status on 2026-11-10:** all 35 items are built and merged. What remains is setup that only an owner can do: repository settings, store accounts, signing certificates and a tagged release. It is listed under [What's left, and who does it](#whats-left-and-who-does-it).

## Where the CLI stands (0.1.0-beta.12)

Merged since beta.12 and waiting for beta.13: Bun lockfiles; Mono, Dojah, Africa's Talking, Korapay and BudPay keys named; secrets read inside notebooks, PEM keys in JSON, base64 values and Kubernetes Secrets; and `fortis scan --verify`.

- **Secrets:** checked in any file. Covers payment keys (Stripe, Paystack, Flutterwave, Monnify, SeerBit, OPay, Squad), cloud, SaaS and registry tokens, and passwords in database and broker URLs.
- **Dependencies:** lockfiles for JavaScript, PHP, Python, Java, Kotlin, Scala, Go, .NET, Ruby, Rust, Dart, Swift, Elixir, Erlang, Haskell and R are checked against OSV. Findings show the fixed version and the upgrade command.
- **Supply chain:** Docker base images and GitHub Actions.
- **Fintech code rules:** JavaScript, TypeScript and Python on syntax trees. The first six checks also run in Go, C#, PHP, Java and Kotlin.
- **`fortis test` and `fortis access`:** test a running app. Access checks cover writes, GraphQL, and Postman or HAR imports. ZAP runs with or without Docker.
- **Pre-push hook:** works with npm, pnpm, Yarn, Bun, pip, uv, Poetry, a global install, or no Node, in every Windows shell.
- **Distribution:** npm, standalone binaries (Alpine too), a Docker image, a GitHub Action, and `fortis update`.
- **Integrations:** pre-commit, seven CI systems, pull-request comments, JUnit reports, and a VS Code extension.

## Every item

### Secrets

| Issue | What | Landed in |
|---|---|---|
| #5 | Database and broker URLs with embedded passwords | `55364f2` |
| #6 | Stripe keys told apart from Paystack keys | `ca28060` |
| #7 | African payment, KYC and messaging provider keys | #64 |
| #8 | Cloud, SaaS and developer tokens | `7afd63f` |
| #9 | Notebooks, multi-line keys and encoded values | #63 |
| #10 | Optional check of whether a leaked key is still live | #62 |

### Dependencies

| Issue | What | Landed in |
|---|---|---|
| #11 | Bun lockfiles | #61 |
| #12 | Swift Package Manager and CocoaPods | #60 |
| #13 | Elixir, Erlang, Haskell and R | #59 |
| #14 | Python projects that pin by range; `pdm.lock` and `pylock.toml` | #40 |
| #15 | Java, Kotlin and Scala without a hand-made SBOM | #58 |
| #16 | .NET and Go without lockfiles; Go workspaces | #57 |
| #17 | JavaScript edge cases | #56 |
| #18 | The fixed version and the exact upgrade command | `90d6029` |
| #19 | Severity from CVSS when the advisory has no label | #40 |
| #21 | Docker base images and unpinned GitHub Actions | #55 |

### Fintech code rules

| Issue | What | Landed in |
|---|---|---|
| #22 | Syntax-aware analysis | #54 |
| #23 | Python: Django, FastAPI, Flask | #40 |
| #24 | Java and Kotlin: Spring Boot | #53 |
| #25 | PHP: Laravel | #52 |
| #26 | Go and C# | #51 |
| #27 | New checks: money as float, card data, weak references, client amounts | #50 |

### Stability and accuracy

| Issue | What | Landed in |
|---|---|---|
| #20 | Company proxies, offline and air-gapped use, caching | `5b51794` |
| #28 | Install-and-push matrix for every package manager and system | `582185a` |
| #29 | The hook and CLI in every Windows shell | `6b745f0` |
| #30 | Shallow clones, submodules, worktrees, very large repositories | `77b0426` |
| #31 | `fortis doctor` and `.fortis.json` validation | #49 |
| #32 | Real-world corpus, nightly run, false-positive feedback | #48 |

### Distribution and release

| Issue | What | Landed in |
|---|---|---|
| #33 | Smaller standalone binary | #47 |
| #34 | Homebrew, Scoop, winget, Alpine builds, signing, `fortis update` | #46 |
| #35 | Release pipeline: trusted publishing, Node 24 actions, provenance | #45 |

### Integrations, staging tests and repository

| Issue | What | Landed in |
|---|---|---|
| #36 | pre-commit, more CI systems, pull-request comments | #44 |
| #37 | VS Code extension | #43 |
| #38 | Access checks beyond GET, GraphQL and Postman, ZAP without Docker | #42 |
| #39 | Security policy, contributing guide, templates, licence | #41 |

## What's left, and who does it

The code for each of these is merged. Each one waits on an account, a setting or a purchase. The last column is what could be seen from outside on 2026-11-09.

### Release

| What | Who | State |
|---|---|---|
| Push the tag `cli-v0.1.0-beta.12`. This builds the binaries, the GitHub release, the Docker image and the attestations. The workflow sees that npm already has the version and skips that step | A maintainer who can push tags | Not done. npm has beta.12, but the newest tag and GitHub release are beta.10, so the install scripts still deliver beta.10 |
| npm: package → Settings → Trusted publishing → GitHub Actions, repository `Divine-mercyx/fortis`, workflow `release-cli.yml` | `divine-fortis`, the only npm maintainer | Not proven. The last three release runs failed, and beta.12 has no release run |
| PyPI: add a pending publisher for `fortis-watchdog`, same repository and workflow, environment `pypi` | Whoever will own the project on pypi.org | Not done. The project doesn't exist, so `pip install fortis-watchdog` fails |
| After the tag: try each install, and check Gatekeeper on macOS and SmartScreen on Windows | A maintainer | Waits on the tag |

### Package managers and signing

Each step is skipped with a notice, and doesn't fail the release, until its secret or repository exists.

| What | Who | State |
|---|---|---|
| Create public repositories `Divine-mercyx/homebrew-tap` and `Divine-mercyx/scoop-bucket`, each with a first commit | `Divine-mercyx` | Not done. `brew install` and `scoop install` fail |
| Settings → Environments: create `release`, limited to `cli-v*` tags. Add `PACKAGE_REPOS_TOKEN` (can push to both repositories above) and `WINGET_TOKEN` (classic token, `public_repo` scope) | `Divine-mercyx`, as admin | Not done. The repository has no environments |
| Join the Apple Developer Program, create a Developer ID Application certificate and an App Store Connect API key, and add the five `APPLE_*` secrets | Whoever can sign up for the company | Not visible from outside |
| Buy a Windows code-signing certificate, and add `WINDOWS_CERT_PFX_BASE64` and `WINDOWS_CERT_PASSWORD` | Whoever can buy it for the company | Not visible from outside |

Microsoft reviews the first winget pull request by hand, so `winget install` works once that is accepted.

### VS Code extension

| What | Who | State |
|---|---|---|
| Create a publisher on the VS Code Marketplace, and an account and namespace on Open VSX | Whoever owns the brand | Not done |
| Set `publisher` in `packages/vscode/package.json` to that ID | Anyone, once the ID exists | Still the placeholder `fortis` |
| Add the secrets `VSCE_PAT` and `OVSX_PAT`, then push the tag `vscode-v0.1.0` | `Divine-mercyx`, as admin | Not done. The release workflow has never run |

### Repository settings

| What | Who | State |
|---|---|---|
| Turn on private vulnerability reporting. `SECURITY.md` sends reporters there | `Divine-mercyx`, as admin | Off |
| Turn on secret scanning with push protection, and Dependabot alerts | `Divine-mercyx`, as admin | Not visible without admin access. No Dependabot pull request has been opened yet |
| Require approval before outside contributors' workflows run | `Divine-mercyx`, as admin | Not visible without admin access |
| Protect the default branch: require a pull request and the `check` job | `Divine-mercyx`, as admin | Not protected |
| Protect `cli-v*` tags | `Divine-mercyx`, as admin | Not visible without admin access |
| Rename `claude/pensive-hawking-w00waj` to `main`, and point the Render API and dashboard services at it. Then replace the old name in `CONTRIBUTING.md` and `.github/workflows/e2e.yml` | `Divine-mercyx`, as admin, then anyone | Not renamed |

### Now that #61 to #64 are merged

| What | Who |
|---|---|
| #62: run migration `0002_secret_status.sql` with `pnpm db:migrate` when the API deploys. Until then the API accepts `secretStatus` but can't store it | Whoever deploys the API |
| #64: for any provider it leaves unnamed, add a link to its key documentation, or a revoked key, to issue #7. Confirm the Africa's Talking key length the same way | A maintainer |
| To release 0.1.0-beta.13: set that version in `packages/cli/package.json` and change "(unreleased)" in the changelog to the date. All four pull requests' lines are already under that one heading | Whoever releases |

### Checks to run once

| What | Who |
|---|---|
| Run each CI template in a sample repository: GitHub Actions, GitLab, Bitbucket, Azure DevOps, Jenkins, CircleCI, Buildkite. The variables each one needs are in the CLI docs under "Other CI systems" | Whoever holds an account on that system |
| Run the `false-positive-shapes` export against production. It needs `DATABASE_URL`, so the nightly job doesn't run it | Whoever has production database access |
| Confirm the nightly accuracy run starts on its schedule (02:30 UTC) and can open an issue | `Divine-mercyx`. It has only run on pull requests so far |

## Known gaps

These are limits of what was built, not missing setup.

- **CocoaPods, Conan and vcpkg:** OSV has no advisories for them. The scan names the packages and says they weren't checked.
- **Java, Kotlin, Scala and .NET without a lockfile:** only direct dependencies are covered. Transitive ones need an SBOM or a lockfile, and the scan says so.
- **Fintech rules in Go, C#, PHP, Java and Kotlin** have the first six checks, on line patterns. The four newer checks (money as floating point, card data, predictable references, client amounts) and the syntax-tree engine cover JavaScript, TypeScript and Python only.
- **Provider keys with no documented format** have no named pattern: Infobip, Termii, Smile ID, Prembly, VerifyMe, Youverify, Anchor, Sudo, Paga, Remita, Okra and Moniepoint. The generic checks still report them in a secret-looking assignment.
- **`fortis scan --verify`** is tested against mocked providers only. No real key has been checked.
- **macOS and Windows binaries are unsigned** until the certificates above exist, so Gatekeeper and SmartScreen warn on first run.
