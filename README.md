# Fortis

Continuous security testing for African fintech: a CLI that checks code before every push,
an API that keeps the evidence, and a dashboard for security and compliance teams.

The marketing site lives in a separate repo (`fortis-website`).

## Repository layout

```
apps/api         Backend API (Fastify, PostgreSQL, Drizzle)
apps/web         Dashboard (Next.js), styled like fortis.dev
packages/cli     The CLI (npm: fortis-watchdog, command: fortis)
packages/vscode  The VS Code extension, also for Cursor and VSCodium
packages/shared  Plans, rule catalogue, masking and request schemas shared by every app
```

## Getting started

Requirements: Node 22+, pnpm 10, PostgreSQL 16.

```bash
pnpm install
cp apps/api/.env.example apps/api/.env   # then set DATABASE_URL
pnpm db:migrate
pnpm dev:api                             # http://localhost:4000
pnpm dev:web                             # http://localhost:3000 (proxies /api to the API)
```

The dashboard calls the API through its own `/api` path (`apps/web/src/app/api/[...path]/route.ts`), so the
session cookie stays first-party. `API_URL` is read at run time, so changing it only needs a restart.

Run the checks:

```bash
pnpm typecheck
pnpm test        # needs a Postgres database; see TEST_DATABASE_URL below
```

Tests drop and recreate the schema of the database in `TEST_DATABASE_URL`
(default `postgres://postgres:postgres@localhost:5432/fortis_test`). Never point it at a real database.

## API overview

| Area | Endpoints |
|---|---|
| Accounts | `POST /v1/auth/signup`, `POST /v1/auth/login`, `POST /v1/auth/logout`, `GET /v1/auth/me` |
| Alerts | `GET/PUT /v1/orgs/:orgId/alerts`, `POST …/alerts/test` |
| Billing | `GET /v1/orgs/:orgId/billing`, `POST …/billing/change`, `POST …/billing/verify`, `POST /v1/billing/paystack/webhook` |
| Single sign-on | `GET/PUT/DELETE /v1/orgs/:orgId/sso`, `POST …/sso/verify`, `POST …/sso/test`, `POST /v1/auth/sso/start`, `POST /v1/auth/sso/callback` |
| Release gates | `GET/PUT /v1/orgs/:orgId/projects/:projectId/gate`, `POST …/gate/exceptions`, `DELETE …/gate/exceptions/:exceptionId` |
| Two-factor | `POST /v1/auth/login/2fa`, `GET /v1/auth/2fa`, `POST /v1/auth/2fa/setup`, `…/enable`, `…/recovery-codes`, `…/disable` |
| Organisation | `GET/PATCH /v1/orgs/:orgId`, members: `GET/POST /v1/orgs/:orgId/members`, `DELETE …/members/:userId` |
| Projects | `GET/POST /v1/orgs/:orgId/projects`, `GET/DELETE …/projects/:projectId` |
| CLI keys | `GET/POST …/projects/:projectId/tokens`, `DELETE …/tokens/:tokenId` |
| Staging targets | `GET/POST …/projects/:projectId/targets`, `POST …/targets/:targetId/verify`, `…/authorize`, `…/pause`, `…/resume`, `DELETE …/targets/:targetId` |
| Exposure checks | `GET/POST …/targets/:targetId/exposure`, `PUT …/exposure/schedule`, more host names: `GET/POST …/targets/:targetId/hosts`, `POST …/hosts/:hostId/verify`, `DELETE …/hosts/:hostId`; `POST /v1/cli/exposure` |
| Findings | `GET /v1/orgs/:orgId/findings`, `GET/PATCH …/findings/:findingId`, `GET …/scans`, `GET …/overview`, `GET …/audit` |
| CLI | `GET /v1/cli/whoami`, `GET /v1/cli/rules` (signed), `GET /v1/cli/rules/public-key`, `POST /v1/cli/scans` |

The CLI authenticates with `Authorization: Bearer fts_…`. The dashboard uses an httpOnly session cookie.

## Security model

- **Tenant isolation:** every org route checks membership first and answers 404 to non-members.
- **Roles:** owner > admin > developer > viewer. Admins manage projects, keys and members; developers change finding status; viewers read.
- **Keys and sessions** are random secrets stored only as SHA-256 hashes. A CLI key is shown once.
- **Passwords** use argon2id. Login errors don't reveal whether an email exists.
- **Alerts:** when a scan (CLI upload, staging test or exposure check) finds new or reopened critical or high findings, Fortis sends one email and one Slack message for the scan, never one per finding, and never twice for a finding that stays open. Alerts carry the masked line, never a secret. Slack accepts only `https://hooks.slack.com/` webhook URLs, stored encrypted and shown masked. Owners and admins choose the severity, who gets email and the Slack channel in Settings, and changes are audited.
- **Billing:** an owner pays for Core or Plus in naira on Paystack's page (card, bank transfer, USSD or bank); Enterprise is a conversation. Prices exclude VAT, which is added at checkout (`BILLING_VAT_PERCENT`, 7.5% by default). A plan changes only when Paystack confirms a payment Fortis started, for the exact amount in naira: by webhook (HMAC-SHA512 signature checked against the raw body, each event handled once) or when the owner comes back from checkout. Upgrades start at once with credit for the unused days; a cheaper plan or Free starts at renewal and can be undone until then. Saved cards are charged monthly; Fortis keeps only Paystack's authorization code, encrypted like authenticator secrets, and shows the brand and last four digits. If a renewal fails the plan stays on for `BILLING_GRACE_DAYS` (7) while the card is retried daily, then the workspace moves to Free with every finding and scan kept. Workspaces that paid by transfer get a reminder three days before renewal. Owners get a receipt for every payment, and every payment, plan change and step down is in the audit log.
- **Single sign-on (Plus and Enterprise):** OpenID Connect with Google Workspace, Microsoft Entra ID (one tenant; `common` and `organizations` are refused), Okta or any OIDC provider. An owner proves the email domain with a DNS TXT record (one workspace per domain), adds the provider's client ID and secret (sealed like authenticator secrets), and must complete a test sign-in before SSO can be required. Sign-in uses the authorization code flow with PKCE, a nonce, and a state tied to the browser by an httpOnly cookie; ID tokens are verified with the provider's published keys (issuer, audience, expiry, nonce), and only a verified email on the workspace's domain gets in (Google also checks the Workspace domain). Every request to a provider goes to public https addresses only. New people join with the default role (viewer or developer) within the plan's seats. When SSO is required, password sign-in and sign-up for the domain are refused and existing password sessions end. SSO sessions last `SSO_SESSION_HOURS` (12), so someone removed in the identity provider is out within that time; removing someone in Fortis ends their SSO sessions at once. To keep someone out for good, remove them in the identity provider, otherwise they rejoin on their next sign-in. Setup, changes, tests and every SSO sign-in go in the audit log.
- **Release gates (Plus and Enterprise):** an admin sets a project's gate on its page: the severity that blocks (critical, high or medium), whether a leaked key that still works always blocks, and the branches it covers. When `fortis scan --ci` uploads, the API judges the scan against the policy and the CLI exits with that verdict, so changing the policy changes what passes CI without touching the repository. Only open findings block; accepted risks and false positives don't. An admin can approve a release through the gate for 1 to 72 hours, for one commit or any, with a written reason; approvals can be withdrawn, and every verdict, approval and withdrawal goes in the audit log and the evidence pack.
- **Two-factor sign-in:** any user can turn on an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, Authy) in Settings. The password then only earns a five-minute challenge with five tries; the session cookie comes after a six-digit code (RFC 6238) or one of ten single-use recovery codes. Each code works once. Secrets are encrypted with AES-256-GCM (`TWO_FACTOR_KEY`), recovery codes are stored as hashes, and turning it off needs the password and a code. Admins see who has it on in the Team list, and turning it on or off, or using a recovery code, goes in the audit log.
- **CSRF:** cookie-authenticated writes must come from an allowed origin, and only JSON bodies are accepted.
- **No source code:** findings carry a masked line of at most 300 characters. The API masks secrets and BVN/NIN again on arrival.
- **Rule packs** are signed with Ed25519 (`RULES_SIGNING_PRIVATE_KEY`); the CLI verifies them with the published public key.
- **Evidence trail:** every detection, fix, reopen and status change is a `finding_events` row; admin actions go to `audit_log`.

## Plans

Plans and limits live in `packages/shared/src/plans.ts`. Free keeps results on the developer's machine;
Core and above upload findings to the dashboard. Until billing is built, set a plan with:

```bash
pnpm --filter @fortis/api exec tsx scripts/set-plan.ts <org-slug> core
```

## CLI

See `packages/cli/README.md`. Build it with `pnpm --filter fortis-watchdog build` (one bundled file in
`dist/fortis.js`); set `FORTIS_DEFAULT_API_URL` at build time to change the default API address.

`pnpm --filter fortis-watchdog build:binary` builds a standalone executable for your machine in `dist-sea/`.
Non-JavaScript teams use these, because they need no Node. The root `action.yml` installs one in GitHub Actions.

## Dashboard

Next.js App Router with no UI framework: the design tokens, fonts, buttons and motion are ported from
the marketing site into `apps/web/src/app/globals.css`.

| Page | What it shows |
|---|---|
| `/login`, `/signup` | Sign in, or create a workspace (free plan, owner role) |
| `/overview` | Open criticals, 30-day detected vs fixed, severity breakdown, fix speed, recent scans, activity |
| `/findings` | Filter and search, then a drawer with the rule explanation, fix, evidence trail and status actions |
| `/projects`, `/projects/:id` | Projects, CLI setup steps, keys (shown once, revocable), scans |
| `/settings` | Workspace name, plan and usage, paying for a plan and past payments, single sign-on, team and roles, audit log |
| `/login/sso` | Where the identity provider sends people back after single sign-on |

The CLI package name shown in the dashboard is set in `apps/web/src/lib/cli.ts`.

## Deploying the API

1. Create the database and set `DATABASE_URL` (and `DATABASE_SSL=true` for DigitalOcean managed Postgres).
2. Generate a rule-signing key with `pnpm --filter @fortis/api keys:rules` and store the private key as `RULES_SIGNING_PRIVATE_KEY`.
3. Set `WEB_ORIGINS` and `WEB_URL` to the dashboard address, and `NODE_ENV=production`.
4. For alert emails, set `RESEND_API_KEY` and `ALERTS_FROM` (a sender on a domain verified in Resend). Without them alerts still go to Slack.
5. For billing, set `PAYSTACK_SECRET_KEY` (`sk_test_…` until you go live), add the webhook URL `https://<api>/v1/billing/paystack/webhook` in Paystack (Settings → API Keys & Webhooks), and set `CRON_SECRET` on the API and the same value as the repository secret `FORTIS_CRON_SECRET` so the daily renewals job runs. Without the key, Settings says paying online isn't switched on and `scripts/set-plan.ts` still works.
6. Set `TWO_FACTOR_KEY` to a random value of at least 32 characters (`openssl rand -base64 32`). It encrypts authenticator secrets; without it a key is derived from the rule-signing key.
7. Start it with `pnpm --filter @fortis/api start`. Pending migrations run first; set `MIGRATE_ON_START=false` to run `pnpm db:migrate` yourself.

### Keeping free Render services awake

Render's free plan puts a service to sleep after 15 minutes without traffic, and the first request after that waits 30–60 seconds. Both services ping each other's health URLs every 10 minutes during a daily window. This switches on automatically on Render, because Render sets `RENDER`. The dashboard's `/api/health` passes through to the API's `/health`, which also queries the database, so the pings keep Supabase active too.

| Variable | Default | |
|---|---|---|
| `KEEPALIVE` | on when on Render | `off` disables it |
| `KEEPALIVE_HOURS` | `9-21` | daily window, 24-hour clock; `0-24` = always |
| `KEEPALIVE_TZ` | `Africa/Lagos` | |
| `KEEPALIVE_URLS` | this service + the other one | comma-separated override |

**The free-hours budget.** Render gives 750 free instance hours a month per workspace, shared by all services. Two services awake 24/7 need about 1,490, so both would be suspended mid-month. The default 12-hour window keeps two services at 744 hours. For always-on, upgrade just the API to a paid instance and set `KEEPALIVE_HOURS=0-24` on it.

Once both services have slept overnight, nothing inside them is running to wake them up. `.github/workflows/wake-render.yml` makes one request each morning to start them. Set the repository variables `FORTIS_WEB_URL` and `FORTIS_API_URL` if your URLs differ from the defaults.

## Contributing, security and licence

- To work on Fortis, see [CONTRIBUTING.md](CONTRIBUTING.md).
- For what's built, and the setup that's still left and who owns it, see [ROADMAP.md](ROADMAP.md).
- To report a vulnerability, follow [SECURITY.md](SECURITY.md). Please do not open a public issue.
- `packages/cli`, `packages/shared` and `packages/python` are MIT licensed. The rest of this repository, including `apps/api` and `apps/web`, is not open source. See [LICENSE](LICENSE).
