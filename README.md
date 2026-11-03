# Fortis

Continuous security testing for African fintech: a CLI that checks code before every push,
an API that keeps the evidence, and a dashboard for security and compliance teams.

The marketing site lives in a separate repo (`fortis-website`).

## Repository layout

```
apps/api         Backend API (Fastify, PostgreSQL, Drizzle)
apps/web         Dashboard (Next.js), styled like fortis.dev
packages/cli     The CLI (npm: fortis-watchdog, command: fortis)
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
| Organisation | `GET/PATCH /v1/orgs/:orgId`, members: `GET/POST /v1/orgs/:orgId/members`, `DELETE …/members/:userId` |
| Projects | `GET/POST /v1/orgs/:orgId/projects`, `GET/DELETE …/projects/:projectId` |
| CLI keys | `GET/POST …/projects/:projectId/tokens`, `DELETE …/tokens/:tokenId` |
| Findings | `GET /v1/orgs/:orgId/findings`, `GET/PATCH …/findings/:findingId`, `GET …/scans`, `GET …/overview`, `GET …/audit` |
| CLI | `GET /v1/cli/whoami`, `GET /v1/cli/rules` (signed), `GET /v1/cli/rules/public-key`, `POST /v1/cli/scans` |

The CLI authenticates with `Authorization: Bearer fts_…`. The dashboard uses an httpOnly session cookie.

## Security model

- **Tenant isolation:** every org route checks membership first and answers 404 to non-members.
- **Roles:** owner > admin > developer > viewer. Admins manage projects, keys and members; developers change finding status; viewers read.
- **Keys and sessions** are random secrets stored only as SHA-256 hashes. A CLI key is shown once.
- **Passwords** use argon2id. Login errors don't reveal whether an email exists.
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

## Dashboard

Next.js App Router with no UI framework: the design tokens, fonts, buttons and motion are ported from
the marketing site into `apps/web/src/app/globals.css`.

| Page | What it shows |
|---|---|
| `/login`, `/signup` | Sign in, or create a workspace (free plan, owner role) |
| `/overview` | Open criticals, 30-day detected vs fixed, severity breakdown, fix speed, recent scans, activity |
| `/findings` | Filter and search, then a drawer with the rule explanation, fix, evidence trail and status actions |
| `/projects`, `/projects/:id` | Projects, CLI setup steps, keys (shown once, revocable), scans |
| `/settings` | Workspace name, plan and usage, team and roles, audit log |

The CLI package name shown in the dashboard is set in `apps/web/src/lib/cli.ts`.

## Deploying the API

1. Create the database and set `DATABASE_URL` (and `DATABASE_SSL=true` for DigitalOcean managed Postgres).
2. Generate a rule-signing key with `pnpm --filter @fortis/api keys:rules` and store the private key as `RULES_SIGNING_PRIVATE_KEY`.
3. Set `WEB_ORIGINS` and `WEB_URL` to the dashboard address, and `NODE_ENV=production`.
4. Run `pnpm db:migrate`, then `pnpm --filter @fortis/api start`.

### Keeping free Render services awake

Render's free plan puts a service to sleep after 15 minutes without traffic, and the first request after that waits 30–60 seconds. Both services ping each other's health URLs every 10 minutes during a daily window. This switches on automatically on Render, because Render sets `RENDER`. The dashboard's `/api/health` passes through to the API's `/health`, which also queries the database, so the pings keep Supabase active too.

| Variable | Default | |
|---|---|---|
| `KEEPALIVE` | on when on Render | `off` disables it |
| `KEEPALIVE_HOURS` | `8-20` | daily window, 24-hour clock; `0-24` = always |
| `KEEPALIVE_TZ` | `Africa/Lagos` | |
| `KEEPALIVE_URLS` | this service + the other one | comma-separated override |

**The free-hours budget.** Render gives 750 free instance hours a month per workspace, shared by all services. Two services awake 24/7 need about 1,490, so both would be suspended mid-month. The default 12-hour window keeps two services at 744 hours. For always-on, upgrade just the API to a paid instance and set `KEEPALIVE_HOURS=0-24` on it.

Once both services have slept overnight, nothing inside them is running to wake them up. `.github/workflows/wake-render.yml` makes one request each morning to start them. Set the repository variables `FORTIS_WEB_URL` and `FORTIS_API_URL` if your URLs differ from the defaults.
