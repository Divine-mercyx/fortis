# fortis-watchdog

Fintech security checks on every push, from [Fortis](https://fortis.dev).

```bash
npm i -D fortis-watchdog
npx fortis init --key fts_…   # from the Fortis dashboard → Projects → New CLI key
git push                       # the pre-push hook checks what you're pushing
```

## What it checks

| Pack | Rules | Plan |
|---|---|---|
| Secrets | Private keys, AWS, GitHub, Slack, Google and Fortis keys; random-looking hard-coded secrets | Free |
| Dependencies | Known vulnerabilities in `package-lock.json`, from [OSV](https://osv.dev) | Free |
| Fintech | Paystack / Flutterwave / Monnify secret keys; money records read without an ownership check; webhooks without a signature check; balance updates outside a transaction; BVN/NIN in logs; weak or leaked OTPs; transfers without an idempotency key | Core and above |

Run `npx fortis rules` for the list and `npx fortis explain FX-OWN-001` for why a rule matters and how to fix it.

## Commands

| Command | What it does |
|---|---|
| `fortis init [--key fts_…] [--no-hook]` | Writes `.fortis.json`, installs the pre-push hook, adds an npm `security:scan` script |
| `fortis scan --pre-push` | Checks only the files in the commits being pushed (the hook runs this) |
| `fortis scan --ci` | Full scan for CI; findings it no longer sees are closed as fixed in the dashboard |
| `fortis scan --fail-on high` | Block at high or above (default: critical) |
| `fortis scan --json` / `--no-upload` / `--offline` | Machine output, keep results local, or skip the network |
| `fortis login <key>` / `fortis logout` | Save or remove the key for this machine |
| `fortis whoami` | Project, workspace and plan for the key |

Exit codes: `0` passed, `1` findings at or above the threshold, `2` usage or configuration error.

## In CI

```yaml
- run: npx fortis scan --ci
  env:
    FORTIS_KEY: ${{ secrets.FORTIS_KEY }}
```

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

Or exclude paths in `.fortis.json`: `{ "ignore": ["fixtures/**"] }`.

The git hook can be skipped once with `git push --no-verify`.

## Configuration

`.fortis.json` (committed; never contains the key):

```json
{ "projectId": "…", "failOn": "critical", "ignore": ["fixtures/**"], "apiUrl": "https://api.fortis.dev" }
```

Keys are read from `FORTIS_KEY`, then from `~/.config/fortis/credentials.json` (written by `fortis login`, mode 0600).
