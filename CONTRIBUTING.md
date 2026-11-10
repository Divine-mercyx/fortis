# Contributing to Fortis

Open an issue before starting anything large. To report a vulnerability, follow [SECURITY.md](SECURITY.md) instead of opening an issue.

`packages/cli`, `packages/shared` and `packages/python` are MIT licensed. `apps/api` and `apps/web` are not open source, so please talk to us in an issue before working on them. See [LICENSE](LICENSE).

## Setup

You need Node 22+, pnpm 10 and PostgreSQL 16.

```bash
pnpm install
```

To run the API and dashboard locally:

```bash
cp apps/api/.env.example apps/api/.env   # then set DATABASE_URL
pnpm db:migrate
pnpm dev:api                             # http://localhost:4000
pnpm dev:web                             # http://localhost:3000
```

## Running the checks

```bash
pnpm typecheck
pnpm test
```

The API tests need Postgres. They drop and recreate the schema of the database in `TEST_DATABASE_URL` (default `postgres://postgres:postgres@localhost:5432/fortis_test`), so never point it at a real database. This starts a matching database in Docker:

```bash
docker run -d --name fortis-test-db -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=fortis_test -p 5432:5432 postgres:16
```

The CLI tests don't need Postgres:

```bash
pnpm --filter fortis-watchdog test
```

## Pull requests

Branch from the deploy branch, `claude/pensive-hawking-w00waj`, and open your pull request against it. Render deploys this branch, so don't push to it directly. CI must pass before merging.

## Adding or fixing a rule

Write the benchmark cases first.

1. Add files to `packages/cli/bench/cases/<RULE-ID>/`. The folder name must be the rule's ID. Mark each line the rule must flag with `@hit`, and include safe code that looks similar: a flag on any unmarked line counts as a false positive.
2. Never commit a real or real-looking key. Use a `{{PLACEHOLDER}}` from `FAKES` in `packages/cli/bench/run.ts`, which builds key-shaped values at run time.
3. Write the rule in `packages/cli/src/rules/`, then register it. JavaScript and TypeScript rules go in `fintech.ts` and its `FINTECH_RULES` list, Python rules in `fintech-python.ts` and `PYTHON_FINTECH_RULES`, and secret rules in `secrets.ts` and `FILE_RULES` in `index.ts`.
4. For a new rule, add its title, severity, summary and fix to `RULE_CATALOG` in `packages/shared/src/rules.ts`.
5. Run the benchmark. It prints precision and recall per rule, with Python scored separately.

   ```bash
   pnpm --filter fortis-watchdog bench
   ```

6. For a new rule, record its floor, then check that the diff to `bench/thresholds.json` changes only your rule. The test suite fails if a rule has no floor or drops below it.

   ```bash
   pnpm --filter fortis-watchdog bench --update
   ```

7. Add a line to the changelog in `packages/cli/README.md`.

When a rule is wrong on real code, add that code to the benchmark first, then fix the rule.

## Releasing the CLI

For maintainers. The full details are under "Releasing (maintainers)" in [packages/cli/README.md](packages/cli/README.md).

1. Set `version` in `packages/cli/package.json`.
2. In the changelog in `packages/cli/README.md`, change that version's heading from "(unreleased)" to the release date. This section becomes the release notes.
3. Merge those changes, then push a matching tag from the deploy branch:

   ```bash
   git tag cli-v<version>
   git push origin cli-v<version>
   ```

`.github/workflows/release-cli.yml` then tests every install method on Linux, macOS and Windows. Nothing is published unless all of them pass. It then publishes the GitHub Release, the Docker image, and the npm and PyPI packages.
