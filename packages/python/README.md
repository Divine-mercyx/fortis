# fortis-watchdog

Fintech security checks on every push, from [Fortis](https://fortis.dev). This package is the Fortis CLI as a standalone binary, so it needs no Node.js.

```bash
pip install fortis-watchdog      # or: pipx install fortis-watchdog, uv tool install fortis-watchdog
fortis init --key fts_…          # from the Fortis dashboard → Projects → New CLI key
git push                         # the pre-push hook checks what you're pushing
```

Install it in your project's `.venv` or `venv`, or globally. The hook finds it either way, even when the virtual environment isn't active.

## What it checks in Python

- **Fintech rules for Django, Django REST, Flask and FastAPI:** money records read without an ownership check, webhooks without a signature check, balance updates without a row lock, BVN or NIN in logs, weak or leaked OTPs, and transfers without an idempotency key.
- **Secrets:** Paystack, Flutterwave and Monnify keys, cloud keys, passwords in connection URLs, and real-looking defaults such as `os.getenv("API_KEY", "…")`.
- **Dependencies:** known vulnerabilities in `uv.lock`, `poetry.lock`, `pdm.lock`, `pylock.toml`, `Pipfile.lock` and pinned requirements files. Dev packages are left out wherever they can be told apart.

Silence a reviewed line with `# fortis-ignore`, or the line after a `# fortis-ignore-next-line` comment.

Binaries exist for Linux (x64 and arm64, glibc only), macOS (arm64 and x64) and Windows (x64). On Alpine or other musl systems, use the Docker image.

Full documentation: [fortis.dev](https://fortis.dev), and the [CLI README](https://github.com/Divine-mercyx/fortis/tree/main/packages/cli).
