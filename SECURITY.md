# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/Divine-mercyx/fortis/security/advisories/new). Don't open a public issue or pull request.

Tell us:

- which part is affected (CLI, API, dashboard, install scripts or GitHub Action) and its version;
- how to reproduce it;
- what an attacker could do with it.

Don't include live keys or real customer data. Please give us time to release a fix before you share the details publicly.

A rule that misses a problem or flags safe code in your project is not a vulnerability in Fortis. Please open a normal [issue](https://github.com/Divine-mercyx/fortis/issues/new/choose) for it.

## Response times

- We acknowledge a report within **3 business days**.
- We give a first assessment within **7 business days**.

## Supported versions

| Component | Supported |
|---|---|
| CLI (`fortis-watchdog` on npm and PyPI, GitHub Release binaries, Docker image, GitHub Action) | The latest published release. Fixes ship in a new release, so please upgrade. |
| Hosted API and dashboard | The version currently deployed. |
