# CodeTitan GitHub Action

Diff-aware security scanning for JavaScript and TypeScript pull requests, running entirely in your CI — no account or API key required.

What it does:
- Scans only the files changed in your PR (diff-aware, not full-repo)
- Posts an inline PR comment with severity, file, line, and explanation
- Emits JSON and markdown reports as artifacts
- Optionally uploads SARIF to GitHub Code Scanning
- Enforces a severity gate in CI

## Public Proof

Live PR with CodeTitan comment:
- PR: `https://github.com/Noa-Lia/codetitan-sarif-demo/pull/1`
- Run: `https://github.com/Noa-Lia/codetitan-sarif-demo/actions/runs/24601119155`
- Live code scanning alert: `https://github.com/Noa-Lia/codetitan-sarif-demo/security/code-scanning/2`

## Example Workflow

```yaml
name: CodeTitan Security Scan

on:
  pull_request:
  workflow_dispatch:

jobs:
  codetitan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: write

    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0

      - uses: Noa-Lia/codetitan-action@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on-severity: HIGH
          format: both
```

No `npm install` or build step needed. The engine bootstraps itself.

## Inputs

- `github-token`: GitHub token for PR comments (pass `secrets.GITHUB_TOKEN`)
- `path`: repo path to analyze (default: `.`)
- `level`: analysis level 1–8 (default: `4`)
- `fail-on-severity`: `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` (default: `HIGH`)
- `format`: `json`, `sarif`, or `both` (default: `json`)
- `changed-only`: scan only PR-changed files (auto-enabled on `pull_request` events)
- `risk-threshold`: fail if PR risk score meets or exceeds this value (default: `80`)
- `config-path`: optional project config path
- `runtime-root`: optional persistent runtime directory for cache-across-runs

## Outputs

- `passed` — whether the quality gate passed
- `findings` — total findings count
- `risk-score` — repo-specific PR risk score
- `runtime-mode` — which runtime path was used
- `runtime-cache-hit` — whether runtime was restored from cache
- `runtime-bootstrap-ms` — bootstrap time in ms
- `analysis-ms` — analysis time in ms
- `total-ms` — total action time in ms
- `report-path` — path to the JSON report artifact
- `summary-path` — path to the markdown summary artifact
- `sarif-path` — path to the SARIF report (when `format: sarif` or `both`)
- `top-findings-summary` — short markdown bullet list of top findings
- `failure-kind` — `none`, `quality_gate`, `risk_gate`, or `action_error`

## Optional: Runtime Cache

Cache the packed runtime to shave ~10s off repeated runs:

```yaml
- uses: actions/cache@v5
  with:
    path: .codetitan-action-runtime
    key: ${{ runner.os }}-codetitan-${{ hashFiles('package.json') }}

- uses: Noa-Lia/codetitan-action@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    runtime-root: .codetitan-action-runtime
```

## License

MIT
