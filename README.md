# CodeTitan GitHub Action

Public GitHub Action distribution for the current CodeTitan wedge.

What it does today:
- verifies JavaScript and TypeScript repos in GitHub Actions
- emits JSON and markdown reports
- optionally emits SARIF for GitHub code scanning
- enforces a severity gate in CI

What it does not do today:
- publish a public CLI package
- expose the private `codetitan.dev` monorepo
- run automatic fixes inside the action

## Public Proof

- Demo repo: `https://github.com/Noa-Lia/codetitan-sarif-demo`
- Successful run: `https://github.com/Noa-Lia/codetitan-sarif-demo/actions/runs/23706295083`
- Live alert: `https://github.com/Noa-Lia/codetitan-sarif-demo/security/code-scanning/1`

## Example Workflow

```yaml
name: CodeTitan Verification

on:
  pull_request:
  workflow_dispatch:

jobs:
  codetitan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write

    steps:
      - uses: actions/checkout@v4

      - uses: actions/cache@v4
        with:
          path: .codetitan-action-runtime
          key: ${{ runner.os }}-codetitan-action-${{ hashFiles('package-lock.json', 'package.json') }}

      - uses: Noa-Lia/codetitan-action@main
        id: codetitan
        with:
          path: .
          fail-on-severity: HIGH
          format: both
          runtime-root: .codetitan-action-runtime
          comment-on-pr: false

      - if: steps.codetitan.outputs.sarif-path != ''
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: ${{ steps.codetitan.outputs.sarif-path }}
```

## Inputs

- `path`: repo path to analyze
- `level`: analysis level, default `4`
- `fail-on-severity`: `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`
- `format`: `json`, `sarif`, or `both`
- `config-path`: optional project config path
- `runtime-root`: optional persistent runtime directory
- `comment-on-pr`: set `false` to suppress PR comments

## Outputs

- `passed`
- `findings`
- `runtime-mode`
- `runtime-cache-hit`
- `runtime-bootstrap-ms`
- `analysis-ms`
- `total-ms`
- `report-path`
- `summary-path`
- `sarif-path`
- `top-findings-summary`

## Scope

This public action is the current CodeTitan distribution surface for:
- GitHub-hosted JavaScript and TypeScript repos
- PR verification and CI verification
- MVP-scope surfaced findings

It is not the full private product surface.
