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

## Quickstart & Common Pitfalls

The most common first-run failure looks like this:

```
Error: Unable to enumerate changed files. fatal: Invalid symmetric difference expression <base>...HEAD
```

Two things cause it. Both are fixable with two lines of YAML.

### Minimum-viable PR-comment workflow (copy this)

```yaml
name: CodeTitan
on:
  pull_request:
  workflow_dispatch:
permissions:
  contents: read
  pull-requests: write
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: Noa-Lia/codetitan-action@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on-severity: none
```

### Why `fetch-depth: 0` is required

The action computes a PR diff to decide what to analyze; without full history the base commit isn't in the clone, so the symmetric-difference expression `<base>...HEAD` cannot be resolved.

`actions/checkout@v4` defaults to `fetch-depth: 1` (shallow clone). Always override it to `fetch-depth: 0`.

### Why `github-token` should always be passed explicitly

`github-token` is used to read the PR's changed-files list via the GitHub API and to post the PR comment. Without it the action falls back to a local `git diff` that often fails on shallow clones, and the PR comment is skipped. Passing `secrets.GITHUB_TOKEN` as the `github-token:` input is enough — no extra `env:` block required.

### Permissions

```yaml
permissions:
  contents: read       # required to clone
  pull-requests: write # required to post the idempotent PR comment
```

Add `security-events: write` if you also pass `format: sarif` and want GitHub Code Scanning alerts.

### Common inputs

| Input | Default | Purpose |
|---|---|---|
| `github-token` | — | GitHub token for PR comment and changed-files API (pass `secrets.GITHUB_TOKEN`) |
| `path` | `.` | Repo sub-path to analyze |
| `level` | `4` | Analysis depth 1–8 (higher = more rules, slower) |
| `fail-on-severity` | `HIGH` | Fail CI if findings at this severity or above exist (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `none`) |
| `changed-only` | _(empty)_ | Auto-activates on `pull_request` events; pass `'false'` to force full-tree scan |
| `risk-threshold` | `80` | Fail CI if the PR risk score (0–100) meets or exceeds this value |

### `changed-only` behavior

When the action runs on a `pull_request` event and `changed-only` is not set (or is empty), it automatically scopes analysis to PR-changed files only. To force a full-tree scan regardless of event type, pass `changed-only: 'false'`.

### Workflow variants

**Full-tree scan** — pass `changed-only: 'false'` to scan the entire repository rather than just the PR diff. Useful on `push` to `main` or `workflow_dispatch` triggers.

**Block merges on CRITICAL only** — pass `fail-on-severity: critical` to let LOW/MEDIUM/HIGH findings through without failing CI, while still blocking on critical issues.

**Manual trigger only** — add `workflow_dispatch:` to `on:` (already in the template above) and omit `pull_request:` if you want on-demand scans without automatic PR gating.

## CLI install (optional)

The engine is also distributed as a standalone CLI for local runs outside CI. The package name is `@noalia/codetitan` — **not** `@noalia/codetitan-cli` — and the binary is `codetitan`.

```bash
npm install -g @noalia/codetitan
codetitan --version
codetitan analyze . --no-ai
```

Common commands:

| Command | Purpose |
|---|---|
| `codetitan analyze <path>` | Analyze a directory (defaults to `.`) |
| `codetitan analyze . --changed-only` | Diff-aware scope (PR mode) |
| `codetitan fix <path> --dry-run` | Preview fixes without applying them |
| `codetitan review` | Summarize the current branch |

See `codetitan --help` for the full command list.

`@noalia/codetitan-core` is an internal engine library consumed by both the CLI and the GitHub Action — you do not need to install it directly.

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
