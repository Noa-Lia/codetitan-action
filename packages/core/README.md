# CodeTitan Core

`@noalia/codetitan-core` is the shared verification engine behind the public CodeTitan CLI and GitHub Action.

Current supported wedge:

- JS/TS-focused verification
- MVP-scope surfaced findings
- deterministic fixer primitives used by the CLI
- SARIF and report generation primitives used by CI integrations

This package is meant to be consumed by CodeTitan surfaces first. The public API is stable at the package root; deep `lib/` imports should be treated as implementation-coupled.

## Install

```bash
npm install @noalia/codetitan-core
```

## Basic Usage

```js
const { analyze } = require('@noalia/codetitan-core');

async function main() {
  const report = await analyze(process.cwd(), {
    level: 4,
    outputFormat: 'json',
  });

  console.log(report.summary);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
```

## Exports

The package root exports the main orchestration layer plus the supported helper classes:

- `CodeTitanOrchestration`
- `HierarchicalOrchestrator`
- `ResultSynthesisEngine`
- `AIProviderManager`
- `analyzeDomain`
- `analyze`

## Scope Notes

- The public product contract is still narrower than the full source tree.
- This package intentionally ships only runtime files needed by supported CodeTitan surfaces.
- Repository-internal tests, caches, and benchmark artifacts are excluded from the published tarball.
