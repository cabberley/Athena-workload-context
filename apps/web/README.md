# Athena Context Studio

This prototype provides a synthetic, accessible web shell for reviewing Athena workload context manifests.

Key features:

- Authenticated shell stub and environment metadata
- Workload catalogue for contextual review
- Production / Development / Training comparison view
- Structured manifest editor instead of raw JSON-only editing
- Draft, validation, approval, and published status badges
- Relationship and provenance panels showing declared, observed, inferred, and exception data
- A typed client port designed to support future WC-007 integration without hardcoded production backends

## Local run

```bash
cd apps/web
npm install
npm run dev
```

## Validation

```bash
npm run test
npm run build
npm run lint
npm run typecheck
```

Synthetic fixture data is intentionally fake and intended for prototype review only.
