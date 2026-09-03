# ShipLock

ShipLock reads a GitHub repository, reports how an attacker could reach user
data, and opens the fix as a pull request. One connection: the GitHub App.
Everything else is inferred from the code.

## How it works

1. **Ingest** — the whole repository as one tarball (`lib/deep/repoArchive.ts`).
2. **Recon** — stack from the manifest and real imports, tables and columns from
   the schema, and a route inventory that records whether each route resolves a
   user identity, a machine gate, or nothing (`lib/graph/routeInventory.ts`).
3. **Hypothesis** — a model proposes attack paths (`lib/agent/attack.ts`); a
   deterministic guard refuses anything citing a route, file or table we did not
   observe (`attackGuard.ts`).
4. **Report** — findings with a claims ledger, plus a Coverage page built from
   what actually happened in the run. Absent is never presented as clean.
5. **Fix** — a pull request on its own branch, never merged by us.

We never attack the customer's application. Anything reproducible is reproduced
on a disposable replica (`lib/proving/`). We never read customer users' data.

## Development

```bash
npm run dev      # local dev server
npm run build    # must pass before commit
npm run lint     # must pass before commit
npm test         # vitest — 1807 tests as of 2026-09-02
```

## Docs

- `CLAUDE.md` — what the code does. Canonical.
- `docs/STATE.md` — current work, withdrawn findings, standing list. Read first.
- `MVP-SPEC.md` — MVP shape and the verified gap list.
- `PRODUCT-DESIGN.md` — rationale of record, not status.
