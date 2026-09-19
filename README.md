# ShipLock

ShipLock is a founder-first security operating system. It starts with one GitHub
App connection, infers the stack from the selected repository, reports how an
attacker could reach user data, and opens a reviewable fix pull request. Optional
provider connections add live configuration evidence; they are not required for
an honest first result.

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
5. **Fix** — a pull request on its own branch, never approved or merged by us.

Customer traffic never passes through ShipLock. Authorized attack proofs run
only on a disposable replica or an explicitly approved test environment, with
synthetic data (`lib/proving/`). We never read customer users' data.

## Development

```bash
npm run dev      # local dev server
npm run build    # must pass before commit
npm run lint     # must pass before commit
npm test         # vitest
```

## Docs

- `AGENTS.md` — binding product, architecture, safety and workflow contract.
- `CLAUDE.md` — what the code does. Canonical.
- `docs/MASTER-PLAN-PROGRESS.md` — current execution status.
- `docs/STATE.md` — current work, withdrawn findings, standing list. Read first.
- `MVP-SPEC.md` — MVP shape and the verified gap list.
