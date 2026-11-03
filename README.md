# ShipLock

ShipLock reads a startup's GitHub repository and reports security problems it can back with evidence: a quoted line of code, a live configuration fact, or a reproduction on a disposable database copy. A finding that is only a code pattern is shown as "To review", never as an exposure. It never calls an AI model itself. The AI part is the customer's own coding agent (Claude Code or Codex), which connects over MCP, proposes concrete attacks, and has every cited line re-read by ShipLock before anything is admitted.

Live at [shiplock.dev](https://shiplock.dev). Free; billing is switched off.

**Status, plainly:** no outside users. The only account that has run the full loop is the maintainer's. The precision bar set for release was not met (see [Evaluation](#evaluation)).

## Who built it

Felipe Alves de Medeiros designed the product and its architecture: the evidence model, the rule that models propose while deterministic guards decide, the approval boundaries, and the evaluation protocol. Most of the code was written by Claude (Anthropic) in Claude Code under that direction. In the private development history, 841 of 863 commits carry a `Co-Authored-By: Claude` trailer. [AGENTS.md](AGENTS.md) is the working contract the agent followed and is the best single read for the design.

## How it works

The product is a loop. Each stage shows its real state; pending work is never shown as done.

| Stage | What happens | Where |
|---|---|---|
| Read | Deterministic checks on a bounded archive of the repository: secrets in source and git history, dependency advisories, server secrets reaching the client, GitHub Actions workflows, Next.js route inventory and missing authorization. Optional read-only Supabase/Postgres checks (RLS policies, grants, storage, auth config) | `lib/deep/`, `lib/graph/`, `lib/agent/` |
| Attack | The audit becomes tasks for the customer's agent. Its hypotheses are untrusted input: ShipLock re-reads every quoted line at the pinned commit and applies severity ceilings before admitting one | `lib/intelligence/reasoning.ts`, `lib/agent/attackGuard.ts` |
| Map | Which routes are wrong and what tables, providers and hot routes they reach, built from audit facts only | `lib/graph/`, `components/v3/` |
| Fix | A pull request for an allowlisted mechanical change, opened only on a customer click (or by their agent under a grant the customer turns on in the dashboard), with a receipt. ShipLock never merges or deploys | `lib/fixes/` |
| Watch | Pull request checks from a signed webhook, daily rechecks, an outside view of the live site, optional traffic metadata | `app/api/monitor/`, `lib/monitoring/`, `lib/traffic/` |

Design rules that tests enforce (`lib/security/`, `.agents/guardrails.json`):

- No model SDK, host or key in product code (`lib/security/modelFunding.test.ts`). Model calls exist only in the developer eval harness (`scripts/corpusModel.ts`).
- Only confirmed evidence sets the status to Exposed or At risk; a model failure or skipped read is shown as not checked, never as clean.
- Every pull request write needs a receipt from a click or the dashboard grant (`lib/security/prWrites.test.ts`).
- Proofs run only against a disposable replica with synthetic data (`lib/proving/`); production is never attacked.
- The status never says "secure" (`lib/verdict.test.ts`).

Runtime: the Next.js app authenticates, checks ownership and enqueues. Jobs run on a leased queue with retries and fencing (`lib/jobs/`), drained by `/api/jobs/drain`, which a Supabase `pg_cron` job calls every minute in production. Postgres (Supabase) is the system of record, with row level security on every table (`supabase/migrations/`, 113 files).

## Repository map

| Path | Role |
|---|---|
| `app/(d)/` | Pages: landing, sign in, onboarding, dashboard, public `/verified/[token]` report |
| `app/api/` | Audit enqueue, GitHub callback and webhook, jobs, MCP, fixes, traffic |
| `lib/deep/` | Repository archive reads and provider checks |
| `lib/graph/` | Route inventory, call paths, permission gaps |
| `lib/agent/` | Stack inference, hypothesis guard, findings, PR checks |
| `lib/intelligence/` | Tasks for the customer's agent and quoted-proof verification |
| `lib/fixes/`, `lib/proving/`, `lib/jobs/` | Pull requests, replica proofs, the job queue |
| `mcp/` | Local stdio MCP server (`shiplock-mcp`, not published to npm) |
| `scripts/corpus.cjs`, `lib/eval/` | Evaluation harness |
| `supabase/migrations/` | Schema and RLS |

Size: about 53,500 lines of TypeScript and JavaScript, 390 test files, 113 SQL migrations.

## Use the hosted version

1. Sign in at [shiplock.dev](https://shiplock.dev/auth) with GitHub, Google or email.
2. Install the GitHub App [`shiplock-security`](https://github.com/apps/shiplock-security) on the repositories you choose. It asks for contents (read and write; writes only push a fix branch you asked for), pull requests and checks (write), and metadata (read).
3. Pick a repository and click "Run the first audit". It runs in the background and shows its work as it goes; files it could not read are listed as not checked.
4. Optional: create a token in Settings and connect your agent to the MCP endpoint `https://shiplock.dev/api/mcp/server` (streamable HTTP, bearer token). It exposes 10 tools: `list_findings`, `get_security_context`, `get_guardrails`, `get_fix`, `list_intelligence_tasks`, `get_intelligence_task`, `submit_intelligence_result`, `report_self_check`, `open_fix_pull_request`, `get_fix_pull_request`.

## Run it yourself

Requires Node 20 or later.

```bash
npm ci
cp .env.example .env.local   # then fill it in
npm run dev                  # http://localhost:3000
```

Checks (the same gate CI runs):

```bash
npm run lint
npx vitest run
npx tsc --noEmit
node scripts/test-foundation-sql.mjs   # migrations against PostgreSQL in WASM, no network
NEXT_PUBLIC_SUPABASE_URL=https://example.supabase.co NEXT_PUBLIC_SUPABASE_ANON_KEY=dummy \
  SUPABASE_SERVICE_ROLE_KEY=dummy npm run build
```

The tests and the build need no real services. Running audits does:

| Need | Variables | Notes |
|---|---|---|
| Supabase project | `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY` | Apply `supabase/migrations/` in order. Enable the GitHub, Google or email auth providers you want and set the site URL |
| App settings | `NEXT_PUBLIC_APP_URL`, `ENCRYPTION_KEY` (`openssl rand -base64 32`), `CRON_SECRET` | All required at startup (`lib/env.ts`) |
| Email | `RESEND_API_KEY`, `RESEND_FROM_EMAIL` | Required by the config schema; alert emails are switched off in code |
| GitHub App | `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_APP_SLUG`, `GITHUB_WEBHOOK_SECRET` | Setup URL `<app>/api/deep/github/callback`, webhook `<app>/api/monitor/github`, permissions as above |
| Worker | `SHIPLOCK_BASE_URL`, `CRON_SECRET` | `npm run worker:audit` drains the queue from your machine. Or keep migration 094's `pg_cron` job, which needs `pg_net` and two Vault secrets, `shiplock_drain_url` and `shiplock_cron_secret` |

Optional: Supabase OAuth, Vercel integration, proof replica and Better Auth variables are listed in `lib/env.ts`, each with a comment on what happens when it is unset.

Honest limits: production was migrated one release at a time. Building a fresh project from all 113 migrations has not been tested end to end, and `test-foundation-sql.mjs` covers selected migrations on a stub schema, not Supabase itself.

## Evaluation

Protocol (fixed in [AGENTS.md](AGENTS.md#benchmarks)): repository populations, prompts and thresholds are frozen before a run, labels are blind, and a zero denominator is reported as unavailable. Results are JSON in `docs/evaluation/`.

**Precision of findings that set the status.** Release attempt 6 ran on public Next.js repositories pinned in `docs/CORPUS-8.json`. 89 of the 103 findings that set a status were labeled true: 86.4%, one-sided 95% lower bound 79.6%. The status was judged on 40 repositories and was right on 33. The bar fixed beforehand (`docs/evaluation/thresholds-release-2026-10-14.json`) was 95% observed, a lower bound of at least 88%, and a correct status on at least 90% of repositories, so the attempt **failed**. Source: `docs/evaluation/runs/attempt6-2026-10/attempt6-gate-total.json`.

The labelers were blind Claude subagents (two per finding, a third on a split), not people. That is the largest caveat on these numbers.

**Recall on planted bugs.** Known vulnerabilities were planted into pinned public repositories, frozen before the run, and the customer agent (Claude Code subagents on the maintainer's subscription) ran blind:

| Run | Planted | Caught | Recall | Lower 95% | File |
|---|---:|---:|---:|---:|---|
| R1, run 1 | 12 | 8 | 66.7% | 39.1% | `recall-r1-run1-2026-10-08.json` |
| R1, run 2 | 12 | 8 | 66.7% | 39.1% | `recall-r1-run2-2026-10-08.json` |
| R1, run 3 | 12 | 7 | 58.3% | 31.5% | `recall-r1-run3-2026-10-08.json` |
| R1c | 14 | 13 | 92.9% | 70.3% | `recall-r1c-run1-2026-10-09.json` |

Samples are small and the intervals are wide.

**What is not here.** Per-repository labels, agent answers and code extracts from third-party repositories are withheld, because they describe issues in other people's projects that were never reported upstream. Project names in comments and tests are replaced by `corpus-a` to `corpus-f`. Repository manifests (`docs/CORPUS*.json`), planted-bug definitions, thresholds and aggregate results are published.

**Running the harness.** `npm run corpus:acquire` downloads the 7 pinned archives of `docs/CORPUS.json` (checked by SHA-256); `npm run corpus:evaluate` then runs the deterministic pipeline offline and writes artifacts under `docs/evaluation/runs/`. With the labels withheld it reports inventories and candidates, not precision. Other manifests are selected with `SHIPLOCK_CORPUS=docs/CORPUS-8.json`.

## License

MIT, see [LICENSE](LICENSE). `lib/traffic/crs/` includes OWASP Core Rule Set material under its own license, and `.agents/skills/ui-ux-pro-max/` keeps its own license.
