# ShipLock

ShipLock is a security harness for a startup without a security team. It reads the company's GitHub repository and reports only what it can back with evidence: a quoted line of code, a live configuration fact, or a reproduction on a disposable copy of the database. It never calls an AI model itself. The intelligence is the customer's own coding agent (Claude Code or Codex), which connects over MCP and proposes attacks. ShipLock re-reads every line the agent cites before it believes anything.

Live at [shiplock.dev](https://shiplock.dev), free, billing switched off. **It has no outside users.** The only account that has run the full loop is mine. The release precision bar I set was not met (see [Evaluation](#evaluation)).

**Contents:** [How I built it](#how-i-built-it) · [Decisions and why](#decisions-and-why) · [Architecture](#architecture) · [Evaluation](#evaluation) · [Reading the code](#reading-the-code) · [Running it](#running-it) · [Repository map](#repository-map)

## How I built it

I designed ShipLock end to end: the product, the architecture, the evidence model, the evaluation protocol and every gate a change had to pass. I built it with Claude Code as my implementation partner. I set direction and constraints in [AGENTS.md](AGENTS.md), Claude wrote most of the code against them, and I judged the results against tests, production observations and frozen evaluations. The commit history shows that split: most commits carry a `Co-Authored-By: Claude` trailer, and their messages record what was measured and why the route changed.

If you read one file, read [AGENTS.md](AGENTS.md). It is the contract the work followed.

## Decisions and why

| Decision | Why |
|---|---|
| **Repository scanning alone is table stakes** (2026-09-29) | Some risks are invisible in code. A missing policy only matters if the live database lacks it; a weak route only matters if traffic reaches it. ShipLock joins code, live provider configuration and traffic, and a join needs a provider-issued link or the customer's confirmation, never a guess |
| **ShipLock pays for no model call** (2026-10-01) | A security product that sends customer source to its own model account carries cost, key custody and trust problems. The customer's agent does the reasoning on their own subscription. ShipLock holds no model key, and a test fails the build if a model SDK enters product code |
| **Models propose, deterministic guards decide** | Agent output is untrusted input. A hypothesis is admitted only if every quoted line matches the file at the pinned commit, and its severity is capped by what the code can show. A model timeout or malformed answer is "not checked", never "clean" |
| **Only confirmed issues set the status** (2026-10-07) | Scanners lose trust through noise. A code pattern alone is "To review"; only quoted proof, replica proof, a live fact or observed traffic can say Exposed or At risk. The status never says "secure" |
| **Unknown is not absent** | Facts are observed, inferred, unknown, corroborated or proven. "We did not find it" is never written as "we checked and it is not there", and partial evidence never retires an earlier finding |
| **Attack only sandboxes** | Proofs run on a disposable replica with synthetic data. Production is never attacked, and there are no destructive, persistence or availability tests |
| **Every write is a click** | A fix pull request needs the customer's click and leaves a receipt. Their agent can request one only after they turn that on for the repository in the dashboard. ShipLock never merges or deploys |
| **The bar is set before the run** (2026-10-14) | Commercial SAST precision is commonly reported at 18 to 36%. I set 95% observed precision, a 95% lower bound of at least 88%, and the right status on 90% of repositories, before running attempt 6. It failed, and it is reported as failed |

## Architecture

### The shape

```
  founder's browser                                founder's coding agent
         │                                          (Claude Code, Codex)
         ▼                                                   │ MCP
  Next.js on Vercel  ◀───────────────────────────────────────┘
  authenticate, check ownership, render, enqueue    ◀── GitHub webhooks
         │                         ▲
         ▼                         │ reads
  Postgres (Supabase): the system of record, row level security on every table
  execution_jobs (leased queue) · audit runs · findings · provider snapshots
         ▲                         │
  pg_cron, every minute:           ▼
  POST /api/jobs/drain      one bounded job per call
                            (audit, source, graph, monitor, pr-check, repair, proof, ...)
                                   │
          ┌────────────────────────┼─────────────────────────────┐
          ▼                        ▼                             ▼
  GitHub repository        live providers, read only       embedded replica
  (bounded archive)        Supabase, Postgres, Vercel,     (PGlite in a worker thread,
                           the live app's public surface    synthetic rows, no network)
```

The web tier never does long work inline. A request authenticates the user, checks they own the repository, and puts a job on a queue in Postgres. Workers drain that queue one bounded job at a time.

### The queue (`lib/jobs/`, `supabase/migrations/056_durable_jobs.sql`)

Every piece of background work is a row in `execution_jobs` with a kind (`audit`, `source`, `graph`, `monitor`, `dependency`, `pr-check`, `notification`, `repair`, `intelligence`, `proof`) and an idempotency key, so a retried webhook or a double click queues one job, not two.

- **Claim with a lease.** `claimJob` leases the next job for 120 seconds and returns a lease token. Long provider reads extend the lease (`withLeaseHeartbeat`).
- **Fencing.** A worker's writes go through SQL functions that check the live lease token. A worker that stalled past its lease cannot write stale results over the job's new owner.
- **Bounded retries.** A failed job is retried up to 5 times with exponential backoff capped at 300 seconds, then marked dead. A permanent error ends it at once.
- **Priority.** `runNextJob` in `lib/jobs/worker.ts` takes work a customer is waiting on first (pull request checks, clicked fixes and proofs, audits), then background refreshes.
- **Waking up.** In production a Supabase `pg_cron` job calls `POST /api/jobs/drain` every minute (migration 094); each call runs one job. A daily Vercel cron (`/api/monitor/scheduled`) admits due rechecks and prunes old data. Locally, `npm run worker:audit` drains and schedules from your machine.

### An audit, step by step (`lib/agent/audit.ts`)

1. **Read.** Download a bounded archive of the repository at one commit (`lib/deep/repoArchive.ts`). Files beyond the budget are recorded as unread, never skipped silently.
2. **Infer the stack** (`lib/agent/stack.ts`): framework, database, auth and providers, from files alone. Inference never creates a provider connection.
3. **Build route facts** (`lib/graph/routeInventory.ts`, `callPath.ts`, `serverActionFacts.ts`, `trpcProcedures.ts`): for each Next.js route handler, server action and tRPC procedure, whether it identifies the caller, scopes data to them, checks a machine signature, and which tables it touches. Each fact is either read or explicitly unreadable.
4. **Deterministic checks**: committed secrets and git history, dependency advisories, server secrets reaching the client bundle, GitHub Actions permissions, routes that write without identifying the caller.
5. **Live facts** (`lib/agent/liveFacts.ts`): if the customer connected a provider and bound it to this repository, its read-only facts join the audit.
6. **Hand reasoning to the customer's agent** (`lib/intelligence/reasoning.ts`): the ranked routes become tasks. The agent proposes attacks over MCP; `lib/agent/attackGuard.ts` admits a proposal only if every quoted line matches the file at that commit, then `lib/agent/findings.ts` caps its severity by what the code shows.
7. **Store and explain**: findings, the Coverage record of everything not read, the route map, and a progress trace written step by step so the dashboard shows work as it happens.

No step writes to the customer's repository. A fix is a separate job after a separate click.

### Cross-layer detection (`lib/graph/`)

This is the part a repository-only scanner cannot do. Read-only collectors (`lib/monitoring/collectors.ts`) take typed snapshots from four sources: a direct Postgres connection, the Supabase Management API, Vercel, and the live app's public surface. Each snapshot records its tenant, connection epoch, observation time, completeness and what it could not read, and never holds a secret or an application row.

Once a repository is bound to a database (a provider-issued link or the customer's confirmation), `lib/jobs/graphWorker.ts` builds an asset graph (`lib/graph/graph.ts`) of routes, tables, buckets and functions, and `lib/graph/attackPaths.ts` looks for paths that need more than one source to see. For example: a route the code shows is anonymous, reaching a table the live database leaves without row level security. Observed traffic (`lib/traffic/`) can raise a path's priority but never its severity. Disconnecting, rotating credentials or reselecting a repository changes the connection epoch and invalidates old joins.

### Proofs (`lib/proving/`)

When a policy looks like it leaks rows between tenants, the customer can authorize one proof with a click. `lib/proving/replica.ts` rebuilds that table and its policies in an in-process Postgres (PGlite, `embeddedHost.ts`) running in a worker thread with no network, a per-statement time limit and a memory bound. It inserts synthetic rows for two tenants and runs a control probe and a leak probe as one of them. A failed control means the run is not trusted. Policies that query other tables cannot be rebuilt faithfully and are refused with a reason. Only this path can mark a finding `proven`.

### Fixes (`lib/fixes/`)

A fix is either an allowlisted mechanical change (a migration file, a dependency bump, security headers, workflow permissions, disabling production source maps, removing secret logging, a rate limit) or a fix-request file the customer's agent can act on. The click creates a receipt and a `repair` job; the worker re-resolves the finding and the files server side, opens a branch and a pull request labeled "ShipLock", and records the outcome. A preview (`lib/fixes/preview.ts`) shows exactly what the click would write before anyone clicks. ShipLock never merges.

### Watching

- **Pull request checks**: a signed GitHub webhook (`app/api/monitor/github`) queues a check of each pull request head; a partial read is never reported as passed.
- **Rechecks**: repositories are re-audited every 48 hours, and connected providers are re-read when their last read goes stale.
- **The live site**: what the deployed app's JavaScript calls, security headers, exposed paths, and API paths the site calls that no audited route declares.
- **Traffic**: an optional customer-side snippet sends minimized request metadata, never bodies, credentials or end-user data, and ShipLock can read the Supabase gateway log with the customer's own connection.

### The agent connection (`mcp/`, `app/api/mcp/`)

The customer creates a token in Settings and points their agent at `https://shiplock.dev/api/mcp/server`. It exposes 10 tools: `list_findings`, `get_security_context`, `get_guardrails`, `get_fix`, `list_intelligence_tasks`, `get_intelligence_task`, `submit_intelligence_result`, `report_self_check`, `open_fix_pull_request`, `get_fix_pull_request`. No tool scans, writes a file or merges. `open_fix_pull_request` works only if the customer turned on agent pull requests for that repository in the dashboard, and it goes through the same queue, cap and receipt as a click. An offline agent leaves its tasks visibly pending, never clean.

### Security boundaries the tests enforce

| Rule | Enforced by |
|---|---|
| No model SDK, host or key in product code | `lib/security/modelFunding.test.ts` |
| Every pull request write has a receipt from a click or the dashboard grant | `lib/security/prWrites.test.ts`, `app/api/mcp/approvalBoundary.test.ts` |
| Proofs need their own authorization and run only on the replica | `lib/proving/embeddedHost.test.ts` |
| Only read-only SQL reaches a customer database | `assertReadOnly` in `lib/deep/supabaseMgmt.ts` |
| Outbound requests to customer hosts go through an SSRF guard | `lib/security/ssrfGuard.ts` |
| Cookie-changing requests refuse cross-site callers | `lib/security/sameOrigin.routes.test.ts` |
| A user with a verified second factor must have used it | `lib/mfa.test.ts` |
| The status never says secure | `lib/verdict.test.ts` |
| Reviewed security files cannot change without a new review | `.agents/guardrails.json` pins each file's syntax hash; `lib/security/repoGuardrails.test.ts` fails on any change |

## Evaluation

The protocol is in [AGENTS.md](AGENTS.md#benchmarks): populations, prompts and thresholds are frozen before a run, labels are blind, and a zero denominator is reported as unavailable, not 100%. Results are JSON in `docs/evaluation/`.

**Precision of findings that set the status.** Release attempt 6 ran on public Next.js repositories pinned in `docs/CORPUS-8.json`. 89 of the 103 findings that set a status were labeled true: 86.4%, one-sided 95% lower bound 79.6%. The status was judged on 40 repositories and was right on 33. Against the bar in `docs/evaluation/thresholds-release-2026-10-14.json`, the attempt **failed**. Source: `docs/evaluation/runs/attempt6-2026-10/attempt6-gate-total.json`.

The labelers were blind Claude subagents (two per finding, a third on a split), not people. That is the largest caveat on these numbers.

**Recall on planted bugs.** Known vulnerabilities were planted into pinned public repositories and frozen before the run; the customer agent (Claude Code subagents) ran blind.

| Run | Planted | Caught | Recall | Lower 95% | File |
|---|---:|---:|---:|---:|---|
| R1, run 1 | 12 | 8 | 66.7% | 39.1% | `recall-r1-run1-2026-10-08.json` |
| R1, run 2 | 12 | 8 | 66.7% | 39.1% | `recall-r1-run2-2026-10-08.json` |
| R1, run 3 | 12 | 7 | 58.3% | 31.5% | `recall-r1-run3-2026-10-08.json` |
| R1c | 14 | 13 | 92.9% | 70.3% | `recall-r1c-run1-2026-10-09.json` |

Samples are small and the intervals are wide. The same 12 plants gave 8, 8 and 7 across three runs, so agent variance alone moves recall by one plant.

**What the misses taught.** Of attempt 6's 14 false findings, 8 were apps open by design (no accounts, any visitor can edit records). That is a labeling question, not a detector bug, so I wrote a rule before any further attempt: a deployed app with no accounts where any visitor can read, change or delete other people's records is a real issue, unless it is a demo or has a single operator.

**What is not published.** Per-repository labels, agent answers and code extracts from third-party repositories are withheld: they describe issues in other people's projects that were never reported upstream. Project names in comments, tests and commit messages are replaced by stand-ins such as `corpus-a`. Repository manifests (`docs/CORPUS*.json`), planted-bug definitions, thresholds and aggregate results are published.

**Running the harness.** `npm run corpus:acquire` downloads the 7 pinned archives of `docs/CORPUS.json` (checked by SHA-256); `npm run corpus:evaluate` runs the deterministic pipeline offline and writes artifacts under `docs/evaluation/runs/`. With labels withheld it reports inventories and candidates, not precision. `SHIPLOCK_CORPUS=docs/CORPUS-8.json` selects another manifest. The math is in `lib/eval/`: `benchmark.ts` (scoring against blind labels), `thresholdout.ts` (reusing a holdout without overfitting it), `plant.ts` (where a known bug can be planted) and `ratchet.ts` (keeping a rule only if it beats a frozen margin).

## Reading the code

A path through the code in the order the product runs:

1. `AGENTS.md`: the rules every change followed.
2. `lib/jobs/queue.ts` and `lib/jobs/worker.ts`: how work is queued, leased and prioritized.
3. `lib/agent/audit.ts`: one audit, from archive to stored findings.
4. `lib/graph/routeInventory.ts`: how a route's caller identity, scope and tables are read from source.
5. `lib/agent/attackGuard.ts`, `lib/agent/findings.ts`, `lib/agent/confirmed.ts`: how a model's claim is checked, capped, and either confirmed or left to review.
6. `lib/graph/graph.ts` and `lib/graph/attackPaths.ts`: the cross-layer join.
7. `lib/proving/replica.ts` and `lib/proving/embeddedHost.ts`: reproduction on a replica.
8. `lib/fixes/prRun.ts` and `lib/jobs/repairWorker.ts`: a click becoming a pull request.
9. `lib/eval/`: how the product was measured.

Tests sit next to the code they cover (`foo.ts` and `foo.test.ts`). Comments explain why something is the way it is, often with the date and the observation that forced it.

## Running it

Requires Node 20 or later.

### Tests and build (no accounts needed)

```bash
npm ci
npm run lint
npx vitest run                          # unit and integration tests
npx tsc --noEmit
node scripts/test-foundation-sql.mjs    # migrations and RLS against PostgreSQL in WASM, no network
NEXT_PUBLIC_SUPABASE_URL=https://example.supabase.co NEXT_PUBLIC_SUPABASE_ANON_KEY=dummy \
  SUPABASE_SERVICE_ROLE_KEY=dummy npm run build
```

This is what CI runs on every push. None of it needs a real service.

### The app

```bash
cp .env.example .env.local   # then fill it in, see below
npm run dev                  # http://localhost:3000
npm run worker:audit         # in a second terminal: drains the job queue
```

Running audits needs real services:

| Need | Variables | Notes |
|---|---|---|
| Supabase project | `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY` | Apply `supabase/migrations/` in order; enable the auth providers you want and set the site URL |
| App settings | `NEXT_PUBLIC_APP_URL`, `ENCRYPTION_KEY` (`openssl rand -base64 32`), `CRON_SECRET` | Required at startup (`lib/env.ts`) |
| Email | `RESEND_API_KEY`, `RESEND_FROM_EMAIL` | Required by the config schema; alert emails are switched off in code |
| GitHub App | `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_APP_SLUG`, `GITHUB_WEBHOOK_SECRET` | Setup URL `<app>/api/deep/github/callback`, webhook `<app>/api/monitor/github`; permissions: contents (read and write), pull requests and checks (write), metadata (read) |
| Worker | `SHIPLOCK_BASE_URL`, `CRON_SECRET` | `npm run worker:audit` drains the queue from your machine, or keep migration 094's `pg_cron` job (needs `pg_net` and the Vault secrets `shiplock_drain_url` and `shiplock_cron_secret`) |

Optional Supabase OAuth, Vercel integration and Better Auth variables are listed in `lib/env.ts`, each with a comment on what happens when it is unset.

Limits, stated plainly: production was migrated one release at a time, so building a fresh project from all 113 migrations has not been tested end to end, and `test-foundation-sql.mjs` covers selected migrations on a stub schema rather than Supabase itself.

### The hosted version

1. Sign in at [shiplock.dev](https://shiplock.dev/auth) with GitHub, Google or email.
2. Install the GitHub App [`shiplock-security`](https://github.com/apps/shiplock-security) on the repositories you choose. Its write access is used only to push a fix branch you asked for.
3. Pick a repository and click "Run the first audit". It shows its work as it runs; files it could not read are listed as not checked.
4. Optional: create a token in Settings and connect your agent to `https://shiplock.dev/api/mcp/server` (streamable HTTP, bearer token).

## Repository map

| Path | Role |
|---|---|
| `app/(d)/` | Pages: landing, sign in, onboarding, dashboard, public `/verified/[token]` report |
| `app/api/` | Audit enqueue, GitHub callback and webhook, job drain, MCP, fixes, proofs, traffic |
| `lib/agent/` | The audit pipeline, stack inference, the hypothesis guard and findings |
| `lib/graph/` | Route facts from source and the cross-layer asset graph |
| `lib/deep/` | Repository and provider readers: GitHub, Supabase, Postgres, Vercel, secrets, dependencies |
| `lib/monitoring/` | Provider collectors, snapshots and rechecks |
| `lib/intelligence/` | Tasks for the customer's agent and quoted-proof verification |
| `lib/proving/` | Replica proofs on embedded Postgres |
| `lib/fixes/` | Fix lanes, previews and pull requests |
| `lib/jobs/` | The leased job queue and its workers |
| `lib/traffic/` | Customer-side traffic metadata and detection |
| `lib/security/` | SSRF guard, same-origin checks, live-site checks, repository guardrails |
| `lib/eval/`, `scripts/corpus.cjs` | Evaluation harness |
| `components/v3/` | Dashboard UI |
| `mcp/` | Local stdio MCP server (`shiplock-mcp`, not published to npm) |
| `supabase/migrations/` | Schema and row level security |

About 53,500 lines of TypeScript and JavaScript outside tests, 389 test files, 113 SQL migrations.

## License

MIT, see [LICENSE](LICENSE). `lib/traffic/crs/` includes OWASP Core Rule Set material under its own license.
