# ShipLock

ShipLock is a security harness for a startup without a security team. It reads the company's GitHub repository and reports only what it can back with evidence: a quoted line of code, a live configuration fact, or a reproduction on a disposable copy of the database. It never calls an AI model itself. The intelligence is the customer's own coding agent (Claude Code or Codex), which connects over MCP and proposes attacks. ShipLock re-reads every line the agent cites before it believes anything.

Live at [shiplock.dev](https://shiplock.dev), free, billing switched off. **It has no outside users.** The only account that has run the full loop is mine. The release precision bar I set was not met (see [Evaluation](#evaluation)).

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

## How it works

The product is one loop. Each stage shows its real state; pending work is never shown as done.

| Stage | What happens | Where |
|---|---|---|
| Read | Deterministic checks on a bounded archive of the repository: secrets in source and git history, dependency advisories, server secrets reaching the client, GitHub Actions workflows, the Next.js route inventory and missing authorization. Optional read-only Supabase/Postgres checks: RLS policies, grants, storage, auth configuration | `lib/deep/`, `lib/graph/`, `lib/agent/` |
| Attack | The audit becomes tasks for the customer's agent; its answers pass the quoted-proof guard before admission | `lib/intelligence/reasoning.ts`, `lib/agent/attackGuard.ts` |
| Map | Which routes are wrong and what tables, providers and hot routes they reach, from audit facts only | `lib/graph/`, `components/v3/` |
| Fix | A pull request for an allowlisted mechanical change, on a click, with a receipt | `lib/fixes/` |
| Watch | Pull request checks from a signed webhook, daily rechecks, an outside view of the live site, optional traffic metadata | `app/api/monitor/`, `lib/monitoring/`, `lib/traffic/` |

Runtime: the Next.js app authenticates, checks ownership and enqueues. Jobs run on a leased queue with retries, heartbeats and fencing (`lib/jobs/`), drained by `/api/jobs/drain`, which a Supabase `pg_cron` job calls every minute in production. Postgres (Supabase) is the system of record, with row level security on every table (`supabase/migrations/`, 113 files).

Tests enforce the rules above: `lib/security/modelFunding.test.ts` (no model in product code), `lib/security/prWrites.test.ts` (every pull request write has a receipt), `lib/proving/embeddedHost.test.ts` (proofs only on the replica), `lib/verdict.test.ts` (the status never says secure), and `.agents/guardrails.json` with `lib/security/repoGuardrails.test.ts` for the contract rules.

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

**Running the harness.** `npm run corpus:acquire` downloads the 7 pinned archives of `docs/CORPUS.json` (checked by SHA-256); `npm run corpus:evaluate` runs the deterministic pipeline offline and writes artifacts under `docs/evaluation/runs/`. With labels withheld it reports inventories and candidates, not precision. `SHIPLOCK_CORPUS=docs/CORPUS-8.json` selects another manifest. The math is in `lib/eval/` (`benchmark.ts`, `thresholdout.ts` for reusing a holdout without overfitting it, `plant.ts`).

## Use the hosted version

1. Sign in at [shiplock.dev](https://shiplock.dev/auth) with GitHub, Google or email.
2. Install the GitHub App [`shiplock-security`](https://github.com/apps/shiplock-security) on the repositories you choose. It asks for contents (read and write; writes only push a fix branch you asked for), pull requests and checks (write), and metadata (read).
3. Pick a repository and click "Run the first audit". It shows its work as it runs; files it could not read are listed as not checked.
4. Optional: create a token in Settings and connect your agent to `https://shiplock.dev/api/mcp/server` (streamable HTTP, bearer token). Its 10 tools: `list_findings`, `get_security_context`, `get_guardrails`, `get_fix`, `list_intelligence_tasks`, `get_intelligence_task`, `submit_intelligence_result`, `report_self_check`, `open_fix_pull_request`, `get_fix_pull_request`.

## Run it yourself

Requires Node 20 or later.

```bash
npm ci
cp .env.example .env.local   # then fill it in
npm run dev                  # http://localhost:3000
```

The gate CI runs on every push:

```bash
npm run lint
npx vitest run
npx tsc --noEmit
node scripts/test-foundation-sql.mjs   # migrations against PostgreSQL in WASM, no network
NEXT_PUBLIC_SUPABASE_URL=https://example.supabase.co NEXT_PUBLIC_SUPABASE_ANON_KEY=dummy \
  SUPABASE_SERVICE_ROLE_KEY=dummy npm run build
```

Tests and the build need no real services. Running audits does:

| Need | Variables | Notes |
|---|---|---|
| Supabase project | `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY` | Apply `supabase/migrations/` in order; enable the auth providers you want and set the site URL |
| App settings | `NEXT_PUBLIC_APP_URL`, `ENCRYPTION_KEY` (`openssl rand -base64 32`), `CRON_SECRET` | Required at startup (`lib/env.ts`) |
| Email | `RESEND_API_KEY`, `RESEND_FROM_EMAIL` | Required by the config schema; alert emails are switched off in code |
| GitHub App | `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_APP_SLUG`, `GITHUB_WEBHOOK_SECRET` | Setup URL `<app>/api/deep/github/callback`, webhook `<app>/api/monitor/github`, permissions as above |
| Worker | `SHIPLOCK_BASE_URL`, `CRON_SECRET` | `npm run worker:audit` drains the queue from your machine, or keep migration 094's `pg_cron` job (needs `pg_net` and the Vault secrets `shiplock_drain_url` and `shiplock_cron_secret`) |

Optional Supabase OAuth, Vercel integration, proof replica and Better Auth variables are listed in `lib/env.ts`, each with a comment on what happens when it is unset.

Limits, stated plainly: production was migrated one release at a time, so building a fresh project from all 113 migrations has not been tested end to end, and `test-foundation-sql.mjs` covers selected migrations on a stub schema rather than Supabase itself.

## Repository map

| Path | Role |
|---|---|
| `app/(d)/` | Pages: landing, sign in, onboarding, dashboard, public `/verified/[token]` report |
| `app/api/` | Audit enqueue, GitHub callback and webhook, jobs, MCP, fixes, traffic |
| `lib/deep/`, `lib/graph/`, `lib/agent/` | Repository and provider checks, route facts, findings and guards |
| `lib/intelligence/` | Tasks for the customer's agent and quoted-proof verification |
| `lib/fixes/`, `lib/proving/`, `lib/jobs/` | Pull requests, replica proofs, the job queue |
| `mcp/` | Local stdio MCP server (`shiplock-mcp`, not published to npm) |
| `scripts/corpus.cjs`, `lib/eval/` | Evaluation harness |
| `supabase/migrations/` | Schema and row level security |

About 53,500 lines of TypeScript and JavaScript, 390 test files, 113 SQL migrations.

## License

MIT, see [LICENSE](LICENSE). `lib/traffic/crs/` includes OWASP Core Rule Set material under its own license, and `.agents/skills/ui-ux-pro-max/` keeps its own license.
