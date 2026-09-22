<!-- BEGIN:nextjs-agent-rules -->
# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may
all differ from training data. Read the relevant guide in
`node_modules/next/dist/docs/` before changing framework behavior. Heed
deprecation notices.
<!-- END:nextjs-agent-rules -->

# ShipLock product and architecture contract

This is the sole living product, architecture, and agent-work contract for both
Claude Code and Codex. Before any implementation, read this file completely,
then `docs/MASTER-PLAN-PROGRESS.md` completely, then inspect the current code and
tests. After every implemented package, update the master ledger with its exact
step/item, evidence, and remaining gaps. Do not create a parallel agent guide,
phase handoff, or alternative product spec. Code and executable tests outrank
prose when they disagree; correct this file in the same change.

## Product

ShipLock is the security operating system for a growing startup without a
security team. The first buyer is a founder, technical or not: the surface must
state consequence, evidence, and the next safe action without requiring security
expertise. The underlying evidence must remain inspectable enough that a strong
backend engineer can challenge every claim.

The first connection is GitHub. ShipLock infers the application stack from the
selected repository—framework, routes, auth, database, hosting, payments, and
other services—rather than asking the customer to describe it. A detected
provider such as Supabase, Firebase, Clerk, Stripe, Railway, Vercel, PostgreSQL,
or MongoDB is an inference, not proof that ShipLock can inspect that account.
The customer may connect a provider later to add live configuration evidence.
Provider connections are optional and must visibly deepen coverage.

The durable advantage is the longitudinal evidence graph: repository facts,
provider configuration, authorized proof results, dependency state, and traffic
summaries bound to the same repository over time. The model is replaceable;
customer-specific history, explicit bindings, and remediation outcomes are the
moat. Native use from the dashboard and coding agents (MCP/terminal/Codex/Claude
Code) must consume the same facts and approval state, never a separate truth.

Felipe's proposed intelligence connector is **not** merely a customer API key
and is not shipped: ShipLock would own the collectors, deterministic checks,
evidence graph, prompts, guards, and approval workflow while a customer-run
coding agent navigates its own authorized checkout and supplies bounded,
structured reasoning/evidence back to ShipLock. The agent is an optional
intelligence and local-code navigation surface, never an independent source of
security truth or a way to bypass provenance and approval. A model-provider API
key alone does not grant that agent's repository/tool access. A passive MCP
server alone cannot guarantee ShipLock can start a cloud audit or command a
desktop agent: the host must support and authorize the interaction and be
running. Preserve the GitHub-only deterministic path and durable workers when
the agent is offline. Validate exact host capabilities with a small local
prototype before claiming this works in Codex, Claude Code, or other clients.

Pricing is undecided. Billing is parked while unit costs are measured. Do not
publish or restore a price, trial, paid tier, Stripe Checkout entry point, or
margin claim until Felipe approves a cost model based on measured model tokens,
provider calls, storage, queue execution, support, and target gross margin. The
old $49/$265/$470 offer and later prototype tiers are superseded. Customer-
supplied agent intelligence and a possible free harness remain product proposals,
not implemented tiers or claims of zero ShipLock cost.

## Customer journey

1. Sign in and install the GitHub App.
2. Select repositories. ShipLock records installation, repository, default
   branch, and commit identity, then inventories the stack automatically.
3. Run the first repository audit. The UI shows progress, useful findings, and
   explicit unknown/unread coverage; it never turns missing evidence into clean.
4. Offer optional provider connections discovered from code. Explain exactly
   what each connection lets ShipLock verify and request minimum read-only scope.
5. Correlate only evidence explicitly bound to that repository and current
   connection. Show an attack path with a claims ledger, not a mystery score.
6. For a mechanical remedy, draft or open a reviewable branch/PR. ShipLock never
   merges, deploys, changes provider configuration, or enables enforcement
   without a separate explicit customer approval.
7. Recheck pull requests and connected evidence continuously. Notify on a
   meaningful change, not on an unchanged recurring scan.

Time-to-first-value for a GitHub-only customer is under ten minutes. A provider
connection may strengthen a claim from inferred/corroborated to verified or
proven; it may not be required to obtain an honest first result.

## Evidence architecture

Collectors are read-only adapters with one job: acquire evidence and return a
typed snapshot. Transport, interpretation, correlation, and presentation stay
separate. Every snapshot must carry:

- tenant and subject scope (repository/provider/project/endpoint as applicable);
- collector and transport identity;
- observation time and immutable source identity when available;
- current connection epoch or opaque credential fingerprint;
- completeness/readability, including why something was not read;
- provenance sufficient to reproduce or inspect the claim; and
- no customer secret or application-row value in jobs, logs, or graph facts.

Stack inference is deterministic first: manifests, lockfiles, imports, config,
schema, environment-variable names, deployment files, and route structure. It
may suggest which connector to offer; it never creates a repository↔provider
binding. A join requires the selected repository, a current connection, and an
unambiguous provider-issued link or explicit customer confirmation. Disconnect,
reconnect, token rotation, repository reselection, and ambiguous transports must
invalidate or exclude stale correlation.

The fact layer represents `observed`, `inferred`, `unknown/unreadable`,
`corroborated`, and `proven` as different states. “Absent” is never equivalent
to “checked and absent.” Source-only or partial evidence may add a warning but
may not retire or demote a prior cross-surface finding.

Deterministic checks produce candidates and facts. A model may propose an attack
path or explanation, but deterministic guards control admission, severity
ceilings, repository/table/route citations, and allowed actions. Model failure,
timeout, malformed output, and skipped reasoning are coverage states—not clean
audits. A probabilistic model is never called “deterministic,” regardless of its
benchmark accuracy.

Authorized attack-based verification is part of the target product, with proof:
run only against a disposable replica or an environment the customer explicitly
authorized for that exact test; use synthetic tenants/data; enforce request,
time, and concurrency budgets; prohibit persistence, destructive payloads,
availability testing, third-party targets, and production customer-data reads.
Production is never the proving ground. Evidence must distinguish “could test,”
“test ran,” and “reproduced.”

## Traffic boundary

Customer traffic does not pass through ShipLock. ShipLock is not Cloudflare, a
reverse proxy, or a WAF. The optional customer-side snippet/edge integration may
send minimized metadata and aggregate counters; never request/response bodies,
credentials, or end-user data. Observation can recommend a rate limit or a
customer-side firewall rule. ShipLock does not block production traffic itself.
Any generated enforcement change is installed in the customer's stack only
after explicit approval and must fail safely with a rollback path.

## Runtime and storage shape

The web/API tier authenticates, validates ownership, renders state, and enqueues
work. Durable workers execute audits and monitoring from leased jobs with
idempotency keys, bounded retries, heartbeats, fencing tokens, checkpoints, and
per-tenant fairness. Web requests are not the durable execution engine. Scheduled
and webhook paths enqueue the same job contracts rather than running parallel
business logic.

Postgres/Supabase is the system of record. Tenant-owned rows use Row Level
Security plus tenant-bound foreign keys; service-only tables deny customer-role
access. Secrets are encrypted, never returned after write, and excluded from
job payloads. Evidence snapshots are append-oriented; derived current state is
rebuildable. Large artifacts use bounded object storage with retention rules.
Audit finding replacement and terminal job/run transitions are transactional
and fenced so a stale worker cannot overwrite a newer result.

Scale claims require load evidence. The target architecture can serve 50,000
accounts by scaling stateless web nodes and workers independently, but no one may
claim that capacity until queue throughput, database contention, provider rate
limits, storage growth, noisy-neighbor behavior, and recovery have been measured.

## Approval and safety boundaries

- Read-only collection and analysis may run within the customer's selected
  scope. A write, PR, provider change, enforcement rule, merge, or deployment is
  a distinct action with an audit record.
- ShipLock may draft or open a PR when the customer has enabled that workflow;
  it never approves or merges its own PR. Authorization/business-policy changes
  require human judgment and are not machine-authored as if mechanical.
- Do not read customer application rows. Schema, policy definitions, counts, and
  synthetic replica data are the allowed evidence surface.
- Never claim that a connected account is secure. Say what was read, what was
  found, what was reproduced, and what remains unknown.
- Never require a customer to buy or upgrade a third-party plan for a core
  ShipLock claim. Degrade honestly when a provider API is unavailable.

## Current implementation truth

The supported deep repository reasoner is Next.js App Router and Pages API in
JavaScript/TypeScript, with Supabase/Postgres as the deepest provider surface.
Other detected stacks are inventory unless a tested collector says otherwise.
The repository contains existing deterministic checks, GitHub onboarding and PR
checks, provider collectors, the evidence graph, reviewable fix paths, traffic
observation, MCP routes, and a durable audit queue foundation. Reuse these; do
not replace them with a greenfield subsystem. A file's existence is not proof
that a production path calls it: trace registration, producer, worker, UI, and
consumer before claiming a capability. `lib/graph/defender.ts` remains unused;
the proving ground and native-agent distribution are not launch-proven.

### Source map and actual flow

- `app/(d)/` is the live founder-facing UI. `/onboarding` installs the GitHub
  App and selects repositories; `/dashboard/{risks,activity,prs,coverage,stack,settings}`
  reads tenant-scoped state through `lib/dashboard.ts`. `/verified/[token]` is
  the shareable report. Static prototype routes were removed; build on the real
  UI, not mock data.
- `app/api/audit/route.ts` enqueues a `repository_audit`; `lib/jobs/` owns typed
  leases, heartbeats, checkpoints, fencing, retries, and workers. The API
  request is not the durable executor. `app/api/monitor/github/route.ts` verifies
  the raw webhook signature, admits selected-repository audit/source/PR-check
  work, and must fail for a safe retry if admission fails.
- `lib/deep/repoArchive.ts` reads a bounded GitHub archive for
  `lib/agent/audit.ts`; the older `lib/deep/githubRun.ts` uses a smaller bounded
  per-file path for source monitoring. Truncation is coverage, not a clean scan.
  `lib/agent/stack.ts` infers providers; `lib/graph/routeInventory.ts`,
  `callPath.ts`, and `declarations.ts` derive Next.js route facts from executed
  handler paths. Current route facts are route-wide, not per HTTP method or CFG.
- `lib/agent/attack.ts` may call a model for hypotheses; `attackGuard.ts`
  checks class and observed citations, `findings.ts` computes confidence and
  severity ceilings, and `lib/proving/` alone may earn `proven`. A model skip or
  malformed response is shown in Coverage and cannot resolve an old finding.
- `lib/monitoring/{registry,collectors,run,findings,diff}.ts` collects provider
  evidence through registered adapters. `lib/graph/{repositorySource,
  databaseSource,repositoryDatabase,graphRun,attackPaths}.ts` admits scoped
  facts and correlates them. Vercel links and Postgres/Supabase associations
  require current explicit repository bindings; partial source cannot retire
  findings. The endpoint scanner's fallback RLS value is unread, not a control.
- `lib/agent/prCheck.ts` and `diffScan.ts` make deterministic PR verdicts;
  partial input must not yield green. `app/api/fix/pr/route.ts` and
  `lib/fixes/prRun.ts` open reviewable branches/PRs only on a customer action.
  Some PRs contain a fix-request document, not a tested code fix; do not blur
  those lanes. No machine-authored business authorization policy.
- `lib/traffic/` and `/api/traffic/*` are optional customer-side metadata
  observation, not a ShipLock proxy. `mcp/` and `/api/mcp/*` are native-agent
  surfaces but their distribution and live setup remain unverified. The target
  is one backend fact and approval boundary across dashboard and MCP; current
  MCP code is not there yet. `lib/mcpAuth.ts`/`app/api/tokens/route.ts` still
  hard-gate on `is_paid` despite preview access, and token-authenticated MCP
  scan/PR tools can act without a separate dashboard approval receipt. Do not
  describe native-agent parity or click-only MCP writes as shipped.
- No agent-intelligence connector currently returns bounded code-navigation
  evidence to the graph. Existing MCP tools expose ShipLock facts/actions to an
  agent; they do not make the customer's agent ShipLock's autonomous worker.
- `supabase/migrations/` is the schema/RLS source. 053–066 are local and
  unapplied. `docs/CORPUS.json`, `scripts/corpus.cjs`, and dated evaluation JSON
  are reproducibility data, not current accuracy marketing claims.

### Security and quality invariants

Use `lib/access.ts` as the central signed-in access gate; `BILLING_ENABLED=false`
does not make anonymous source access okay. Supabase admin stays server-only;
tokens are encrypted (`lib/crypto.ts`) or one-way hashed (`lib/apiTokens.ts`).
Provider SQL is read-only (`lib/deep/supabaseMgmt.ts`, `postgresDirect.ts`),
customer-supplied hosts pass `lib/security/ssrfGuard.ts`, and GitHub/Stripe
webhooks verify signatures and idempotency. Preserve per-request CSP in
`proxy.ts`. Do not weaken a guard, access boundary, RLS policy, finding
continuity, or no-merge rule to make a test pass.

Before changing a security fact, identify every consumer and the false-positive
and false-negative direction; freeze the affected route census; add negative
fixtures; and rerun the offline corpus where relevant. The historical 54-route
candidate baseline and 2 true positives of 8 admitted corpus-b criticals are
dated, narrow evidence, not product-wide precision. Any route/parser/ranking
change invalidates comparisons unless the population is remeasured. No paid
model runs without Felipe's approval.

Migrations 053–066 and the current working packages require deployment-grade
verification before production use. Remaining master work includes connection
epochs and traffic binding, a production always-on worker plus migration of all
remaining producers, provider evidence contracts, safe proof execution,
detection quality, the approval/repair loop, continuous monitoring, native-agent
polish, traffic recommendations, and measured scale/economics. Exact status
lives only in `docs/MASTER-PLAN-PROGRESS.md`.

## Felipe's working agreement

- Address the user as Felipe in every response.
- Work only in ShipLock-v2 unless Felipe explicitly expands scope.
- Never spend money, purchase or activate a subscription, call a paid model/API,
  or deploy billable infrastructure without Felipe's explicit approval. Prefer
  local tests, fixtures, emulators, and mocked providers.
- Make changes reviewable and cohesive. Report the master section, step, and
  item; update `docs/MASTER-PLAN-PROGRESS.md` after every implementation. A
  package is not a finished phase. Preserve unrelated working-tree changes.
- Before editing: read this file and the master ledger fully; run `git status`,
  inspect relevant code, callers, tests, migrations, and current framework docs.
  Before handing off: inspect `git diff`, check for stale cross-references and
  leaked secrets, and report skipped verification honestly.
- Before a commit, run focused tests and then the proportional full gate:
  `npx vitest run`, `npm run lint`, `npx tsc --noEmit`, and `npm run build`.
  Database changes also require the local SQL suite. Do not commit a failing
  gate or hide a skipped check.
- Do not deploy, apply migrations remotely, alter GitHub/provider settings,
  merge PRs, or push to a remote unless Felipe explicitly requests it.

## Skill routing for Claude Code and Codex

The checked-in canonical skill text is under `.claude/skills/`; Codex discovers
thin adapters under `.agents/skills/`. Read the relevant `SKILL.md` completely
before using it. Do not infer that an installed summary is an executable skill.

- Ponytail (`.claude/skills/ponytail/SKILL.md`): default for scoped code cleanup
  and changes. Trace the flow first, then delete dead paths rather than adding
  abstractions; never simplify a safety boundary away.
- Superpowers (`.claude/skills/using-superpowers/SKILL.md`): use its applicable
  planning, debugging, and verification discipline. This repo's two-document
  rule overrides any instruction to create another design/plan Markdown file.
- GStack-style review (`.claude/skills/shiplock-gstack-review/SKILL.md`): the
  checked-in, repo-safe review subset works in both agents. An upstream GStack
  download is optional and not a ShipLock dependency; do not run its setup,
  auto-updates, telemetry, network setup, or `CLAUDE.md` injection as part of a
  ShipLock review. No paid tests or external state changes by default.
- Ruflo (`.claude/skills/swarm-orchestration/SKILL.md`): optional orchestration
  only when Felipe explicitly asks for parallel agents and its CLI is already
  installed. A downloaded skill is not an installed CLI. Do not `npx`-install
  packages, run project initialization, or add a swarm dependency merely for
  this repo. Autonomous swarm infrastructure is not a ShipLock requirement.

On Felipe's current machine, upstream GitHub GStack and Ruflo skill sources are
downloaded under `~/.codex/skills/{gstack,ruflo}` and linked into
`~/.claude/skills/` for Claude Code. These machine-local installs
are not repo dependencies or a substitute for the checked-in skill adapters.
Neither upstream setup/CLI nor paid service was run during installation.

## Documentation hygiene and handoff

`AGENTS.md` is stable policy and code orientation; the master ledger is dynamic
status and the exact next package. These are the only two non-skill Markdown
files in the repo. Change this file only when product/architecture or working
rules truly change. Date every master-ledger update; identify the exact
section/step/item finished, evidence/tests, incomplete sibling items, and next
reviewable action. A locally completed package does not close a step with live
acceptance still open. Keep older measurement inputs as JSON/source and, for
retired narrative, use Git history rather than a parallel README/spec/handoff.
Completed steps may be compacted out of the active queue only after their key
proof and remaining caveats are retained in the ledger; do not erase unfinished
2/3/4 work just because a later step started.
