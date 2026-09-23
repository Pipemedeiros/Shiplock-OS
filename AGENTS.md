<!-- BEGIN:nextjs-agent-rules -->
# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may
all differ from training data. Read the relevant guide in
`node_modules/next/dist/docs/` before changing framework behavior. Heed
deprecation notices.
<!-- END:nextjs-agent-rules -->

# ShipLock product and architecture contract

This is the sole living product, architecture, and agent-work contract for both
Claude Code and Codex. Claude Code v2.1.277+ reads `AGENTS.md` in supported
sessions when this project has no `CLAUDE.md`; older or unsupported sessions
must be pointed here explicitly. Before any implementation, read this file and
`docs/MASTER-PLAN-PROGRESS.md` completely, then read the Ponytail and
Superpowers skills and inspect the relevant code and tests. For every coherent
repository change, including a partial or documentation-only package, record
progress in the dynamic master ledger before handoff or commit: exact
step/item, evidence, and remaining gaps. Do not create another agent guide,
phase handoff, or alternative product spec. Code and executable tests decide
implementation truth; if they conflict with this
contract, report the mismatch and seek Felipe's approval before editing
`AGENTS.md`.

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
proposed advantage, not a proven moat. Native use from the dashboard and coding
agents (MCP/terminal/Codex/Claude Code) must consume the same facts and approval
state, never a separate truth.

The approved target packaging is a free GitHub-first entry and a paid
cross-layer product; neither tier is implemented or priced yet. After sign-in,
GitHub installation, and selection of a repository, ShipLock funds **one
bounded first scan per account** to show value. Do not silently grant another
funded model run on repository changes, retries, or account recreation. The
token ceiling and abuse policy remain open in the master ledger and must be
measured before launch. The first scan still reports partial/unread/model-skipped
coverage honestly.

For subsequent scheduled deep scans, PR reasoning, and AI-assisted repair,
the customer supplies the intelligence and its token allowance through an
explicitly connected, supported mode: a customer-owned model API credential,
a running coding agent such as Claude Code or Codex, or a ChatGPT connector.
These are **different transports**, not interchangeable credentials. An API
key can fund inference but cannot by itself navigate a checkout; a passive MCP
server cannot command a dormant desktop agent or debit a ChatGPT subscription
on ShipLock's schedule. A ChatGPT plugin can expose ShipLock tools, but
reliable trigger, result return, plan eligibility, and limits require a real
host-specific proof. No adapter may be marketed or billed as working until it
can return schema-validated, scoped evidence to the same guarded graph. When
customer intelligence is disconnected, exhausted, or unavailable, deterministic
collection may continue within budget; model-assisted work is explicitly
pending/unread, never clean. ShipLock owns collectors, prompts, guards,
correlation, approval, and audit history in every mode. Customer model output
never overrides source identity, deterministic admission, or approval.

Free targets repository inventory, deterministic findings, honest coverage,
and bounded manual/PR-triggered/scheduled rechecks; AI-assisted rechecks
require the customer's connected intelligence. Paid targets optional live
provider connections and cross-layer detection/proof, with the same
customer-funded intelligence direction after the first scan. Meaningful-change
email alerts belong to paid only. A reviewable PR suggestion may be shown in
either tier, but **every branch/PR write requires a separate customer click**;
mere connection or a standing opt-in is insufficient. A suggestion is not proof
that a change cannot break production. Before opening a code PR, require an
allowlisted mechanical change, current evidence, tests/CI or an explicit unverified label,
an action receipt, and customer authorization. ShipLock never merges or deploys.

Pricing is undecided. Billing/Checkout stays parked while first-scan and hosted
COGS are measured: model tokens, GitHub/provider calls, queue execution,
storage, support, and target margin. A free price to the customer is not zero
ShipLock cost. Never purchase or activate customer/provider plans to make a
core claim. The old $49/$265/$470 offer and prototype tiers are superseded.

### ICP and market validation

Start with founders of small, growing GitHub-based Next.js/Supabase SaaS teams
without a security specialist; other stacks remain inventory until supported.
This is a testable initial ICP, not evidence that all founders will buy.
Repository scanning and AI repair alone are not differentiation: [GitHub Code
Security](https://github.com/security/advanced-security/code-security) already
combines scanning and remediation, and [Codex Security](https://openai.com/index/codex-security-now-in-research-preview/)
describes vulnerability discovery, validation, and proposed fixes. The hypothesis
is that current, explicitly bound provider configuration plus repository and
traffic evidence finds actionable cross-layer issues and saves founder triage
time beyond those baselines. Do not claim competitors lack a capability without
testing that specific comparison.

The weakest commercial assumption is willingness to connect both provider access
and customer intelligence for incremental value. Test connection completion,
incremental confirmed findings, false alarms, time to reviewed remedy, repeat
use, willingness to pay, and hosted cost on consented pilot repos. If pilots
cannot show incremental value or complete setup reliably, revisit scope before
expanding connectors. Customer-supplied models improve potential economics,
not necessarily onboarding; no universal subscription-to-API bridge is assumed.
The market supports a credible experiment, not a claim of product-market fit.

## Customer journey

1. Sign in and install the GitHub App.
2. Select repositories. ShipLock records installation, repository, default
   branch, and commit identity, then inventories the stack automatically.
3. Run one budgeted ShipLock-funded first audit of the selected repository. The
   UI shows progress, findings, and explicit unknown/unread coverage; it never
   turns missing evidence into clean.
4. Ask the user to connect a supported customer-intelligence mode for later
   model-assisted runs. Show what it can do, its limits, and whether it is
   currently reachable; do not mistake GitHub access for AI funding.
5. Admit selected-repository PR events and customer schedules through durable,
   bounded jobs. Deterministic rechecks can continue; deep reasoning waits for
   customer intelligence and never falls back to ShipLock-funded calls silently.
6. Offer optional read-only provider connections inferred from code as paid
   depth. Explain what each lets ShipLock verify; a detected provider is not a
   bound account. Correlate only current, explicitly bound evidence.
7. Show consequences, citations, uncertainty, and a reviewable fix proposal.
   Open a code PR only after the customer's click; never approve, merge,
   deploy, or enable enforcement on the customer's behalf.
8. Recheck changes. Paid email alerts notify only on a meaningful new state,
   not on every unchanged recurring scan; free may show in-app state but sends
   no email alerts.

The time-to-first-value target for a GitHub-only customer is under ten minutes.
A provider connection may strengthen a claim from inferred/corroborated to verified or
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

Every intelligence mode must return the same bounded result contract: tenant,
selected repository and immutable commit, run/attempt identity, host/provider,
credential or connection epoch (never the secret), source citations, structured
hypotheses, usage/limit receipt when available, and explicit completeness or
failure. The server validates identity, freshness, schema, citations, and
deterministic admission before persistence. Treat customer model text as
untrusted input, not as a collector snapshot or authorization to write. The
first-scan credit is a durable, idempotent per-account entitlement with hard
token/time ceilings; retrying the same run cannot mint a second credit.

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

Jobs distinguish deterministic collection from intelligence requests and record
who funds model invocation. After the first-scan entitlement is consumed, no
worker may call a ShipLock-funded model as a fallback. Customer credentials are
encrypted references, never job payloads; host/agent integrations need explicit
availability and result-return contracts. A PR webhook may enqueue a
deterministic recheck while the customer agent is offline, but its AI leg stays
pending/unread. Bound per-account runs, repository bytes, provider calls, model
output, concurrency, and retention before opening the free tier.

Postgres/Supabase is the system of record. Tenant-owned rows use Row Level
Security plus tenant-bound foreign keys; service-only tables deny customer-role
access. Secrets are encrypted, never returned after write, and excluded from
job payloads. Evidence snapshots are append-oriented; derived current state is
rebuildable. Large artifacts use bounded object storage with retention rules.
Audit finding replacement and terminal job/run transitions are transactional
and fenced so a stale worker cannot overwrite a newer result.

Scale claims require load evidence. The architecture targets 50,000
accounts by scaling stateless web nodes and workers independently, but no one may
claim that capacity until queue throughput, database contention, provider rate
limits, storage growth, noisy-neighbor behavior, and recovery have been measured.

### Target data flow and benchmark contract

GitHub selection/event → authenticated, quota-checked job admission → leased
worker → bounded read-only collectors → versioned snapshots → deterministic
facts/candidates → optional funded intelligence → citation/admission guards →
repository-bound evidence graph → founder findings/coverage → customer click
and action receipt → reviewable repair PR → human merge → recheck. Paid provider
snapshots and minimized traffic aggregates join only through current explicit
repository bindings. This is the target flow; the source map and ledger disclose
which links are incomplete. Document changed producer, consumer, storage, trust
boundary, failure/retry behavior, and cost owner in the ledger for every change
to this flow. Do not introduce a parallel source of truth.

Benchmark detection and system behavior separately. Before detector changes,
freeze commit/archive identities, labeled vulnerability/negative populations,
supported scope, model/version/prompt/settings, and run budgets. Record TP, FP,
FN, precision (TP/(TP+FP)), recall (TP/(TP+FN)), false-critical counts, unread
coverage, sample sizes, and uncertainty; zero denominators mean unavailable,
not 100%. Candidate recall is not end-to-end recall. Use held-out labels not
used for tuning, compare before/after on the same population, and report missed
cases as well as wins. Store bounded machine-readable results, never a new MD.
Do not invent a passing quality threshold after seeing results; propose and
record release thresholds before the release benchmark.

System benchmarks must name workload and environment, distinguish accounts
from simultaneous scans, and measure queue wait, throughput, p50/p95 latency,
retry/recovery, database contention, tenant fairness, provider rate limits,
storage/retention, and cost per completed run. Fault tests cover stale workers,
disconnect/reconnect, partial reads, exhausted AI budget, offline hosts, and
duplicate delivery. Local mocks and queue admission are not production capacity
or model accuracy evidence. Paid benchmark runs require Felipe's approval.

## Approval and safety boundaries

- Read-only collection and analysis may run within the customer's selected
  scope. A write, PR, provider change, enforcement rule, merge, or deployment is
  a distinct action with an audit record.
- ShipLock may show a PR proposal, but each branch/PR write requires its own
  customer click and audit receipt. It never approves or merges its own PR.
  Authorization/business-policy changes require human judgment and are not
  machine-authored as if mechanical.
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
  This path currently uses ShipLock's `ANTHROPIC_API_KEY` directly; `lib/env.ts`
  requires that key at startup. Neither one-time first-scan funding nor a
  customer-funded intelligence adapter is implemented.
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
  MCP code is not there yet. PAT issuance and resolution use the central
  product-access gate. The public MCP server exposes read tools plus task
  polling and proposal submission; it has no scan, file-write, merge, or PR
  tools, and every PR still needs its own customer click. Legacy PAT
  scan/PR endpoints return 403 until they share durable admission and a
  separate approval receipt. Distribution and agent-intelligence callbacks
  remain unverified; do not describe native-agent parity as shipped.
- No agent-intelligence connector currently returns bounded code-navigation
  evidence to the graph. Existing MCP tools expose ShipLock facts/actions to an
  agent; they do not make the customer's agent ShipLock's autonomous worker.
  There is no customer-key funding separation, ChatGPT result callback, or
  proven recurring customer-funded AI path. `app/api/audit/route.ts` enqueues
  through the existing access gate; it does not enforce the new once-per-account
  first-scan entitlement or free/paid feature matrix.
- `supabase/migrations/` is the schema/RLS source. Production has every
  migration through 078 (released 2026-09-23 with its code; each stored
  statement is md5-verified against its file). Any newer file is local until
  released the same way. `docs/CORPUS.json`, `scripts/corpus.cjs`, and dated evaluation JSON
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

New migrations and working packages still require deployment-grade
verification (hosted grants, advisors, smoke) before production use; the
local PGlite suite does not prove hosted behavior. Remaining master work includes connection
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
  item; update `docs/MASTER-PLAN-PROGRESS.md` for every coherent repository
  change before handoff or commit, even if the step remains partial or the
  change is documentation-only. Include the date, changed behavior,
  verification, unfinished sibling items, and next reviewable action. This is
  the only project Markdown file an agent is required to change per step.
  A package is not a finished phase. Preserve unrelated working-tree changes.
- Keep `AGENTS.md` as deep, stable product/architecture/implementation context.
  Do not edit it for routine progress, and do not change it at all without
  Felipe's explicit approval, an explicit request to edit it, or his explicit
  change to the product plan that requires reconciliation. Report any such edit.
- Execute one numbered reviewable item at a time. Before starting, announce its
  number, intended outcome, and scope. Before moving to another item, update the
  master ledger and report completed versus partial/blocked work. Never silently
  skip an unfinished prerequisite or mark a phase complete from a substep.
- Agents have implementation freedom inside the approved contract: choose
  helpers, tests, and proven-dead-code cleanup without asking for every detail.
  Record meaningful design/deletion decisions and reasons. New/reordered future
  items may be added to the ledger only with an explicit report of scope and
  dependencies; product/approval/spend changes still require Felipe's decision.
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

The four checked-in, self-contained skill entry points live only in
`.agents/skills/`. Read and apply both Ponytail and Superpowers on **every
implementation**, including cleanup and documentation changes. Read their full
`SKILL.md` files, not just their names. Use GStack for security-sensitive diff
review, higher-risk QA, or an explicit review request; use Ruflo only for
explicitly authorized parallel-agent coordination. Codex discovers this skill
directory; Claude Code's new `AGENTS.md` support does not by itself establish
automatic discovery of
`.agents/skills/`, so Claude must follow these paths and read the selected
skill files. No repo-local `.claude` directory or duplicate tree is needed.

- Ponytail (`.agents/skills/ponytail/SKILL.md`): scoped cleanup after tracing
  callers; preserve security boundaries.
- Superpowers (`.agents/skills/superpowers/SKILL.md`): planning, root-cause
  debugging, test-first changes, and fresh verification within this repo's
  two-document rule.
- GStack (`.agents/skills/gstack/SKILL.md`): a repo-safe review subset, not the
  upstream runtime. No setup, auto-update, telemetry, paid tests, or external
  mutation by default.
- Ruflo (`.agents/skills/ruflo/SKILL.md`): optional coordination only with
  explicit delegation and an already-installed CLI; no package installation
  or autonomous swarm is required for ShipLock.

Upstream GitHub GStack and Ruflo source downloads on Felipe's machine are
optional user-level tools, not repository dependencies. A downloaded skill is
not proof its CLI is installed, and neither agent may silently activate it.

## Documentation hygiene and handoff

Maintain a single active handoff near the top of the master ledger: date, active
step/item, completed changes, unfinished siblings, changed files, actual test
results (including failures/skips), decisions, blockers, and exact next action.
At takeover, reconcile that record with Git status/diff before editing. Claude
and Codex work sequentially against the same record; do not overwrite the
previous agent's unfinished work or infer completion from its last message.

`AGENTS.md` is stable policy and code orientation; the master ledger is dynamic
status and the exact next package. These are the only two non-skill Markdown
files in the repo. Change this file only under Felipe's authority described above;
write all ordinary implementation progress to the master ledger. Date every
master-ledger update; identify the exact section/step/item finished,
evidence/tests, incomplete sibling items, and next
reviewable action. A locally completed package does not close a step with live
acceptance still open. Keep older measurement inputs as JSON/source and, for
retired narrative, use Git history rather than a parallel README/spec/handoff.
Completed steps may be compacted out of the active queue only after their key
proof and remaining caveats are retained in the ledger; do not erase unfinished
2/3/4 work just because a later step started.
Do not create any additional project Markdown without Felipe's explicit request.
Keep all other project Markdown out of the repo, including a second agent
guide, generated handoff notes, and a repo-local `.claude` tree. Skill Markdown
under `.agents/skills/` is the sole exception.
