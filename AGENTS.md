<!-- BEGIN:nextjs-agent-rules -->
# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may
all differ from training data. Read the relevant guide in
`node_modules/next/dist/docs/` before changing framework behavior. Heed
deprecation notices.
<!-- END:nextjs-agent-rules -->

# ShipLock product and architecture contract

This file is the short, binding product contract. `CLAUDE.md` describes verified
implementation detail. `docs/MASTER-PLAN-PROGRESS.md` records execution status.
Current code and executable tests outrank prose when they disagree; fix the
prose in the same change rather than preserving two stories.

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

Pricing is undecided. Billing is parked while unit costs are measured. Do not
publish or restore a price, trial, paid tier, Stripe Checkout entry point, or
margin claim until Felipe approves a cost model based on measured model tokens,
provider calls, storage, queue execution, support, and target gross margin. The
old $49/$265/$470 offer and later prototype tiers are superseded.

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
not replace them with a greenfield subsystem.

Migrations 053–058 and the current working packages require deployment-grade
verification before production use. Remaining master work includes connection
epochs and traffic binding, a production always-on worker plus migration of all
producers, provider evidence contracts, safe proof execution, detection quality,
the approval/repair loop, continuous monitoring, native-agent polish, traffic
recommendations, and measured scale/economics. Exact status lives only in
`docs/MASTER-PLAN-PROGRESS.md`.

## Felipe's working agreement

- Address the user as Felipe in every response.
- Work only in ShipLock-v2 unless Felipe explicitly expands scope.
- Never spend money, purchase or activate a subscription, call a paid model/API,
  or deploy billable infrastructure without Felipe's explicit approval. Prefer
  local tests, fixtures, emulators, and mocked providers.
- Keep changes small and reviewable. Report the master section, step, and item;
  update `docs/MASTER-PLAN-PROGRESS.md`. A package is not a finished phase.
- Read `CODEX.md` and the relevant current code before editing. Preserve
  unrelated working-tree changes and review the diff before every handoff.
- Before a commit, run focused tests and then the proportional full gate:
  `npx vitest run`, `npm run lint`, `npx tsc --noEmit`, and `npm run build`.
  Database changes also require the local SQL suite. Do not commit a failing
  gate or hide a skipped check.
- Do not deploy, apply migrations remotely, alter GitHub/provider settings,
  merge PRs, or push to a remote unless Felipe explicitly requests it.

## Documentation hygiene

Do not create a handoff Markdown file for every substep. Put durable product and
architecture decisions here, implementation facts in `CLAUDE.md`, dated research
or measurement under `docs/`, and progress in
`docs/MASTER-PLAN-PROGRESS.md`. Pricing experiments, prototypes, and superseded
plans must be clearly marked as historical or removed; they are not alternative
specifications.
