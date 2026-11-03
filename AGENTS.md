# This is NOT the Next.js you know

This version has breaking changes. Read the relevant guide in
`node_modules/next/dist/docs/` before changing framework behavior. Heed
deprecation notices.

# ShipLock contract

The stable product, architecture and working contract. Status lives only in
`docs/MASTER-PLAN-PROGRESS.md` (the ledger), a local file git ignores: it
names production state and is never published. Code and executable tests decide
implementation truth; if they conflict with this file, report it and ask
Felipe before editing here. Claude Code is the only agent; it reads this file
and the ledger fully before any work.

## Product

ShipLock is the security harness for a growing startup without a security
team. It points the customer's own intelligence at security. The first buyer
is a founder, technical or not: every claim states consequence, evidence and
the next safe action, and the evidence stays open for a strong engineer to
challenge.

**The loop** (Felipe 2026-10-06), each stage shown live with its real state,
pending never shown as done:

| Stage | What happens |
|---|---|
| Read | Every deterministic check on the repository |
| Attack | The customer's agent proposes concrete attacks; each is checked against quoted lines, and where possible replayed on a disposable replica with synthetic data |
| Map | What reaches what: wrong routes only, and the tables, providers and hot routes they reach |
| Fix | A reviewable PR or an agent handoff, on a customer click, with a receipt |
| Watch | Rechecks, PR checks, traffic and live provider context |

**The thesis** (2026-09-29): some risks are invisible in code alone. ShipLock
joins what the code says, what the live stack is configured to do, and what
traffic hits. Repository-only scanning is table stakes, not the product.

**Locked decisions**

| Decision | Rule |
|---|---|
| No paid intelligence (2026-10-01) | ShipLock makes no model call, holds no model key, offers no API-key mode. The intelligence is the customer's agent over MCP (or an approved OpenAI partner connector) on their subscription. Guardrails `model-clients`, `model-keys` |
| Confirmed only (2026-10-07) | Only confirmed issues (quoted proof, replica proof, live fact, observed traffic) set Exposed or At risk. Code-pattern signals are "To review" |
| Attack safely | Sandbox only: the agent reading code and disposable replicas. Production is never attacked; no destructive, persistence or availability tests; no third-party targets |
| External tools | Strix-style agents and scanners run on the customer's side; their claims are admitted only after ShipLock re-reads the cited code |
| Any stack | Every inferred provider is named; a live connection is offered only where a collector exists, otherwise "Live connection coming soon" |
| Every write is a click, or the customer's agent | Each branch or PR write needs its own customer click and receipt, except where the customer turned on agent pull requests for that repository in the dashboard after acknowledging the risks (Felipe 2026-10-15): then their own agent may request the same allowlisted fix over MCP, with the same queue, cap and receipt naming the grant. Only the dashboard grants it, never a token. A code PR also needs an allowlisted mechanical change, current evidence, and tests or CI (else an explicit unverified label). A suggestion is not proof it cannot break production. ShipLock never merges or deploys |
| Packaging | Free and Pro, unpriced; billing stays off until Felipe sets a price. Free: inventory, deterministic findings, bounded rechecks. Pro: provider connections, cross-layer proof, traffic, email alerts on a meaningful new state only. Never buy a customer or provider plan to make a claim |

**Customer agent as transport.** A passive MCP server cannot wake a dormant
agent, so tasks wait visibly as pending. No host is marketed as working until
it returns schema-validated, scoped evidence to the same guarded graph. Agent
output is untrusted input: it never overrides source identity, deterministic
admission or approval. Offline agent means AI work is pending or unread,
never clean.

**Market.** Initial ICP: founders of small GitHub-based Next.js/Supabase SaaS
teams. Scanning plus AI repair is not differentiation (GitHub Code Security,
Codex Security already do it). The hypothesis is that bound provider config
plus repository and traffic evidence finds actionable cross-layer issues.
Never claim a competitor lacks a capability without testing that comparison
on the same repositories. Pilots measure setup completion, incremental
confirmed findings, false alarms, time to reviewed fix, repeat use,
willingness to pay and hosted cost.

## Customer journey

Sign in → install the GitHub App → select a repository (stack inferred, never
asked) → first audit, every deterministic check, unread shown as unread →
connect your own agent over MCP (offered to everyone) → PR and scheduled
rechecks → optional provider connections and the traffic snippet (Pro) →
reviewable fixes on a click → recheck. Each step says what it unlocks and
works without the later ones. First value under ten minutes with GitHub only.

## Evidence

- Collectors are read-only adapters returning a typed snapshot with: tenant
  and subject scope, collector and transport, observation time and immutable
  source identity, connection epoch or opaque fingerprint, completeness and
  why something was not read, provenance, and no secret or application-row
  value.
- Fact states are distinct: observed, inferred, unknown or unreadable,
  corroborated, proven. "Absent" is never "checked and absent". Partial
  evidence may warn but never retires a prior finding.
- Stack inference is deterministic and never creates a binding. A join needs
  the selected repository, a current connection and a provider-issued link or
  customer confirmation. Disconnect, rotation or reselection invalidates
  stale correlation.
- Models propose; deterministic guards decide admission, severity ceilings,
  citations and allowed actions. Model failure, timeout, malformed or skipped
  output is a coverage state, never clean. A model is never called
  deterministic.
- Every agent host returns the same contract: tenant, repository and commit,
  run and attempt, host, connection epoch, citations, structured hypotheses,
  usage when available, completeness or failure. The server validates all of
  it before persistence.
- Proof distinguishes "could test", "test ran" and "reproduced". Only
  `lib/proving/` earns `proven`.

## Boundaries

| Area | Rule |
|---|---|
| Traffic | Never passes through ShipLock (not a proxy or WAF). The customer-side snippet sends minimized metadata and counts, never bodies, credentials or end-user data. ShipLock recommends; any enforcement is installed by the customer after approval, with rollback |
| Customer data | Never read application rows. Schema, policy definitions, counts and synthetic replica data only |
| Claims | Never say an account or app is secure. Say what was read, found, reproduced, and what is unknown |
| Third parties | Never require a customer to buy a plan for a core claim; degrade honestly |
| Business policy | Authorization and business-policy changes need human judgment and are never machine-authored as mechanical |

## Runtime and storage

The web tier authenticates, checks ownership, renders and enqueues. Durable
workers run leased jobs with idempotency keys, bounded retries, heartbeats,
fencing and per-tenant fairness. Webhooks and schedules enqueue the same
contracts. No worker calls a model; credentials are encrypted references,
never job payloads. Postgres/Supabase is the system of record: RLS plus
tenant-bound foreign keys on tenant rows, service-only tables deny client
roles, snapshots are append-oriented, terminal transitions are transactional
and fenced. No capacity claim (the target is 50,000 accounts) without
measured load.

## Benchmarks

Freeze identities, populations, prompts and budgets before any detector
change. Report TP, FP, FN, precision, recall, false criticals, unread
coverage, sample size and uncertainty; a zero denominator is unavailable, not
100%. Held-out labels only; thresholds are set before the run, never after.
Results are JSON under `docs/evaluation/`. Per-repository labels and run
extracts of third-party code never enter the tree: findings in other
people's projects are unreported, so only manifests, plants and aggregates
are published. System benchmarks name workload and environment. Paid runs need Felipe's approval.

## Code map

| Path | Role |
|---|---|
| `app/(d)/` | Live founder UI: onboarding, dashboard (risks, activity, prs, coverage, stack, settings) via `lib/dashboard.ts`; `/verified/[token]` report |
| `app/api/audit`, `lib/jobs/` | Audit enqueue; typed leases, fencing, retries, workers |
| `app/api/monitor/github` | Signed webhook; admits audits and PR checks, fails for a safe retry |
| `lib/deep/repoArchive.ts`, `githubRun.ts` | Bounded archive and per-file reads; truncation is coverage |
| `lib/agent/stack.ts`, `lib/graph/{routeInventory,callPath,declarations,methodRefusal}.ts` | Stack inference and Next.js route facts (no control-flow graph) |
| `lib/agent/{attackGuard,findings,confirmed}.ts` | Hypothesis guard, confidence and ceilings, the one `confirmed` flag |
| `lib/intelligence/reasoning.ts` | Audit to attack task, quoted-proof verification, admission for the newest audit |
| `lib/monitoring/`, `lib/graph/` | Provider collectors, scoped facts, bound correlation |
| `lib/agent/{prCheck,diffScan}.ts`, `lib/fixes/prRun.ts` | PR verdicts (partial never green); clicked, receipted PRs |
| `lib/traffic/`, `/api/traffic/*` | Customer-side metadata observation |
| `mcp/`, `/api/mcp/*` | Read tools, task polling, proposal submission, and a fix PR request that works only under the customer's agent pull request grant; no scan, file write or merge tool |
| `scripts/corpus.cjs`, `scripts/corpusModel.ts`, `lib/eval/` | Developer harness; the only place model calls exist, never product code |
| `supabase/migrations/` | Schema and RLS source; released only with Felipe's OK, md5-verified |

A file existing is not proof a production path calls it: trace producer,
worker, UI and consumer before claiming a capability.

## Security invariants (tests enforce; never weaken one to pass)

| Invariant | Enforced by |
|---|---|
| Contract rules | `.agents/guardrails.json` via `lib/security/repoGuardrails.test.ts`; a reviewed exception is a pinned file |
| Central access gate; billing off does not open source access | `lib/access.ts` |
| aal2 for any user with a verified factor; factors from the auth server; unreadable fails closed | `lib/mfa.test.ts`, `lib/dashboard.session.test.ts`, `lib/deep/proGate.test.ts`, `app/api/tokens/route.test.ts` |
| No model SDK, host or key in product code | `lib/security/modelFunding.test.ts` |
| Every PR needs a receipt from a click or the customer's dashboard grant; only the dashboard grants | `lib/security/prWrites.test.ts`, `app/api/mcp/approvalBoundary.test.ts` |
| Proofs need their own authorization and run only on the replica | `lib/proving/embeddedHost.test.ts` |
| Cookie mutations refuse cross-site requests | `lib/security/sameOrigin.routes.test.ts` |
| Email off while the switch is off | `lib/monitoring/emailKillSwitch.test.ts` |
| A partial PR check never shows passed | `components/v3/CheckedPullRequests.test.tsx` |
| The status never says secure | `lib/verdict.test.ts` |
| Read-only provider SQL; SSRF guard on customer hosts; signed, idempotent webhooks; encrypted or hashed tokens; per-request CSP in `proxy.ts` | `lib/deep/{supabaseMgmt,postgresDirect}.ts`, `lib/security/ssrfGuard.ts`, `lib/crypto.ts`, `lib/apiTokens.ts` |

Before changing a security fact: list every consumer and the false-positive
and false-negative direction, freeze the affected census, add negative
fixtures, rerun the offline corpus.

## Interface and copy

- Founder first: consequence, evidence, next safe action in plain words;
  proof one click away. Calm security-engineer voice, no dashes, no AI filler.
- Unread, partial, pending and skipped are shown as such, never as clean.
- Overview: one status (Exposed, At risk, No open issues, Not audited; glyph
  and colour), four metrics (open issues, exposed routes, blocked PRs, not
  checked), the map, the issues table. One view for everyone; detail on click.
- The map: a zoomable Obsidian-style graph, not 3D, of wrong routes only and
  what they reach; red for confirmed critical or an open way to data, yellow
  for weaker exposure; built from audit facts only.
- Feel: like Stripe. Show work as it happens, never a bare spinner. Short noun
  titles, plain labels. Keep the v3 design; build on the live UI, no mocks.
- Learn from Aikido (one verdict, noise hidden), Strix (proof per finding),
  Wiz (code to data graph), Snyk and Semgrep (reachability, PR checks).
- ShipLock PRs are labeled "ShipLock", titled as ShipLock changes, and run
  the customer's own CI.

## Working agreement (Felipe)

- Address him as Felipe. Felipe decides product, pricing, spend, releases and
  approvals; when a decision is his, stop and ask.
- **Engineering freedom:** Claude chooses the route to a ledger goal. Before
  starting, say why this task beats the alternatives, its outcome and scope.
  Claude may propose new goals or challenge existing ones in the ledger.
- Never without Felipe's explicit OK: spend money, call a paid model or API,
  handle secrets, deploy, apply remote migrations, change GitHub or provider
  settings, push, or merge. Push and deploy may be standing approvals he
  states.
- Test first, read real exit codes. Gate before every commit: focused tests,
  `npx vitest run`, `npm run lint`, `npx tsc --noEmit`, `npm run build` (dummy
  env: `NEXT_PUBLIC_SUPABASE_URL=https://example.supabase.co
  NEXT_PUBLIC_SUPABASE_ANON_KEY=dummy SUPABASE_SERVICE_ROLE_KEY=dummy`), and
  `node scripts/test-foundation-sql.mjs` when SQL changed. Never commit red
  or hide a skipped check; the commit message carries the evidence.
- Before handoff: inspect the diff, stale references and leaked secrets.
- Commits are cohesive; the working tree is clean after each. Preserve
  unrelated changes. Subagents do bounded work; Claude reviews it first.
- Edit this file only with Felipe's approval and report the edit.

## Skills

Read the full `SKILL.md`, not the name. The work graph
(`.agents/skills/work-graph/`) routes every task: its nodes, the skill each
uses, Felipe's gates and the anchors; `lib/security/workGraph.test.ts` keeps
it and the skills in step. Every implementation: Ponytail and Superpowers.
Anything a person sees: UI UX Pro plus the design references at
`~/starred-repos/VoltAgent__awesome-design-md/design-md/` (Linear, Sentry,
Vercel; principles, never palettes). Security-sensitive review: GStack.
Metric work: Autoresearch. Parallel agents only when delegated: Ruflo. Tooling
index before building workflow tools:
`~/starred-repos/hesreallyhim__awesome-claude-code/`.

## Documents

Project Markdown is this file, the public `README.md` and the local,
untracked ledger (skill files excepted). The README states only what code
and result files show. The ledger is working memory: goals with why and acceptance,
measured state, the plan, production snapshot, Felipe's steps, decisions waiting. Under
150 lines. Delete what is finished; history is the commit log. Never add another guide,
plan, handoff or `.claude` tree.
