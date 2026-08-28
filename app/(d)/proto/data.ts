// Mock data for the product prototype. Nothing here talks to a server —
// every screen under /proto is a sketch of the experience, driven by this file
// plus client state in store.tsx.

export type Severity = "critical" | "high" | "medium" | "low";
export type Confidence = "proven" | "corroborated" | "inferred";
export type FixKind = "pr" | "one_click" | "manual";

export interface ChainNode {
  label: string;
  detail: string;
  broken?: boolean;
}

export interface AttackPath {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  /** One sentence a non-security founder can act on. */
  consequence: string;
  chain: ChainNode[];
  blastRadius: string;
  evidenceFile: string;
  evidence: string;
  proof?: string;
  reasoning: string[];
  fixKind: FixKind;
  fixTitle: string;
  fixDiff: string;
  firstSeen: string;
  status: "open" | "fixing" | "fixed";
}

export const PATHS: AttackPath[] = [
  {
    id: "p-invoices-tenant",
    title: "Any signed-in user can read every workspace's invoices",
    severity: "critical",
    confidence: "proven",
    consequence:
      "One customer's account is enough to pull the billing history, legal names and addresses of all 1,140 workspaces.",
    chain: [
      { label: "GET /api/invoices/[id]", detail: "app/api/invoices/[id]/route.ts:14" },
      { label: "auth() — Clerk", detail: "identity resolved: userId present" },
      { label: "no org scope", detail: "orgId never compared to invoice.workspaceId", broken: true },
      { label: "invoices", detail: "41,882 rows · 9 PII columns", broken: true },
    ],
    blastRadius: "41,882 rows across 1,140 workspaces · name, email, address, last4, amount",
    evidenceFile: "app/api/invoices/[id]/route.ts:14",
    evidence: `export async function GET(req, { params }) {
  const { userId } = await auth();
  if (!userId) return new Response("Unauthorized", { status: 401 });

  // ← authenticated, but never scoped to the caller's workspace
  const invoice = await db.query.invoices.findFirst({
    where: eq(invoices.id, params.id),
  });
  return Response.json(invoice);
}`,
    proof:
      "Replayed on a disposable copy of your schema seeded with two synthetic workspaces. Signed in as workspace A, requested an invoice belonging to workspace B: 200 OK, full row returned. Your own data was never read.",
    reasoning: [
      "Route is exported from app/api/invoices/[id]/route.ts and is reachable without a machine gate (no cron secret, no HMAC).",
      "auth() from @clerk/nextjs resolves a USER identity — so this is not an anonymous hole, it is a horizontal one.",
      "The Drizzle query filters on the path parameter alone. No column in the where clause belongs to the caller.",
      "invoices.workspaceId exists in schema.ts:88 and is used by 6 other routes — so the scoping convention exists and this route misses it.",
      "The table carries columns matching our PII patterns (email, address_line1, card_last4).",
    ],
    fixKind: "pr",
    fixTitle: "Scope the invoice lookup to the caller's active organisation",
    fixDiff: `  const { userId, orgId } = await auth();
  if (!userId) return new Response("Unauthorized", { status: 401 });
+ if (!orgId) return new Response("Forbidden", { status: 403 });

  const invoice = await db.query.invoices.findFirst({
-   where: eq(invoices.id, params.id),
+   where: and(
+     eq(invoices.id, params.id),
+     eq(invoices.workspaceId, orgId),
+   ),
  });
+ if (!invoice) return new Response("Not found", { status: 404 });`,
    firstSeen: "Found in the first audit",
    status: "open",
  },
  {
    id: "p-stripe-webhook",
    title: "The Stripe webhook trusts unsigned payloads",
    severity: "critical",
    confidence: "corroborated",
    consequence:
      "Anyone who knows the URL can POST a fake checkout.session.completed and hand themselves a paid plan — or cancel a real customer's.",
    chain: [
      { label: "POST /api/webhooks/stripe", detail: "app/api/webhooks/stripe/route.ts:9" },
      { label: "no signature check", detail: "stripe.webhooks.constructEvent never called", broken: true },
      { label: "subscriptions", detail: "write · plan, status, seats", broken: true },
      { label: "entitlements", detail: "gates every paid feature", broken: true },
    ],
    blastRadius: "Write access to billing state for every account, unauthenticated",
    evidenceFile: "app/api/webhooks/stripe/route.ts:9",
    evidence: `export async function POST(req: Request) {
  const event = await req.json();          // ← parsed, never verified

  if (event.type === "checkout.session.completed") {
    await db.update(subscriptions)
      .set({ status: "active", plan: event.data.object.metadata.plan })
      .where(eq(subscriptions.workspaceId, event.data.object.client_reference_id));
  }
  return Response.json({ received: true });
}`,
    reasoning: [
      "stripe is a direct dependency (package.json) and STRIPE_WEBHOOK_SECRET is declared in .env.example — the secret exists and is unused.",
      "No call to stripe.webhooks.constructEvent anywhere in the repository.",
      "The handler performs a write keyed entirely on attacker-supplied JSON.",
      "The route is not covered by middleware.ts's matcher, so no upstream gate compensates.",
    ],
    fixKind: "pr",
    fixTitle: "Verify the Stripe signature before trusting the event",
    fixDiff: `- const event = await req.json();
+ const sig = req.headers.get("stripe-signature");
+ if (!sig) return new Response("Missing signature", { status: 400 });
+ let event: Stripe.Event;
+ try {
+   event = stripe.webhooks.constructEvent(
+     await req.text(), sig, process.env.STRIPE_WEBHOOK_SECRET!,
+   );
+ } catch {
+   return new Response("Invalid signature", { status: 400 });
+ }`,
    firstSeen: "Found in the first audit",
    status: "open",
  },
  {
    id: "p-db-url-client",
    title: "Your database URL is reachable from a client component",
    severity: "high",
    confidence: "corroborated",
    consequence:
      "DATABASE_URL is pulled into the browser bundle by the import graph. A visitor can read it from the shipped JavaScript.",
    chain: [
      { label: "components/UsageChart.tsx", detail: '"use client"' },
      { label: "lib/analytics/usage.ts", detail: "server-only helper, imported anyway" },
      { label: "lib/db/admin.ts", detail: "reads process.env.DATABASE_URL", broken: true },
      { label: "Neon Postgres", detail: "full read/write, bypasses every app check", broken: true },
    ],
    blastRadius: "Direct connection to production Postgres, no application checks in the way",
    evidenceFile: "components/UsageChart.tsx → lib/db/admin.ts:4",
    evidence: `components/UsageChart.tsx        "use client"
  └─ lib/analytics/usage.ts        (no "server-only" guard)
       └─ lib/db/admin.ts:4
            const pool = new Pool({
              connectionString: process.env.DATABASE_URL,
            })`,
    reasoning: [
      "Next.js bundles the whole module graph reachable from a client component — the client file itself never mentions the key, which is why this is invisible in review.",
      "lib/db/admin.ts reads a non-NEXT_PUBLIC env var, so the bundler inlines it at build time.",
      "No 'server-only' import guards the chain at any hop.",
    ],
    fixKind: "pr",
    fixTitle: "Cut the client→admin import and add a server-only guard",
    fixDiff: `+ import "server-only";
  import { Pool } from "pg";

  // components/UsageChart.tsx
- import { getUsage } from "@/lib/analytics/usage";
+ // usage is now passed in as a prop from the server component`,
    firstSeen: "Found in the first audit",
    status: "open",
  },
  {
    id: "p-upload-sign",
    title: "Upload signing lets a user write into any workspace's folder",
    severity: "high",
    confidence: "inferred",
    consequence:
      "The signed S3 URL is generated from a client-supplied key, so a user can overwrite another workspace's documents.",
    chain: [
      { label: "POST /api/uploads/sign", detail: "app/api/uploads/sign/route.ts:11" },
      { label: "auth() — Clerk", detail: "identity resolved" },
      { label: "key from request body", detail: "no prefix check against orgId", broken: true },
      { label: "S3 · ll-documents", detail: "putObject on any path", broken: true },
    ],
    blastRadius: "Write to any object in the documents bucket",
    evidenceFile: "app/api/uploads/sign/route.ts:11",
    evidence: `const { key, contentType } = await req.json();
const url = await getSignedUrl(s3, new PutObjectCommand({
  Bucket: process.env.S3_BUCKET,
  Key: key,               // ← "workspaces/<any-org>/contract.pdf"
  ContentType: contentType,
}), { expiresIn: 900 });`,
    reasoning: [
      "The object key comes straight from the request body with no validation.",
      "Other upload paths in the repo prefix keys with `workspaces/${orgId}/`, so the convention exists and this route skips it.",
      "Marked inferred, not proven: we have not observed a cross-workspace write, and your bucket policy may compensate in a way we cannot read from the code alone.",
    ],
    fixKind: "pr",
    fixTitle: "Derive the object key server-side from the caller's organisation",
    fixDiff: `- const { key, contentType } = await req.json();
+ const { filename, contentType } = await req.json();
+ const { orgId } = await auth();
+ const key = \`workspaces/\${orgId}/\${crypto.randomUUID()}-\${safe(filename)}\`;`,
    firstSeen: "Found in the first audit",
    status: "open",
  },
  {
    id: "p-enumeration",
    title: "Invoice IDs are sequential and the endpoint is unthrottled",
    severity: "medium",
    confidence: "inferred",
    consequence:
      "Once the scoping bug above is fixed this stops mattering much — until then it is the multiplier that turns one leak into all of them.",
    chain: [
      { label: "invoices.id", detail: "serial primary key · schema.ts:84" },
      { label: "GET /api/invoices/[id]", detail: "no rate limit middleware" },
    ],
    blastRadius: "Whole-table walk in minutes",
    evidenceFile: "lib/db/schema.ts:84",
    evidence: `export const invoices = pgTable("invoices", {
  id: serial("id").primaryKey(),      // ← guessable
  workspaceId: text("workspace_id").notNull(),
  ...
});`,
    reasoning: [
      "Primary key is a serial, not a uuid — adjacent records are trivially addressable.",
      "No rate-limiting wrapper or middleware matcher covers /api/invoices.",
    ],
    fixKind: "manual",
    fixTitle: "Move to opaque public identifiers (schema change — your call)",
    fixDiff: `// Suggested, not applied: add a uuid public_id column, expose that,
// keep the serial internally. Migration touches read paths in 6 files.`,
    firstSeen: "Found in the first audit",
    status: "open",
  },
];

export const RESOLVED = [
  { id: "r1", title: "Public read on the ll-avatars bucket", closedBy: "PR #412", when: "6 days ago" },
  { id: "r2", title: "Debug route /api/_admin/reset reachable in production", closedBy: "PR #408", when: "11 days ago" },
  { id: "r3", title: "next-auth 4.24.5 — CVE-2025-29927 middleware bypass", closedBy: "PR #401", when: "3 weeks ago" },
];

/* ── the stack, read out of the code ── */
export interface StackItem {
  name: string;
  role: string;
  glyph: string;
  evidence: string;
  depth: "read" | "reasoned" | "offer";
  note: string;
}

export const STACK: StackItem[] = [
  { name: "Next.js 15", role: "Framework · App Router", glyph: "▲", depth: "read",
    evidence: "package.json · next@15.4.2 · 63 route handlers found",
    note: "Every route handler enumerated, with its guards and the tables it reaches." },
  { name: "Clerk", role: "Authentication", glyph: "◈", depth: "reasoned",
    evidence: "@clerk/nextjs · auth() at 41 call sites · middleware.ts matcher",
    note: "We know which routes resolve a user, which resolve an organisation, and which resolve nothing." },
  { name: "Neon Postgres", role: "Database · Drizzle ORM", glyph: "◉", depth: "reasoned",
    evidence: "lib/db/schema.ts · 24 tables, 6 with PII-shaped columns",
    note: "Schema read from your migrations. Connect the database read-only to upgrade findings from reasoned to proven." },
  { name: "Stripe", role: "Payments", glyph: "$", depth: "reasoned",
    evidence: "stripe@17 · 1 webhook handler · 4 write paths into subscriptions",
    note: "Webhook verification, price-id trust, and entitlement writes are all checked." },
  { name: "AWS S3", role: "File storage", glyph: "▤", depth: "reasoned",
    evidence: "@aws-sdk/client-s3 · 2 buckets referenced · 3 signing routes",
    note: "Bucket policy itself is not visible from the code — that part is inferred and labelled." },
  { name: "Upstash Redis", role: "Cache · rate limiting", glyph: "◍", depth: "read",
    evidence: "@upstash/ratelimit imported in 2 of 63 routes",
    note: "We can tell you exactly which 61 routes are unthrottled." },
  { name: "Inngest", role: "Background jobs", glyph: "⟳", depth: "read",
    evidence: "inngest/client.ts · 11 functions · 1 unsigned entry point",
    note: "Background workers are routes too, and they usually run with more privilege." },
  { name: "OpenAI", role: "LLM calls", glyph: "✳", depth: "read",
    evidence: "openai@4 · 3 call sites · 1 builds a prompt from request body",
    note: "Prompt-injection reachable surfaces are enumerated, not scored." },
  { name: "Vercel", role: "Hosting", glyph: "◭", depth: "offer",
    evidence: "vercel.json present · 4 cron entries",
    note: "Optional. Connecting it would let us read env var names and preview-deploy protection." },
];

/* ── the agent run trace ── */
export interface TraceStep {
  t: string;
  icon: string;
  body: string;
  note?: string;
  found?: boolean;
}

export const TRACE: TraceStep[] = [
  { t: "00:00", icon: "◇", body: "Cloned ledgerloop/app at 4f1e9c2", note: "1,412 files · 138k lines · read-only checkout" },
  { t: "00:04", icon: "◇", body: "Identified the stack from manifests and imports", note: "Next.js 15 · Clerk · Drizzle/Neon · Stripe · S3 · Upstash · Inngest" },
  { t: "00:11", icon: "◈", body: "Enumerated 63 route handlers and 11 background functions", note: "Follows re-exports and helper wrappers two hops deep" },
  { t: "00:19", icon: "◈", body: "Classified the guard on each entry point", note: "38 resolve a user · 9 resolve an organisation · 12 machine-gated · 4 open by design" },
  { t: "00:26", icon: "◉", body: "Read the schema and mapped every table to the routes that touch it", note: "24 tables · 6 carry PII-shaped columns" },
  { t: "00:33", icon: "⚑", body: "GET /api/invoices/[id] resolves a user but never compares it to invoice.workspaceId", found: true },
  { t: "00:35", icon: "↳", body: "Checked the other 6 routes reading invoices — all scope by workspaceId", note: "So this is a miss, not a convention we misread" },
  { t: "00:41", icon: "⚑", body: "POST /api/webhooks/stripe parses the body without constructEvent", found: true },
  { t: "00:48", icon: "◈", body: "Walked the client import graph for server-only values", note: "312 modules reachable from 'use client' entry points" },
  { t: "00:52", icon: "⚑", body: "DATABASE_URL reachable from components/UsageChart.tsx", found: true },
  { t: "01:06", icon: "▣", body: "Built a disposable copy of your schema with two synthetic workspaces", note: "No production data copied. Your database was never read." },
  { t: "01:14", icon: "✓", body: "Replayed the invoice request as workspace A against workspace B's row: 200 OK", note: "Cross-tenant read reproduced — this finding is now proven, not inferred", found: true },
  { t: "01:19", icon: "✓", body: "Applied the candidate fix to the copy and replayed: 404. Legitimate read still 200.", note: "Fix validated on both gates before it was offered to you" },
  { t: "01:24", icon: "◇", body: "Torn down the copy", note: "5 paths open · 3 previously reported now resolved" },
];

/* ── pull requests ── */
export const PULLS = [
  { n: 431, title: "feat: bulk invoice export", author: "mara", state: "blocked",
    verdict: "Adds GET /api/invoices/export with the same missing org scope as path #1.", when: "12 min ago" },
  { n: 430, title: "chore: bump drizzle-orm to 0.44", author: "dependabot", state: "clear",
    verdict: "No new reachable surface. Advisory diff clean.", when: "2 hours ago" },
  { n: 429, title: "fix: scope invoice lookup to org", author: "shiplock", state: "ours",
    verdict: "Opened by ShipLock. Validated on a disposable copy before it was raised.", when: "3 hours ago" },
  { n: 428, title: "feat: document uploads v2", author: "tom", state: "warned",
    verdict: "New signing route reuses the client-supplied key pattern. Flagged, not blocking.", when: "yesterday" },
  { n: 427, title: "refactor: extract billing helpers", author: "mara", state: "clear",
    verdict: "Guards preserved across the move. No path changed.", when: "yesterday" },
];

/* ── plans ── */
export interface ProtoPlan {
  id: string;
  name: string;
  monthly: number;
  annualMonthly: number;
  who: string;
  limits: string[];
  features: string[];
  cogs: number;
  featured?: boolean;
  cta: string;
}

export const PROTO_PLANS: ProtoPlan[] = [
  {
    id: "solo", name: "Solo", monthly: 129, annualMonthly: 99,
    who: "One founder, one repo, first customers.",
    limits: ["1 repository, up to 50k lines", "30 pull-request audits / month", "Deep re-audit weekly"],
    features: ["Attack paths with evidence", "Fix pull requests", "Shareable posture report"],
    cogs: 22, cta: "Start free audit",
  },
  {
    id: "startup", name: "Startup", monthly: 399, annualMonthly: 319,
    who: "Seed to Series A. Two to eight engineers shipping daily.",
    limits: ["5 repositories, up to 250k lines", "200 pull-request audits / month", "Deep re-audit every 48 hours"],
    features: ["Everything in Solo", "Proof runs on a disposable copy of your schema", "PR status check that can block a merge", "Security questionnaire answers, generated", "Slack alerts"],
    cogs: 62, featured: true, cta: "Start free audit",
  },
  {
    id: "scale", name: "Scale", monthly: 999, annualMonthly: 849,
    who: "Series A/B. Multiple services, a compliance deadline, a named security owner.",
    limits: ["20 repositories, up to 1.5M lines", "750 pull-request audits / month", "Deep re-audit daily"],
    features: ["Everything in Startup", "SSO and audit log", "SOC 2 evidence export", "Custom policy rules", "Shared Slack channel, 1 business day"],
    cogs: 212, cta: "Start free audit",
  },
  {
    id: "enterprise", name: "Enterprise", monthly: 2500, annualMonthly: 2500,
    who: "Regulated, self-hosted, or more than 20 repositories.",
    limits: ["Unlimited repositories", "Volume-priced audits", "Self-hosted runner option"],
    features: ["Everything in Scale", "Named engineer", "Contractual SLA and DPA", "Runs inside your own cloud"],
    cogs: 560, cta: "Talk to us",
  },
];

/* Marginal unit costs behind the sizing calculator on /proto/pricing. */
export const UNIT = {
  deepAuditPerLine: 0.00014,   // agentic pass, cache-heavy
  prAudit: 0.35,               // diff-scoped reasoning
  proofRun: 0.10,              // disposable schema copy
  platformPerRepo: 1.6,        // clone, index, storage
  supportPerSeat: 1.2,
};
