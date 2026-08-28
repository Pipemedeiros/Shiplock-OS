// Demo data for prototype v3. Nothing here reaches a server — every screen is
// driven by this file plus client state in store.tsx.
//
// The model merges the two earlier sketches: typed path nodes and short finding
// codes from /proto-codex, the reasoning depth and fix tiers from /proto, and
// one new element — `claims`, an evidence ledger where every claim carries the
// collector that produced it. See PROTO-V3-SYNTHESIS.md.

export type Severity = "critical" | "high" | "medium";
export type Confidence = "proven" | "corroborated" | "inferred";
export type FixKind = "pr" | "one_click" | "manual";
export type Status = "open" | "fixing" | "fixed";

/** The four kinds of node an attack path can contain. `gap` is the one that failed. */
export type NodeKind = "entry" | "identity" | "gap" | "asset";

/** Where a claim came from. Every claim has exactly one origin — that is the point. */
export type Origin = "routes" | "imports" | "schema" | "policy" | "replica" | "traffic";

export const ORIGIN_LABEL: Record<Origin, string> = {
  routes: "Route inventory",
  imports: "Import graph",
  schema: "Database schema",
  policy: "Database policy",
  replica: "Disposable replica",
  traffic: "Traffic",
};

export interface PathNode {
  kind: NodeKind;
  label: string;
  detail: string;
}

export interface Claim {
  claim: string;
  origin: Origin;
  verified: boolean;
}

export interface Gate {
  label: string;
  detail: string;
  passed: boolean;
}

export interface Risk {
  id: string;
  /** Short code, so a finding can be named in a message to a colleague. */
  code: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  /** One sentence, in the consequence a founder cares about. */
  consequence: string;
  blastRadius: string;
  area: string;
  age: string;
  path: PathNode[];
  claims: Claim[];
  file: string;
  /** The code that is wrong. Evidence is the bug, never the patch. */
  vulnerableCode: string;
  fixKind: FixKind;
  fixTitle: string;
  fixDiff: string;
  gates: Gate[];
  /** Present only when the finding was reproduced on a replica. */
  proof?: string;
  /** Present only when it was not. Never both. */
  notProvenBecause?: string;
  status: Status;
}

/**
 * Confidence is mechanical, not editorial: it is a function of the claims.
 * Proven — a replica claim verified. Corroborated — two or more independent
 * origins verified. Inferred — a single origin, read from code alone.
 */
export function confidenceOf(risk: Risk): Confidence {
  const verified = risk.claims.filter((c) => c.verified);
  if (verified.some((c) => c.origin === "replica")) return "proven";
  return new Set(verified.map((c) => c.origin)).size >= 2 ? "corroborated" : "inferred";
}

export const CONFIDENCE_RULE: Record<Confidence, string> = {
  proven: "Reproduced on a disposable copy of your schema, seeded with synthetic tenants. None of your data was read.",
  corroborated: "Two or more independent readings of your code agree. We did not run it.",
  inferred: "One reading of your code. Something outside the repository could compensate for it.",
};

export const RISKS: Risk[] = [
  {
    id: "invoice-scope",
    code: "SL-184",
    title: "Any signed-in user can read every workspace's invoices",
    severity: "critical",
    confidence: "proven",
    consequence:
      "One customer account is enough to pull the billing history, legal names and addresses of all 1,140 workspaces.",
    blastRadius: "41,882 rows · 1,140 workspaces · name, email, address, card last four",
    area: "Billing",
    age: "11 minutes",
    file: "app/api/invoices/[id]/route.ts:14",
    path: [
      { kind: "entry", label: "GET /api/invoices/:id", detail: "Reachable by anyone with an account" },
      { kind: "identity", label: "Clerk auth()", detail: "Resolves who the caller is" },
      { kind: "gap", label: "No workspace check", detail: "Never compares the caller's workspace to the invoice's" },
      { kind: "asset", label: "invoices", detail: "41,882 rows, 9 personal columns" },
    ],
    claims: [
      { claim: "The route is exported and reachable without a machine gate — no cron secret, no signature.", origin: "routes", verified: true },
      { claim: "auth() resolves a user, so this is a horizontal hole between customers, not an open door.", origin: "routes", verified: true },
      { claim: "The query filters on the URL parameter alone. No column in it belongs to the caller.", origin: "imports", verified: true },
      { claim: "invoices.workspaceId exists and six other routes filter on it. This route is the outlier.", origin: "schema", verified: true },
      { claim: "Signed in as workspace A, a request for workspace B's invoice returned the full row.", origin: "replica", verified: true },
    ],
    vulnerableCode: `export async function GET(req, { params }) {
  const { userId } = await auth();
  if (!userId) return new Response("Unauthorized", { status: 401 });

  // authenticated — but never scoped to the caller's workspace
  const invoice = await db.query.invoices.findFirst({
    where: eq(invoices.id, params.id),
  });

  return Response.json(invoice);
}`,
    fixKind: "pr",
    fixTitle: "Scope the invoice lookup to the caller's workspace",
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
    gates: [
      { label: "The problem reproduces", detail: "Workspace A read workspace B's row", passed: true },
      { label: "The fix stops it", detail: "The same request now returns 404", passed: true },
      { label: "Real access still works", detail: "Workspace A still reads its own invoices", passed: true },
    ],
    proof:
      "Rebuilt your invoices table and its constraints on a disposable copy, seeded two synthetic workspaces, signed in as one and requested the other's invoice. It returned 200 with the full row. Your database was never touched.",
    status: "open",
  },
  {
    id: "webhook-trust",
    code: "SL-179",
    title: "The Stripe webhook trusts payloads it never verifies",
    severity: "critical",
    confidence: "corroborated",
    consequence:
      "Anyone who knows the URL can post a fake completed checkout and grant themselves a paid plan, or cancel a real customer's.",
    blastRadius: "Write access to billing state for every account, with no credential",
    area: "Platform",
    age: "2 hours",
    file: "app/api/webhooks/stripe/route.ts:9",
    path: [
      { kind: "entry", label: "POST /api/webhooks/stripe", detail: "Open to the internet by design" },
      { kind: "gap", label: "No signature check", detail: "constructEvent is never called" },
      { kind: "asset", label: "subscriptions", detail: "Plan, status and seat count" },
    ],
    claims: [
      { claim: "The handler parses the request body before establishing who sent it.", origin: "routes", verified: true },
      { claim: "STRIPE_WEBHOOK_SECRET is declared in .env.example but is read nowhere in the repository.", origin: "imports", verified: true },
      { claim: "The handler writes directly to subscriptions and entitlements.", origin: "schema", verified: true },
    ],
    vulnerableCode: `export async function POST(req: Request) {
  const event = await req.json();   // parsed, never verified

  if (event.type === "checkout.session.completed") {
    await db.update(subscriptions)
      .set({ status: "active", plan: event.data.object.metadata.plan })
      .where(eq(subscriptions.workspaceId, event.data.object.client_reference_id));
  }

  return Response.json({ received: true });
}`,
    fixKind: "pr",
    fixTitle: "Verify the signature before reading the payload",
    fixDiff: `- const event = await req.json();
+ const signature = req.headers.get("stripe-signature");
+ const body = await req.text();
+ let event;
+ try {
+   event = stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET);
+ } catch {
+   return new Response("Invalid signature", { status: 400 });
+ }`,
    gates: [
      { label: "The problem reproduces", detail: "An unsigned payload changed plan state", passed: true },
      { label: "The fix stops it", detail: "The unsigned payload is now rejected with 400", passed: true },
      { label: "Real access still works", detail: "A correctly signed event is still processed", passed: true },
    ],
    notProvenBecause:
      "Reproducing this would mean sending a forged event to your live endpoint, which is your production app. We read it from the code instead, and tested the fix against a local fixture.",
    status: "open",
  },
  {
    id: "client-secret",
    code: "SL-166",
    title: "A database credential can reach the browser bundle",
    severity: "high",
    confidence: "corroborated",
    consequence:
      "A client component imports a server helper that holds your production connection string, so the credential can be bundled into what visitors download.",
    blastRadius: "Direct privileged access to the production database",
    area: "Analytics",
    age: "6 days",
    file: "components/UsageChart.tsx → lib/db/admin.ts:4",
    path: [
      { kind: "entry", label: "Browser bundle", detail: "Anything a visitor can download" },
      { kind: "gap", label: "Server boundary crossed", detail: "A \"use client\" file imports lib/db/admin" },
      { kind: "asset", label: "DATABASE_URL", detail: "Full read and write, no row filtering" },
    ],
    claims: [
      { claim: "components/UsageChart.tsx carries the \"use client\" directive.", origin: "routes", verified: true },
      { claim: "It imports lib/db/admin.ts, three hops down, which reads DATABASE_URL at module scope.", origin: "imports", verified: true },
      { claim: "That connection is not subject to any row filtering — it is the privileged path.", origin: "schema", verified: true },
    ],
    vulnerableCode: `"use client";
import { adminDb } from "@/lib/db/admin";  // ← server-only, three hops down
//                       lib/db/admin.ts:4
//                       const url = process.env.DATABASE_URL;

export function UsageChart({ workspaceId }: Props) {
  // ...
}`,
    fixKind: "manual",
    fixTitle: "Move the query behind a server boundary",
    fixDiff: `  // The mechanical change is small, but where the boundary belongs is a
  // decision about your architecture, so we are not going to guess it:
  //
  //   · a server component that passes rows down as props, or
  //   · a route handler the chart fetches, or
  //   · a server action.
  //
  // Whichever you pick, lib/db/admin must stop being reachable from a
  // "use client" file.`,
    gates: [
      { label: "The problem reproduces", detail: "The import chain resolves from the client file", passed: true },
      { label: "The fix stops it", detail: "Not applicable — no candidate fix to test", passed: false },
      { label: "Real access still works", detail: "Not applicable", passed: false },
    ],
    notProvenBecause:
      "We can prove the import chain exists. Whether your bundler strips it depends on build configuration we cannot see from the repository, so we will not claim the credential shipped.",
    status: "open",
  },
  {
    id: "avatar-bucket",
    code: "SL-152",
    title: "The avatar bucket is listable by anyone",
    severity: "medium",
    confidence: "inferred",
    consequence:
      "Anyone can enumerate every file in ll-avatars, which exposes the set of your users even where the images themselves are harmless.",
    blastRadius: "Filenames in one bucket · 3,410 objects",
    area: "Platform",
    age: "6 days",
    file: "infra/storage.tf:22",
    path: [
      { kind: "entry", label: "Public bucket URL", detail: "No credential required" },
      { kind: "gap", label: "Listing not restricted", detail: "The policy grants list as well as read" },
      { kind: "asset", label: "ll-avatars", detail: "3,410 objects" },
    ],
    claims: [
      { claim: "The bucket policy in infra/storage.tf grants list to the public principal.", origin: "routes", verified: true },
    ],
    vulnerableCode: `resource "aws_s3_bucket_policy" "avatars" {
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject", "s3:ListBucket"]  # ← listing, not just reading
      Resource  = ["\${aws_s3_bucket.avatars.arn}", "\${aws_s3_bucket.avatars.arn}/*"]
    }]
  })
}`,
    fixKind: "one_click",
    fixTitle: "Drop s3:ListBucket, keep public reads",
    fixDiff: `-     Action    = ["s3:GetObject", "s3:ListBucket"]
+     Action    = ["s3:GetObject"]`,
    gates: [
      { label: "The problem reproduces", detail: "An anonymous list request returned object keys", passed: true },
      { label: "The fix stops it", detail: "Listing returns 403 after the change", passed: true },
      { label: "Real access still works", detail: "Direct object reads are unaffected", passed: true },
    ],
    notProvenBecause:
      "Read from your Terraform, which is what you intend to deploy — not from the bucket itself. If it was changed by hand in the console since the last apply, we would not see that.",
    status: "open",
  },
];

export interface Resolved {
  id: string;
  title: string;
  closedBy: string;
  when: string;
}

export const RESOLVED: Resolved[] = [
  { id: "r-1", title: "Public read on the ll-exports bucket", closedBy: "PR #412 · merged", when: "6 days ago" },
  { id: "r-2", title: "Password reset token compared without a constant-time check", closedBy: "PR #398 · merged", when: "18 days ago" },
  { id: "r-3", title: "Debug route returned environment variables", closedBy: "commit 8c21f04", when: "24 days ago" },
];

export interface PullRequest {
  number: number;
  title: string;
  author: string;
  verdict: string;
  state: "blocked" | "warned" | "clear" | "ours";
  when: string;
}

export const PULL_REQUESTS: PullRequest[] = [
  { number: 431, title: "Add invoice export endpoint", author: "marta", verdict: "Repeats the missing workspace check from SL-184.", state: "blocked", when: "12 minutes ago" },
  { number: 430, title: "Bump drizzle-orm to 0.44", author: "dependabot", verdict: "No advisories in the new version.", state: "clear", when: "2 hours ago" },
  { number: 429, title: "Cache workspace lookups in middleware", author: "felipe", verdict: "Cache key omits the workspace. Worth a second look.", state: "warned", when: "yesterday" },
  { number: 428, title: "Scope the invoice lookup to the caller's workspace", author: "shiplock", verdict: "Opened by us for SL-184. Three gates passed.", state: "ours", when: "11 minutes ago" },
];

export interface Run {
  id: string;
  kind: "Deep audit" | "Pull request" | "Hourly check";
  target: string;
  when: string;
  duration: string;
  outcome: string;
  found: number;
}

export const RUNS: Run[] = [
  { id: "run-1", kind: "Deep audit", target: "ledgerloop/app · 4f1e9c2", when: "11 minutes ago", duration: "4m 12s", outcome: "No new paths. One fix validated.", found: 0 },
  { id: "run-2", kind: "Pull request", target: "#431 · Add invoice export endpoint", when: "12 minutes ago", duration: "38s", outcome: "Merge blocked — repeats SL-184.", found: 1 },
  { id: "run-3", kind: "Hourly check", target: "ledgerloop/app", when: "1 hour ago", duration: "6s", outcome: "Nothing changed.", found: 0 },
  { id: "run-4", kind: "Deep audit", target: "ledgerloop/workers · 22a9d1e", when: "yesterday", duration: "1m 51s", outcome: "Two new route handlers, both machine-gated.", found: 0 },
];

export interface Activity {
  title: string;
  detail: string;
  when: string;
  tone: "alert" | "good" | "quiet";
}

export const ACTIVITY: Activity[] = [
  { title: "PR #431 blocked before merge", detail: "It reintroduces the missing workspace check from SL-184.", when: "12 min ago", tone: "alert" },
  { title: "Fix validated for SL-184", detail: "All three gates passed on a disposable copy. PR #428 is open.", when: "11 min ago", tone: "good" },
  { title: "Deep audit finished", detail: "63 entries, 24 tables. No new paths.", when: "11 min ago", tone: "quiet" },
  { title: "Public read closed on ll-exports", detail: "PR #412 merged by you. Re-audited: the path is gone.", when: "6 days ago", tone: "good" },
];

export interface TraceStep {
  time: string;
  label: string;
  note?: string;
  found?: boolean;
}

export const TRACE: TraceStep[] = [
  { time: "00:00", label: "Read-only checkout of ledgerloop/app at 4f1e9c2" },
  { time: "00:14", label: "Stack read from the code", note: "Next.js 15 · Clerk · Drizzle on Postgres · Stripe · S3" },
  { time: "00:41", label: "63 application entries mapped", note: "48 route handlers, 11 server actions, 4 webhooks" },
  { time: "01:07", label: "Identity resolved for each entry", note: "51 require a user · 4 machine-gated · 8 anonymous by design" },
  { time: "01:36", label: "24 tables and their columns read from schema.ts", note: "9 carry columns matching personal-data patterns" },
  { time: "02:02", label: "Followed each entry through to the data it reaches" },
  { time: "02:29", label: "Invoice route reaches customer rows with no workspace filter", found: true },
  { time: "02:44", label: "Stripe webhook writes billing state without verifying the sender", found: true },
  { time: "03:01", label: "Server-only database helper reachable from a client component", found: true },
  { time: "03:18", label: "Avatar bucket policy grants listing to everyone", found: true },
  { time: "03:35", label: "Disposable copy of the invoices schema created", note: "Your data was not copied. Structure and constraints only." },
  { time: "03:58", label: "Confirmed on the copy: workspace A read workspace B's invoice", found: true },
  { time: "04:06", label: "Candidate fix applied to the copy — attack fails, real access still works" },
  { time: "04:12", label: "Copy destroyed. Audit complete." },
];

export interface StackItem {
  name: string;
  detail: string;
  source: string;
}

/** What the repository told us. Every row names how we know. */
export const STACK_SEEN: StackItem[] = [
  { name: "Clerk", detail: "Identity for 51 of 63 entries", source: "package.json · imports in 51 route files" },
  { name: "Postgres via Drizzle", detail: "24 tables, 9 with personal data", source: "schema.ts · drizzle.config.ts" },
  { name: "Stripe", detail: "Checkout and one webhook", source: "package.json · app/api/webhooks/stripe" },
  { name: "S3", detail: "3 buckets, 1 public", source: "infra/storage.tf" },
  { name: "Vercel", detail: "Deploy target, 2 regions", source: "vercel.json" },
  { name: "142 dependencies", detail: "None with an open advisory", source: "package-lock.json" },
];

export interface Blind {
  name: string;
  why: string;
  effect: string;
  upgrade?: string;
}

/**
 * The screen neither earlier prototype had. Absent is not the same as clean,
 * and a thinner audit must never look like a cleaner one.
 */
export const STACK_BLIND: Blind[] = [
  {
    name: "Row-level policies on your database",
    why: "We read your schema from the repository, but not the policies that live in the database itself.",
    effect: "Findings that depend on them stay inferred instead of proven.",
    upgrade: "Connect a read-only database role",
  },
  {
    name: "What your users actually do",
    why: "We can see which code paths exist, not which ones anyone uses.",
    effect: "We will not close anything on the assumption that nothing reads it.",
    upgrade: "Add the edge snippet",
  },
  {
    name: "Values of your environment variables",
    why: "We read .env.example, which names your secrets. We never read their values.",
    effect: "We can say a secret is missing or misplaced, never that it is weak.",
  },
  {
    name: "Settings changed by hand in a dashboard",
    why: "Configuration made outside the repository is not in the repository.",
    effect: "If the console and your Terraform disagree, we describe the Terraform.",
  },
];

export interface QuestionnaireAnswer {
  question: string;
  answer: string;
  basis: "observed" | "attested";
}

export const QUESTIONNAIRE: QuestionnaireAnswer[] = [
  { question: "Do you enforce authorization on every API endpoint?", answer: "63 application entries are inventoried and checked on every push. One open exception is tracked as SL-184 with a validated fix awaiting merge.", basis: "observed" },
  { question: "How do you manage secrets?", answer: "No credential is committed to the repository; this is re-checked on every pull request. Storage and rotation are handled by the platform.", basis: "observed" },
  { question: "Do you perform regular security testing?", answer: "A full audit runs every 48 hours and on every pull request, with results retained for 12 months.", basis: "observed" },
  { question: "Do you have an incident response plan?", answer: "Your team must answer this one. ShipLock cannot observe a process.", basis: "attested" },
];

export interface Plan {
  id: string;
  name: string;
  who: string;
  monthly: number;
  annualMonthly: number;
  limits: string[];
  featured?: boolean;
  cta: string;
}

export const PLANS: Plan[] = [
  { id: "solo", name: "Solo", who: "One product, one person shipping it", monthly: 129, annualMonthly: 99, limits: ["1 repository", "50k lines", "30 pull-request audits a month"], cta: "Start free" },
  { id: "startup", name: "Startup", who: "A funded team with customers to answer to", monthly: 399, annualMonthly: 319, limits: ["5 repositories", "250k lines", "200 pull-request audits a month"], featured: true, cta: "Start free" },
  { id: "scale", name: "Scale", who: "Several products and a compliance calendar", monthly: 999, annualMonthly: 849, limits: ["20 repositories", "1.5M lines", "750 pull-request audits a month"], cta: "Start free" },
  { id: "enterprise", name: "Enterprise", who: "Runs inside your own infrastructure", monthly: 2500, annualMonthly: 2500, limits: ["Unlimited repositories", "Self-hosted runner", "SSO and evidence export"], cta: "Talk to us" },
];

/** Every plan includes everything. Size is the only difference. */
export const INCLUDED = [
  "Every finding, at every severity",
  "Validated fixes and fix pull requests",
  "Merge checks on pull requests",
  "The full audit trace for every run",
  "The shareable posture report",
  "Unlimited teammates",
];
