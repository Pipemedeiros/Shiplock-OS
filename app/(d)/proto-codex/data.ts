// Display-only sample data for the Codex dashboard concept.
// Nothing under /proto-codex imports a production loader or calls a real service.

export type Severity = "critical" | "high" | "medium";
export type Confidence = "proven" | "corroborated" | "inferred";

export interface PathNode {
  kind: "entry" | "identity" | "gap" | "asset";
  label: string;
  detail: string;
}

export interface Risk {
  id: string;
  code: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  consequence: string;
  blastRadius: string;
  owner: string;
  age: string;
  path: PathNode[];
  evidence: string[];
  fix: string;
  file: string;
  diff: string;
  gates: { label: string; detail: string; passed: boolean }[];
}

export const RISKS: Risk[] = [
  {
    id: "invoice-scope",
    code: "SL-184",
    severity: "critical",
    confidence: "proven",
    title: "Any signed-in user can read another workspace’s invoices",
    consequence:
      "A valid account is enough to retrieve billing history, legal names, postal addresses, and payment metadata belonging to other customers.",
    blastRadius: "41,882 invoice rows · 1,140 workspaces · 9 sensitive fields",
    owner: "Billing",
    age: "11 minutes",
    file: "app/api/invoices/[id]/route.ts:14",
    path: [
      { kind: "entry", label: "GET /api/invoices/:id", detail: "Public application entry" },
      { kind: "identity", label: "Signed-in user", detail: "User identity resolved" },
      { kind: "gap", label: "Workspace scope missing", detail: "Caller workspace never compared" },
      { kind: "asset", label: "Invoices", detail: "Customer billing records" },
    ],
    evidence: [
      "The route resolves a user but never resolves the active workspace.",
      "Six neighboring invoice routes scope reads by workspaceId; this route does not.",
      "A synthetic tenant A retrieved tenant B’s row on the disposable proof environment.",
    ],
    fix: "Add the active workspace to the lookup and return the same not-found response for foreign records.",
    diff: `  const { userId, orgId } = await auth();
+ if (!userId || !orgId) return notFound();

  const invoice = await db.query.invoices.findFirst({
-   where: eq(invoices.id, params.id),
+   where: and(
+     eq(invoices.id, params.id),
+     eq(invoices.workspaceId, orgId),
+   ),
  });`,
    gates: [
      { label: "Finding reproduced", detail: "Synthetic workspace A read workspace B", passed: true },
      { label: "Attack stopped", detail: "Foreign invoice now returns 404", passed: true },
      { label: "Real flow preserved", detail: "Own invoice still returns 200", passed: true },
    ],
  },
  {
    id: "webhook-trust",
    code: "SL-179",
    severity: "critical",
    confidence: "corroborated",
    title: "The billing webhook trusts events it cannot authenticate",
    consequence:
      "A forged request could alter subscription state and unlock paid entitlements without a legitimate purchase.",
    blastRadius: "Subscription and entitlement state · every workspace",
    owner: "Platform",
    age: "2 hours",
    file: "app/api/webhooks/stripe/route.ts:9",
    path: [
      { kind: "entry", label: "POST /api/webhooks/stripe", detail: "Internet-facing webhook" },
      { kind: "gap", label: "Sender not verified", detail: "Authenticity not established" },
      { kind: "asset", label: "Entitlements", detail: "Plan and access state" },
    ],
    evidence: [
      "The handler accepts request JSON before establishing sender authenticity.",
      "A webhook secret is declared by the project but is not used on this path.",
      "The handler writes directly to subscription and entitlement records.",
    ],
    fix: "Establish event authenticity before parsing or acting on the payload.",
    diff: `- const event = await req.json();
+ const signature = req.headers.get("stripe-signature");
+ const rawBody = await req.text();
+ const event = verifyWebhook(rawBody, signature);`,
    gates: [
      { label: "Finding reproduced", detail: "Unsigned fixture changed state in replica", passed: true },
      { label: "Attack stopped", detail: "Unsigned fixture rejected", passed: true },
      { label: "Real flow preserved", detail: "Signed fixture processed", passed: true },
    ],
  },
  {
    id: "client-secret",
    code: "SL-166",
    severity: "high",
    confidence: "corroborated",
    title: "A production database credential crosses into the client graph",
    consequence:
      "The shipped browser bundle can inherit a privileged database connection through a server helper imported from a client component.",
    blastRadius: "Production database · direct privileged connection",
    owner: "Analytics",
    age: "6 days",
    file: "components/UsageChart.tsx → lib/db/admin.ts:4",
    path: [
      { kind: "entry", label: "Browser bundle", detail: "Visitor-controlled runtime" },
      { kind: "gap", label: "Server boundary crossed", detail: "Client import reaches server helper" },
      { kind: "asset", label: "Production database", detail: "Privileged connection string" },
    ],
    evidence: [
      "UsageChart is a client boundary and imports the analytics helper.",
      "That helper reaches the database administrator module through two imports.",
      "No server-only boundary protects any hop in the chain.",
    ],
    fix: "Move the read to a server component and make the privileged module server-only.",
    diff: `+ import "server-only";
  import { Pool } from "pg";

- import { getUsage } from "@/lib/analytics/usage";
+ // usage arrives as serialized server data`,
    gates: [
      { label: "Bundle path confirmed", detail: "Import graph contains 3 hops", passed: true },
      { label: "Boundary restored", detail: "Client chunk no longer reaches module", passed: true },
      { label: "Chart preserved", detail: "Serialized usage renders identically", passed: true },
    ],
  },
  {
    id: "upload-prefix",
    code: "SL-158",
    severity: "high",
    confidence: "inferred",
    title: "Upload signing accepts a workspace path from the browser",
    consequence:
      "A signed-in user may be able to overwrite another workspace’s documents by requesting a signed destination outside their own folder.",
    blastRadius: "Customer document bucket · cross-workspace writes",
    owner: "Documents",
    age: "8 days",
    file: "app/api/uploads/sign/route.ts:11",
    path: [
      { kind: "entry", label: "POST /api/uploads/sign", detail: "Signed-in application route" },
      { kind: "identity", label: "Signed-in user", detail: "User identity resolved" },
      { kind: "gap", label: "Destination is client-owned", detail: "Workspace prefix not derived" },
      { kind: "asset", label: "Document bucket", detail: "Customer uploads" },
    ],
    evidence: [
      "The browser supplies the complete object key.",
      "Sibling upload paths derive the workspace prefix on the server.",
      "Bucket policy may compensate, so this remains inferred until that boundary is observed.",
    ],
    fix: "Accept a filename only and derive the destination from the caller’s active workspace.",
    diff: `- const { key, contentType } = await req.json();
+ const { filename, contentType } = await req.json();
+ const { orgId } = await auth();
+ const key = buildWorkspaceKey(orgId, filename);`,
    gates: [
      { label: "Code path confirmed", detail: "Client controls the full destination", passed: true },
      { label: "External policy observed", detail: "Database connection required", passed: false },
      { label: "Safe patch drafted", detail: "No automatic claim of proof", passed: true },
    ],
  },
];

export const PULL_REQUESTS = [
  { number: 431, title: "feat: bulk invoice export", author: "mara", avatar: "MA", branch: "feat/bulk-export", state: "blocked", delta: "+842 −116", verdict: "Repeats SL-184 on a new export route", time: "12m", files: 17 },
  { number: 430, title: "chore: bump drizzle-orm", author: "dependabot", avatar: "DB", branch: "deps/drizzle-044", state: "clear", delta: "+44 −39", verdict: "No reachable boundary changed", time: "2h", files: 3 },
  { number: 429, title: "fix: scope invoice lookup to org", author: "shiplock", avatar: "SL", branch: "shiplock/invoice-scope", state: "ours", delta: "+12 −4", verdict: "Validated against two synthetic workspaces", time: "3h", files: 2 },
  { number: 428, title: "feat: document uploads v2", author: "tom", avatar: "TO", branch: "feat/uploads-v2", state: "warning", delta: "+391 −102", verdict: "New signing path needs workspace ownership", time: "1d", files: 11 },
  { number: 427, title: "refactor: extract billing helpers", author: "mara", avatar: "MA", branch: "refactor/billing", state: "clear", delta: "+81 −126", verdict: "Existing guards preserved through the move", time: "1d", files: 9 },
];

export const RUNS = [
  { id: "run-902", label: "Deep audit", trigger: "Scheduled", commit: "4f1e9c2", state: "complete", paths: 0, duration: "4m 18s", time: "11m ago", coverage: 96 },
  { id: "run-901", label: "PR #431", trigger: "Pull request", commit: "ee91a70", state: "blocked", paths: 1, duration: "38s", time: "12m ago", coverage: 24 },
  { id: "run-900", label: "PR #430", trigger: "Pull request", commit: "7b0b1f8", state: "complete", paths: 0, duration: "29s", time: "2h ago", coverage: 11 },
  { id: "run-899", label: "Deep audit", trigger: "Manual", commit: "3a4c801", state: "complete", paths: 2, duration: "4m 42s", time: "2d ago", coverage: 96 },
  { id: "run-898", label: "PR #428", trigger: "Pull request", commit: "08fd2a1", state: "warning", paths: 1, duration: "44s", time: "1d ago", coverage: 19 },
];

export const TRACE = [
  { time: "00:00", phase: "checkout", label: "Pinned ledgerloop/app at 4f1e9c2", note: "1,412 files · 138k lines · read-only checkout" },
  { time: "00:07", phase: "map", label: "Mapped 63 entries into 24 data assets", note: "41 user gates · 12 machine gates · 10 intentionally public" },
  { time: "00:19", phase: "identity", label: "Resolved identity and workspace boundaries", note: "Clerk convention found at 41 call sites" },
  { time: "00:31", phase: "signal", label: "Workspace scope absent on invoice lookup", note: "Compared against six sibling routes", alert: true },
  { time: "00:52", phase: "graph", label: "Walked 312 modules reachable from client boundaries", note: "One privileged value crossed the server boundary", alert: true },
  { time: "01:18", phase: "proof", label: "Rebuilt the affected schema with synthetic tenants", note: "No production rows or customer data copied" },
  { time: "01:42", phase: "proof", label: "Reproduced cross-workspace invoice access", note: "Workspace A received workspace B’s row", alert: true },
  { time: "02:08", phase: "fix", label: "Applied the candidate scope patch", note: "Foreign read 404 · legitimate read 200" },
  { time: "04:18", phase: "done", label: "Audit closed and disposable environment destroyed", note: "4 open paths · 3 fixes ready" },
];

export const STACK = [
  { id: "next", name: "Next.js", role: "Application", detail: "63 route handlers · App Router", confidence: "Observed", x: 50, y: 12 },
  { id: "clerk", name: "Clerk", role: "Identity", detail: "41 user gates · 9 org gates", confidence: "Mapped", x: 20, y: 33 },
  { id: "stripe", name: "Stripe", role: "Billing", detail: "1 webhook · 4 entitlement writes", confidence: "Mapped", x: 80, y: 32 },
  { id: "neon", name: "Postgres", role: "Data", detail: "24 tables · 6 sensitive", confidence: "Reasoned", x: 28, y: 75 },
  { id: "s3", name: "S3", role: "Files", detail: "2 buckets · 3 signing paths", confidence: "Inferred", x: 72, y: 76 },
  { id: "inngest", name: "Inngest", role: "Jobs", detail: "11 functions · 1 open entry", confidence: "Observed", x: 50, y: 48 },
];

export const QUESTIONNAIRE = [
  { q: "Do you perform recurring application security testing?", a: "Yes. Pull-request changes are reviewed before merge and the full codebase is re-audited on a 48-hour cadence. The latest complete audit ran 11 minutes ago." },
  { q: "How do you prevent one customer from accessing another customer’s data?", a: "Tenant ownership is mapped from each authenticated entry point to the data operation it reaches. Suspected cross-tenant paths are validated with synthetic tenants in a disposable environment containing no production data." },
  { q: "Are dependencies monitored for newly disclosed vulnerabilities?", a: "Yes. Dependency state is checked on pull requests and re-evaluated against new advisories during recurring audits, including when no new deployment has occurred." },
  { q: "Can your security provider access production customer data?", a: "No. ShipLock reads selected source repositories. Proof runs use reconstructed schemas and synthetic records; production customer rows are not copied or read." },
];

export const ACTIVITY = [
  { tone: "signal", title: "Merge blocked on PR #431", detail: "A new export route repeats the open invoice ownership path.", time: "12m" },
  { tone: "verified", title: "Deep audit completed", detail: "No net-new paths. Coverage reached 96% of mapped entries.", time: "11m" },
  { tone: "bronze", title: "Fix PR #429 validated", detail: "Attack stopped; the legitimate invoice flow remained available.", time: "3h" },
  { tone: "quiet", title: "Stack map changed", detail: "Two worker entries added; both carry a machine identity.", time: "1d" },
];
