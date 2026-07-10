// DESIGN EXPLORATION — mock data only. Nothing here touches the real
// product. All three directions render this exact same content so the
// comparison is about visual execution, not information architecture.

export type Severity = "critical" | "high" | "medium" | "low";

export interface FixStep {
  title: string;
  body: string;
}

// Auto-PR is only offered for safe, templated fixes (headers, dependency
// bumps, secret removal). Database, RLS, and auth changes NEVER get a PR
// button — that mirrors the real product's permanent policy.
export interface FixPr {
  title: string;
  branch: string;
  diff: string[]; // unified-diff-ish lines, prefixed with "+", "-", or " "
}

export const NO_PR_POLICY =
  "No auto-PR for database or auth changes — by design, permanently. Changes to your data layer deserve your hands on the wheel; we prepare the brief instead.";

export interface Finding {
  id: string;
  checkId: number; // which of the 15 checks caught it
  severity: Severity;
  title: string; // plain-language, non-technical
  tech: string; // the precise technical statement (dual-register copy)
  plain: string; // one-sentence human explanation
  consequence: string;
  detectedAgo: string;
  steps: FixStep[];
  sql?: string;
  aiPrompt: string;
  pr?: FixPr; // present only when the fix is safely templatable
}

export interface Check {
  id: number;
  name: string;
  surface: SurfaceName;
}

export type SurfaceName =
  | "Auth & access"
  | "Data exposure"
  | "Configuration"
  | "Injection & logic";

export const MOCK_PROJECT = {
  appName: "acme-crm",
  appUrl: "acme-crm.vercel.app",
  supabaseUrl: "https://xyzcompany.supabase.co",
  anonKeyPreview: "eyJhbGciOiJIUzI1NiIsInR5cCI6...",
  firebaseProjectId: "acme-crm-4f2a1",
  webApiKeyPreview: "AIzaSyD4kQ1cGB0dXJlLXByZXZp...",
  grade: "C" as const,
  // This sample project's detected stack. Category-first by design: UI
  // shows SLOTS (database / host / source / builder) and the provider
  // inside each slot is data — never design a tile around one brand.
  stack: {
    database: "Supabase",
    host: "Vercel",
    source: "GitHub",
    builder: "Lovable",
  },
};

// What each slot speaks — the breadth roster. The sample above is one
// combination; the product's story must hold for every provider here.
export type StackSlot = "database" | "host" | "source" | "builder";

export const STACK_SPEAKS: Record<StackSlot, string[]> = {
  database: ["Supabase", "Firebase"],
  host: ["Vercel", "Netlify"],
  source: ["GitHub"],
  builder: ["Lovable", "Bolt", "v0", "Cursor", "Replit"],
};

export const SURFACES: { name: SurfaceName; blurb: string }[] = [
  {
    name: "Auth & access",
    blurb: "Who can sign in, and how easily an attacker can pretend to be them.",
  },
  {
    name: "Data exposure",
    blurb: "Whether your database answers questions it should refuse to answer.",
  },
  {
    name: "Configuration",
    blurb: "Settings and headers that quietly decide how protected you are.",
  },
  {
    name: "Injection & logic",
    blurb: "Whether crafted input can make your app do things you never wrote.",
  },
];

export const CHECKS: Check[] = [
  { id: 1, name: "Row-level security", surface: "Data exposure" },
  { id: 2, name: "Table enumeration", surface: "Data exposure" },
  { id: 3, name: "Column exposure", surface: "Data exposure" },
  { id: 4, name: "Storage bucket access", surface: "Data exposure" },
  { id: 5, name: "Realtime channel access", surface: "Data exposure" },
  { id: 6, name: "Email verification", surface: "Auth & access" },
  { id: 7, name: "Anonymous sign-ins", surface: "Auth & access" },
  { id: 8, name: "OAuth redirect allowlist", surface: "Auth & access" },
  { id: 9, name: "Auth rate limiting", surface: "Auth & access" },
  { id: 10, name: "Service-key leakage", surface: "Configuration" },
  { id: 11, name: "Security headers", surface: "Configuration" },
  { id: 12, name: "CORS policy", surface: "Configuration" },
  { id: 13, name: "Webhook signatures", surface: "Configuration" },
  { id: 14, name: "SQL injection surface", surface: "Injection & logic" },
  { id: 15, name: "Mass assignment", surface: "Injection & logic" },
];

export const FINDINGS: Finding[] = [
  {
    id: "rls-customers",
    checkId: 1,
    severity: "critical",
    title: "Your customer table is readable by anyone",
    tech: "RLS disabled on public.customers",
    plain:
      "The `customers` table answers requests from anyone on the internet — no login required.",
    consequence:
      "Anyone who finds your project URL can download every customer row: names, emails, whatever you store. This is the exact pattern behind most vibe-coded-app data leaks.",
    detectedAgo: "2 days ago",
    steps: [
      {
        title: "Understand what's open",
        body: "Row-level security (RLS) is the lock on each table. On `customers` it is switched off, so the database serves every row to every request.",
      },
      {
        title: "Turn the lock on",
        body: "Run the SQL below in your Supabase SQL editor. It enables RLS and adds a policy so people can only read their own rows.",
      },
      {
        title: "Tell us when it's done",
        body: "We re-check within a minute and confirm the table stopped answering strangers.",
      },
    ],
    sql: `ALTER TABLE customers ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users read own rows"
  ON customers FOR SELECT
  USING (auth.uid() = user_id);`,
    aiPrompt:
      "My Supabase table `customers` has row-level security disabled. Enable RLS on it and add a SELECT policy so authenticated users can only read rows where user_id = auth.uid(). Show me the exact SQL and where to run it.",
  },
  {
    id: "email-autoconfirm",
    checkId: 6,
    severity: "high",
    title: "New accounts skip email verification",
    tech: "auth.mailer_autoconfirm = true",
    plain:
      "Sign-ups are auto-confirmed — nobody has to prove they own the email address they typed.",
    consequence:
      "Anyone can create accounts with emails they don't own, including your customers' addresses. Spam sign-ups and account impersonation both start here.",
    detectedAgo: "6 days ago",
    steps: [
      {
        title: "See the setting",
        body: "In your Supabase dashboard, open Authentication → Providers → Email. “Confirm email” is currently off.",
      },
      {
        title: "Switch it on",
        body: "Enable “Confirm email.” New sign-ups will get a verification link before their account works.",
      },
      {
        title: "Tell us when it's done",
        body: "We re-check the auth configuration and clear this finding automatically.",
      },
    ],
    aiPrompt:
      "My Supabase project has email auto-confirm enabled (mailer_autoconfirm = true), so sign-ups skip verification. Walk me through turning email confirmation on in the Supabase dashboard, and check whether my app's sign-up flow needs changes to handle the confirmation step.",
  },
  {
    id: "anon-signins",
    checkId: 7,
    severity: "medium",
    title: "Anonymous sign-ins are switched on",
    tech: "auth.external.anonymous_users = true",
    plain:
      "Your project lets people create throwaway sessions without any account at all.",
    consequence:
      "If your app doesn't intentionally use guest accounts, this is an open side door: rate-limit abuse and junk data usually arrive through it.",
    detectedAgo: "19 days ago",
    steps: [
      {
        title: "Check if you use it",
        body: "If your app has no “continue as guest” feature, you don't need anonymous sign-ins.",
      },
      {
        title: "Turn it off",
        body: "In Supabase: Authentication → Providers → toggle “Allow anonymous sign-ins” off.",
      },
      {
        title: "Tell us when it's done",
        body: "We confirm the setting on the next check.",
      },
    ],
    aiPrompt:
      "My Supabase project allows anonymous sign-ins but my app has no guest feature. Confirm nothing in my codebase depends on signInAnonymously, then tell me how to disable anonymous sign-ins in the Supabase dashboard.",
  },
  {
    id: "csp-headers",
    checkId: 11,
    severity: "low",
    title: "Your app is missing browser security headers",
    tech: "no content-security-policy header on responses",
    plain:
      "Responses ship without a Content-Security-Policy, so browsers apply no script restrictions.",
    consequence:
      "If an attacker ever gets a script injected (through a comment box, a URL, a dependency), nothing tells the browser to refuse to run it.",
    detectedAgo: "19 days ago",
    steps: [
      {
        title: "Add the headers",
        body: "Add a Content-Security-Policy and related headers in your framework config or middleware.",
      },
      {
        title: "Start strict, loosen carefully",
        body: "Begin with a policy that only allows your own domain, then add exceptions one at a time as the browser console reports blocks.",
      },
      {
        title: "Tell us when it's done",
        body: "We re-check your headers on the next scan.",
      },
    ],
    aiPrompt:
      "My Next.js app on Vercel sends no Content-Security-Policy header. Add a sensible CSP (self-only scripts with a per-request nonce) plus X-Content-Type-Options and Referrer-Policy headers, and explain what each one blocks.",
    pr: {
      title: "chore(security): add missing security headers",
      branch: "shiplock/fix-security-headers",
      diff: [
        "  // middleware.ts",
        "+ const nonce = crypto.randomUUID();",
        "+ response.headers.set(",
        "+   \"Content-Security-Policy\",",
        "+   `script-src 'self' 'nonce-${nonce}'; object-src 'none'`",
        "+ );",
        "+ response.headers.set(\"X-Content-Type-Options\", \"nosniff\");",
        "+ response.headers.set(\"Referrer-Policy\", \"strict-origin-when-cross-origin\");",
      ],
    },
  },
];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

// ── 30-day monitoring timeline (day 0 = today, negative = days ago) ──────────
export type TimelineKind = "quiet" | "deploy" | "finding" | "resolved";

export interface TimelineDay {
  daysAgo: number;
  kind: TimelineKind;
  note: string;
  severity?: Severity;
}

export const TIMELINE: TimelineDay[] = [
  { daysAgo: 29, kind: "quiet", note: "Scheduled deep scan — clean" },
  { daysAgo: 23, kind: "deploy", note: "Deploy detected → re-scan — clean" },
  {
    daysAgo: 19,
    kind: "finding",
    severity: "medium",
    note: "2 new findings: anonymous sign-ins, missing headers",
  },
  { daysAgo: 16, kind: "resolved", note: "1 finding resolved: exposed storage bucket" },
  { daysAgo: 12, kind: "deploy", note: "Deploy detected → re-scan — clean" },
  {
    daysAgo: 6,
    kind: "finding",
    severity: "high",
    note: "New finding: accounts skip email verification",
  },
  {
    daysAgo: 2,
    kind: "finding",
    severity: "critical",
    note: "New critical finding: customer table readable by anyone",
  },
];

// ── shared copy facts (identical structure across directions) ─────────────────
export const HOW_IT_WORKS: { title: string; body: string }[] = [
  {
    title: "Connect in one paste",
    body: "Your project URL and anon key — the same key your app already shares with every visitor's browser. We never ask for more than that.",
  },
  {
    title: "First scan in 90 seconds",
    body: "Fifteen checks across four attack surfaces, the same ground an enterprise audit covers. You get a grade and a plain-English list of what we found.",
  },
  {
    title: "Then we keep watching",
    body: "Every deploy triggers a re-scan, deep scans run on a schedule, and you only hear from us when something new appears. Silence means you're clean.",
  },
];

export const PRICING = {
  free: {
    name: "Free scan",
    price: "$0",
    tagline: "Find out where you stand.",
    features: [
      "One full 15-check scan",
      "Security grade, A through F",
      "Every issue named, with severity",
    ],
    locked: ["Step-by-step fixes", "Copy-paste AI prompts", "Continuous monitoring"],
  },
  paid: {
    name: "Monitor",
    price: "$49",
    per: "/month",
    tagline: "The $50k audit, running all the time.",
    features: [
      "Everything in the free scan",
      "Step-by-step fixes for every finding",
      "Copy-paste prompts for whatever you build in — Cursor, Lovable, Bolt, v0",
      "Re-scan on every deploy",
      "Scheduled deep scans",
      "Alerts only when something new appears",
    ],
  },
  rescan: "Need a one-off re-check? $2, any time, no subscription.",
};

export const TRUST_LINE =
  "We only ever ask for your app's public key — the same credential your own frontend already exposes to every visitor. No repo access, no admin tokens, no exceptions.";

export const DISCLAIMER =
  "Design exploration — not the live product. Everything on this page is sample data.";
