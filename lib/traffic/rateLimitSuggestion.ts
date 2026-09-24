/**
 * A customer-side rate-limit suggestion from observed traffic (Q12-2 /
 * Step 11). Deterministic. It adds exactly one new helper file and never edits
 * the customer's handlers or middleware: wiring it in is the customer's
 * decision, spelled out in the PR body. The helper is off unless
 * SHIPLOCK_RATE_LIMIT=on, keeps state in memory per server instance, and
 * fails open: any error lets the request through. ShipLock never blocks
 * traffic itself and never merges.
 */
export type HotRoute = { file: string; pattern: string; suspiciousRequests: number; paths: string[] };
export type RateLimitSuggestion =
  | { kind: "pr"; title: string; body: string; files: { path: string; content: string }[] }
  | { kind: "refused"; reason: "helper_exists" };

const HELPER = `// Added by a ShipLock suggestion. Safe to delete.
//
// A small fixed-window rate limit for one route handler. It is OFF unless the
// environment variable SHIPLOCK_RATE_LIMIT is "on", keeps counts in memory
// per server instance (so limits are approximate on serverless), and fails
// open: if anything goes wrong the request is allowed.
const WINDOW_MS = 60_000;
const LIMIT = 60;
const hits = new Map<string, { count: number; resetAt: number }>();

export function shiplockRateLimit(request: Request): Response | null {
  try {
    if (process.env.SHIPLOCK_RATE_LIMIT !== "on") return null;
    const forwarded = request.headers.get("x-forwarded-for") ?? "";
    const key = forwarded.split(",")[0].trim() || "unknown";
    const now = Date.now();
    const entry = hits.get(key);
    if (!entry || entry.resetAt <= now) {
      hits.set(key, { count: 1, resetAt: now + WINDOW_MS });
      if (hits.size > 10_000) hits.clear();
      return null;
    }
    entry.count += 1;
    if (entry.count <= LIMIT) return null;
    return new Response("Too many requests", {
      status: 429,
      headers: { "Retry-After": String(Math.ceil((entry.resetAt - now) / 1000)) },
    });
  } catch {
    return null;
  }
}
`;

export function buildRateLimitSuggestion(hot: HotRoute, repositoryFiles: string[], evidence: { windowHours: number }): RateLimitSuggestion {
  const base = hot.file.startsWith("src/") ? "src/lib" : "lib";
  const path = `${base}/shiplock-rate-limit.ts`;
  if (repositoryFiles.includes(path)) return { kind: "refused", reason: "helper_exists" };
  const alias = "@/lib/shiplock-rate-limit";
  const shown = hot.paths.slice(0, 5).map((p) => `\`${p}\``).join(", ");
  const body = [
    "## Why",
    `ShipLock observed ${hot.suspiciousRequests} suspicious requests to \`${hot.pattern}\` in the last ${evidence.windowHours} hours (for example ${shown}). They reach \`${hot.file}\`.`,
    "",
    "## What this changes",
    `This pull request adds one file, \`${path}\`. It does not change any existing file, so merging it alone changes nothing.`,
    "",
    "## To use it",
    `1. In \`${hot.file}\`, at the start of each handler: \`const limited = shiplockRateLimit(request); if (limited) return limited;\` (import it from \`${alias}\` or a relative path).`,
    "2. Set `SHIPLOCK_RATE_LIMIT=on` in the environment where you want it active.",
    "",
    "## To turn it off",
    "Remove `SHIPLOCK_RATE_LIMIT` or set it to anything other than `on`. The helper then lets every request through. Deleting the file and the two lines above undoes it completely.",
    "",
    "## Limits",
    "Counts are kept in memory per server instance, so on serverless hosting the limit is approximate. Any error inside the helper lets the request through.",
    "",
    "**Unverified:** ShipLock did not run your tests or CI on this change. Review it and let your CI run before merging. ShipLock never merges.",
  ].join("\n");
  return { kind: "pr", title: `Rate limit ${hot.pattern} (suggested by ShipLock)`, body, files: [{ path, content: HELPER }] };
}
