import type { RepoFile } from "@/lib/deep/githubScan";
import { stripComments, resolveImport } from "@/lib/deep/clientExposure";

// The source collector's structural output: which HTTP routes exist, which
// tables each one touches, and whether it checks who is asking.
//
// This is deliberately NOT a check. It emits no findings and makes no judgements
// — it produces facts for the graph to reason over (PRODUCT-DESIGN.md §5.1,
// "collectors: facts, no judgement"). Keeping it judgement-free is what lets the
// reasoner combine it with database and traffic facts without double-counting.
//
// It is the missing edge in the graph. We can already see that `invoices` has a
// permissive policy, but "a permissive policy on a table nothing exposes" and "a
// permissive policy on a table your public API reads" are different problems, and
// today we report them identically. The route inventory is what tells them apart:
//
//   reads(route) -> table    the edge that makes exposure real
//   authenticates(route)     whether the caller is identified at all
//   filters(route, owner)    whether rows are scoped to the caller
//
// PRECISION: this is regex-level structural analysis, not a type-aware parse. It
// is therefore reported as EVIDENCE with confidence, never as proof — the
// reasoner is allowed to say "this route appears to read invoices", and the
// autonomy ladder's "validated by observation, not inferred" precondition means
// no Tier 1-3 action may fire on this alone.

export interface RouteFact {
  /** URL path, derived from the file path: app/api/x/[id]/route.ts -> /api/x/[id] */
  path: string;
  /** Source file, so findings can point at something real. */
  file: string;
  /** HTTP methods the file exports. */
  methods: string[];
  /** Tables referenced via a Supabase client call, deduped. */
  tables: string[];
  /** Whether the handler resolves the caller's USER identity. */
  authenticated: boolean;
  /**
   * Whether it is gated by a shared secret or signature (cron secret, webhook
   * HMAC) rather than a user session. Not anonymous, but there is no user.
   */
  machineGated: boolean;
  /** Whether it uses the service-role client, which bypasses RLS entirely. */
  usesServiceRole: boolean;
  /** Whether any query is scoped to the caller (an ownership filter). */
  ownershipFiltered: boolean;
  /** True for Next.js route handlers under app/; false for page-level code. */
  isApiRoute: boolean;
  /**
   * Modules the route pulls in that contributed facts (auth, tables). Evidence,
   * so a finding can say WHERE it saw the gate rather than asserting one exists.
   */
  via: string[];
}

const ROUTE_FILE_RE = /(^|\/)route\.(ts|js|tsx|jsx)$/;
const PAGES_API_RE = /^(src\/)?pages\/api\/.+\.(ts|js|tsx|jsx)$/;

/** app/api/scan/route.ts -> /api/scan ; app/(d)/api/x/route.ts -> /api/x */
export function routePathFromFile(file: string): string {
  let p = file.replace(/^(src\/)?/, "");

  // pages/api/foo.ts -> /api/foo ; pages/api/foo/index.ts -> /api/foo
  if (PAGES_API_RE.test(file)) {
    return (
      "/" +
      p
        .replace(/^pages\//, "")
        .replace(/\.(ts|js|tsx|jsx)$/, "")
        .replace(/\/index$/, "")
    );
  }

  p = p.replace(/^app\//, "").replace(/\/route\.(ts|js|tsx|jsx)$/, "");
  // Route groups — `(d)` — organise files without appearing in the URL.
  const segments = p.split("/").filter((s) => s.length > 0 && !/^\(.+\)$/.test(s));
  return "/" + segments.join("/");
}

const METHOD_RE = /export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g;
// `export const GET = handler(...)` is equally common.
const METHOD_CONST_RE = /export\s+const\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*[:=]/g;

export function extractMethods(src: string): string[] {
  const out = new Set<string>();
  for (const re of [METHOD_RE, METHOD_CONST_RE]) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(src)) !== null) out.add(m[1]);
  }
  // A pages/api default export handles every method.
  if (out.size === 0 && /export\s+default\s/.test(src)) out.add("ALL");
  return [...out].sort();
}

// `.from("table")` / `.from('table')` — the Supabase query entry point. Also
// covers `.rpc("fn")`, recorded with an rpc: prefix so the graph can tell a
// function call from a table read.
const FROM_RE = /\.from\s*\(\s*["'`]([A-Za-z_][\w.]*)["'`]/g;
const RPC_RE = /\.rpc\s*\(\s*["'`]([A-Za-z_]\w*)["'`]/g;

export function extractTables(src: string): string[] {
  const out = new Set<string>();
  FROM_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = FROM_RE.exec(src)) !== null) out.add(m[1]);
  RPC_RE.lastIndex = 0;
  while ((m = RPC_RE.exec(src)) !== null) out.add(`rpc:${m[1]}`);
  return [...out].sort();
}

// Resolving the caller's USER identity.
//
// The critical distinction, learned from dogfooding: READING an inbound
// Authorization header is a gate; SETTING one on an outbound fetch is not. The
// first version matched `Authorization: \`Bearer ${token}\`` and therefore
// credited every module that calls an external API — lib/supabase.ts,
// lib/deep/github.ts — with authenticating the caller. That made the Stripe
// webhook and the public traffic-ingest endpoint look user-authenticated, which
// is exactly backwards: those are the two endpoints anyone can POST to.
//
// So the header patterns below only match a GET/index READ of an inbound header.
const STRONG_USER_AUTH_RE =
  /\b(auth\.getUser\s*\(|auth\.getSession\s*\(|getUser\s*\(|getSession\s*\(|requireDashboardSession|getServerSession|currentUser\s*\(|verifyJwt|jwtVerify)/i;

/**
 * Reading an inbound Authorization header. WEAK evidence of a user session on
 * its own, because the same code shape reads a shared secret — a cron endpoint
 * comparing `Bearer <CRON_SECRET>` looks identical to one validating a user
 * token. Resolved below: when a machine gate is also present, the secret reading
 * wins, because that is what it almost always is.
 */
const HEADER_READ_RE =
  /\.headers\s*\.get\s*\(\s*["']authorization|\.headers\s*\[\s*["']authorization|\bheaders\s*\(\s*\)\s*\.get\s*\(\s*["']authorization|\breq(uest)?\.headers\.authorization/i;

/**
 * A MACHINE gate: a shared secret or signature, not a user session.
 *
 * Tracked separately rather than folded into `authenticated`, because the two
 * mean different things to the reasoner. A cron endpoint behind CRON_SECRET is
 * not anonymous, but it also has no user — so "unauthenticated route reads
 * user_profiles" would be a false alarm, while "user-authenticated route reads
 * every tenant's rows" would be a real one. Conflating them loses that.
 */
const MACHINE_GATE_RE =
  /\b(CRON_SECRET|WEBHOOK_SECRET|constructEvent|timingSafeEqual|createHmac|verifyHmac|verifySignature|x-hub-signature|stripe-signature)\b|\.eq\s*\(\s*["']\w*token["']/i;

const SERVICE_ROLE_RE =
  /\b(getSupabaseAdmin|SUPABASE_SERVICE_ROLE_KEY|SERVICE_ROLE_KEY|service_role)\b/;

/**
 * An ownership filter: the query is narrowed to the caller.
 *
 * Requires the filter VALUE to look like caller identity (`user.id`, `session`,
 * `auth.uid()`), not merely that `.eq()` was called — `.eq("status","paid")` is
 * not an ownership check, and treating it as one would make the reasoner declare
 * safe routes safe for the wrong reason.
 */
// The VALUE side: an expression that resolves to the CALLER's identity.
//
// The previous version used `\b(user|auth|org|…)\w*`, which made every one of
// those a PREFIX match, so the filter only had to contain the letters. Verified
// false positives: `.eq("status","authorized")`, `.eq("category","organization")`,
// `.eq("author_name", x)` — all marked as ownership-filtered, which suppresses
// the tenant-isolation attack path and reports an unscoped route as safe. That
// is the exact failure the comment above was written to prevent, so the fix is
// to make the code do what the comment already said.
//
// Each alternative now requires identity STRUCTURE, not a substring:
//   auth.uid()  ·  user.id / session.user.id / claims.sub  ·  userId / ownerId
// "authorized" cannot match because nothing follows `auth` but letters; the
// pattern needs a `.` or a camelCase `Id`.
const OWNERSHIP_RE =
  /\bauth\s*\??\s*\.\s*uid\s*\(|\b(?:user|session|claims|profile|account|tenant|org|owner)\s*\??\s*\.\s*(?:\w+\s*\??\s*\.\s*)?(?:id|uid|sub)\b|\b(?:user|owner|account|tenant|org|profile)Id\b/;

// The COLUMN side: filtering on an ownership column at all. Weaker evidence than
// an identity value, and kept deliberately — dropping it would swing the error
// the other way and invent attack paths for routes that are actually scoped,
// which this file's header calls the worst outcome. Already word-bounded on both
// sides, so it never had the prefix problem above (`user_identity` does not
// match `\buser_id\b`).
const OWNERSHIP_ALT_RE = /\b(user_id|owner_id|account_id|tenant_id|org_id|profile_id)\b\s*[,)]/i;

/**
 * How far to follow local imports out of a route file.
 *
 * Necessary, not optional. Auth is almost always delegated to a project-specific
 * helper — `requireProUser()`, `authMcp(req)`, `requireDashboardSession()` — and
 * no list of names can cover every customer's naming. Reading only the route file
 * made 20 of ShipLock's own 34 routes look unauthenticated when they are not,
 * which is the worst possible error here: the reasoner would invent attack paths
 * through endpoints that are properly gated.
 *
 * Depth 2 covers route -> helper -> nested helper, and bounds over-attribution
 * from shared modules.
 */
const MAX_IMPORT_DEPTH = 2;

// TYPE-ONLY IMPORTS ARE EXCLUDED. `import type { X } from "./server"` is erased
// by TypeScript at compile time — nothing from that module reaches the browser,
// so following it would be reasoning about code that does not exist at runtime.
// Found by running this detector against ShipLock's own codebase: it reported
// components/d/TrafficPulse.tsx as leaking the service-role key through a type
// import of an interface. Telling a customer to rotate their service-role key
// because of an erased import would be a false positive on the single
// highest-severity finding we produce.
const IMPORT_RE =
  /(?:import|export)(?!\s+type\s)[\s\S]{0,200}?from\s*["']([^"']+)["']|require\s*\(\s*["']([^"']+)["']\s*\)/g;

/**
 * The route file plus the local modules it reaches. Comment-stripped once each.
 *
 * Over-attribution is possible: a route importing a module that queries several
 * tables is credited with all of them. That is deliberate — it errs toward
 * "this endpoint can reach this table", which is the reachability question the
 * graph asks, and every such fact is evidence rather than proof (see the header
 * note on the autonomy ladder's validated-by-observation precondition).
 */
export function reachableSources(
  entry: RepoFile,
  byPath: Map<string, RepoFile>
): { path: string; src: string }[] {
  const out: { path: string; src: string }[] = [{ path: entry.path, src: stripComments(entry.content) }];
  const seen = new Set<string>([entry.path]);
  let frontier = [entry.path];

  for (let depth = 0; depth < MAX_IMPORT_DEPTH; depth++) {
    const next: string[] = [];
    for (const current of frontier) {
      const src = out.find((o) => o.path === current)?.src;
      if (src === undefined) continue;
      IMPORT_RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = IMPORT_RE.exec(src)) !== null) {
        const spec = m[1] ?? m[2];
        if (!spec) continue;
        const resolved = resolveImport(current, spec, byPath);
        if (!resolved || seen.has(resolved)) continue;
        seen.add(resolved);
        const file = byPath.get(resolved)!;
        out.push({ path: resolved, src: stripComments(file.content) });
        next.push(resolved);
      }
    }
    frontier = next;
    if (frontier.length === 0) break;
  }

  return out;
}

/**
 * Facts for one route. `byPath` enables import following; omit it to analyse the
 * single file only.
 */
export function analyzeRouteFile(
  file: string,
  content: string,
  byPath?: Map<string, RepoFile>
): RouteFact {
  const sources = byPath
    ? reachableSources({ path: file, content }, byPath)
    : [{ path: file, src: stripComments(content) }];

  const entrySrc = sources[0].src;
  const tables = new Set<string>();
  const via = new Set<string>();
  let authenticated = false;
  let strongAuth = false;
  let machineGated = false;
  let usesServiceRole = false;
  let ownershipFiltered = false;

  for (const { path, src } of sources) {
    const isEntry = path === file;
    let contributed = false;

    for (const table of extractTables(src)) {
      if (!tables.has(table)) contributed = true;
      tables.add(table);
    }
    if (STRONG_USER_AUTH_RE.test(src)) {
      if (!authenticated) contributed = true;
      authenticated = true;
      strongAuth = true;
    } else if (HEADER_READ_RE.test(src)) {
      if (!authenticated) contributed = true;
      authenticated = true;
    }
    // A machine gate only counts from the ROUTE FILE. A helper that happens to
    // mention a secret name does not gate the endpoint that imports it.
    if (isEntry && MACHINE_GATE_RE.test(src)) machineGated = true;
    if (SERVICE_ROLE_RE.test(src)) usesServiceRole = true;
    if (OWNERSHIP_RE.test(src) || OWNERSHIP_ALT_RE.test(src)) {
      if (!ownershipFiltered) contributed = true;
      ownershipFiltered = true;
    }
    if (contributed && !isEntry) via.add(path);
  }

  // A bare inbound-header read next to a machine gate is a shared secret, not a
  // user session. Without this, every CRON_SECRET-gated cron endpoint claims a
  // user identity it does not have, and "authenticated route reads user_profiles
  // unfiltered" would fire on all of them.
  if (machineGated && !strongAuth) authenticated = false;

  return {
    path: routePathFromFile(file),
    file,
    // Methods must be exported by the route file itself — an imported helper
    // exporting GET does not make the route respond to GET.
    methods: extractMethods(entrySrc),
    tables: [...tables].sort(),
    authenticated,
    machineGated,
    usesServiceRole,
    ownershipFiltered,
    isApiRoute: true,
    via: [...via].sort(),
  };
}

/** True for files that define an HTTP endpoint. */
export function isRouteFile(path: string): boolean {
  if (PAGES_API_RE.test(path)) return true;
  if (!ROUTE_FILE_RE.test(path)) return false;
  // Only under app/ (or src/app/) — a `route.ts` elsewhere isn't an endpoint.
  return /^(src\/)?app\//.test(path);
}

/**
 * The collector entry point: every HTTP route in the repo, as facts.
 *
 * Routes with no table references are kept deliberately. "This endpoint exists
 * and touches no data" is a useful fact for the graph, and dropping it would
 * make the inventory silently incomplete.
 */
export function collectRoutes(files: RepoFile[]): RouteFact[] {
  const byPath = new Map(files.map((f) => [f.path, f]));
  return files
    .filter((f) => isRouteFile(f.path))
    .map((f) => analyzeRouteFile(f.path, f.content, byPath))
    .sort((a, b) => a.path.localeCompare(b.path));
}

/** Table -> routes that reference it. The graph's `exposes` edge, inverted. */
export function tablesToRoutes(routes: RouteFact[]): Map<string, RouteFact[]> {
  const out = new Map<string, RouteFact[]>();
  for (const route of routes) {
    for (const table of route.tables) {
      const list = out.get(table) ?? [];
      list.push(route);
      out.set(table, list);
    }
  }
  return out;
}
