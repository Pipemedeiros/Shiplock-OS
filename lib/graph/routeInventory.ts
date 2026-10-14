import type { RepoFile } from "@/lib/deep/githubScan";
import { stripComments, resolveImport, stringSpans, stringLiteralRanges } from "@/lib/deep/clientExposure";
import { filteredParameters, functionBody, helperGuard, importsOf } from "./helperGuard";
import { blankDeclarations } from "./declarations";
import { traceExecutedSources } from "./callPath";
import { isWorkspacePackageImport } from "./tsconfigPaths";
import { findPermissionGaps, type PermissionGap } from "./permissionGaps";
import { middlewareGap, unrefusedMethods } from "./methodRefusal";

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
  /**
   * False when a machine gate exists in an imported module but not in the route
   * file. Distinguishes "the gate may be one file away" from "there is no gate";
   * consumers reporting an ungated webhook must not fire on the first.
   */
  machineGateReadable: boolean;
  /** Why the machine gate was unreadable, or null. */
  machineGateGap: string | null;
  /** Whether it uses the service-role client, which bypasses RLS entirely. */
  usesServiceRole: boolean;
  /**
   * False when a service-role token was seen only inside a string literal.
   *
   * The inverse-direction case: this field guards against asserting `true` on
   * weak evidence, not against a missing `false`.
   */
  serviceRoleReadable: boolean;
  /** Whether any query is scoped to the caller (an ownership filter). */
  ownershipFiltered: boolean;
  /**
   * Whether we could READ how this route scopes its query to the caller.
   *
   * The twin of `identityReadable`, and the field behind seven of corpus-b's
   * eight remaining reasoned criticals. `ownershipFiltered: false` was carrying
   * both "we read the query and it is not narrowed to the caller" and "the
   * narrowing happens somewhere we cannot see", and only the first is a finding.
   *
   * The second is not exotic. It is the ordinary shape of a scoped read once an
   * application grows past one file: the session lookup IS the tenant boundary
   * (`verifyDataroomSession(req, linkId, dataroomId)`), the tenant arrives on a
   * context object a wrapper injected, or the filter lives in the data helper
   * that owns the query.
   */
  ownershipReadable: boolean;

  /** Why ownership was unreadable, or null when we could read it. */
  ownershipGap: string | null;

  /**
   * Whether we could READ how this route decides who is calling.
   *
   * `authenticated: false` used to mean two different things -- "we read this
   * route and there is no gate" and "we could not follow how this route is
   * gated" -- and only the first justifies reporting that anyone on the
   * internet can call the endpoint. Collapsing them is a fail-open, and it was
   * the single cause of thirteen of fourteen false CRITICALs across five real
   * startup codebases.
   *
   * This is the route-level twin of AuthzFacts.rulesRead, which already draws
   * exactly this line for database policies: "we read every policy and none
   * filters" is a finding, "we never read the policies" is a gap. The same
   * distinction simply never reached the routes.
   *
   * False means UNREADABLE, and an unreadable route is never called anonymous.
   */
  identityReadable: boolean;

  /** Why identity was unreadable, for the coverage note and the finding text. */
  identityGap: string | null;

  /**
   * Whether we could READ this route's data access at all.
   *
   * The call-path work made many routes reach no table rather than be credited
   * with tables they never touch -- the right failure direction, and still
   * silently unassessed: a route whose query sits behind an import we could
   * not resolve looks identical to a route that touches nothing. False when
   * the route reaches no table AND imports something local we could not
   * follow. "Absent is not clean" is the second design commitment of this
   * codebase, and this field is what lets Coverage keep it for data access.
   */
  dataReadable: boolean;
  /** Why data access was unreadable, or null. */
  dataGap: string | null;

  /**
   * Modules the route pulls in that contributed facts (auth, tables). Evidence,
   * so a finding can say WHERE it saw the gate rather than asserting one exists.
   */
  via: string[];

  /**
   * Handlers here that write a model with a weaker declared permission than
   * another handler writing the same model requires (Step 7C, read from
   * source; see ./permissionGaps.ts). Absent means none was read.
   */
  permissionGaps?: PermissionGap[];

  /**
   * Methods whose handler we read in full and in which nothing refuses an
   * anonymous caller, on a route read as `authenticated` (R1b, see
   * ./methodRefusal.ts). `authenticated` is route-wide: one method's 401 kept
   * it true while another method had none. Absent when none was read.
   */
  unrefusedMethods?: string[];
  /** A middleware that may refuse those methods before the handler runs, or absent. */
  refusalGap?: string;
}

const ROUTE_FILE_RE = /(^|\/)route\.(ts|js|tsx|jsx)$/;

/**
 * `export * from "./elsewhere"` as the whole of a route file.
 *
 * The handler is not here. `handlerRoots` reads a module's own export NAMES and
 * a star re-export names none, so `traceExecutedSources` returns null and the
 * route falls back to whole-file import reading. That fallback reaches the
 * target's queries -- ownership and tables partly propagate -- but the shim
 * spends one of the two import hops, so a wrapper reached through a barrel sits
 * three hops out and its session call is never read.
 *
 * corpus-a keeps sixteen of these under `app/api/(old)/`. They were reported
 * `authenticated: false` with `identityReadable: TRUE` about handlers that are
 * `withWorkspace(...)`: not an admitted unknown but a confident assertion that
 * we read the route and found no gate. Pinned by reExportShim.test.ts.
 */
const STAR_REEXPORT_RE = /^\s*export\s*\*\s*(?:as\s+\w+\s+)?from\s*["']([^"']+)["']/m;

// A workspace prefix before app/ or pages/, because startup codebases are
// monorepos. Auditing corpus-g, 2,359 files with 112 tables, returned ZERO
// routes: every endpoint sits at apps/web/src/app/api/.../route.ts and the
// matcher required the path to START with app/. The agent then skipped the run
// entirely with "no route reaches a table", so the largest and most valuable
// codebases were exactly the ones we said nothing about.
const WORKSPACE_PREFIX = "(?:[\\w.-]+\\/)*?";
const PAGES_API_RE = new RegExp(`^${WORKSPACE_PREFIX}(?:src\\/)?pages\\/api\\/.+\\.(ts|js|tsx|jsx)$`);
const APP_DIR_RE = new RegExp(`^${WORKSPACE_PREFIX}(?:src\\/)?app\\/`);

/** app/api/scan/route.ts -> /api/scan ; app/(d)/api/x/route.ts -> /api/x */
export function routePathFromFile(file: string): string {
  // pages/api/foo.ts -> /api/foo ; pages/api/foo/index.ts -> /api/foo
  if (PAGES_API_RE.test(file)) {
    const fromPages = file.slice(file.indexOf("pages/") + "pages/".length);
    return (
      "/" +
      fromPages.replace(/\.(ts|js|tsx|jsx)$/, "").replace(/\/index$/, "")
    );
  }

  // Everything up to and including the app/ segment is workspace layout, not
  // URL. apps/web/src/app/api/x/route.ts and app/api/x/route.ts are the same
  // endpoint as far as an attacker is concerned.
  const appMatch = APP_DIR_RE.exec(file);
  let p = appMatch ? file.slice(appMatch[0].length) : file.replace(/^(src\/)?app\//, "");
  p = p.replace(/\/route\.(ts|js|tsx|jsx)$/, "");
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

// Drizzle and Prisma name the table with an identifier rather than a string, so
// FROM_RE never saw them. A route reading `db.query.invoices.findFirst(...)`
// reported NO tables at all, which meant the graph believed an endpoint touching
// customer billing data touched nothing -- and an entry that reaches no table
// cannot produce an attack path. Silence again, in the direction that hides.
//
//   db.query.invoices.findFirst   ·   .from(invoices)   ·   prisma.invoice.findMany
const DRIZZLE_QUERY_RE = /\bdb\s*\??\s*\.\s*query\s*\.\s*([A-Za-z_]\w*)/g;
// `.from(identifier)` is Drizzle reading a table -- and also Buffer.from(bytes),
// Array.from(iterable) and every other built-in with the same spelling. Reading
// this repository, `Buffer.from(contentUtf8, "utf8")` was collected as a table
// named contentUtf8, and a route credited with a table it never touches is a
// route the graph believes reaches data. That is a false attack path waiting to
// happen, so the receiver has to be excluded, not the name pattern loosened.
const JS_BUILTIN_FROM =
  "Buffer|Array|Object|String|Number|Boolean|Map|Set|WeakMap|WeakSet|Promise|JSON|Date|" +
  "Int8Array|Uint8Array|Uint8ClampedArray|Int16Array|Uint16Array|Int32Array|Uint32Array|" +
  "Float32Array|Float64Array|BigInt64Array|BigUint64Array";
const DRIZZLE_FROM_IDENT_RE = new RegExp(
  `(?<!\\b(?:${JS_BUILTIN_FROM})\\s*)\\.from\\s*\\(\\s*([A-Za-z_]\\w*)\\s*[),]`,
  "g",
);
// The Prisma client is not always named `prisma`: interactive transactions
// hand it in as `tx` (corpus-a, corpus-d) and corpus-af injects `prismaClient`. Those
// calls read as touching no table until Step 7H. Receivers are listed, not
// generalised: `client.user.findMany` is as often an SDK as a database.
const PRISMA_MODEL_RE = /\b(?:prisma|prismaClient|tx|trx)\s*\??\s*\.\s*([a-z][A-Za-z0-9_]*)\s*\.\s*(?:find|create|update|delete|upsert|count|aggregate)/g;
// Drizzle writes name the table as the call's argument: db.insert(monitor),
// tx.update(page), db.delete(member). Only the db / tx receivers the corpus
// uses (286 and 62 writes): the same spelling on a Map, URLSearchParams, a
// cookie store or an HMAC is not a table (Step 7H, negative fixtures).
const DRIZZLE_WRITE_RE = /\b(?:db|tx|trx)\s*\.\s*(?:insert|update|delete)\s*\(\s*([A-Za-z_]\w*)\s*\)/g;

/** Identifiers that are query-builder plumbing, not tables. */
const NOT_A_TABLE = new Set([
  "db", "sql", "table", "query", "select", "insert", "update", "delete", "raw", "schema", "$queryRaw",
]);

// `stringSpans` lives in lib/deep/clientExposure.ts, which owns the source-
// reading helpers this file already imports. It was moved there when the same
// "a token inside a string is not code" rule was needed by the client-exposure
// detector -- two copies of a scanner like that drift, and the copy that drifts
// is the one that stops catching things.

export function extractTables(src: string): string[] {
  const out = new Set<string>();
  const inString = stringSpans(src);
  FROM_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = FROM_RE.exec(src)) !== null) {
    if (!inString(m.index)) out.add(m[1]);
  }
  RPC_RE.lastIndex = 0;
  while ((m = RPC_RE.exec(src)) !== null) {
    if (!inString(m.index)) out.add(`rpc:${m[1]}`);
  }

  for (const re of [DRIZZLE_QUERY_RE, DRIZZLE_FROM_IDENT_RE, DRIZZLE_WRITE_RE, PRISMA_MODEL_RE]) {
    re.lastIndex = 0;
    while ((m = re.exec(src)) !== null) {
      if (inString(m.index)) continue;
      const name = m[1];
      if (!NOT_A_TABLE.has(name) && name.length > 1) out.add(name);
    }
  }

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
// `verify<Anything>Session` is the shape a project-specific session check
// takes once an app outgrows the framework helper: corpus-b resolves a visitor
// with verifyDataroomSession() and verifyLinkSessionInPagesRouter(), both of
// which return 401 on failure, and both of which read as ANONYMOUS here. Four
// of that repository's twelve reported criticals were routes that verify a
// session through a helper this list did not know.
//
// Widening auth recognition can only cause us to MISS a finding, never to
// invent one, which is the direction this file's header already commits to.
export const STRONG_USER_AUTH_RE =
  /\b(auth\.getUser\s*\(|auth\.getSession\s*\(|getUser\s*\(|getSession\s*\(|requireDashboardSession|getServerSession|currentUser\s*\(|verifyJwt|jwtVerify|await\s+auth\s*\(|clerkClient|verify[A-Za-z]*Session[A-Za-z]*\s*\()/i;

/**
 * Reading an inbound Authorization header. NOT evidence of a user session, and
 * NOT evidence of a machine gate: the same code shape reads a user token, a
 * cron secret, or -- corpus-a's SCIM endpoint -- a per-directory bearer that is
 * handed to a library to verify. Which of those it is cannot be read from the
 * header access alone.
 *
 * It used to set `authenticated: true` unless a machine gate was also present.
 * That made the SCIM route, which has no caller-user by design, read as a user
 * route that "does not narrow to the caller", and the merge check BLOCKED on
 * it. A bare header read now lands where every other credential check we
 * cannot classify lands: identityReadable: false, disclosed as unassessed. The
 * route is never called anonymous, and never credited with a session we did
 * not read.
 */
// The last alternative is the indirection form: `const h = await headers()`
// followed by `h.get("Authorization")`. Counted across the five audited
// repositories: six route files, including corpus-e and corpus-b's SCIM
// endpoint, which hands the bearer secret to @boxyhq/saml-jackson to verify and
// read as completely ungated.
//
// NOT covered, and left for the wrapper-body work on the standing list: a
// helper that takes the request and reads the header inside itself
// (`getAuthHeader(req)`) -- five more files. That is import-following, not
// pattern-widening, and pretending otherwise would be another wordlist.
const HEADER_READ_RE =
  /\.headers\s*\.get\s*\(\s*["']authorization|\.headers\s*\[\s*["']authorization|\bheaders\s*\(\s*\)\s*\.get\s*\(\s*["']authorization|\breq(uest)?\.headers\.authorization|\b(?:const|let)\s+\w+\s*=\s*(?:await\s+)?headers\s*\(\s*\)[\s\S]{0,400}?\.\s*get\s*\(\s*["']authorization/i;

/**
 * A MACHINE gate: a shared secret or signature, not a user session.
 *
 * Tracked separately rather than folded into `authenticated`, because the two
 * mean different things to the reasoner. A cron endpoint behind CRON_SECRET is
 * not anonymous, but it also has no user — so "unauthenticated route reads
 * user_profiles" would be a false alarm, while "user-authenticated route reads
 * every tenant's rows" would be a real one. Conflating them loses that.
 */
// The additions after the original list all came from real repositories:
//
//   receiver.verify({signature})        Upstash QStash, corpus-b's cron routes
//   verifyQstashSignature(...)          the same thing behind a project helper;
//                                       `verifySignature` alone did not match it
//   token !== process.env.INTERNAL_API_KEY
//                                       the generic shape this comment block
//                                       already describes -- a header compared
//                                       against an environment secret
//
// The last one is why the comparison is required rather than the mere presence
// of an env secret: reading `process.env.STRIPE_SECRET_KEY` to CALL Stripe is
// not a gate, and treating it as one would silence real findings.
const MACHINE_GATE_RE =
  /\b(CRON_SECRET|WEBHOOK_SECRET|constructEvent|timingSafeEqual|createHmac|verifyHmac|verifySignature|x-hub-signature|stripe-signature)\b|\.eq\s*\(\s*["']\w*token["']|\bverify[A-Za-z]*(?:Signature|Webhook)[A-Za-z]*\s*\(|\breceiver\s*\.\s*verify\s*\(|(?:!==|===|!=|==)\s*process\.env\.[A-Z0-9_]*(?:SECRET|TOKEN|API_KEY|KEY)\b/i;

/**
 * A bare shared-secret NAME gates only a route that reads something inbound
 * to compare it with (headers, URL, query). A route that only sends
 * CRON_SECRET to another endpoint (inspector /api/sync/trigger) is not gated.
 */
const BARE_SECRET_NAME_RE = /\b(?:CRON_SECRET|WEBHOOK_SECRET)\b/gi;
// A comparison with a template holding the secret, or Hono's bearerAuth
// given it, is the check itself wherever the headers came from.
const SECRET_COMPARED_RE = /(?:!==|===|!=|==)\s*`[^`]*\b(?:CRON|WEBHOOK)_SECRET\b|\bbearerAuth\s*\(\s*\{\s*token\s*:/;
const INBOUND_READ_RE = /\b(?:_?req|request|\w{1,24}Request)\s*\??\.\s*(?:headers|nextUrl|url|query|cookies)\b|\bheaders\s*\(\s*\)|\bsearchParams\b/i;
function machineGateIn(src: string): boolean {
  if (MACHINE_GATE_RE.test(src.replace(BARE_SECRET_NAME_RE, " "))) return true;
  return MACHINE_GATE_RE.test(src) && (INBOUND_READ_RE.test(src) || SECRET_COMPARED_RE.test(src));
}

/** A wrapper that looked the caller up in a membership table. */
const MEMBERSHIP_LOOKUP_RE = /\.from\s*\(\s*["'`]\w*(?:member|membership)\w*["'`]\s*\)|\b\w*[mM]embership\w*\s*\.\s*(?:findFirst|findUnique|findMany)\s*\(/;

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
//
// THE THIRD ALTERNATIVE REQUIRES A FILTER POSITION, NOT A MENTION. It used to
// be the bare token `\buserId\b`, which matched anywhere in any file a route
// reaches -- and what it mostly reached was declarations: `userId: string` in
// an interface, `userId?: string` in a type, `.omit({ userId: true })` in a Zod
// schema, `select: { userId: true }` in a projection. Those describe SHAPE, not
// behaviour. Measured on corpus-b: 82% of routes were marked owner-filtered,
// most of them from lib/types.ts, which suppresses the tenant-isolation attack
// path on the one check class this product exists for.
//
// A use looks like one of these, and nothing else:
//   `: userId`             a value in an object literal   where: { ownerId: userId }
//   `{ userId }` `, userId }`   shorthand in an object     where: { userId }
//   `, userId)` `, user.userId)`   a trailing call argument   .eq('user_id', user.userId)
//   `=== userId` / `userId !==`   a comparison               if (doc.ownerId !== userId)
// The value may be a member chain (`ctx.userId`, `session.user.userId`): an
// earlier draft forgot that and silently broke `.eq('user_id', user.userId)`,
// which only the existing suite caught. `routeInventory.stacks.test.ts` now
// pins every shape above, keep and drop, by name.
//
// Template literals are CODE here, not strings: `sql\`... where user_id =
// ${userId}\`` is exactly where a raw-SQL filter lives. Only quoted strings are
// excluded from the match (see the loop in analyzeRouteFile).
// `serverEstablished` is not a domain noun: it is the marker
// withoutIdentityResolution() writes over a value it traced to a verifier.
const OWNER_VALUE = "(?:\\w+\\s*\\??\\.\\s*)*(?:user|owner|account|tenant|org|profile|serverEstablished)Id";
// `user.id`, `session.user.id`, `claims.sub`: the caller, by structure.
const CALLER_IDENTITY =
  "(?:user|session|claims|profile|account|tenant|org|owner)\\s*\\??\\s*\\.\\s*(?:\\w+\\s*\\??\\s*\\.\\s*)?(?:id|uid|sub)";
// A comparison is an ownership check when ONE operand carries verified
// PROVENANCE. That is the fourth time a wordlist has failed here: corpus-a's
// /partners.corpus-a.co/invoices/[payoutId] genuinely checks `payout.partnerId !==
// partner.id` and returned unauthorized, `partner` was correctly traced to a
// session-resolving wrapper and renamed to the marker below, and the rule then
// discarded it because it demanded BOTH sides match user|owner|account|tenant|
// org|profile -- and `partnerId` is a domain noun outside that list. The next
// codebase uses merchant, vendor, subscriber, or a noun nobody has thought of.
//
// So: one side must be a value we TRACED to the caller -- the marker
// withoutIdentityResolution writes over anything bound from a verifier, a
// session lookup or a session-resolving wrapper's injection -- or a caller
// identity that is structural (`session.user.id`). The other operand may be
// named anything at all, because a row's ownership column is unbounded
// vocabulary and what makes the comparison authorization is that it is
// compared against THE CALLER, which tracing establishes and naming does not.
//
// THE EXCLUSION RUNS THE OTHER WAY, and it is the viewerId lesson: a
// comparison against a value the caller supplied is not an ownership check, so
// the request marker disqualifies an operand on either side. Erring that way
// keeps a finding alive rather than silencing one, which is the direction this
// file's header commits to.
const TRACED_IDENTITY = `(?:serverEstablishedId|${CALLER_IDENTITY})`;
/** Anything except a value provenance already marked as caller-supplied. */
const NOT_SUPPLIED = "(?!(?:\\w+\\s*\\??\\s*\\.\\s*)*attackerSupplied\\b)";
const OPERAND = `${NOT_SUPPLIED}(?:\\w+\\s*\\??\\s*\\.\\s*)*\\w+`;
const CMP = "(?:===|!==|==|!=)";
export const OWNERSHIP_RE = new RegExp(
  "\\bauth\\s*\\??\\s*\\.\\s*uid\\s*\\(" +
    `|\\b${CALLER_IDENTITY}\\b` +
    `|:\\s*${OWNER_VALUE}\\b` +
    `|[{,]\\s*${OWNER_VALUE}\\s*[,}]` +
    `|,\\s*${OWNER_VALUE}\\s*[,)]` +
    `|\\b${TRACED_IDENTITY}\\s*${CMP}\\s*${OPERAND}\\b` +
    `|\\b${OPERAND}\\s*${CMP}\\s*${TRACED_IDENTITY}\\b` +
    // A value we TRACED to the caller, anywhere inside a where clause, however
    // it is wrapped: `where: { id: normalizeWorkspaceId(workspace.id) }`.
    // Restricted to the traced marker on purpose -- a vocabulary match inside
    // a call argument would count `console.log(userId)`.
    "|\\bwhere\\s*:\\s*\\{[^}]*\\bserverEstablishedId\\b",
);

// The COLUMN side: filtering on an ownership column at all. Weaker evidence than
// an identity value, and kept deliberately — dropping it would swing the error
// the other way and invent attack paths for routes that are actually scoped,
// which this file's header calls the worst outcome. Already word-bounded on both
// sides, so it never had the prefix problem above (`user_identity` does not
// match `\buser_id\b`).
const OWNERSHIP_ALT_RE = /\b(user_id|owner_id|account_id|tenant_id|org_id|profile_id)\b\s*[,)]/i;

/**
 * Statements that merely OBTAIN the caller's identity, which are not evidence
 * that anything was filtered by it.
 *
 * Found by running the pipeline on a Clerk + Drizzle route with a real tenant
 * isolation bug. `const { userId } = await auth();` contains `userId`, which
 * OWNERSHIP_RE matches, so the unscoped route was reported as scoped and the
 * finding never appeared. That is a fail-open on the single check class this
 * product exists for.
 *
 * The fix is deliberately narrow. This file's header argues that inventing an
 * attack path for a scoped route is the worst outcome, and that trade-off is
 * unchanged: we remove ONLY the line that resolves identity, so an ownership
 * token used anywhere else -- including on the very next line -- still counts.
 */
const IDENTITY_RESOLUTION_RE =
  /(?:const|let|var)\s*\{[^}]*\}\s*=\s*(?:await\s+)?(?:auth|currentUser|getUser|getSession|getServerSession)\s*\([^;]*;|(?:const|let|var)\s+\w+\s*=\s*(?:await\s+)?(?:auth|currentUser)\s*\(\s*\)\s*;/g;

/**
 * The other half: refusing the request when there is no identity.
 *
 * `if (!userId) return new Response("Unauthorized", { status: 401 });` is an
 * AUTHENTICATION check. It establishes that somebody is calling, and says
 * nothing about which rows that somebody may read. Counting it as ownership
 * filtering is precisely how a horizontal access bug hides behind a login.
 *
 * Only a guard whose whole body is a return or a throw is stripped, so a branch
 * that actually does something with the identity still counts.
 */
const IDENTITY_GUARD_RE =
  /if\s*\(\s*!\s*[\w.?]*\b(?:user|owner|account|tenant|org|profile)Id\b[^)]*\)\s*(?:\{\s*(?:return|throw)[^;]*;\s*\}|(?:return|throw)[^;]*;)/gi;

/**
 * Identity-shaped names that came from the REQUEST, which are not identities.
 *
 * `const { userId } = await request.json()` reads as ownership to OWNERSHIP_RE,
 * because the NAME is all that pattern can see. But a value the caller supplied
 * is the opposite of a value that identifies the caller: filtering by it is
 * exactly the bug, not the fix.
 *
 * Removing the declaration alone does not help, because the USE still carries
 * the name: `.eq('id', userId)` matches on its own. So the name itself is
 * collected and then neutralised everywhere in the route.
 *
 * Found on a real repository, where a route destructured userId from the body
 * and updated that row. We marked it owner-filtered, and once the prompt began
 * telling the model to trust that label the genuine vulnerability vanished from
 * the report: a fail-open on the one check class this product exists for.
 */
// The `(?::\s*\{[^}]*\})?` is a TypeScript annotation on the destructure, and
// leaving it out cost a real finding: the repository that exposed this fail-open
// writes `const { userId, avatarUrl }: { userId: string; avatarUrl: string } =
// await request.json()`, and the pattern expected `}` followed directly by `=`.
// Both routers. The app router reads the request through a call --
// `await req.json()`, `req.formData()` -- and the pages router through a
// property: `req.query`, `req.body`, optionally followed by a cast. The first
// version knew only the call forms, so in pages/api `const { userId } =
// req.query` was never neutralised and `where: { userId }` read as an
// ownership filter. corpus-b is pages/api throughout.
const REQUEST_READ = "(?:req|request)\\s*\\.\\s*(?:(?:json|formData)\\s*\\(|(?:body|query)\\b)";
const REQUEST_DESTRUCTURE_RE = new RegExp(
  `(?:const|let|var)\\s*\\{([^}]*)\\}\\s*(?::\\s*\\{[^}]*\\})?\\s*=\\s*(?:await\\s+)?${REQUEST_READ}`,
  "g",
);
const REQUEST_DESTRUCTURE_STATEMENT_RE = new RegExp(
  `(?:const|let|var)\\s*\\{[^}]*\\}\\s*(?::\\s*\\{[^}]*\\})?\\s*=\\s*(?:await\\s+)?${REQUEST_READ}[^;]*;`,
  "g",
);
const REQUEST_ASSIGN_RE =
  /(?:const|let|var)\s+(\w+)\s*=\s*[^;=]*?(?:(?:req|request)\s*\.\s*(?:json|body|query|formData|nextUrl)|searchParams|params)\b[^;]*;/g;
/**
 * A value bound DIRECTLY from a request accessor, whatever the binding is
 * called. `const body = req.body as { userId: string }` followed by
 * `where: { userId: body.userId }` read as an ownership filter, because
 * requestSuppliedIdentities registers a binding only when its NAME matches
 * IDENTITY_NAME_RE and `body` does not. That is a caller-supplied value
 * counted as ownership -- the fifth wordlist failure here, and the only one
 * that fails OPEN, silencing a real finding rather than inventing one.
 *
 * The name is irrelevant: provenance is the source, not the identifier.
 *
 * "DIRECTLY" IS THE WHOLE GUARD. The initializer must BEGIN with the accessor,
 * so `req.body`, `await req.json()` and `await params` qualify while
 * `getUser(params)` does not. If this fired on any initializer that merely
 * mentioned a request accessor, a session resolved by a helper taking the
 * request would be marked caller-supplied, every filter behind it would be
 * neutralised, and the collector would invent unscoped findings on correct
 * code -- recall loss expressed as false criticals, which is worse than the
 * bug it fixes.
 */
const REQUEST_HOLDER_RE =
  // The word boundary belongs to each bare-word alternative, NOT to the group:
  // after `json()` the next character is `;`, and `\b` cannot match between two
  // non-word characters, so a trailing `\b` silently killed every call form
  // while leaving `req.body` working. Caught by the test for the call form.
  /(?:const|let|var)\s+(\w+)\s*(?::[^=;]*)?=\s*(?:await\s+)?(?:(?:req|request)\s*\??\.\s*(?:json\s*\(\s*\)|formData\s*\(\s*\)|(?:body|query|params|nextUrl)\b)|(?:params|searchParams)\b)/g;

/** A request value read in place: `params.id`, `req.query.userId`, `searchParams.get("x")`. */
const REQUEST_MEMBER_RE =
  /\b(?:req|request)\s*\.\s*(?:query|body|params|nextUrl)\s*(?:\??\.\s*\w+)+|\b(?:params|searchParams)\s*\??\.\s*(?:get\s*\([^)]*\)|\w+)/g;

/**
 * A name that looks like an identifier. NOT a list of domain nouns.
 *
 * THE WORDLIST WAS THE WRONG INSTRUMENT AND IT DEFEATED CORRECT LOGIC. The rule
 * this file enforces is "a value the caller supplied is not a value that
 * identifies the caller" -- the discriminator is PROVENANCE, and provenance is
 * already traced: requestSuppliedIdentities only inspects names bound from
 * req.json/body/query/params. The wordlist then threw most of them away.
 *
 * It covered user|owner|account|tenant|org|profile, and missed `viewerId`, which
 * corpus-b's conversations endpoint takes from the query and uses as the actor
 * -- an unauthenticated route that reads as owner-filtered because it "filters"
 * by a value the caller handed it. Counted across the five audited repositories:
 * partnerId 667 occurrences in corpus-a, viewerId 156 in corpus-b, plus customerId,
 * contactId, memberId, clientId, sourcePartnerId, referredByPartnerId. Domain
 * identity nouns are unbounded; every codebase invents its own.
 *
 * Shape, not vocabulary: anything ending in Id or _id that came from the
 * request. `format` and `limit` are still ignored because they are not
 * identifiers, which is the only discrimination this needs to make.
 */
const IDENTITY_NAME_RE = /Id$|_id$/i;

/**
 * PROVENANCE, NOT VOCABULARY, in both directions.
 *
 * The request rule above neutralises a name because of where its VALUE came
 * from. The same principle runs the other way: a value bound from a signature
 * verification or a session lookup is the caller's identity no matter what it
 * is called. corpus-b's /api/unsubscribe/yir filters `userId_teamId: {
 * userId: viewerId, teamId }` where `viewerId` was destructured from
 * jwt.verify()'s payload -- a genuine server-established scope that the
 * tightened pattern dropped because "viewerId" is not in its wordlist. It was
 * safe only because that route happened to be identity-unreadable, which is
 * luck, not design.
 *
 * And a value bound from a DECODE or a PARSE of request data is the caller's
 * input no matter what it is called: `jwt.decode(token).userId` is whatever
 * the caller put in the token. Before this rule that read as ownership.
 *
 * Both follow one hop through a holder: `const payload = verify(token)` then
 * `payload.viewerId` or `const { viewerId } = payload`. Names the request rule
 * already neutralised are never promoted.
 */
// Any receiver chain is allowed before the method: `jwt.verify(`,
// `supabase.auth.getUser(`, `receiver.verify(`.
const RECEIVER = "(?:[\\w$]+\\s*\\??\\.\\s*)*";
const VERIFIER_CALL =
  `${RECEIVER}(?:verify[A-Za-z]*|jwtVerify|getServerSession|getSession|getUser|currentUser|auth)\\s*\\(`;
// decode…() of anything, and parse()/safeParse()/JSON.parse() of something that
// is visibly the request: the argument is the provenance, so `JSON.parse(await
// redis.get(k))` is NOT caught -- that is server data.
const DECODER_CALL =
  `(?:${RECEIVER}decode[A-Za-z]*\\s*\\(|${RECEIVER}(?:safeParse|parse)\\s*\\(\\s*(?:await\\s+)?(?:req|request|body|rawBody|raw|formData|payload|input)\\b)`;

function boundNames(list: string): string[] {
  const out: string[] = [];
  for (const raw of list.split(",")) {
    const name = raw.includes(":") ? raw.split(":")[1] : raw;
    const clean = name.trim().replace(/\s*=.*$/, "").replace(/^\.\.\./, "");
    if (/^\w+$/.test(clean)) out.push(clean);
  }
  return out;
}

/** Names and holders bound from `call`, one hop deep. */
function boundFrom(src: string, call: string): { names: string[]; holders: string[] } {
  const names = new Set<string>();
  const holders = new Set<string>();
  const destructure = new RegExp(`(?:const|let|var)\\s*\\{([^}]*)\\}\\s*(?::\\s*\\{[^}]*\\})?\\s*=\\s*(?:await\\s+)?${call}`, "g");
  const holder = new RegExp(`(?:const|let|var)\\s+(\\w+)\\s*(?::[^=;]*)?=\\s*(?:await\\s+)?${call}`, "g");
  let m: RegExpExecArray | null;
  while ((m = destructure.exec(src)) !== null) for (const n of boundNames(m[1])) names.add(n);
  while ((m = holder.exec(src)) !== null) holders.add(m[1]);
  for (const h of holders) {
    const esc = h.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const hop = new RegExp(`(?:const|let|var)\\s*\\{([^}]*)\\}\\s*(?::[^=;]*)?=\\s*${esc}\\s*[;,)]`, "g");
    while ((m = hop.exec(src)) !== null) for (const n of boundNames(m[1])) names.add(n);
    const member = new RegExp(`(?:const|let|var)\\s+(\\w+)\\s*(?::[^=;]*)?=\\s*${esc}\\s*\\??\\.\\s*\\w+\\s*;`, "g");
    while ((m = member.exec(src)) !== null) names.add(m[1]);
  }
  return { names: [...names], holders: [...holders] };
}

/** Names and holders whose value came out of a verifier: server-established. */
export function serverEstablishedIdentities(src: string, resolvers: string[] = []): { names: string[]; holders: string[] } {
  const verified = boundFrom(src, VERIFIER_CALL);
  if (resolvers.length === 0) return verified;
  const more = boundFrom(src, `${RECEIVER}(?:${resolvers.map((r) => r.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})\\s*\\(`);
  // `const workspaceId = await requireWorkspaceId()`: an id-named holder is the id.
  const bareIds = more.holders.filter((h) => /(?:^id|Id)$/.test(h));
  return { names: [...verified.names, ...more.names, ...bareIds], holders: [...verified.holders, ...more.holders] };
}

/**
 * Imported functions that look the CALLER up in a membership table: their
 * body (or a function it calls, one import away) resolves a user session and
 * reads a membership table. What they return is the caller's own membership,
 * so its ids are server-established (class C, 2026-10-06).
 */
export function membershipResolvers(file: string, content: string, byPath: Map<string, RepoFile>): string[] {
  const out: string[] = [];
  for (const [name, path] of importsOf(file, content, byPath)) {
    const helper = byPath.get(path);
    const body = helper ? functionBody(helper.content, name) : null;
    if (!helper || body === null) continue;
    // One call away: imported callees, and callees declared in the helper's own file.
    const reached = [body];
    const imported = importsOf(path, helper.content, byPath);
    for (const callee of new Set([...body.matchAll(/\b(\w+)\s*\(/g)].map((m) => m[1]))) {
      if (callee === name) continue;
      if (!imported.has(callee) && !new RegExp(`\\bfunction\\s+${callee}\\b|\\b(?:const|let)\\s+${callee}\\s*=`).test(helper.content)) continue;
      const calleeBody = functionBody(imported.has(callee) ? byPath.get(imported.get(callee)!)?.content ?? "" : helper.content, callee);
      if (calleeBody) reached.push(calleeBody);
    }
    const text = reached.join("\n");
    if (STRONG_USER_AUTH_RE.test(text) && MEMBERSHIP_LOOKUP_RE.test(text)) out.push(name);
  }
  return out;
}

/** Whether `filterable` hands the server-established marker to an imported
 * function at a position that function's own query filters on. */
function scopesThroughHelper(file: string, original: string, filterable: string, byPath: Map<string, RepoFile>): boolean {
  const imports = importsOf(file, original, byPath);
  for (const m of filterable.matchAll(/\b(\w+)\s*\(([^()]*)\)/g)) {
    const path = imports.get(m[1]);
    if (!path) continue;
    const args = m[2].split(",").map((a) => a.trim());
    const at = args.indexOf("serverEstablishedId");
    if (at === -1) continue;
    const helper = byPath.get(path);
    if (helper && filteredParameters(helper.content, m[1]).has(at)) return true;
  }
  return false;
}

/** Names and holders whose value came out of decoding or parsing request data: caller-supplied. */
export function callerDecodedIdentities(src: string): { names: string[]; holders: string[] } {
  return boundFrom(src, DECODER_CALL);
}

/**
 * One more hop: a value computed FROM a traced identity is still the caller's.
 * `const programId = getDefaultProgramIdOrThrow(workspace)` on a route that
 * received `workspace` from a session-resolving wrapper; the query then
 * filters by programId. Applied after the identity renames, so it sees the
 * marker and nothing else.
 */
export function propagateDerived(text: string): string {
  const names = new Set<string>();
  // The argument list may not nest: `[^()]*` keeps the match inside one call,
  // so `export const GET = withWorkspace(async () => { const x = f(marker) …`
  // does not bind GET.
  const derived = /(?:const|let|var)\s+(\w+)\s*(?::[^=;]*)?=\s*(?:await\s+)?[\w.$]+\s*\([^()]*\bserverEstablishedId\b[^()]*\)/g;
  let m: RegExpExecArray | null;
  while ((m = derived.exec(text)) !== null) names.add(m[1]);
  return renameAll(text, [...names], [], "serverEstablishedId");
}

function renameAll(text: string, names: string[], holders: string[], to: string): string {
  let out = text;
  for (const h of holders) {
    const esc = h.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    // `payload.viewerId` -> the marker; other members of the holder are left alone.
    out = out.replace(new RegExp(`\\b${esc}\\s*\\??\\.\\s*\\w*Id\\b`, "g"), to);
  }
  for (const n of names) {
    out = out.replace(new RegExp(`\\b${n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "g"), to);
  }
  return out;
}

/** Bindings taken straight from a request accessor, by provenance not by name. */
export function requestSuppliedHolders(src: string): string[] {
  const out = new Set<string>();
  REQUEST_HOLDER_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = REQUEST_HOLDER_RE.exec(src)) !== null) out.add(m[1]);
  return [...out];
}

/** Identity-looking names this route reads out of the request. */
export function requestSuppliedIdentities(src: string): string[] {
  const names = new Set<string>();

  REQUEST_DESTRUCTURE_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = REQUEST_DESTRUCTURE_RE.exec(src)) !== null) {
    for (const raw of m[1].split(",")) {
      // `{ userId: caller }` renames it; the local name is what appears later.
      const name = raw.includes(":") ? raw.split(":")[1] : raw;
      const clean = name.trim().replace(/\s*=.*$/, "");
      if (IDENTITY_NAME_RE.test(clean)) names.add(clean);
    }
  }

  REQUEST_ASSIGN_RE.lastIndex = 0;
  while ((m = REQUEST_ASSIGN_RE.exec(src)) !== null) {
    if (IDENTITY_NAME_RE.test(m[1])) names.add(m[1]);
  }

  return [...names];
}

/**
 * `original` is the text the request-supplied names are read from. When `src`
 * has had its declarations blanked (see ./declarations.ts) the destructure
 * `const { userId } = await req.json()` is already gone from it, and the names
 * it bound -- which must still be neutralised everywhere they are USED -- can
 * only be recovered from the unblanked text.
 */
export function withoutIdentityResolution(src: string, original: string = src, resolvers: string[] = []): string {
  let out = src.replace(IDENTITY_RESOLUTION_RE, " ").replace(IDENTITY_GUARD_RE, " ");

  // Drop the request-reading statement itself. Neutralising the local name is
  // not enough when the destructure renames: `const { userId: ownerId } =
  // await request.json()` still leaves the KEY `userId` on the line, and that
  // matches the ownership pattern on its own.
  // The destructure statement goes whole: it binds names and nothing else.
  // An assignment does NOT: `const enrollment = getEnrollment({ partnerId:
  // partner.id, programId: params.programId })` carries a real filter beside
  // the request read, and deleting the statement deleted the filter (corpus-a's
  // partner-profile routes read as unscoped for exactly that). The request
  // read itself is neutralised in place instead.
  out = out
    .replace(REQUEST_DESTRUCTURE_STATEMENT_RE, " ")
    .replace(REQUEST_MEMBER_RE, "attackerSupplied");

  // Neutralise every mention of a name the caller supplied, so filtering by it
  // stops counting as filtering by the caller.
  const supplied = new Set(requestSuppliedIdentities(original));
  for (const name of supplied) {
    out = out.replace(new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "g"), "attackerSupplied");
  }

  // Provenance in both directions (see serverEstablishedIdentities). Decoded
  // request data is neutralised first, so a name can never be promoted after
  // being neutralised.
  // A binding taken straight from the request taints every identity-shaped
  // member read off it, however the binding is named.
  const requestHolders = requestSuppliedHolders(original);
  for (const h of requestHolders) {
    const esc = h.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    out = out.replace(new RegExp(`\\b${esc}\\s*\\??\\.\\s*(?:\\w*Id|id|uid|sub)\\b`, "g"), "attackerSupplied");
  }

  const decoded = callerDecodedIdentities(original);
  out = renameAll(out, decoded.names.filter((n) => !supplied.has(n)), decoded.holders, "attackerSupplied");
  const server = serverEstablishedIdentities(original, resolvers);
  const tainted = new Set([...supplied, ...decoded.names, ...decoded.holders, ...requestHolders]);
  out = renameAll(
    out,
    server.names.filter((n) => !tainted.has(n)),
    server.holders.filter((h) => !tainted.has(h)),
    "serverEstablishedId",
  );

  return propagateDerived(out);
}

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
 * Signals that this route decides who is calling in a way we could not follow.
 *
 * Each one came from a real repository, and each is evidence the route HAS a
 * gate rather than evidence it lacks one. Order matters only for the message.
 *
 * The reasoning is the same one already applied when a route looked anonymous
 * while filtering by the caller: those cannot both be true, so the safer half
 * wins. A route that answers 401 is not a route with no notion of who is
 * asking.
 */

/**
 * `export const GET = withWorkspace(async (…) => …)` — the body is inside a call.
 *
 * THE NEGATIVE LOOKAHEAD IS THE LOAD-BEARING PART. This regex captures the
 * identifier between `=` and `(`, and on the single most common handler form in
 * modern Next.js —
 *
 *     export const GET = async (req: NextRequest) => { … }
 *
 * — that identifier is `async`, a language keyword, not a wrapper. The route was
 * therefore marked "wrapped in something we could not read" and suppressed.
 * Measured across five real codebases: 45 routes mis-captured this way, and it
 * silenced corpus-a's /api/links/exists, a genuinely unauthenticated endpoint that
 * takes workspaceId from the query string — exactly the shape this product
 * exists to catch.
 *
 * The fix is deliberately a KEYWORD exclusion and not another entry in
 * NEUTRAL_WRAPPERS. The set of JavaScript keywords that can legally sit here is
 * closed and finite; the set of library wrapper names is neither. Patching the
 * two instances we happened to see would have left the parse bug in place for
 * the next one.
 *
 * Enumerated against all five repositories before choosing this shape. Forms
 * that do NOT occur even once in 975 route files, and are therefore not built
 * for: `= Ident<T>(…)` generic calls and `= a.b(…)` member calls. Forms that are
 * already safe because they produce no identifier-before-paren: `= (…)` plain
 * arrows (12 in corpus-a) and `= Ident;` direct references (15 across the set).
 */
const RESERVED_BEFORE_PAREN = "async|await|new|typeof|void|delete|function|return|yield|import";
const WRAPPED_HANDLER_RE = new RegExp(
  `export\\s+(?:const|let|var)\\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\\s*(?::[^=]+)?=` +
    `\\s*(?!(?:${RESERVED_BEFORE_PAREN})\\b)([A-Za-z_$][\\w$]*)\\s*\\(`,
  "g",
);

/**
 * Handler factories that wrap without gating — a wrapper is not automatically auth.
 *
 * `withAxiom` is here under protest, and the limitation is worth stating rather
 * than hiding: it is a real wrapper that genuinely cannot gate (next-axiom is a
 * logging decorator), but its body lives in node_modules, outside the corpus, so
 * we cannot READ that it cannot gate — we are asserting it from the name. The
 * next logging decorator with a different name will be wrong in the same way.
 *
 * The principled fix, and it is a real one, is scoped out of this change: when
 * the wrapper resolves to a LOCAL module we already read, inspect that module
 * for an auth pattern and decide from its body instead of its name. That covers
 * every wrapper in corpus-a, which are all under lib/auth/. It cannot cover a wrapper
 * imported from a package, and for those there is no principled distinction
 * between "a decorator that cannot gate" and "a gate we have not read" — so a
 * name list is the honest floor, not a solution.
 */
const NEUTRAL_WRAPPERS = new Set([
  "handler", "createHandler", "route", "createRoute", "defineHandler",
  "NextResponse", "Response", "json", "compose", "pipe",
  // Logging/telemetry decorators, asserted by name — see the caveat above.
  "withAxiom", "withAxiomBodyLog", "withLogging", "withSentry",
]);

/** The route refuses somebody. Whatever it checks, it checks something. */
const REJECTS_RE =
  /\b(?:status|Status)\s*[(:]\s*(?:401|403)\b|\b(?:401|403)\s*[,)]|\bunauthorized(?:Response)?\b|\bforbidden\b|"Unauthorized"|'Unauthorized'/i;

/**
 * A call that verifies a credential we cannot classify.
 *
 * `verifyUnsubscribeToken(token)` gates corpus-b's unsubscribe endpoint.
 * STRONG_USER_AUTH_RE requires "Session" in the name and MACHINE_GATE_RE
 * requires "Signature" or "Webhook", so it matched neither and the route read
 * as completely ungated. Counted across the five repositories: seventeen route
 * files carry a verifier-shaped call that neither regex gates.
 *
 * DELIBERATELY NOT `authenticated: true`, and this is the trade worth stating.
 * Widening a NAME pattern to assert authentication marks routes as gated on the
 * evidence of a string, which stage 1b flagged as an unmeasured false-negative
 * hazard -- a `validateInput()` whose boolean nobody checks would silence a real
 * finding. Routing these to identityReadable: false instead takes NO such risk:
 * it says only "there is a check here we could not attribute", which is exactly
 * what we know. The guard refuses the critical, Coverage discloses the route as
 * unjudged, and we never claim a gate we did not read.
 */
// The two shapes added after the call-path tracer landed both come from corpus-a's
// /api/resend/webhook: `new Webhook(secret).verify(rawBody, { "svix-signature":
// … })`. A member call named verify() on anything, and an inbound header whose
// name ends in "signature", are each the shape of a check -- and neither says
// which kind, so both land here rather than in MACHINE_GATE_RE. That route
// had been masked by an unrelated gap; once the tracer removed the gap the
// merge check BLOCKED it as anonymous, on a route that verifies every request.
// Two more from the alias-resolution census (2026-09-02): `authenticate*()` --
// corpus-c' v2 API wrapper authenticates by API key through
// authenticateRequest(), and once the wrapper was readable the route read as
// anonymous and BLOCKED the merge check -- and a database lookup keyed by a
// token, `where: { token, expires: { gte } }` in corpus-a's reset-password route,
// which is the Prisma spelling of the `.eq("...token", …)` MACHINE_GATE_RE has
// known for Supabase. Both land here, never as a gate: a lookup whose result
// nobody checks would silence a real finding.
const UNCLASSIFIED_VERIFIER_RE =
  /\b(?:verify|validate|decode|parse)[A-Za-z]*(?:Token|Credential|Bearer)[A-Za-z]*\s*\(|\b(?:assert|require|check)[A-Za-z]*(?:Auth|Access|Permission|Member)[A-Za-z]*\s*\(|\bauthenticate[A-Za-z]*\s*\(|\.\s*verify\s*\(|["'][\w-]*-signature["']|\bwhere\s*:\s*\{\s*(?:\w*[tT]oken|hashedKey|hashed_key|apiKey|api_key|secret)\b/i;

/** A session carried in a cookie we do not recognise by name. */
const COOKIE_AUTH_RE =
  /\bcookies\s*\(\s*\)|\breq(?:uest)?\.cookies\b|\.headers\.get\s*\(\s*["']cookie|\breq(?:uest)?\.headers\.cookie\b|parseCookieHeader\s*\(/i;

/** A module whose name says it may be a gate; used only to disclose, never to credit. */
const GATE_LIKE_MODULE_RE = /auth|session|guard|middleware|permission|policy|acl|rbac|token|identity|clerk|current-?user|require/i;

/**
 * Q24: the executed path continued into a file past the read budget. If that
 * file's name says it may be the gate, the route is unread, never anonymous
 * (corpus-y: route, barrel, validator, then getServerSession three files in).
 */
export function unfollowedGateGap(unfollowed: string[]): string | null {
  const gate = unfollowed.find((path) => GATE_LIKE_MODULE_RE.test(path));
  return gate ? `the route's code continues into ${gate}, past what we read, and that file may be its gate` : null;
}

/**
 * Why we could not read this route's identity check, or null if we could.
 *
 * Only consulted when the route looks anonymous — a route we DID read as
 * authenticated or machine-gated has no gap to report.
 */
export function identityGapFor(
  entrySrc: string,
  unresolvedImports: string[],
  machineGateWitness: string | null = null,
  headerReadWitness: string | null = null,
  conditionalIdentityWitness: string | null = null,
  untracedReExport: string | null = null,
): string | null {
  // Checked FIRST: every other gap below describes something we read in the
  // handler. This one says the handler is not in this file at all and we could
  // not follow it, which subsumes the rest -- there is nothing to have read.
  if (untracedReExport) {
    return `the handler is re-exported from ${untracedReExport}, and we could not follow it to read what gates it`;
  }
  // A wrapper that resolves a session only when an option says so (corpus-c'
  // withApiLogging: `switch (authenticationMethod)`). Which option this route
  // set is data we did not read, so the gate is neither asserted nor denied.
  if (conditionalIdentityWitness) {
    return `${conditionalIdentityWitness} resolves a session only when an option tells it to, and we could not read which option this route sets`;
  }
  // A signature or shared-secret check sitting in a module this route imports.
  // We deliberately do not credit it as a gate ON this route -- a helper that
  // mentions a secret does not gate its importer -- but it is plainly evidence
  // that a gate exists somewhere, so it belongs here rather than in silence.
  // Folded into identityReadable rather than given its own consumer wiring,
  // because every consumer that must not call this route anonymous already
  // reads identityReadable.
  if (machineGateWitness) {
    return `a signature or shared-secret check appears in ${machineGateWitness}, which this route imports, but not in the route itself`;
  }
  // An inbound Authorization header is read and nothing we recognise verifies
  // it. A user token, a cron secret and a SCIM directory secret all arrive this
  // way, so the only honest claim is that a credential check exists here.
  if (headerReadWitness) {
    return `the route reads the Authorization header${
      /route\.[tj]sx?$|pages\//.test(headerReadWitness) ? "" : ` in ${headerReadWitness}`
    }, and we could not read what verifies the credential`;
  }
  WRAPPED_HANDLER_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = WRAPPED_HANDLER_RE.exec(entrySrc)) !== null) {
    if (!NEUTRAL_WRAPPERS.has(m[1])) {
      return `the handler is wrapped in ${m[1]}(), and we could not read what it checks`;
    }
  }

  if (REJECTS_RE.test(entrySrc)) {
    return "the route answers 401 or 403, so it checks something we could not attribute";
  }

  if (COOKIE_AUTH_RE.test(entrySrc)) {
    return "the route reads cookies, and we could not tell which of them is a session";
  }

  const verifier = UNCLASSIFIED_VERIFIER_RE.exec(entrySrc);
  if (verifier) {
    const what = verifier[0].replace(/\s*\($/, "").replace(/^\./, "");
    return /^["']/.test(what)
      ? `the route reads a ${what} header, a signature check we could not classify`
      : `the route calls ${what}(), a credential check we could not classify`;
  }

  // Only an unread module that could plausibly BE the gate. The first version
  // fired on any unresolved local import, which made `import { getSupabaseAdmin }
  // from "@/lib/supabase"` — a database client — read as a possible auth check,
  // and a genuinely anonymous route stopped being reported. Caught by the test
  // named "still reports a genuinely anonymous route", which is exactly the
  // regression this whole change must not cause: the cure cannot be silence.
  const gateLike = unresolvedImports.find((spec) => GATE_LIKE_MODULE_RE.test(spec));
  if (gateLike) {
    return `we could not read ${gateLike}, which this route imports and which may be its gate`;
  }

  return null;
}

/** The first match of `re` that does not begin inside a string literal, or null. */
export function matchOutsideStrings(src: string, re: RegExp): number | null {
  const scan = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
  const inString = stringSpans(src);
  scan.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = scan.exec(src)) !== null) {
    if (!inString(m.index)) return m.index;
  }
  return null;
}

/**
 * The same, excluding only QUOTED strings. A template literal is code: it is
 * where raw SQL and its `${userId}` filter live, and dropping it would invent
 * attack paths for routes that scope through `sql\`...\``.
 */
export function matchOutsideQuotes(src: string, re: RegExp): number | null {
  const scan = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
  const inside = new Uint8Array(src.length);
  for (const { start, end, quote } of stringLiteralRanges(src)) {
    if (quote === "`") continue;
    for (let i = start; i < end && i < inside.length; i++) inside[i] = 1;
  }
  scan.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = scan.exec(src)) !== null) {
    if (!(m.index < inside.length && inside[m.index] === 1)) return m.index;
  }
  return null;
}

/**
 * An identity call carrying MORE than the request.
 *
 * `verifyDataroomSession(req, linkId, dataroomId)` does not merely establish who
 * is calling -- the extra arguments are the scope, and the lookup succeeds only
 * for a caller entitled to that link and that dataroom. The session check IS the
 * ownership filter, and no `.eq()` will ever appear in the route.
 */
const SCOPED_IDENTITY_CALL_RE =
  /\b(?:verify|require|assert|check|get|load)[A-Za-z]*(?:Session|Access|Auth|Permission|Member|Tenant)[A-Za-z]*\s*\(\s*[^)]*,[^)]*\)/;

/**
 * A tenant handed to the handler by something above it.
 *
 * `withWorkspace(async ({ workspace }) => …)` and Hono's `c.get("apiAuth")` both
 * mean the scope was resolved before this code ran. The query below may be
 * narrowed by a value we can see being destructured but never see assigned.
 */
// THE `) =>` IS THE WHOLE SIGNAL. Without it this matched any call carrying an
// object literal that mentioned one of these words anywhere -- including inside
// a string. Measured across the five audited repositories it fired on twelve
// routes and was wrong on all twelve: an error message reading "No workspace
// slug provided", an outbound sendEmail({ stripeId: workspace.stripeId }), a
// feature-flag lookup, and -- worst -- Prisma `where: { id, teamId }` clauses,
// which ARE the ownership filter. A signal meant to say "we cannot see the
// scoping" was firing on the scoping itself.
//
// It cost a real finding. corpus-b's /api/links/[id]/annotations reads linkId
// and viewId straight from the query with no auth anywhere in 94 lines, and it
// was marked unreadable because of `getFeatureFlags({ teamId: ... })`. Once the
// compatibility guard landed, that stopped being a softened finding and became
// a refused one, invisible in four runs out of five.
//
// Requiring the destructure to close into `) =>` restricts it to what it was
// written for: an object destructured as a FUNCTION PARAMETER, which is how a
// wrapper hands a tenant to the handler it wraps.
const INJECTED_CONTEXT_RE = new RegExp(
  "\\(\\s*\\{[^}]*\\b(?:workspace|workspaceId|team|teamId|tenant|tenantId|org|orgId|" +
    "space|spaceId|session|account|accountId)\\b[^}]*\\}\\s*(?::[^)=]*)?\\)\\s*=>",
);
const CONTEXT_GET_RE =
  /\bc\s*\.\s*get\s*\(\s*["'][^"']+["']\s*\)|\bctx\s*\.\s*(?:workspace|team|tenant|session|auth)\b|\breq(?:uest)?\s*\.\s*(?:workspace|team|tenant)\b/;

/**
 * Q24: the same unattributed-check questions, asked of every file the entry's
 * executed path runs, not only of the entry. Q23 measured the cost of asking
 * them of the entry alone: routes that verify a cookie JWT in a helper
 * (`verifyHeaderCookie()` into `jwt.verify`) and actions that call their own
 * `checkAdmin()` read as ANONYMOUS, and 82 of 157 agreed-false findings sat on
 * routes read that way. A check we cannot attribute is unread, never absent;
 * this can only move an entry from judged to unjudged, never add a finding.
 * Sources are the call-path tracer's executed text, so a helper function the
 * entry never calls is already blank and cannot count. A bare 401/403 in a
 * helper is NOT asked: corpus-b's conversations handler refuses on some
 * branches and not on the GET that leaks (a Q16 agreed-real bug), and a
 * refusal on one branch says nothing about the others.
 */
export function executedCheckGap(sources: { path: string; src: string }[]): string | null {
  for (const { path, src } of sources) {
    const verifier = UNCLASSIFIED_VERIFIER_RE.exec(src);
    if (verifier) {
      const what = verifier[0].replace(/\s*\($/, "").replace(/^\./, "");
      return /^["']/.test(what)
        ? `a ${what} header is checked in ${path}, on this entry's path, and we could not classify the check`
        : `${what}() runs in ${path}, on this entry's path, and we could not classify the credential it checks`;
    }
    if (COOKIE_AUTH_RE.test(src)) return `${path}, on this entry's path, reads cookies, and we could not tell which of them is a session`;
    if (HEADER_READ_RE.test(src)) return `${path}, on this entry's path, reads the Authorization header, and we could not read what verifies it`;
  }
  return null;
}

/**
 * A role check on the path. `withAdmin()` resolves a session and then requires
 * a role; read whole, an admin route is "authenticated and unscoped", and the
 * merge check blocked corpus-a's /api/admin/domains/renew as an outlier on invoice.
 * A route admitted by role is not narrowed to one tenant BY DESIGN, so its
 * scope is disclosed as unreadable rather than judged. "role" is the concept,
 * not a domain noun: the discriminator is a comparison on a value so named.
 */
const ROLE_GATE_RE =
  /\brequiredRoles?\b|\b\w*[rR]ole\b\s*(?:===|!==|==|!=)|\.includes\s*\(\s*\w*[rR]ole\w*\s*\)|\bis(?:Super)?Admin\b/;

/**
 * Q24: an ADMIN gate, read at any URL. Q23 found about 51 agreed-false
 * findings on routes and actions admitted only to administrators (an
 * `ADMIN_*` allowlist, `role !== "admin"`, `isAdminUser()`, `role < 4`) whose
 * URLs carry no /admin segment, over catalog tables no tenant owns. Only
 * admin tests count: a workspace role requirement (corpus-a's requiredRoles) is a
 * permission inside the caller's own tenant, which the ROLE_GATE_RE comment
 * above shows must stay judged. An allowlist counts only as an environment
 * list of admins (`env.ADMINS`, `CLERK_ADMIN_IDS`): "admin" in a Supabase
 * service-role client's name is the opposite of a gate (corpus-r2, Q24 dev
 * replay). Read only on executed text.
 */
export const ADMIN_GATE_RE =
  /\b(?:get)?[iI]s(?:Super)?Admin\w*\s*\(|\b(?:check|assert|require|ensure|verify)(?:Super)?Admin\w*\s*\(|\brole\w*\s*(?:===|!==|==|!=)\s*(?:[\w.]*\.)?["'`]?(?:super_?)?admin\b|["'`](?:super_?)?admin["'`]\s*(?:===|!==|==|!=)|\bUserRole\.(?:SUPER_)?ADMIN\b|\bUserRole\.admin\b|\benv\.(?:[A-Z]+_)*ADMIN(?:S|_(?:[A-Z]+_)*(?:IDS?|EMAILS?|USERS?|LOGINS?|LIST))\b|\.role\s*[<>]=?\s*\d|\badmin(?:Ids|Emails|Logins|List|Users)\b|\bisAdmin\b/;

/**
 * Why the ownership filter could not be read, or null if it could.
 *
 * Only asked of a route we are about to describe as unscoped -- a route we DID
 * read a filter on has nothing to explain.
 */
export function ownershipGapFor(
  entrySrc: string,
  identityReadable: boolean,
  tablesFromImport: string[],
  roleGateWitness: string | null = null,
): string | null {
  if (!identityReadable) {
    return "we could not read how this route resolves its caller, so the scope it runs under is decided somewhere we could not read";
  }
  if (roleGateWitness) {
    return `the caller is admitted by role in ${roleGateWitness}, so the query is deliberately not narrowed to one tenant`;
  }
  if (SCOPED_IDENTITY_CALL_RE.test(entrySrc)) {
    return "the caller is resolved by a call that also carries the scope, so the session lookup may itself be the filter";
  }
  if (INJECTED_CONTEXT_RE.test(entrySrc) || CONTEXT_GET_RE.test(entrySrc)) {
    return "the tenant arrives on a context object created before this handler ran";
  }
  if (tablesFromImport.length > 0) {
    return `the query runs inside ${tablesFromImport[0]}, so any filter it applies is out of this file`;
  }
  return null;
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
  // PER-CALL-PATH ATTRIBUTION (./callPath.ts). When the handler can be found,
  // each source is the text of what that handler actually runs: unexecuted
  // functions blanked, declarations blanked, parameters no call site supplies
  // renamed. When it cannot, whole files two hops deep, as before.
  const traced = byPath
    ? traceExecutedSources({ path: file, content }, byPath, {
        isIdentityCall: (callee) => STRONG_USER_AUTH_RE.test(`${callee}(`),
      })
    : null;
  const sources: { path: string; src: string; original: string; prepared: boolean; host: boolean; infra: boolean }[] = traced
    ? traced.sources.map((s) => ({ path: s.path, src: s.src, original: s.original, prepared: true, host: s.host, infra: s.identityInfrastructure }))
    : byPath
      ? reachableSources({ path: file, content }, byPath).map((s) => ({ ...s, original: s.src, prepared: false, host: s.path === file, infra: false }))
      : [{ path: file, src: stripComments(content), original: stripComments(content), prepared: false, host: true, infra: false }];

  // WHAT A WRAPPER INJECTS IS THE WRAPPER'S TO ESTABLISH. `withPartnerProfile(
  // async ({ partner }) => …)` hands the handler a partner it looked up by the
  // session it resolved. `partner.id` in a filter is then the caller's identity
  // by provenance, whatever the name -- but only when the wrapper resolved an
  // identity; a wrapper that injects a value it read from the URL injects the
  // caller's input.
  const wrapperResolvesIdentity =
    traced !== null &&
    traced.wrapperPaths.some((p) => {
      const w = traced.sources.find((s) => s.path === p);
      return w !== undefined && STRONG_USER_AUTH_RE.test(w.src);
    });
  // Context handed on in other shapes (a later parameter, or destructured in
  // the body) counts only when the wrapper also looked the caller up in a
  // membership table: then the id is the membership's, not the request's.
  const wrapperReadsMembership = traced !== null && traced.wrapperPaths.some((p) => {
    const w = traced.sources.find((s) => s.path === p);
    return w !== undefined && MEMBERSHIP_LOOKUP_RE.test(w.src);
  });
  // Membership helpers the route itself calls (class C).
  const resolvers = byPath ? membershipResolvers(file, stripComments(content), byPath) : [];
  const injectedIdentities = wrapperResolvesIdentity
    ? [...traced!.injected, ...(wrapperReadsMembership ? traced!.contextInjected : [])] : [];

  // The gap questions are asked of the route as written -- wrapper names,
  // `({ workspace }) =>` parameters, 401s -- so they read the unblanked entry
  // text, plus the text of any file that HOSTS the handler (a re-exported
  // handler's 401 is this route's 401).
  const entrySrc = [
    stripComments(content),
    ...sources.filter((s) => s.host && s.path !== file).map((s) => s.src),
  ].join("\n");

  // Local imports the read budget did not reach. A route whose gate lives in a
  // file we never downloaded is unreadable, not ungated. Bare package
  // specifiers are excluded: node_modules is out of scope by design, and
  // treating every framework import as a gap would make every route unreadable.
  const unresolvedImports: string[] = [];
  if (byPath) {
    const seen = new Set<string>();
    IMPORT_RE.lastIndex = 0;
    let im: RegExpExecArray | null;
    while ((im = IMPORT_RE.exec(entrySrc)) !== null) {
      const spec = im[1] ?? im[2] ?? im[3];
      if (!spec || seen.has(spec)) continue;
      seen.add(spec);
      // A workspace package (`@corpus-a/utils`, `@corpus-e/db`) is this
      // repository's own code that we do not resolve; it is disclosed as
      // unresolved, never mistaken for a third-party dependency.
      if (!/^[.~]|^@\//.test(spec) && !isWorkspacePackageImport(spec, byPath)) continue;
      if (resolveImport(file, spec, byPath) === null) unresolvedImports.push(spec);
    }
  }
  const tables = new Set<string>();
  const tablesFromImport = new Set<string>();
  const via = new Set<string>();
  let authenticated = false;
  let machineGated = false;
  let machineGateWitness: string | null = null;
  let headerReadWitness: string | null = null;
  let usesServiceRole = false;
  let serviceRoleReadable = true;
  let ownershipFiltered = false;

  let roleGateWitness: string | null = null;
  const isAdminPath = /(^|\/)admin(\/|$)/.test(routePathFromFile(file));
  const conditionalIdentityWitness = traced?.conditionalIdentityPaths[0] ?? null;
  // The handler lives in another module and the trace could not reach it. Only
  // consulted when we ended up with no identity: if it propagated anyway,
  // `authenticated` is already true and no gap is asked for.
  const untracedReExport = traced === null ? (STAR_REEXPORT_RE.exec(stripComments(content))?.[1] ?? null) : null;

  for (const { path, src: raw, original, prepared, host, infra } of sources) {
    // A HOST file is the route: the entry itself, or the file its handler was
    // re-exported from or resolved into. Its queries and its machine gate are
    // the route's own. Everything else is a helper the route calls.
    const isEntry = host;
    let contributed = false;

    // THE DECLARATION RULE. Every pattern below reads `src`, which has its
    // declarations blanked: types, interfaces, imports, parameter bindings and
    // projections describe shape, and no collector may draw evidence from
    // shape. The unblanked text is kept as `raw` for the one thing that needs
    // it -- recovering the names a request destructure bound, so their uses
    // can still be neutralised. A traced source arrives already prepared.
    const src = prepared ? raw : blankDeclarations(raw, path);

    // Identity infrastructure (NextAuth options handed to getServerSession, or
    // a NextAuth v5 module that builds `auth` with NextAuth({...})) resolves
    // identity by definition, even when no pattern in it says so. Its sign-in
    // callbacks write users and viewers; those writes are not the route's
    // (Step 7H, corpus-e).
    const resolvesIdentity = infra || STRONG_USER_AUTH_RE.test(src) || HEADER_READ_RE.test(src) || /\bNextAuth\s*\(/.test(src);
    // Only under an admin URL. corpus-a's withWorkspace() ALSO takes requiredRoles
    // -- a permission inside the caller's own workspace -- and the first
    // version of this rule made 59 workspace-scoped routes unreadable, hiding
    // exactly the unscoped-lookup class the check exists for. The role check
    // is textually the same in both wrappers; what differs is that the
    // application segregates its admin surface by URL. That is a convention,
    // stated as one, not a fact read from the code.
    if (isAdminPath && ROLE_GATE_RE.test(src)) roleGateWitness ??= path;
    // Q24: an admin test on the executed path gates at any URL.
    if ((prepared || isEntry) && !infra && ADMIN_GATE_RE.test(src)) roleGateWitness ??= path;

    // Tables from an IMPORTED auth helper are the helper's own scoped read of
    // whoever is signed in, not data the route exposes. requireProUser selects
    // from user_profiles to check the gate, and crediting that made
    // /api/deep/github/connect -- a route whose entire body is a redirect and
    // which queries nothing -- report as CRITICAL for reading user_profiles
    // without narrowing it to the caller.
    //
    // Same rule as the ownership evidence below and for the same reason: a
    // helper that establishes WHO is calling is infrastructure, and its own
    // queries belong to it. The entry file's queries always count, and a data
    // helper that does not resolve identity still counts.
    if (isEntry || !resolvesIdentity) {
      for (const table of extractTables(src)) {
        if (!tables.has(table)) contributed = true;
        tables.add(table);
        // Remembered for the ownership gap below: a query that runs inside an
        // imported helper carries any filter that helper applies, and that
        // filter is not in the file we are judging.
        if (path !== file) tablesFromImport.add(path);
      }
    }
    if (STRONG_USER_AUTH_RE.test(src)) {
      if (!authenticated) contributed = true;
      authenticated = true;
    } else if (HEADER_READ_RE.test(src)) {
      // Remembered, not credited. Consulted only if the route ends up with no
      // session and no machine gate, where it becomes the identity gap.
      headerReadWitness ??= path;
    }
    // A machine gate only counts from the ROUTE FILE. A helper that happens to
    // mention a secret name does not gate the endpoint that imports it.
    if (isEntry && machineGateIn(src)) {
      machineGated = true;
    } else if (!isEntry && MACHINE_GATE_RE.test(src)) {
      // The existing conservatism is kept exactly: a helper that MENTIONS a
      // secret does not gate the endpoint importing it, so this still does not
      // set machineGated. What changes is that it is no longer indistinguishable
      // from silence. HMAC verification factored into a shared verifyWebhook()
      // is the normal refactor, and "the gate may be one file away" is a
      // different claim from "there is no gate".
      machineGateWitness = path;
    }
    // A SERVICE-ROLE MENTION INSIDE A STRING IS NOT A CLIENT.
    //
    // `.eq("role", "service_role")` is an RBAC comparison -- code CHECKING a
    // role, the opposite of code assuming one. Without this guard that route was
    // marked as using the service-role client, which removes the
    // `rlsCouldStillProtect` hedge in findings.ts and promotes the finding from
    // `inferred` to `corroborated`. A route doing a role check earned a MORE
    // confident critical than one that was not.
    //
    // Same rule and same helper as extractTables, which has had it since the
    // string-literal fix; this call site never got it.
    const serviceRoleAt = matchOutsideStrings(src, SERVICE_ROLE_RE);
    if (serviceRoleAt !== null) {
      usesServiceRole = true;
    } else if (SERVICE_ROLE_RE.test(src)) {
      // Seen, but only as text. We cannot confirm a client from a string, and we
      // must not assert one -- so this is the unreadable state, not `false`.
      serviceRoleReadable = false;
    }
    // Ownership from an IMPORTED source counts only when that source is a data
    // helper, not an auth helper. An auth helper filters by the caller to fetch
    // the caller: this repository's own requireProUser does
    // `.eq("id", user.id)` to read the profile of whoever is signed in. That is
    // identity construction, not row scoping, and counting it made EVERY route
    // calling requireProUser read as owner-filtered whether it filtered or not.
    //
    // Found when the merge check passed a route that reads scan_history by an
    // id straight from the URL. Same reasoning as the machine gate above: a
    // helper that mentions the shape does not apply it to the importer.
    //
    // A data helper that genuinely scopes on the route's behalf still counts,
    // because it does not resolve identity itself.
    const ownershipCounts = isEntry || !resolvesIdentity;
    let filterable = withoutIdentityResolution(src, original, isEntry ? resolvers : []);
    if (isEntry && injectedIdentities.length > 0) {
      for (const name of injectedIdentities) {
        const esc = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        filterable = filterable.replace(new RegExp(`\\b${esc}\\s*\\??\\.\\s*(?:\\w*Id|id|uid|sub)\\b`, "g"), "serverEstablishedId");
        // The whole injected object handed on: getDefaultProgramIdOrThrow(workspace).
        filterable = filterable.replace(new RegExp(`\\(\\s*${esc}\\s*\\)`, "g"), "(serverEstablishedId)");
        // An id the wrapper established, used by itself: `.eq("workspace_id", workspaceId)`.
        if (/(?:Id|_id)$|^id$/.test(name)) filterable = filterable.replace(new RegExp(`\\b${esc}\\b`, "g"), "serverEstablishedId");
      }
      filterable = propagateDerived(filterable);
    }
    // A trusted id handed to a data helper whose own query filters on that
    // parameter (one hop, by position): computeSetupStatus(membership.workspaceId).
    if (isEntry && byPath && !ownershipFiltered && filterable.includes("serverEstablishedId")
        && scopesThroughHelper(file, original, filterable, byPath)) {
      contributed = true;
      ownershipFiltered = true;
    }
    // The column-side pattern is NOT quote-filtered: its match begins inside
    // the column name's own quotes (`.eq('user_id', ...)`), which is the shape
    // it exists to see.
    if (
      ownershipCounts &&
      (matchOutsideQuotes(filterable, OWNERSHIP_RE) !== null || OWNERSHIP_ALT_RE.test(filterable))
    ) {
      if (!ownershipFiltered) contributed = true;
      ownershipFiltered = true;
    }
    if (contributed && path !== file) via.add(path);
  }

  // A GATE ONE CALL AWAY (./helperGuard.ts). The route rejects with 401 or
  // 403 on the answer of a helper it imports, and that helper compares a
  // secret or resolves a hashed token: then the helper's gate is the route's.
  // Asked only when nothing above credited a gate, so it can only move a route
  // from unreadable to gated, never the reverse.
  if (!authenticated && !machineGated && byPath) {
    const guard = helperGuard(file, stripComments(content), byPath);
    if (guard?.kind === "machine") machineGated = true;
    if (guard?.kind === "user") authenticated = true;
    if (guard) via.add(guard.path);
  }

  // Only a route we are about to call anonymous needs the question asked.
  //
  // A route the application files under a directory it names "(public)" is
  // anonymous by its own declaration. Like the admin URL rule, this is the
  // application's layout read as intent -- a convention, stated as one -- and
  // it discloses rather than judges: "anyone can call this" is not a finding
  // about a page built to be called by anyone.
  const publicByLayout = /(^|\/)\(public\)\//.test(file);
  const identityGap =
    authenticated || machineGated
      ? null
      : publicByLayout
        ? "the route sits in a directory the application names (public), so anonymous access appears to be by design"
        : identityGapFor(entrySrc, unresolvedImports, machineGateWitness, headerReadWitness, conditionalIdentityWitness, untracedReExport) ??
          // Q24: helpers on the executed path, not only the entry (hosts were asked above).
          (traced ? executedCheckGap(sources.filter((s) => !s.host && !s.infra)) ?? unfollowedGateGap(traced.unfollowed) : null);
  const identityReadable = identityGap === null;

  // Same question, one field over. Only asked when we are about to call the
  // route unscoped.
  // "The query runs inside a helper, so its filter is out of this file" is a
  // whole-file-reading gap. When the handler was traced, the helper's executed
  // path WAS read, filter and all, so that clause no longer applies.
  const ownershipGap = ownershipFiltered
    ? null
    : ownershipGapFor(entrySrc, identityReadable, traced ? [] : [...tablesFromImport], roleGateWitness);

  return {
    path: routePathFromFile(file),
    file,
    // Methods must be exported by the route file itself — an imported helper
    // exporting GET does not make the route respond to GET. The parser also
    // sees `export { handler as GET }`, which the regex never did.
    methods: [...new Set([...extractMethods(stripComments(content)), ...(traced?.methods ?? [])])]
      .filter((m, _, all) => m !== "ALL" || all.length === 1)
      .sort(),
    tables: [...tables].sort(),
    authenticated,
    machineGated,
    // False when a machine gate was seen in an imported module but not in the
    // route file: we cannot attribute it to this endpoint, and we must not
    // report the endpoint as ungated either.
    machineGateReadable: machineGated || machineGateWitness === null,
    machineGateGap: machineGated || machineGateWitness === null
      ? null
      : `a signature or shared-secret check appears in ${machineGateWitness}, which this route imports, but not in the route itself`,
    usesServiceRole,
    // True unless a service-role token appeared ONLY as text. Consumers that
    // rely on `usesServiceRole === false` to justify a hedge must keep the hedge
    // when this is false.
    serviceRoleReadable,
    ownershipFiltered,
    identityReadable,
    identityGap,
    dataReadable: tables.size > 0 || unresolvedImports.length === 0,
    dataGap:
      tables.size > 0 || unresolvedImports.length === 0
        ? null
        : `the route reaches no table we could see, but it imports ${unresolvedImports[0]}${unresolvedImports.length > 1 ? ` and ${unresolvedImports.length - 1} more` : ""}, which we could not follow`,
    ownershipReadable: ownershipGap === null,
    ownershipGap,
    via: [...via].sort(),
  };
}

// E3 (release attempt 4): a directory before app/ or pages/ that names an
// example, demo, sample, template, starter or playground holds code the
// project ships for others to copy, not its own deployed endpoints.
const EXAMPLE_DIR_RE = /(^|\/)(examples?|demos?|samples?|templates?|starters?|playgrounds?)\//i;
const APP_ROOT_RE = /(^|\/)(?:src\/)?(?:app|pages)\//;

/** True for files that define an HTTP endpoint. */
export function isRouteFile(path: string): boolean {
  const root = APP_ROOT_RE.exec(path);
  if (root && EXAMPLE_DIR_RE.test(path.slice(0, root.index + root[1].length))) return false;
  if (PAGES_API_RE.test(path)) return true;
  if (!ROUTE_FILE_RE.test(path)) return false;
  // Under an app/ directory anywhere, so a monorepo workspace still counts. A
  // `route.ts` outside one is not an endpoint.
  return APP_DIR_RE.test(path);
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
  const gaps = new Map<string, PermissionGap[]>();
  for (const gap of findPermissionGaps(files)) gaps.set(gap.file, [...(gaps.get(gap.file) ?? []), gap]);
  const routes = files
    .filter((f) => isRouteFile(f.path))
    .map((f) => {
      const route = analyzeRouteFile(f.path, f.content, byPath);
      return withRefusal(gaps.has(f.path) ? { ...route, permissionGaps: gaps.get(f.path) } : route, f, byPath, files);
    });
  // Step 7I: a monorepo may serve the same path from several apps (corpus-e:
  // /api/trpc/lambda/[trpc] in three). The path is what hypotheses, findings,
  // cross-tenant notes and possession gates key on, so a collision let one
  // app's facts judge, or a note hide, another app's route. Only colliding
  // paths are qualified, by the directory the app lives in (or the file, if
  // that is not distinct), so single-app finding identities do not change.
  const count = new Map<string, number>();
  for (const r of routes) count.set(r.path, (count.get(r.path) ?? 0) + 1);
  const appRoot = (file: string) => file.match(/^(.*?)\/(?:src\/)?(?:app|pages)\//)?.[1] ?? "";
  const roots = new Map<string, Set<string>>();
  for (const r of routes) if (count.get(r.path)! > 1) roots.set(r.path, (roots.get(r.path) ?? new Set()).add(appRoot(r.file)));
  return routes
    .map((r) => {
      if (count.get(r.path)! < 2) return r;
      const root = appRoot(r.file);
      const distinct = root && roots.get(r.path)!.size === count.get(r.path);
      return { ...r, path: `${distinct ? root : r.file}:${r.path}` };
    })
    .sort((a, b) => a.path.localeCompare(b.path));
}

/** R1b: the per-method refusal fact, only where the route-wide fact says signed in. */
function withRefusal(route: RouteFact, f: RepoFile, byPath: Map<string, RepoFile>, files: RepoFile[]): RouteFact {
  if (!route.authenticated || route.machineGated || !ROUTE_FILE_RE.test(f.path)) return route;
  const imports = importsOf(f.path, f.content, byPath);
  const body = (name: string) => {
    const target = imports.get(name);
    return functionBody(target ? byPath.get(target)?.content ?? "" : f.content, name);
  };
  const methods = unrefusedMethods(f.content, body);
  if (methods.length === 0) return route;
  const gap = middlewareGap(f.path, route.path, files);
  return { ...route, unrefusedMethods: methods, ...(gap ? { refusalGap: gap } : {}) };
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
