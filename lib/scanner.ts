import {
  validateSupabaseUrl,
  validateAnonKey,
  ValidationError,
} from "./sanitize";

// ── Result types ──────────────────────────────────────────────────────────────

export interface RLSPolicy {
  policyName: string;
  tableName:  string;
  command:    string;
  permissive: boolean;
  roles:      string[];
  using:      string | null;
  withCheck:  string | null;
}

export interface TableResult {
  name: string;
  rlsEnabled:        boolean;
  policies:          RLSPolicy[];
  policiesRetrieved: boolean;
}

// Check 2 & 5: JWT key analysis
export interface KeyAnalysis {
  role:          string | null;
  isServiceRole: boolean;
  jwtValid:      boolean;
  projectRef:    string | null;
}

// Check 3: Rate limiting
export interface RateLimitCheck {
  tested:      boolean;
  endpoint:    string;
  requests:    number;
  successes:   number;
  rateLimited: boolean;
}

// Check 4: Unauthenticated access
export interface UnauthAccessResult {
  tableName:  string;
  accessible: boolean;
  rowCount:   number;
}
export interface UnauthAccessCheck {
  tested:  boolean;
  results: UnauthAccessResult[];
}

// Check 5: Slop squatting
export interface SuspiciousPackage {
  name:       string;
  reason:     "NOT_FOUND" | "VERY_NEW" | "ZERO_DOWNLOADS";
  createdAt?: string;
}
export interface SlopSquattingCheck {
  tested:                boolean;
  packageJsonAccessible: boolean;
  suspiciousPackages:    SuspiciousPackage[];
}

// Check 6: Mass assignment
export interface MassAssignmentResult {
  tableName:  string;
  vulnerable: boolean;
}
export interface MassAssignmentCheck {
  tested:  boolean;
  results: MassAssignmentResult[];
}

// Check 7: Auth security — admin endpoint accessibility
export interface AuthSecurityCheck {
  tested:               boolean;
  adminEndpointBlocked: boolean; // true = good (blocked), false = bad (accessible)
}

// Check 8: IDOR — user-sensitive tables readable without user context
export interface IdorResult {
  tableName:      string;
  rowsAccessible: boolean;
}
export interface IdorCheck {
  tested:  boolean;
  results: IdorResult[];
}

// Check 9: Secrets exposure — env files publicly reachable
export interface SecretsExposureCheck {
  tested:       boolean;
  exposedFiles: string[];
}

// Check 10: Secure auth — login endpoint rate limiting
export interface SecureAuthCheck {
  tested:           boolean;
  loginRateLimited: boolean;
}

// Check 11: HTTPS enforcement
export interface HttpsCheck {
  tested:   boolean;
  enforced: boolean;
}

// Check 15: Stack trace exposure
export interface StackTraceCheck {
  tested:  boolean;
  exposed: boolean;
}

// Check 12: Bot protection — rate-limit response headers
export interface BotProtectionCheck {
  tested:                  boolean;
  rateLimitHeadersPresent: boolean;
}

// Check 13: Input validation — SQL injection in query params
export interface InputValidationCheck {
  tested:          boolean;
  sqlErrorExposed: boolean;
}

// Check 14: CORS configuration — wildcard Access-Control-Allow-Origin
export interface CorsConfigCheck {
  tested:          boolean;
  wildcardOrigin:  boolean;
  allowOriginValue: string | null;
}

// ── Composite scan result ─────────────────────────────────────────────────────

export interface ScanResult {
  // Check 1  — RLS per table
  tables:           TableResult[];
  // Check 2 & 5 — key type / service_role detection
  keyAnalysis:      KeyAnalysis;
  // Check 3  — rate limiting (429 responses)
  rateLimiting:     RateLimitCheck;
  // Check 4  — access without any auth headers
  unauthAccess:     UnauthAccessCheck;
  // Check 5  — slop squatting via package.json
  slopSquatting:    SlopSquattingCheck;
  // Check 6  — mass assignment via privileged PATCH
  massAssignment:   MassAssignmentCheck;
  // Check 7  — auth admin endpoint accessibility
  authSecurity:     AuthSecurityCheck;
  // Check 8  — IDOR on user-sensitive tables
  idor:             IdorCheck;
  // Check 9  — secrets exposure (.env files)
  secretsExposure:  SecretsExposureCheck;
  // Check 10 — login endpoint rate limiting
  secureAuth:       SecureAuthCheck;
  // Check 11 — HTTPS enforcement
  httpsCheck:       HttpsCheck;
  // Check 15 — Stack trace exposure
  stackTraceCheck:  StackTraceCheck;
  // Check 12 — rate-limit response headers
  botProtection:    BotProtectionCheck;
  // Check 13 — SQL injection in query params
  inputValidation:  InputValidationCheck;
  // Check 14 — CORS wildcard
  corsConfig:       CorsConfigCheck;
  /** Kept for backwards compatibility; true when keyAnalysis.isServiceRole */
  exposedKeyInCode: boolean;
  timestamp:        string;
}

// ── Error types ───────────────────────────────────────────────────────────────

export type ScanErrorCode =
  | "INVALID_CREDENTIALS"
  | "NETWORK_TIMEOUT"
  | "PROJECT_NOT_FOUND"
  | "MALFORMED_URL"
  | "FETCH_ERROR";

export class ScanError extends Error {
  constructor(
    message: string,
    public readonly code: ScanErrorCode,
    public readonly statusCode?: number
  ) {
    super(message);
    this.name = "ScanError";
  }
}

// ── Internal types ────────────────────────────────────────────────────────────

interface PostgRESTSpec { paths?: Record<string, unknown>; }
interface RawPolicy {
  policyname: string; tablename: string; cmd: string;
  permissive: string; roles: string[];
  qual: string | null; with_check: string | null;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const TIMEOUT_MS      = 10_000;
const SHORT_TIMEOUT   = 5_000;
const RATE_LIMIT_REQS = 10;
const RATE_LIMIT_TO   = 5_000;

const COMMON_TABLE_NAMES: readonly string[] = [
  "users", "profiles", "accounts", "customers", "members", "employees",
  "posts", "articles", "comments", "messages", "notifications", "events",
  "products", "orders", "payments", "transactions", "invoices",
  "subscriptions", "subscribers", "plans", "features",
  "settings", "preferences", "configs", "api_keys",
  "files", "uploads", "documents", "media", "images", "assets",
  "sessions", "tokens", "logs", "audit_logs", "analytics",
  "teams", "organizations", "groups", "roles", "permissions",
  "categories", "tags", "labels", "reviews", "ratings", "feedback",
  "leads", "contacts", "projects", "tasks", "notes",
];

// Tables whose names suggest they hold user-specific data (IDOR probe targets)
const USER_SENSITIVE_TABLES = new Set([
  "users", "profiles", "user_profiles", "accounts", "members", "customers",
  "employees", "contacts", "leads", "subscribers", "clients", "people",
]);

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeHeaders(key: string): Record<string, string> {
  return {
    apikey:        key,
    Authorization: `Bearer ${key}`,
    Accept:        "application/json",
  };
}

async function fetchJSON<T>(url: string, key: string): Promise<T> {
  let response: Response;
  try {
    response = await fetch(url, {
      method:  "GET",
      headers: makeHeaders(key),
      signal:  AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (err) {
    if (err instanceof Error) {
      if (err.name === "TimeoutError" || err.name === "AbortError")
        throw new ScanError("Request timed out after 10 seconds.", "NETWORK_TIMEOUT");
      if (err.name === "TypeError")
        throw new ScanError("Network error — could not reach the Supabase project.", "FETCH_ERROR");
    }
    throw err;
  }
  if (response.status === 401)
    throw new ScanError("Authentication failed — credentials are invalid.", "INVALID_CREDENTIALS", 401);
  if (response.status === 404)
    throw new ScanError("Supabase project not found — verify the project URL.", "PROJECT_NOT_FOUND", 404);
  if (!response.ok)
    throw new ScanError(`Unexpected response (HTTP ${response.status}).`, "FETCH_ERROR", response.status);
  return response.json() as Promise<T>;
}

// ── Check 2 & 5: JWT key analysis ─────────────────────────────────────────────

function decodeJwtPayload(jwt: string): Record<string, unknown> | null {
  try {
    const parts = jwt.split(".");
    if (parts.length !== 3) return null;
    const b64    = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    return JSON.parse(Buffer.from(padded, "base64").toString("utf-8")) as Record<string, unknown>;
  } catch { return null; }
}

function analyzeKey(anonKey: string): KeyAnalysis {
  const claims = decodeJwtPayload(anonKey);
  if (!claims) return { role: null, isServiceRole: false, jwtValid: false, projectRef: null };
  const role          = typeof claims.role === "string" ? claims.role : null;
  const isServiceRole = role === "service_role";
  const projectRef    =
    typeof claims.ref === "string" ? claims.ref :
    typeof claims.sub === "string" ? claims.sub : null;
  return { role, isServiceRole, jwtValid: true, projectRef };
}

// ── Check 1: Table probe ──────────────────────────────────────────────────────

interface ProbeResult { exists: boolean; accessible: boolean; }

async function probeTable(restBase: string, tableName: string, anonKey: string): Promise<ProbeResult> {
  try {
    const url      = `${restBase}/${encodeURIComponent(tableName)}?limit=1`;
    const response = await fetch(url, {
      method: "GET", headers: makeHeaders(anonKey),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (response.status === 404)                             return { exists: false, accessible: false };
    if (response.status === 401 || response.status === 403) return { exists: true,  accessible: false };
    if (response.ok) {
      try {
        const rows = await response.json() as unknown[];
        return { exists: true, accessible: Array.isArray(rows) && rows.length > 0 };
      } catch { return { exists: true, accessible: false }; }
    }
    return { exists: true, accessible: false };
  } catch { return { exists: false, accessible: false }; }
}

// Fetch rowsecurity status for all public tables in one request.
// Returns a map of tableName → rlsEnabled (true = RLS on, false = RLS off).
// Returns empty map if pg_tables is not accessible; callers must handle gracefully.
async function fetchRlsStatusMap(
  restBase: string, anonKey: string
): Promise<Map<string, boolean>> {
  const map = new Map<string, boolean>();
  try {
    const url = `${restBase}/pg_tables?schemaname=eq.public&select=tablename,rowsecurity`;
    const res = await fetch(url, {
      method: "GET", headers: makeHeaders(anonKey),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) return map;
    const rows = await res.json() as Array<{ tablename: string; rowsecurity: boolean }>;
    if (!Array.isArray(rows)) return map;
    for (const row of rows) {
      if (typeof row.tablename === "string") {
        map.set(row.tablename, row.rowsecurity === true);
      }
    }
  } catch { /* network error — return empty map, callers fall back */ }
  return map;
}

async function fetchTablePolicies(
  restBase: string, tableName: string, anonKey: string
): Promise<{ policies: RLSPolicy[]; retrieved: boolean }> {
  try {
    const url = `${restBase}/pg_policies?tablename=eq.${encodeURIComponent(tableName)}` +
                `&select=policyname,tablename,cmd,permissive,roles,qual,with_check`;
    const response = await fetch(url, {
      method: "GET", headers: makeHeaders(anonKey), signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!response.ok) return { policies: [], retrieved: false };
    const raw = await response.json() as RawPolicy[];
    if (!Array.isArray(raw)) return { policies: [], retrieved: false };
    return {
      retrieved: true,
      policies: raw.map((p) => ({
        policyName: p.policyname, tableName: p.tablename,
        command: p.cmd, permissive: p.permissive === "PERMISSIVE",
        roles: Array.isArray(p.roles) ? p.roles : [],
        using: p.qual ?? null, withCheck: p.with_check ?? null,
      })),
    };
  } catch { return { policies: [], retrieved: false }; }
}

// ── Check 3: Rate limiting ─────────────────────────────────────────────────────

async function checkRateLimiting(
  restBase: string, anonKey: string, testTable: string | null
): Promise<RateLimitCheck> {
  const endpoint = testTable
    ? `${restBase}/${encodeURIComponent(testTable)}?limit=0`
    : `${restBase}/`;
  const statuses = await Promise.all(
    Array.from({ length: RATE_LIMIT_REQS }, () =>
      fetch(endpoint, {
        method: "GET", headers: makeHeaders(anonKey),
        signal: AbortSignal.timeout(RATE_LIMIT_TO),
      }).then((r) => r.status).catch(() => 0)
    )
  );
  const valid       = statuses.filter((s) => s > 0);
  const rateLimited = valid.some((s) => s === 429);
  return {
    tested: true, endpoint, requests: RATE_LIMIT_REQS,
    successes: valid.filter((s) => s >= 200 && s < 300).length, rateLimited,
  };
}

// ── Check 4: Unauthenticated access ───────────────────────────────────────────

async function checkUnauthAccess(
  restBase: string, exposedTableNames: string[]
): Promise<UnauthAccessCheck> {
  if (exposedTableNames.length === 0) return { tested: false, results: [] };
  const results = await Promise.all(
    exposedTableNames.map(async (name): Promise<UnauthAccessResult> => {
      try {
        const url      = `${restBase}/${encodeURIComponent(name)}?limit=5`;
        const response = await fetch(url, {
          method: "GET",
          headers: { Accept: "application/json" }, // Deliberately omit apikey + Authorization
          signal: AbortSignal.timeout(TIMEOUT_MS),
        });
        if (!response.ok) return { tableName: name, accessible: false, rowCount: 0 };
        const rows  = await response.json() as unknown[];
        const count = Array.isArray(rows) ? rows.length : 0;
        return { tableName: name, accessible: count > 0, rowCount: count };
      } catch { return { tableName: name, accessible: false, rowCount: 0 }; }
    })
  );
  return { tested: true, results };
}

// ── Check 5: Slop squatting ───────────────────────────────────────────────────

const NPM_REGISTRY_URL = "https://registry.npmjs.org";
const MAX_PACKAGES     = 20;
const NEW_PACKAGE_DAYS = 30;

async function slopSquattingCheck(supabaseUrl: string): Promise<SlopSquattingCheck> {
  const empty: SlopSquattingCheck = { tested: true, packageJsonAccessible: false, suspiciousPackages: [] };
  let pkgJson: Record<string, unknown>;
  try {
    const res = await fetch(`${supabaseUrl}/package.json`, {
      signal: AbortSignal.timeout(SHORT_TIMEOUT), headers: { Accept: "application/json" },
    });
    if (!res.ok) return empty;
    pkgJson = await res.json() as Record<string, unknown>;
  } catch { return empty; }

  const allDeps = new Set<string>();
  for (const section of ["dependencies", "devDependencies"]) {
    const block = pkgJson[section];
    if (block && typeof block === "object")
      Object.keys(block as Record<string, unknown>).forEach((n) => allDeps.add(n));
  }
  if (allDeps.size === 0) return { ...empty, packageJsonAccessible: true };

  const packages = Array.from(allDeps).slice(0, MAX_PACKAGES);
  const cutoff   = Date.now() - NEW_PACKAGE_DAYS * 24 * 60 * 60 * 1000;

  const suspicious: SuspiciousPackage[] = (
    await Promise.all(
      packages.map(async (name): Promise<SuspiciousPackage | null> => {
        try {
          const res  = await fetch(`${NPM_REGISTRY_URL}/${encodeURIComponent(name)}`, {
            signal: AbortSignal.timeout(SHORT_TIMEOUT), headers: { Accept: "application/json" },
          });
          if (res.status === 404) return { name, reason: "NOT_FOUND" };
          if (!res.ok) return null;
          const data    = await res.json() as Record<string, unknown>;
          const time    = data.time as Record<string, string> | undefined;
          const created = time?.created ? new Date(time.created).getTime() : null;
          if (created !== null && created > cutoff)
            return { name, reason: "VERY_NEW", createdAt: time!.created };
          return null;
        } catch { return null; }
      })
    )
  ).filter((p): p is SuspiciousPackage => p !== null);

  return { tested: true, packageJsonAccessible: true, suspiciousPackages: suspicious };
}

// ── Check 6: Mass assignment ──────────────────────────────────────────────────

const MASS_ASSIGN_PAYLOAD = JSON.stringify({ is_paid: true, is_admin: true, role: "admin" });

async function massAssignmentCheck(
  restBase: string, anonKey: string, exposedTables: string[]
): Promise<MassAssignmentCheck> {
  if (exposedTables.length === 0) return { tested: false, results: [] };
  const results = await Promise.all(
    exposedTables.map(async (name): Promise<MassAssignmentResult> => {
      try {
        const url = `${restBase}/${encodeURIComponent(name)}?id=eq.00000000-0000-0000-0000-000000000000`;
        const res = await fetch(url, {
          method:  "PATCH",
          headers: { ...makeHeaders(anonKey), "Content-Type": "application/json", Prefer: "return=minimal" },
          body:    MASS_ASSIGN_PAYLOAD,
          signal:  AbortSignal.timeout(TIMEOUT_MS),
        });
        return { tableName: name, vulnerable: res.ok };
      } catch { return { tableName: name, vulnerable: false }; }
    })
  );
  return { tested: true, results };
}

// ── Check 7: Auth security ────────────────────────────────────────────────────

async function checkAuthSecurity(supabaseUrl: string, anonKey: string): Promise<AuthSecurityCheck> {
  try {
    // The admin user-list endpoint requires service_role — anon key must be blocked.
    const res = await fetch(`${supabaseUrl}/auth/v1/admin/users`, {
      headers: { apikey: anonKey, Authorization: `Bearer ${anonKey}`, Accept: "application/json" },
      signal:  AbortSignal.timeout(SHORT_TIMEOUT),
    });
    // 403 / 401 = correctly blocked. 200 = admin endpoint accessible with anon key = bad.
    return { tested: true, adminEndpointBlocked: !res.ok };
  } catch {
    return { tested: true, adminEndpointBlocked: true }; // network error → assume blocked
  }
}

// ── Check 8: IDOR ─────────────────────────────────────────────────────────────

async function checkIdor(
  restBase: string, anonKey: string, tableNames: string[]
): Promise<IdorCheck> {
  const targets = tableNames.filter((n) => USER_SENSITIVE_TABLES.has(n.toLowerCase())).slice(0, 5);
  if (targets.length === 0) return { tested: false, results: [] };

  const results = await Promise.all(
    targets.map(async (name): Promise<IdorResult> => {
      try {
        // Send only the apikey header — no Authorization bearer = truly anonymous caller
        const res = await fetch(`${restBase}/${encodeURIComponent(name)}?limit=1`, {
          headers: { apikey: anonKey, Accept: "application/json" },
          signal:  AbortSignal.timeout(SHORT_TIMEOUT),
        });
        if (!res.ok) return { tableName: name, rowsAccessible: false };
        const rows = await res.json() as unknown[];
        return { tableName: name, rowsAccessible: Array.isArray(rows) && rows.length > 0 };
      } catch { return { tableName: name, rowsAccessible: false }; }
    })
  );
  return { tested: true, results };
}

// ── Check 9: Secrets exposure ─────────────────────────────────────────────────

const SECRET_FILES = ["/.env", "/.env.local", "/.env.production", "/.env.development"];

async function checkSecretsExposure(supabaseUrl: string): Promise<SecretsExposureCheck> {
  const exposedFiles: string[] = [];
  await Promise.all(
    SECRET_FILES.map(async (file) => {
      try {
        const res = await fetch(`${supabaseUrl}${file}`, { signal: AbortSignal.timeout(4_000) });
        if (!res.ok) return;
        const text = await res.text();
        // Only flag if content contains key=value lines with sensitive-sounding names
        if (text.includes("=") && /KEY|SECRET|TOKEN|PASSWORD|PASS/i.test(text)) {
          exposedFiles.push(file);
        }
      } catch { /* network error = safe */ }
    })
  );
  return { tested: true, exposedFiles };
}

// ── Check 10: Secure auth ─────────────────────────────────────────────────────

async function checkSecureAuth(supabaseUrl: string, anonKey: string): Promise<SecureAuthCheck> {
  // Rapid-fire 5 login attempts with a dummy address; check for any 429 response
  const authUrl = `${supabaseUrl}/auth/v1/token?grant_type=password`;
  const payload = JSON.stringify({ email: "probe@scan.shiplock.dev", password: "xQ9!nope_invalid" });
  const statuses = await Promise.all(
    Array.from({ length: 5 }, () =>
      fetch(authUrl, {
        method:  "POST",
        headers: { apikey: anonKey, "Content-Type": "application/json", Accept: "application/json" },
        body:    payload,
        signal:  AbortSignal.timeout(4_000),
      }).then((r) => r.status).catch(() => 0)
    )
  );
  return { tested: true, loginRateLimited: statuses.some((s) => s === 429) };
}

// ── Check 11: HTTPS enforcement ───────────────────────────────────────────────

function checkHttps(supabaseUrl: string): HttpsCheck {
  return { tested: true, enforced: supabaseUrl.startsWith("https://") };
}

// ── Check 15: Stack trace exposure ────────────────────────────────────────────

async function checkStackTrace(supabaseUrl: string, anonKey: string): Promise<StackTraceCheck> {
  try {
    // Send a deliberately malformed query to try to elicit a raw error
    const res = await fetch(
      `${supabaseUrl}/rest/v1/?select=*&order=nonexistent_column.asc.nullslast.extra`,
      { headers: makeHeaders(anonKey), signal: AbortSignal.timeout(4_000) }
    );
    if (!res.ok) {
      const text = await res.text();
      const exposed =
        text.includes("stack") || text.includes("Error:") ||
        text.includes(" at ")  || text.includes(".js:");
      return { tested: true, exposed };
    }
    return { tested: true, exposed: false };
  } catch {
    return { tested: false, exposed: false };
  }
}

// ── Check 12: Bot protection ──────────────────────────────────────────────────

async function checkBotProtection(
  restBase: string, anonKey: string, testTable: string | null
): Promise<BotProtectionCheck> {
  const url = testTable
    ? `${restBase}/${encodeURIComponent(testTable)}?limit=0`
    : `${restBase}/`;
  try {
    const res = await fetch(url, {
      headers: makeHeaders(anonKey), signal: AbortSignal.timeout(4_000),
    });
    const hasHeaders =
      res.headers.has("x-ratelimit-limit")     ||
      res.headers.has("x-ratelimit-remaining") ||
      res.headers.has("retry-after")           ||
      res.headers.has("x-rate-limit");
    return { tested: true, rateLimitHeadersPresent: hasHeaders };
  } catch {
    return { tested: false, rateLimitHeadersPresent: false };
  }
}

// ── Check 13: Input validation ────────────────────────────────────────────────

async function checkInputValidation(
  restBase: string, anonKey: string, testTable: string | null
): Promise<InputValidationCheck> {
  if (!testTable) return { tested: false, sqlErrorExposed: false };
  try {
    // PostgREST operator injection attempt — malformed filter value
    const url = `${restBase}/${encodeURIComponent(testTable)}?id=eq.%27%20OR%20%271%27%3D%271`;
    const res  = await fetch(url, {
      headers: makeHeaders(anonKey), signal: AbortSignal.timeout(4_000),
    });
    const text = await res.text();
    const sqlErrorExposed =
      text.includes("syntax error") || text.includes("PostgreSQL") ||
      text.includes("ERROR:")       || text.includes("pg_query")   ||
      text.includes("relation ")    || text.includes("column ");
    return { tested: true, sqlErrorExposed };
  } catch {
    return { tested: false, sqlErrorExposed: false };
  }
}

// ── Check 14: CORS configuration ─────────────────────────────────────────────

async function checkCorsConfig(supabaseUrl: string, anonKey: string): Promise<CorsConfigCheck> {
  try {
    const res = await fetch(`${supabaseUrl}/rest/v1/`, {
      headers: {
        ...makeHeaders(anonKey),
        Origin: "https://evil.example.com",
      },
      signal: AbortSignal.timeout(4_000),
    });
    const allowOriginValue = res.headers.get("access-control-allow-origin");
    const wildcardOrigin   = allowOriginValue === "*";
    return { tested: true, wildcardOrigin, allowOriginValue };
  } catch {
    return { tested: false, wildcardOrigin: false, allowOriginValue: null };
  }
}

// ── Main scanner ──────────────────────────────────────────────────────────────

/**
 * Runs 15 security checks against a Supabase project using only the
 * caller-supplied anon key and project URL. Our own service role key is
 * never used.
 *
 * Check 1  — RLS per table            (rlsEnabled true/false)
 * Check 2  — Key type                 (anon vs service_role JWT)
 * Check 3  — Rate limiting            (10-request burst, look for 429)
 * Check 4  — Unauthenticated access   (request without any auth headers)
 * Check 5  — Slop squatting           (exposed package.json + npm registry)
 * Check 6  — Mass assignment          (privileged PATCH on exposed tables)
 * Check 7  — Auth security            (admin endpoint blocked to anon key)
 * Check 8  — IDOR                     (user-sensitive tables, anon-key probe)
 * Check 9  — Secrets exposure         (/.env files publicly reachable)
 * Check 10 — Secure auth              (login endpoint rate limiting)
 * Check 11 — HTTPS enforcement        (URL uses HTTPS)
 * Check 12 — Bot protection           (rate-limit response headers)
 * Check 13 — Input validation         (SQL error via injected query param)
 * Check 14 — CORS configuration       (wildcard Access-Control-Allow-Origin)
 * Check 15 — Stack trace exposure     (malformed request leaks internals)
 */
export async function scanProject(
  rawUrl:     string,
  rawAnonKey: string
): Promise<ScanResult> {

  // Step 1: Sanitize inputs
  let supabaseUrl: string;
  let anonKey:     string;
  try {
    supabaseUrl = validateSupabaseUrl(rawUrl);
    anonKey     = validateAnonKey(rawAnonKey);
  } catch (err) {
    if (err instanceof ValidationError) throw new ScanError(err.message, "MALFORMED_URL");
    throw err;
  }

  const restBase = `${supabaseUrl}/rest/v1`;

  // Step 2: JWT key analysis (checks 2 & 5)
  const keyAnalysis = analyzeKey(anonKey);

  // Step 3: Enumerate tables
  let tableNames: string[];
  try {
    const spec = await fetchJSON<PostgRESTSpec>(`${restBase}/`, anonKey);
    tableNames  = Object.keys(spec.paths ?? {})
      .filter((p) => p.length > 1 && !p.startsWith("/rpc/"))
      .map((p) => p.slice(1));
  } catch (err) {
    if (err instanceof ScanError && err.code === "INVALID_CREDENTIALS") {
      tableNames = [...COMMON_TABLE_NAMES];
    } else {
      throw err;
    }
  }

  // Step 4: Probe tables for existence + fetch authoritative RLS status from pg_tables.
  // These two fetches are independent so run them concurrently.
  const [probeResults, rlsStatusMap] = await Promise.all([
    Promise.all(tableNames.map(async (name) => ({ name, ...(await probeTable(restBase, name, anonKey)) }))),
    fetchRlsStatusMap(restBase, anonKey),
  ]);

  const tables: TableResult[] = await Promise.all(
    probeResults
      .filter((r) => r.exists)
      .map(async (r) => {
        // Use pg_tables.rowsecurity as the authoritative source for RLS status.
        // A 200 response with rows does NOT mean RLS is off — the table may have
        // policies that intentionally permit anon SELECT (e.g. a public feedback table).
        // Fall back to true (safe default) if pg_tables was not accessible for this table.
        const rlsEnabled = rlsStatusMap.has(r.name) ? rlsStatusMap.get(r.name)! : true;
        const { policies, retrieved } = await fetchTablePolicies(restBase, r.name, anonKey);
        return { name: r.name, rlsEnabled, policies, policiesRetrieved: retrieved };
      })
  );

  const exposedNames    = tables.filter((t) => !t.rlsEnabled).map((t) => t.name);
  const rateLimitTable  = tables[0]?.name ?? null;

  // Step 5: Run all remaining checks in parallel
  const [
    rateLimiting,
    unauthAccess,
    slopSquatting,
    massAssignment,
    authSecurity,
    idor,
    secretsExposure,
    secureAuth,
    httpsCheck,
    botProtection,
    inputValidation,
    corsConfig,
    stackTraceCheck,
  ] = await Promise.all([
    checkRateLimiting(restBase, anonKey, rateLimitTable),
    checkUnauthAccess(restBase, exposedNames),
    slopSquattingCheck(supabaseUrl),
    massAssignmentCheck(restBase, anonKey, exposedNames),
    checkAuthSecurity(supabaseUrl, anonKey),
    checkIdor(restBase, anonKey, tableNames),
    checkSecretsExposure(supabaseUrl),
    checkSecureAuth(supabaseUrl, anonKey),
    Promise.resolve(checkHttps(supabaseUrl)),
    checkBotProtection(restBase, anonKey, rateLimitTable),
    checkInputValidation(restBase, anonKey, rateLimitTable),
    checkCorsConfig(supabaseUrl, anonKey),
    checkStackTrace(supabaseUrl, anonKey),
  ]);

  return {
    tables,
    keyAnalysis,
    rateLimiting,
    unauthAccess,
    slopSquatting,
    massAssignment,
    authSecurity,
    idor,
    secretsExposure,
    secureAuth,
    httpsCheck,
    stackTraceCheck,
    botProtection,
    inputValidation,
    corsConfig,
    exposedKeyInCode: keyAnalysis.isServiceRole,
    timestamp:        new Date().toISOString(),
  };
}

// ── Lightweight critical-check pass (hourly monitoring) ────────────────────────
// Added separately from scanProject() — does not modify or share mutable state
// with it, and scanProject()'s own behavior/output is unchanged above this
// line. Checks only 4 items: RLS presence, secrets/key exposure, public
// storage buckets, and service-role-key submission. Deliberately skips the
// other 11 checks entirely (no rate-limit burst, no per-table IDOR/mass-
// assignment probes, no slop-squatting npm lookups, etc.) and, within RLS
// checking itself, skips the per-table policy-detail fetch that scanProject()
// does (fetchTablePolicies) — this pass only needs the enabled/disabled
// boolean per table, not policy contents, so it's materially cheaper than
// scanProject()'s equivalent step, not just a subset of the same work.

// Check: public storage buckets. Not one of the original 15 checks — new,
// added for this fast pass specifically per the monitoring spec.
export interface PublicBucketCheck {
  tested: boolean;
  publicBuckets: string[];
}

async function checkPublicBuckets(supabaseUrl: string, anonKey: string): Promise<PublicBucketCheck> {
  try {
    const res = await fetch(`${supabaseUrl}/storage/v1/bucket`, {
      headers: makeHeaders(anonKey),
      signal:  AbortSignal.timeout(SHORT_TIMEOUT),
    });
    if (!res.ok) return { tested: false, publicBuckets: [] };
    const buckets = await res.json() as Array<{ name?: string; public?: boolean }>;
    if (!Array.isArray(buckets)) return { tested: false, publicBuckets: [] };
    return {
      tested: true,
      publicBuckets: buckets
        .filter((b) => b.public === true && typeof b.name === "string")
        .map((b) => b.name as string),
    };
  } catch {
    return { tested: false, publicBuckets: [] };
  }
}

export interface FastScanResult {
  keyAnalysis:      KeyAnalysis;
  tables:           TableResult[]; // policies always [] / policiesRetrieved false — not fetched in this pass
  secretsExposure:  SecretsExposureCheck;
  publicBuckets:    PublicBucketCheck;
  timestamp:        string;
}

export async function scanCriticalChecks(rawUrl: string, rawAnonKey: string): Promise<FastScanResult> {
  let supabaseUrl: string;
  let anonKey:     string;
  try {
    supabaseUrl = validateSupabaseUrl(rawUrl);
    anonKey     = validateAnonKey(rawAnonKey);
  } catch (err) {
    if (err instanceof ValidationError) throw new ScanError(err.message, "MALFORMED_URL");
    throw err;
  }

  const restBase = `${supabaseUrl}/rest/v1`;

  // Service-role-key submission — synchronous, free, no network call.
  const keyAnalysis = analyzeKey(anonKey);

  // Table enumeration straight from the PostgREST spec — the spec already
  // only lists tables genuinely exposed via the API, so unlike scanProject()
  // this pass does not additionally probeTable() each one to confirm
  // existence; that's scanProject()'s extra defensiveness for the full/paid
  // report, not needed just to know which tables to check RLS on here.
  let tableNames: string[];
  try {
    const spec = await fetchJSON<PostgRESTSpec>(`${restBase}/`, anonKey);
    tableNames = Object.keys(spec.paths ?? {})
      .filter((p) => p.length > 1 && !p.startsWith("/rpc/"))
      .map((p) => p.slice(1));
  } catch (err) {
    if (err instanceof ScanError && err.code === "INVALID_CREDENTIALS") {
      tableNames = [...COMMON_TABLE_NAMES];
    } else {
      throw err;
    }
  }

  // RLS presence — one batched pg_tables query for every table's rowsecurity
  // flag, no per-table policy-detail fetch.
  const rlsStatusMap = await fetchRlsStatusMap(restBase, anonKey);
  const tables: TableResult[] = tableNames.map((name) => ({
    name,
    rlsEnabled:        rlsStatusMap.has(name) ? rlsStatusMap.get(name)! : true,
    policies:           [],
    policiesRetrieved: false,
  }));

  const [secretsExposure, publicBuckets] = await Promise.all([
    checkSecretsExposure(supabaseUrl),
    checkPublicBuckets(supabaseUrl, anonKey),
  ]);

  return {
    keyAnalysis,
    tables,
    secretsExposure,
    publicBuckets,
    timestamp: new Date().toISOString(),
  };
}
