import type { FixableFinding } from "./lane";

// Builds the file each fix PR commits (seeds the editable preview). migration-pr
// → a Supabase migration .sql; code-pr/draft-pr → a fix-request markdown the
// human/agent turns into the real change (we never auto-author app logic).
// Pure + tested. deep-link fixes produce a URL, not a file.

export interface FixArtifact {
  path: string;
  content: string;
}

export function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "fix";
}

// YYYYMMDDHHMMSS — sorts after the customer's numbered migrations, collision-safe.
function stamp(now: Date): string {
  return now.toISOString().replace(/[-:T]/g, "").slice(0, 14);
}

/**
 * A fix file ShipLock names with the click's timestamp: its directory and the
 * pattern its name matches under any timestamp, or null. Only ShipLock's own
 * fix files qualify, never a customer's migration.
 */
export function stampedFixName(path: string): { dir: string; name: RegExp } | null {
  const m = /^(supabase\/migrations|shiplock-fixes)\/\d{14}([_-][^/]+)$/.exec(path);
  if (!m || (m[1] === "supabase/migrations" && !m[2].startsWith("_shiplock_"))) return null;
  return { dir: m[1], name: new RegExp(`^\\d{14}${m[2].replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`) };
}

// Pull runnable SQL out of the fix text: prefer the "SQL Editor:" marker our
// analyzer uses, else keep the SQL-looking lines. null when there's no clean SQL.
export function extractSql(fix: string): string | null {
  const marked = fix.match(/SQL Editor:\s*\n?([\s\S]+)$/i);
  if (marked) return marked[1].trim();
  const lines = fix.split("\n").filter((l) => /\b(alter|create|enable row level security|revoke|grant|drop)\b/i.test(l));
  return lines.length ? lines.join("\n").trim() : null;
}

export function buildMigrationFix(f: FixableFinding, now = new Date()): FixArtifact {
  const sql = extractSql(f.fix);
  const header =
    `-- ShipLock fix: ${f.title}\n` +
    `-- Review and adjust if needed, then merge — your own deploy applies it.\n` +
    `-- ShipLock never writes to your database directly.\n`;
  const body = sql
    ? `${header}${sql}\n`
    : `${header}-- Guidance: ${f.fix}\n-- TODO: complete the SQL for this fix before merging.\n`;
  return { path: `supabase/migrations/${stamp(now)}_shiplock_${slug(f.title)}.sql`, content: body };
}

export function buildCodeFix(f: FixableFinding, now = new Date()): FixArtifact {
  const loc = f.filePath ? `\n**File:** \`${f.filePath}\`` : "";
  const content =
    `# ShipLock fix: ${f.title}\n\n**Severity:** ${f.severity}${loc}\n\n` +
    `## What to change\n\n${f.fix}\n\n` +
    `> This PR is a fix request. Apply the change above (your coding agent can do it straight ` +
    `from this file), then delete this file and merge. ShipLock never rewrites application ` +
    `logic automatically — you stay in control of the actual change.\n`;
  return { path: `shiplock-fixes/${stamp(now)}-${slug(f.title)}.md`, content };
}

const SUPABASE_SETTINGS: { test: RegExp; path: string }[] = [
  // Most specific first — the redirect allow-list and Site URL both live on the
  // URL-configuration page, and their fix text mentions "api key" often enough
  // that a later rule would otherwise win.
  { test: /redirect allow-list|site url|url configuration/i, path: "/auth/url-configuration" },
  { test: /leaked.?password|password settings/i, path: "/auth/providers" },
  { test: /jwt|signing keys/i, path: "/settings/auth" },
  { test: /rotate|service.?role|api key/i, path: "/settings/api" },
];

/** `owner/name` from a namespaced finding id (`owner/name::github:…`). */
export function repoFromFindingId(id: string): string | null {
  const [prefix] = id.split("::");
  return /^[\w.-]+\/[\w.-]+$/.test(prefix) ? prefix : null;
}

/**
 * Where a deep-link fix sends the user, or `null` when there is genuinely no
 * page to send them to.
 *
 * Returning null matters. Two of these fixes have no destination: an email-auth
 * record is edited wherever the customer's DNS happens to live, which we don't
 * know, and a leaked third-party key is rotated in that vendor's console, not
 * Supabase's. Pointing those at a plausible-looking Supabase settings page would
 * be worse than showing no button — it sends someone confidently to the wrong
 * place and lets them believe they've done the fix.
 */
export function buildDeepLink(
  f: FixableFinding,
  projectRef?: string | null,
  external?: "supabase" | "provider" | "github" | "dns"
): string | null {
  // DNS: no destination we can know.
  if (external === "dns") return null;

  if (external === "github") {
    const repo = repoFromFindingId(f.id);
    return repo ? `https://github.com/${repo}/settings` : "https://github.com/settings/repositories";
  }

  // A non-Supabase credential is rotated in the vendor's own console. We don't
  // maintain a URL table for every provider, and guessing would be worse than
  // letting the fix text say which key to roll.
  if (external === "provider" && !/supabase/i.test(`${f.title}\n${f.fix}`)) return null;

  // Supabase dashboard deep links require a project ref (/project/<ref>/…). With
  // no ref, a settings path is malformed — send the user to the project picker.
  if (!projectRef) return "https://supabase.com/dashboard/projects";
  const base = `https://supabase.com/dashboard/project/${projectRef}`;
  const hay = `${f.title}\n${f.fix}`;
  for (const s of SUPABASE_SETTINGS) if (s.test.test(hay)) return base + s.path;
  return base + "/settings/api";
}
