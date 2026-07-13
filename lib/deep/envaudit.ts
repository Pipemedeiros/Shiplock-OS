// Vercel env-var audit (A05-ish: security misconfiguration). Pure logic over a
// project's environment variables. NEVER stores or logs a variable's VALUE —
// findings carry the KEY and a reason only.
import type { Severity } from "@/lib/types";

export interface VercelEnvVar {
  key: string;
  value?: string | null; // null for "sensitive"-typed vars (Vercel won't decrypt them) — value checks skip those
  target?: string[];
  type?: string;
}

export interface EnvFinding {
  id: string; // stable diff key: vercel:<project>:<key>:<reason>
  severity: Severity;
  title: string;
  consequence: string;
  key: string;
}

// Clearly server-only secret name tokens. Deliberately EXCLUDES generic "API_KEY"
// / "_KEY" so legitimately-public values (NEXT_PUBLIC_SUPABASE_ANON_KEY,
// NEXT_PUBLIC_POSTHOG_KEY) are not false-flagged — the anon/publishable keys are
// meant to ship to the client.
const SECRET_NAME_RE = /(SERVICE_ROLE|SECRET|PRIVATE_KEY|PASSWORD|PASSWD|CREDENTIAL)/i;

// Prefixes that inline a variable into the client bundle (framework conventions).
const CLIENT_PREFIX_RE = /^(NEXT_PUBLIC_|VITE_|REACT_APP_|GATSBY_|EXPO_PUBLIC_|PUBLIC_)/;

const WEAK_VALUES = new Set([
  "test", "test123", "changeme", "change-me", "password", "passwd", "secret",
  "123456", "12345678", "admin", "default", "example", "foobar", "placeholder",
  "todo", "xxx", "your-secret-here", "s3cret",
]);

function looksSecret(key: string): boolean {
  return SECRET_NAME_RE.test(key);
}

export function auditEnv(projectName: string, vars: VercelEnvVar[]): EnvFinding[] {
  const findings: EnvFinding[] = [];

  for (const v of vars) {
    const nameSecret = looksSecret(v.key);

    // 1) Server-only-looking secret exposed to the client bundle via a public prefix.
    if (nameSecret && CLIENT_PREFIX_RE.test(v.key)) {
      findings.push({
        id: `vercel:${projectName}:${v.key}:client_exposed_secret`,
        severity: "CRITICAL",
        title: `Secret-looking variable "${v.key}" is exposed to the client bundle`,
        consequence:
          `Variables with a public prefix (e.g. NEXT_PUBLIC_) are inlined into the browser bundle and visible to anyone. ` +
          `"${v.key}" looks like a server-only secret — rotate it immediately and move it to a server-only variable.`,
        key: v.key,
      });
    }

    // 2) Weak / placeholder / too-short-for-a-secret value. Only when the value
    // is visible (sensitive-typed vars come back null and are skipped).
    const val = typeof v.value === "string" ? v.value : "";
    if (val) {
      const low = val.trim().toLowerCase();
      const weak = WEAK_VALUES.has(low);
      const shortSecret = nameSecret && val.length < 12;
      if (weak || shortSecret) {
        findings.push({
          id: `vercel:${projectName}:${v.key}:weak_value`,
          severity: "WARNING",
          title: `"${v.key}" has a weak or placeholder value`,
          consequence: weak
            ? `The value looks like a placeholder or default. Replace it with a strong, unique secret before production.`
            : `The value is unusually short for a secret (${val.length} characters), making it easy to brute-force. Use a long random value.`,
          key: v.key,
        });
      }
    }
  }

  return findings;
}

// Same only-new-alerts contract as the GitHub A03 / monitoring diff.
export function diffEnv(previous: EnvFinding[], current: EnvFinding[]): { newFindings: EnvFinding[] } {
  const prevIds = new Set(previous.map((f) => f.id));
  return { newFindings: current.filter((f) => !prevIds.has(f.id)) };
}
