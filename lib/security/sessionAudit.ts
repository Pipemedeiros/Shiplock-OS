import type { Severity } from "@/lib/types";

// Session/JWT signing posture — externally checkable with just the project URL,
// no new credential. Supabase now signs JWTs with asymmetric keys published at
// a JWKS endpoint; a token signed that way can't be forged without the private
// key. Older projects use the legacy shared HS256 secret — forgeable if that
// secret ever leaks. This is surfaced as guidance in the dashboard guardrail
// panel, NOT wedged into lib/scanner.ts's 16 checks (CLAUDE.md: don't modify
// the scanner without instruction).

export interface JwtSigningPosture {
  severity: Severity; // INFO = asymmetric/safe, WARNING = legacy/forgeable-if-secret-leaks, INFO+unknown on error
  ok: boolean;
  title: string;
  detail: string;
}

const TIMEOUT_MS = 8_000;

// Pure classifier — separated from the fetch so it's unit-testable. `keys` is
// the parsed JWKS `keys` array (or null when the endpoint couldn't be read).
export function classifyJwks(keys: unknown): JwtSigningPosture {
  if (!Array.isArray(keys)) {
    return {
      severity: "INFO",
      ok: true,
      title: "Session signing — could not determine",
      detail:
        "Couldn't read your project's JWT signing keys right now. This is informational only; re-check later.",
    };
  }

  const asymmetric = keys.some((k) => {
    const kty = (k as { kty?: unknown })?.kty;
    // RSA / elliptic-curve / Edwards keys are asymmetric; "oct" is a symmetric secret.
    return kty === "RSA" || kty === "EC" || kty === "OKP";
  });

  if (asymmetric) {
    return {
      severity: "INFO",
      ok: true,
      title: "Session tokens are asymmetrically signed",
      detail:
        "Your project publishes asymmetric JWT signing keys — session tokens can't be forged without the private key, which never leaves Supabase. This is the safe configuration.",
    };
  }

  return {
    severity: "WARNING",
    ok: false,
    title: "Session tokens use legacy shared-secret signing",
    detail:
      "No asymmetric signing keys are published, so this project signs sessions with the legacy shared HS256 secret. If that secret ever leaks, an attacker can forge a valid session for any user. In Supabase → Authentication → JWT settings, migrate to asymmetric signing keys.",
  };
}

export async function auditJwtSigning(supabaseUrl: string): Promise<JwtSigningPosture> {
  try {
    const base = supabaseUrl.replace(/\/+$/, "");
    const res = await fetch(`${base}/auth/v1/.well-known/jwks.json`, {
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) return classifyJwks(null);
    const body = (await res.json()) as { keys?: unknown };
    return classifyJwks(body?.keys ?? null);
  } catch {
    return classifyJwks(null);
  }
}
