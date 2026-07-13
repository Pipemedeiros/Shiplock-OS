import { describe, it, expect } from "vitest";
import { auditEnv, diffEnv, type VercelEnvVar, type EnvFinding } from "./envaudit";

describe("auditEnv", () => {
  it("flags a server-secret-looking name exposed via NEXT_PUBLIC_ as CRITICAL", () => {
    const vars: VercelEnvVar[] = [{ key: "NEXT_PUBLIC_SERVICE_ROLE_KEY", value: "eyJreallylongvalidlookingjwt" }];
    const findings = auditEnv("proj", vars);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("CRITICAL");
    expect(findings[0].id).toBe("vercel:proj:NEXT_PUBLIC_SERVICE_ROLE_KEY:client_exposed_secret");
  });

  it("does not flag a legitimate public anon/publishable key", () => {
    const vars: VercelEnvVar[] = [{ key: "NEXT_PUBLIC_SUPABASE_ANON_KEY", value: "eyJreallylongvalidlookingjwt" }];
    expect(auditEnv("proj", vars)).toHaveLength(0);
  });

  it("does not flag a server-only secret that stays server-only", () => {
    const vars: VercelEnvVar[] = [{ key: "SUPABASE_SERVICE_ROLE_KEY", value: "eyJreallylongvalidlookingjwt" }];
    expect(auditEnv("proj", vars)).toHaveLength(0);
  });

  it("flags each other client-bundle prefix (VITE_, REACT_APP_, GATSBY_, EXPO_PUBLIC_, PUBLIC_)", () => {
    const prefixes = ["VITE_", "REACT_APP_", "GATSBY_", "EXPO_PUBLIC_", "PUBLIC_"];
    for (const prefix of prefixes) {
      const findings = auditEnv("proj", [{ key: `${prefix}SECRET_TOKEN`, value: "long-enough-value-1234" }]);
      expect(findings, `expected ${prefix}SECRET_TOKEN to be flagged`).toHaveLength(1);
      expect(findings[0].severity).toBe("CRITICAL");
    }
  });

  it("flags a weak/placeholder value regardless of key name", () => {
    const findings = auditEnv("proj", [{ key: "SOME_CONFIG", value: "changeme" }]);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("WARNING");
    expect(findings[0].id).toBe("vercel:proj:SOME_CONFIG:weak_value");
  });

  it("flags a too-short secret-looking value even if not on the weak-value list", () => {
    const findings = auditEnv("proj", [{ key: "API_SECRET", value: "abc123" }]);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("WARNING");
    expect(findings[0].title).toContain("weak or placeholder");
  });

  it("does not flag a long, non-placeholder secret value", () => {
    const findings = auditEnv("proj", [{ key: "API_SECRET", value: "a-genuinely-long-random-looking-secret-value-9f8e7d" }]);
    expect(findings).toHaveLength(0);
  });

  it("skips value checks for sensitive-typed vars with a null value", () => {
    const findings = auditEnv("proj", [{ key: "SOME_SECRET", value: null }]);
    expect(findings).toHaveLength(0);
  });

  it("can raise both findings for the same variable (exposed AND weak)", () => {
    const findings = auditEnv("proj", [{ key: "NEXT_PUBLIC_PASSWORD", value: "admin" }]);
    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.severity).sort()).toEqual(["CRITICAL", "WARNING"]);
  });

  it("never includes the variable's value in any finding", () => {
    const findings = auditEnv("proj", [
      { key: "NEXT_PUBLIC_SECRET_TOKEN", value: "super-secret-plaintext-value" },
    ]);
    for (const f of findings) {
      expect(JSON.stringify(f)).not.toContain("super-secret-plaintext-value");
    }
  });

  it("returns no findings for an empty var list", () => {
    expect(auditEnv("proj", [])).toHaveLength(0);
  });
});

describe("diffEnv", () => {
  const mk = (id: string): EnvFinding => ({ id, severity: "WARNING", title: "t", consequence: "c", key: "k" });

  it("returns only findings not present in the previous set", () => {
    const previous = [mk("a"), mk("b")];
    const current = [mk("a"), mk("b"), mk("c")];
    expect(diffEnv(previous, current).newFindings.map((f) => f.id)).toEqual(["c"]);
  });

  it("returns empty when nothing changed", () => {
    const previous = [mk("a")];
    const current = [mk("a")];
    expect(diffEnv(previous, current).newFindings).toHaveLength(0);
  });

  it("treats everything as new when previous is empty", () => {
    const current = [mk("a"), mk("b")];
    expect(diffEnv([], current).newFindings).toHaveLength(2);
  });
});
