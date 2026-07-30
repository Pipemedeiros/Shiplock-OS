import { describe, expect, it } from "vitest";
import { fixLane, stripRepoNamespace, type FixableFinding } from "./lane";

const f = (over: Partial<FixableFinding>): FixableFinding => ({
  id: "x", source: "github", title: "t", severity: "WARNING", fix: "", ...over,
});

describe("fixLane — routes each finding to the right apply method", () => {
  it("dependency CVE → dep PR (not editable)", () => {
    const l = fixLane(f({ id: "github:dep:lodash:GHSA-x" }));
    expect(l.method).toBe("dep-pr");
    expect(l.editable).toBe(false);
  });
  it("injection/XSS/crypto logic → draft PR (editable)", () => {
    for (const id of ["github:injection:sql_injection:a.ts", "github:xss_sink:eval_call:b.ts", "github:weak_hash:c.ts", "github:token_storage:localstorage"]) {
      expect(fixLane(f({ id })).method).toBe("draft-pr");
    }
  });
  it("committed secret → code PR (remove + editable)", () => {
    expect(fixLane(f({ id: "github:committed_env:.env" })).method).toBe("code-pr");
    expect(fixLane(f({ id: "github:secret:aws_access_key:x.ts" })).method).toBe("code-pr");
  });
  it("RLS policy finding → migration PR (editable)", () => {
    const l = fixLane(f({ id: "policy:public.orders:p:unrestricted_read", source: "policy" }));
    expect(l.method).toBe("migration-pr");
    expect(l.editable).toBe(true);
  });
  it("leaked-password / JWT advisor → deep-link to Supabase", () => {
    const l = fixLane(f({ id: "advisor:auth_leaked_password_protection:z", source: "advisor" }));
    expect(l.method).toBe("deep-link");
    expect(l.external).toBe("supabase");
  });
  it("permissive-policy advisor → migration PR", () => {
    expect(fixLane(f({ id: "advisor:permissive_rls_policy:z", source: "advisor" })).method).toBe("migration-pr");
  });
});

describe("fixLane — scan (Supabase config) findings by fix content", () => {
  it("SQL fix → migration PR", () => {
    const l = fixLane(f({ id: "scan:rls", source: "scan", fix: "Run in Supabase SQL Editor:\nALTER TABLE orders ENABLE ROW LEVEL SECURITY;" }));
    expect(l.method).toBe("migration-pr");
  });
  it("dashboard/rotate instruction → deep-link", () => {
    const rotate = fixLane(f({ id: "scan:key", source: "scan", fix: "Go to Supabase → Project Settings → API → Rotate service_role key." }));
    expect(rotate.method).toBe("deep-link");
    expect(rotate.external).toBe("supabase");
  });
  it("a pure provider rotation (no Supabase) → provider deep-link", () => {
    const l = fixLane(f({ id: "scan:secret", source: "scan", fix: "Rotate the exposed key in your provider dashboard immediately." }));
    expect(l.method).toBe("deep-link");
    expect(l.external).toBe("provider");
  });
});

// Every finding class added in Phase 1 must land in an HONEST lane. The failure
// mode being guarded against is the fallback: an unrouted id becomes "Open fix
// PR", which for a DNS record or a repo setting is a button that cannot work.
describe("Phase 1 finding classes route to lanes that can actually apply", () => {
  const f = (id: string, fix = "do the thing", title = "t") => ({
    id,
    source: "github" as const,
    title,
    severity: "CRITICAL" as const,
    fix,
  });

  it("a server-only secret in client code is a draft PR — the fix is an architecture call", () => {
    const l = fixLane(f("acme/app::github:client_server_secret:app/p.tsx"));
    expect(l.method).toBe("draft-pr");
  });

  it("a public-prefixed secret leads with rotation, not a rename", () => {
    const l = fixLane(f("acme/app::github:public_prefixed_secret:NEXT_PUBLIC_X_SECRET:.env"));
    expect(l.method).toBe("deep-link");
    expect(l.label).toBe("Rotate secret");
  });

  // There is no pull request that can change a repo's visibility.
  it("repo visibility is a GitHub setting, never a PR", () => {
    for (const id of ["acme/app::github:repo_public:acme/app", "acme/app::github:repo_public_with_secrets:acme/app"]) {
      const l = fixLane(f(id));
      expect(l.method, id).toBe("deep-link");
      expect(l.external).toBe("github");
    }
  });

  it("a secret shipped in the bundle is a rotation — no code change un-publishes it", () => {
    const l = fixLane(f("bundle:shipped_secret:supabase_service_role_jwt"));
    expect(l.method).toBe("deep-link");
    expect(l.label).toBe("Rotate secret");
  });

  it("source maps ARE a code change (a build flag), so they stay a PR", () => {
    expect(fixLane(f("bundle:source_map_exposed:with_content")).method).toBe("code-pr");
  });

  it("email auth is DNS — not code, not SQL, and not a page we can link to", () => {
    for (const id of ["email_auth:spf_missing", "email_auth:dmarc_policy_none", "email_auth:dkim_revoked:resend"]) {
      const l = fixLane(f(id));
      expect(l.method, id).toBe("deep-link");
      expect(l.external).toBe("dns");
    }
  });

  it("auth URL configuration points at the Supabase page that owns it", () => {
    for (const id of ["auth_redirect:wildcard_any_host", "auth_site_url:localhost"]) {
      const l = fixLane(f(id));
      expect(l.external, id).toBe("supabase");
    }
  });

  it("no Phase 1 finding falls through to the code-pr fallback by accident", () => {
    const unrouted = [
      "acme/app::github:client_server_secret:a.tsx",
      "acme/app::github:public_prefixed_secret:X:.env",
      "acme/app::github:repo_public:acme/app",
      "bundle:shipped_secret:aws_access_key",
      "email_auth:spf_missing",
      "auth_redirect:wildcard_any_host",
      "auth_site_url:localhost",
    ].filter((id) => {
      const l = fixLane(f(id));
      return l.method === "code-pr" && l.label === "Open fix PR";
    });
    expect(unrouted).toEqual([]);
  });
});

// This bug was live before Phase 1 and affected every GitHub finding: ids arrive
// namespaced `owner/name::github:…`, so every `github:` rule silently missed and
// everything landed in the code-pr fallback.
describe("repo namespace stripping — the rules must match REAL ids", () => {
  const f = (id: string) => ({
    id,
    source: "github" as const,
    title: "t",
    severity: "CRITICAL" as const,
    fix: "x",
  });

  it("strips an owner/name:: prefix", () => {
    expect(stripRepoNamespace("acme/app::github:dep:lodash")).toBe("github:dep:lodash");
  });

  it("leaves an un-namespaced id alone", () => {
    expect(stripRepoNamespace("email_auth:spf_missing")).toBe("email_auth:spf_missing");
  });

  it("does not strip a :: that isn't a repo namespace", () => {
    expect(stripRepoNamespace("advisor::weird")).toBe("advisor::weird");
  });

  it("routes a NAMESPACED dependency finding to the automated dep-pr lane", () => {
    const l = fixLane(f("acme/app::github:dep:lodash"));
    expect(l.method).toBe("dep-pr");
    expect(l.editable).toBe(false);
  });

  // CLAUDE.md: injection/XSS/crypto logic is never machine-authored.
  it("routes NAMESPACED logic findings to a DRAFT pr, as the doctrine requires", () => {
    for (const id of [
      "acme/app::github:injection:sql_injection:a.ts",
      "acme/app::github:xss_sink:eval_call:a.tsx",
      "acme/app::github:weak_hash:a.ts",
      "acme/app::github:insecure_random:a.ts",
    ]) {
      expect(fixLane(f(id)).method, id).toBe("draft-pr");
    }
  });

  it("routes a namespaced committed-secret finding to code-pr deliberately, not by fallback", () => {
    expect(fixLane(f("acme/app::github:committed_env:.env")).method).toBe("code-pr");
  });

  it("gives namespaced and bare ids the same lane", () => {
    expect(fixLane(f("acme/app::github:dep:lodash"))).toEqual(fixLane(f("github:dep:lodash")));
  });
});
