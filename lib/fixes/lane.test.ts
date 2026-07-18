import { describe, expect, it } from "vitest";
import { fixLane, type FixableFinding } from "./lane";

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
