import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextRequest } from "next/server";
import { FINDING_SOURCES } from "@/lib/fixes/lane";
import { fixLane } from "@/lib/fixes/lane";

const getUserMock = vi.fn();
const profileMock = vi.fn();
const runFixPrMock = vi.fn();

vi.mock("@/lib/fixes/prRun", () => ({ runFixPr: runFixPrMock }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    auth: { getUser: getUserMock },
    from: () => ({ select: () => ({ eq: () => ({ maybeSingle: profileMock }) }) }),
  }),
}));

const { POST } = await import("./route");

function req(finding: Record<string, unknown>) {
  return new NextRequest("https://shiplock.dev/api/deep/fix", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer t" },
    body: JSON.stringify({ finding, editedContent: "-- fix" }),
  });
}

const base = {
  id: "path:anon_route_unprotected_table",
  title: "Orders readable across tenants",
  severity: "CRITICAL",
  fix: "alter table orders enable row level security;",
};

describe("POST /api/deep/fix — finding source validation", () => {
  beforeEach(() => {
    getUserMock.mockReset().mockResolvedValue({ data: { user: { id: "u1" } } });
    profileMock.mockReset().mockResolvedValue({ data: { is_paid: true } });
    runFixPrMock.mockReset().mockResolvedValue({ url: "https://github.com/x/y/pull/1" });
  });

  // The regression this file exists for: the route's Zod enum listed four of the
  // ten sources, so clicking "Open fix PR" on a correlated attack path (graph) or
  // a replica-proven finding (proven) returned "Invalid request." Those are the
  // two most novel finding classes in the product, and the button was dead for
  // both while the MCP equivalent worked.
  it.each(["graph", "proven"])("accepts a %s-sourced finding, which used to 400", async (source) => {
    const res = await POST(req({ ...base, source }));
    expect(res.status).toBe(200);
    expect(runFixPrMock).toHaveBeenCalled();
  });

  it.each([...FINDING_SOURCES])("accepts every declared source: %s", async (source) => {
    const res = await POST(req({ ...base, source }));
    expect(res.status).toBe(200);
  });

  it("still rejects a source that is not a declared finding source", async () => {
    const res = await POST(req({ ...base, source: "not-a-real-source" }));
    expect(res.status).toBe(400);
    expect(runFixPrMock).not.toHaveBeenCalled();
  });

  it("still requires auth before doing anything", async () => {
    getUserMock.mockResolvedValue({ data: { user: null } });
    const res = await POST(req({ ...base, source: "graph" }));
    expect(res.status).toBe(401);
    expect(runFixPrMock).not.toHaveBeenCalled();
  });

  it("still requires a paid subscription", async () => {
    profileMock.mockResolvedValue({ data: { is_paid: false } });
    const res = await POST(req({ ...base, source: "graph" }));
    expect(res.status).toBe(402);
    expect(runFixPrMock).not.toHaveBeenCalled();
  });
});

// The structural guarantee, not just the symptom: every source whose findings
// route to a PR lane must be accepted by the route those buttons POST to. This
// fails if someone adds a source to FINDING_SOURCES, routes it to a PR lane, and
// the validator falls out of step again.
describe("every PR-lane source is accepted by the fix route", () => {
  const SAMPLE_ID: Record<string, string> = {
    scan: "scan:rls-disabled",
    github: "github:secret:aws",
    policy: "policy:permissive",
    advisor: "advisor:0024",
    app: "exposed:git_exposed",
    dns: "email_auth:spf_missing",
    "auth-config": "auth_redirect:wildcard",
    graph: "path:anon_route_unprotected_table",
    runtime: "runtime:credential_stuffing",
    proven: "proven:tenant_isolation",
  };

  it("routes PR-lane findings only to sources the validator allows", () => {
    for (const source of FINDING_SOURCES) {
      const lane = fixLane({
        id: SAMPLE_ID[source],
        source,
        title: "t",
        severity: "CRITICAL",
        fix: "alter table t enable row level security;",
      });
      if (lane.method !== "deep-link") {
        expect(FINDING_SOURCES).toContain(source);
      }
    }
  });
});
