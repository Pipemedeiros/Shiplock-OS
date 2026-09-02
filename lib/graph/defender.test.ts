import { describe, it, expect, vi } from "vitest";
import { runDefence, applyDefenceResults, type DefenceProposer } from "./defender";
import type { DefenceClaim, DefenceEvidence } from "./defenderGuard";
import type { AttackPath } from "./attackPaths";
import type { AuthzFacts } from "./graph";
import type { RouteFact } from "./routeInventory";

function route(over: Partial<RouteFact> = {}): RouteFact {
  return {
    path: "/api/invoices",
    file: "app/api/invoices/route.ts",
    methods: ["GET"],
    tables: ["invoices"],
    authenticated: false,
    machineGated: false,
    usesServiceRole: false,
    ownershipFiltered: false,
    isApiRoute: true,
    identityReadable: true,
    identityGap: null,
    via: [],
    ...over,
  };
}

function table(over: Partial<AuthzFacts> = {}): AuthzFacts {
  return {
    schema: "public",
    name: "invoices",
    qualified: "public.invoices",
    provider: "postgres-rls",
    enforced: true,
    unconditionalGrant: false,
    rulesRead: true,
    grantedRoles: [],
    provable: true,
    sensitive: true,
    ...over,
  };
}

const evidence: DefenceEvidence = { routes: [route()], tables: [table()] };

function path(over: Partial<AttackPath> = {}): AttackPath {
  return {
    id: "graph:anon_sensitive:public.invoices",
    severity: "CRITICAL",
    title: "Anonymous route reaches invoices",
    consequence: "…",
    evidence: [{ collector: "source", fact: "route is anonymous" }],
    score: 90,
    surfaces: ["source", "db"],
    ...over,
  };
}

const proposing = (claims: Record<string, DefenceClaim[]>): DefenceProposer =>
  async () => new Map(Object.entries(claims));

describe("runDefence", () => {
  it("does not call the model when there is nothing defensible", async () => {
    const propose = vi.fn();
    const r = await runDefence([path({ id: "proven:x" })], evidence, propose as unknown as DefenceProposer);
    expect(propose).not.toHaveBeenCalled();
    expect(r.skipped).toBe("no defensible paths");
    expect(r.results.size).toBe(0);
  });

  it("never sends a proven finding to the model", async () => {
    const seen: AttackPath[][] = [];
    const propose: DefenceProposer = async (paths) => {
      seen.push(paths);
      return new Map();
    };
    await runDefence([path(), path({ id: "proven:agent_tenant_leak:a:b" })], evidence, propose);
    expect(seen[0].map((p) => p.id)).toEqual(["graph:anon_sensitive:public.invoices"]);
  });

  // The failure posture. Every one of these must leave findings untouched.
  it("keeps findings unchanged when the proposer throws", async () => {
    const r = await runDefence([path()], evidence, async () => {
      throw new Error("network");
    });
    expect(r.skipped).toBe("proposer failed");
    expect(r.results.size).toBe(0);
  });

  it("keeps findings unchanged when the model returns nothing", async () => {
    const r = await runDefence([path()], evidence, async () => new Map());
    expect(r.results.size).toBe(0);
  });

  it("keeps findings unchanged when every claim is refuted", async () => {
    const r = await runDefence(
      [path()],
      evidence,
      proposing({ "graph:anon_sensitive:public.invoices": [{ kind: "route_authenticated", route: "/api/invoices" }] })
    );
    expect(r.results.size).toBe(0);
  });

  it("downranks when the model finds real, verifiable counter-evidence", async () => {
    const r = await runDefence(
      [path()],
      { routes: [route({ ownershipFiltered: true })], tables: [table()] },
      proposing({
        "graph:anon_sensitive:public.invoices": [{ kind: "route_ownership_filtered", route: "/api/invoices" }],
      })
    );
    const result = r.results.get("graph:anon_sensitive:public.invoices")!;
    expect(result.outcome).toBe("downranked");
    expect(result.severity).toBe("WARNING");
  });

  it("annotates but does not downrank when a claim cannot be checked", async () => {
    const r = await runDefence(
      [path()],
      evidence,
      proposing({
        "graph:anon_sensitive:public.invoices": [{ kind: "route_ownership_filtered", route: "/api/nowhere" }],
      })
    );
    const result = r.results.get("graph:anon_sensitive:public.invoices")!;
    expect(result.outcome).toBe("annotated");
    expect(result.severity).toBe("CRITICAL");
  });
});

describe("applyDefenceResults", () => {
  it("passes undefended paths through untouched", async () => {
    const p = path();
    const { published, withdrawn } = applyDefenceResults([p], new Map());
    expect(published).toEqual([p]);
    expect(withdrawn).toEqual([]);
  });

  it("lowers severity and appends counter-evidence to the same evidence trail", async () => {
    const p = path();
    const r = await runDefence(
      [p],
      { routes: [route({ ownershipFiltered: true })], tables: [table()] },
      proposing({ [p.id]: [{ kind: "route_ownership_filtered", route: "/api/invoices" }] })
    );
    const { published } = applyDefenceResults([p], r.results);
    expect(published[0].severity).toBe("WARNING");
    expect(published[0].evidence).toHaveLength(2);
    expect(published[0].evidence[1].fact).toMatch(/Counter-evidence confirmed/);
  });

  // A finding we decided not to show must stay auditable — same reasoning as
  // recording refused agent queries.
  it("removes a withdrawn path from published but returns it with its reason", async () => {
    const p = path();
    const r = await runDefence(
      [p],
      evidence,
      proposing({ [p.id]: [{ kind: "table_not_referenced", route: "/api/invoices", table: "public.payments" }] })
    );
    const { published, withdrawn } = applyDefenceResults([p], r.results);
    expect(published).toEqual([]);
    expect(withdrawn).toHaveLength(1);
    expect(withdrawn[0].result.notes[0]).toMatch(/^Withdrawn —/);
  });
});
