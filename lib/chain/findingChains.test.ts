import { describe, expect, it } from "vitest";
import { withChains } from "./findingChains";

// The founder sees the same evidence chain the agent reads over MCP: reach
// from the newest audit's stored route facts for that repository, pressure
// from attack traffic already joined to the finding (findingTraffic.ts).
const base = { severity: "CRITICAL" as const, confidence: "proven" as const, attackClass: "missing_authentication",
  claims: [], confirmed: true, entry: "/api/notes/[id]", file: "app/api/notes/[id]/route.ts" };
const runs = [
  { fullName: "acme/app", status: "complete", routeFacts: [{ path: "/api/notes/[id]", calledBy: ["components/Note.tsx"] }] },
  { fullName: "acme/app", status: "complete", routeFacts: [{ path: "/api/notes/[id]", calledBy: ["old.tsx"] }] },
];
const repos = [{ id: "r1", fullName: "acme/app" }];

describe("withChains", () => {
  it("reads reach from the newest audit of the finding's repository and pressure from its traffic", () => {
    const [f] = withChains([{ ...base, repositoryId: "r1", hitHard: { pattern: "/api/notes/:id", suspiciousRequests: 40 } }],
      { runs, repos, trafficConnected: true });
    expect(f.chain.links.map((l) => `${l.id}:${l.state}`)).toEqual(["reach:met", "gap:met", "proof:met", "pressure:met"]);
    expect(f.chain.links[0].evidence).toContain("components/Note.tsx");
    expect(f.chain.links[0].evidence).not.toContain("old.tsx");
  });

  it("says unknown, never met, when no audit stored route facts or the repository is not found", () => {
    const [f] = withChains([{ ...base, repositoryId: "other", hitHard: null }], { runs, repos, trafficConnected: false });
    expect(f.chain.links.map((l) => `${l.id}:${l.state}`)).toEqual(["reach:unknown", "gap:met", "proof:met", "pressure:unknown"]);
  });

  it("gives the self-check the method the newest route facts say reaches data unsigned", () => {
    const facts = [{ fullName: "acme/app", status: "complete", routeFacts: [{ path: "/api/notes/[id]", methods: ["GET", "POST"], unrefusedMethods: ["POST"] }] }];
    const [f] = withChains([{ ...base, confidence: "corroborated" as const, repositoryId: "r1", hitHard: null }], { runs: facts, repos, trafficConnected: false });
    expect(f.methods).toEqual(["POST"]);
    expect(f.chain.links[2].evidence).toContain("curl -i -X POST");
  });

  it("shows the agent's reported self-check for that finding's row only", () => {
    const reports = new Map([["row-1", { status: 404, host: "localhost:3000", reportedAt: null }]]);
    const [mine, other] = withChains([{ ...base, confidence: "corroborated" as const, repositoryId: "r1", rowId: "row-1", hitHard: null },
      { ...base, confidence: "corroborated" as const, repositoryId: "r1", rowId: "row-2", hitHard: null }], { runs, repos, trafficConnected: false, reports });
    expect(mine.chain.links[2].evidence).toContain("reported 404");
    expect(other.chain.links[2].evidence).not.toContain("reported");
  });

  // P5: live reach joins only the repository the founder bound the address to.
  it("joins what the live site calls only to the bound repository's findings", () => {
    const live = { repositoryId: "r1", host: "app.acme.com", observedAt: "2026-10-17T10:00:00.000Z", paths: ["/api/notes/"] };
    const [bound, other] = withChains([{ ...base, repositoryId: "r1", hitHard: null }, { ...base, repositoryId: "r2", hitHard: null }],
      { runs: [], repos: [...repos, { id: "r2", fullName: "acme/other" }], trafficConnected: false, live });
    expect(bound.chain.links[0]).toMatchObject({ state: "met" });
    expect(bound.chain.links[0].evidence).toContain("app.acme.com");
    expect(other.chain.links[0].state).toBe("unknown");
  });
});
