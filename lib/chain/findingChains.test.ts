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
});
