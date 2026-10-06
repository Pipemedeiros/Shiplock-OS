import { describe, expect, it } from "vitest";
import { withTraffic } from "./findingTraffic";

// Felipe 2026-10-06: watch with traffic context. A finding on a route real
// traffic is hammering is the one to look at first, within its severity.
const f = (id: string, severity: "CRITICAL" | "WARNING" | "INFO", file: string | null, repositoryId = "r1") =>
  ({ id, severity, file, repositoryId });
const hot = { r1: [{ file: "app/api/orders/route.ts", pattern: "/api/orders", suspiciousRequests: 2000 }] };

describe("findings with traffic", () => {
  it("marks a finding whose route is hit hard, in the same repository only", () => {
    const out = withTraffic([f("a", "WARNING", "app/api/orders/route.ts"), f("b", "WARNING", "app/api/orders/route.ts", "r2")], hot);
    expect(out.find((x) => x.id === "a")!.hitHard).toEqual({ pattern: "/api/orders", suspiciousRequests: 2000 });
    expect(out.find((x) => x.id === "b")!.hitHard).toBeNull();
  });

  it("orders by severity first, then hit hard, then the original order", () => {
    const out = withTraffic([f("w1", "WARNING", "x.ts"), f("w2", "WARNING", "app/api/orders/route.ts"), f("c1", "CRITICAL", "y.ts"), f("i1", "INFO", null)], hot);
    expect(out.map((x) => x.id)).toEqual(["c1", "w2", "w1", "i1"]);
  });

  it("changes nothing about a finding's severity", () => {
    const out = withTraffic([f("w2", "WARNING", "app/api/orders/route.ts")], hot);
    expect(out[0].severity).toBe("WARNING");
  });

  it("marks nothing without traffic", () => {
    expect(withTraffic([f("a", "WARNING", "app/api/orders/route.ts")], {})[0].hitHard).toBeNull();
  });
});
