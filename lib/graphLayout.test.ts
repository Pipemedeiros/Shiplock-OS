import { describe, expect, it, vi } from "vitest";
import { cosSin, forceLayout } from "./graphLayout";

// The map's Obsidian-style layout (Felipe 2026-10-06: not 3D, like Obsidian).
// Deterministic, so two visits draw the same picture, and pure, so it renders
// on the server without a library.
const ids = ["a", "b", "c", "d", "e", "f"];
const edges = [{ from: "a", to: "b" }, { from: "b", to: "c" }, { from: "d", to: "e" }];

describe("forceLayout", () => {
  it("is deterministic", () => {
    expect(forceLayout(ids, edges)).toEqual(forceLayout(ids, edges));
  });

  it("puts linked nodes closer than unlinked ones", () => {
    const p = forceLayout(ids, edges);
    const d = (x: string, y: string) => Math.hypot(p.get(x)!.x - p.get(y)!.x, p.get(x)!.y - p.get(y)!.y);
    expect(d("a", "b")).toBeLessThan(d("a", "e"));
    expect(d("d", "e")).toBeLessThan(d("d", "c"));
  });

  it("keeps every node finite, apart, and inside the requested radius", () => {
    const many = Array.from({ length: 200 }, (_, i) => `n${i}`);
    const chain = many.slice(1).map((id, i) => ({ from: many[i], to: id }));
    const p = forceLayout(many, chain, { radius: 300 });
    const pts = [...p.values()];
    expect(pts).toHaveLength(200);
    for (const q of pts) {
      expect(Number.isFinite(q.x) && Number.isFinite(q.y)).toBe(true);
      expect(Math.hypot(q.x, q.y)).toBeLessThanOrEqual(300.001);
    }
    let close = 0;
    for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) if (Math.hypot(pts[i].x - pts[j].x, pts[i].y - pts[j].y) < 1) close++;
    expect(close).toBe(0);
  });

  it("ignores edges to unknown nodes and handles an empty graph", () => {
    expect(forceLayout([], []).size).toBe(0);
    expect(forceLayout(["a"], [{ from: "a", to: "zzz" }]).get("a")).toEqual({ x: 0, y: 0 });
  });
});

// The map is laid out on the server and again in the browser (hydration).
// Math.cos and Math.sin differ in the last bit between Node's and Chrome's
// V8 on about 3% of angles (measured 2026-10-20), and the force iterations
// amplify that into a different picture (7 px apart), so the layout uses
// only arithmetic, which IEEE makes identical in every engine.
describe("forceLayout is engine independent", () => {
  it("never calls Math.cos or Math.sin", () => {
    const cos = vi.spyOn(Math, "cos"), sin = vi.spyOn(Math, "sin");
    forceLayout(["a", "b", "c", "d"], [{ from: "a", to: "b" }, { from: "b", to: "c" }]);
    expect(cos).not.toHaveBeenCalled();
    expect(sin).not.toHaveBeenCalled();
    cos.mockRestore(); sin.mockRestore();
  });

  it("computes the spiral's angles to within float error of the real functions", () => {
    for (let i = 0; i < 500; i++) {
      const a = i * Math.PI * (3 - Math.sqrt(5));
      const [c, s] = cosSin(a);
      expect(Math.abs(c - Math.cos(a))).toBeLessThan(1e-12);
      expect(Math.abs(s - Math.sin(a))).toBeLessThan(1e-12);
    }
  });
});
