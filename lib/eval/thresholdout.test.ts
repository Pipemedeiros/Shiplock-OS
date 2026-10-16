import { describe, expect, it } from "vitest";
import { createThresholdout, laplace, seededRandom } from "./thresholdout";

describe("Thresholdout: a holdout a self-improving loop can ask many times without learning it", () => {
  it("answers with the development value when development and holdout agree", () => {
    // Noise far below the threshold, so agreement is unambiguous.
    const gate = createThresholdout({ threshold: 0.04, sigma: 0.001, budget: 3, seed: 7 });
    const answer = gate.ask({ development: 0.9, holdout: 0.905 });
    expect(answer.value).toBe(0.9);
    expect(answer.usedHoldout).toBe(false);
    expect(gate.remaining()).toBe(3);
  });

  it("spends budget and answers with a noisy holdout value when they disagree (overfitting shows)", () => {
    const gate = createThresholdout({ threshold: 0.04, sigma: 0.01, budget: 3, seed: 7 });
    const answer = gate.ask({ development: 0.97, holdout: 0.86 });
    expect(answer.usedHoldout).toBe(true);
    expect(Math.abs(answer.value - 0.86)).toBeLessThan(0.1);
    expect(gate.remaining()).toBe(2);
  });

  it("refuses once the budget is spent, so the holdout is never worn out silently", () => {
    const gate = createThresholdout({ threshold: 0.01, sigma: 0.001, budget: 1, seed: 1 });
    gate.ask({ development: 0.99, holdout: 0.5 });
    expect(() => gate.ask({ development: 0.99, holdout: 0.5 })).toThrow(/budget/);
  });

  it("is reproducible from its seed", () => {
    const a = createThresholdout({ threshold: 0.0, sigma: 0.02, budget: 5, seed: 42 });
    const b = createThresholdout({ threshold: 0.0, sigma: 0.02, budget: 5, seed: 42 });
    expect(a.ask({ development: 0.5, holdout: 0.9 }).value).toBe(b.ask({ development: 0.5, holdout: 0.9 }).value);
  });

  it("draws Laplace noise centred on zero with the given scale", () => {
    const rand = seededRandom(3);
    const draws = Array.from({ length: 20000 }, () => laplace(rand, 1));
    const mean = draws.reduce((s, x) => s + x, 0) / draws.length;
    const meanAbs = draws.reduce((s, x) => s + Math.abs(x), 0) / draws.length;
    expect(Math.abs(mean)).toBeLessThan(0.05);
    expect(meanAbs).toBeGreaterThan(0.9);
    expect(meanAbs).toBeLessThan(1.1);
  });
});
