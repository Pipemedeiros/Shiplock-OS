/**
 * Thresholdout, the reusable holdout (Dwork, Feldman, Hardt, Pitassi,
 * Reingold, Roth, "The reusable holdout", Science 2015).
 *
 * The self-improving loop (Karpathy's autoresearch idea: change one rule,
 * score it, keep it only if the score rises) asks the labels again and again.
 * Asked plainly, a holdout leaks: each kept change fits it a little more, and
 * the final number flatters. Thresholdout answers with the development value
 * while development and holdout agree, and only when they differ by more
 * than a noisy threshold does it reveal a noisy holdout value and spend one
 * unit of budget. When the budget is gone it refuses, so a worn-out holdout
 * is never mistaken for a fresh one. Pure and seeded, so a run is replayable.
 */
type ThresholdoutOptions = { threshold: number; sigma: number; budget: number; seed: number };
type ThresholdoutAnswer = { value: number; usedHoldout: boolean };

/** Mulberry32: small, fast, and good enough for noise that must be replayable. */
export function seededRandom(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** One draw from Laplace(0, scale) by inverse transform. */
export function laplace(rand: () => number, scale: number): number {
  const u = rand() - 0.5;
  return -scale * Math.sign(u) * Math.log(1 - 2 * Math.abs(u));
}

/** Thresholdout (Dwork et al. 2015): answers from the development set unless
 * it drifts from the holdout, then spends budget on a noisy holdout answer,
 * so a holdout can be reused without overfitting it. */
export function createThresholdout(options: ThresholdoutOptions) {
  const rand = seededRandom(options.seed);
  let budget = options.budget;
  // The threshold itself is noisy and refreshed after each overfit answer.
  let noisyThreshold = options.threshold + laplace(rand, 2 * options.sigma);
  return {
    ask(query: { development: number; holdout: number }): ThresholdoutAnswer {
      if (budget <= 0) throw new Error("Thresholdout budget spent: freeze a fresh holdout before asking again");
      const gap = Math.abs(query.holdout - query.development);
      if (gap > noisyThreshold + laplace(rand, 4 * options.sigma)) {
        budget--;
        noisyThreshold = options.threshold + laplace(rand, 2 * options.sigma);
        return { value: query.holdout + laplace(rand, options.sigma), usedHoldout: true };
      }
      return { value: query.development, usedHoldout: false };
    },
    remaining: () => budget,
  };
}
