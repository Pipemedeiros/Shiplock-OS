/**
 * A force-directed layout for the map (Felipe 2026-10-06: like an Obsidian
 * graph, not 3D). Fruchterman-Reingold: every pair repels, every edge pulls,
 * a weak pull keeps the graph centred, and the step cools each round. Starts
 * on a sunflower spiral in input order, so it is deterministic: no random
 * numbers, and two visits draw the same picture. Pure and dependency free.
 */
export type Point = { x: number; y: number };
type LayoutEdge = { from: string; to: string };

const GOLDEN = Math.PI * (3 - Math.sqrt(5));
const TAU = 2 * Math.PI;

/** Cosine and sine from arithmetic alone. Math.cos and Math.sin differ in the
 * last bit between Node and the browser, and the layout runs in both (server
 * render, then hydration); the iterations amplify that into a different
 * picture. Range reduced to [-pi, pi], then Taylor series. */
export function cosSin(angle: number): [number, number] {
  const a = angle - TAU * Math.floor(angle / TAU + 0.5);
  const a2 = a * a;
  let c = 0, s = 0, termC = 1, termS = a;
  for (let n = 0; n < 16; n++) {
    c += termC; s += termS;
    termC *= -a2 / ((2 * n + 1) * (2 * n + 2));
    termS *= -a2 / ((2 * n + 2) * (2 * n + 3));
  }
  return [c, s];
}

/** A deterministic force-directed layout (Fruchterman-Reingold) for the route
 * map. */
export function forceLayout(ids: readonly string[], edges: readonly LayoutEdge[],
  { radius = 320, iterations = 300, gravity = 1 }: { radius?: number; iterations?: number; gravity?: number } = {}): Map<string, Point> {
  const n = ids.length;
  const out = new Map<string, Point>();
  if (n === 0) return out;
  if (n === 1) return out.set(ids[0], { x: 0, y: 0 });

  const index = new Map(ids.map((id, i) => [id, i]));
  const links = edges.map((e) => [index.get(e.from), index.get(e.to)] as const)
    .filter((l): l is readonly [number, number] => l[0] !== undefined && l[1] !== undefined && l[0] !== l[1]);
  const k = radius * Math.sqrt(Math.PI / n) * 0.9; // ideal spacing for n nodes in the disc
  const x = new Float64Array(n), y = new Float64Array(n);
  for (let i = 0; i < n; i++) {
    const r = k * Math.sqrt(i + 0.5);
    const [c, s] = cosSin(i * GOLDEN);
    x[i] = r * c;
    y[i] = r * s;
  }

  const dx = new Float64Array(n), dy = new Float64Array(n);
  for (let step = 0; step < iterations; step++) {
    const temperature = (radius / 6) * (1 - step / iterations) + 0.5;
    dx.fill(0); dy.fill(0);
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        let ex = x[i] - x[j], ey = y[i] - y[j];
        let d2 = ex * ex + ey * ey;
        if (d2 < 1e-6) { ex = 0.01 * (i - j); ey = 0.01; d2 = ex * ex + ey * ey; }
        const f = (k * k) / d2; // repulsion k²/d, applied along the unit vector
        dx[i] += ex * f; dy[i] += ey * f; dx[j] -= ex * f; dy[j] -= ey * f;
      }
    }
    for (const [a, b] of links) {
      const ex = x[a] - x[b], ey = y[a] - y[b];
      const d = Math.sqrt(ex * ex + ey * ey) || 0.01;
      const f = d / k; // attraction d²/k, along the unit vector
      dx[a] -= ex * f; dy[a] -= ey * f; dx[b] += ex * f; dy[b] += ey * f;
    }
    for (let i = 0; i < n; i++) {
      dx[i] -= x[i] * gravity; dy[i] -= y[i] * gravity; // gravity toward the centre
      const len = Math.sqrt(dx[i] * dx[i] + dy[i] * dy[i]) || 1;
      const move = Math.min(len, temperature);
      x[i] += (dx[i] / len) * move; y[i] += (dy[i] / len) * move;
    }
  }

  // Centre, then scale to fill the radius (the centre pull keeps outliers close,
  // so filling the disc spreads the graph instead of squashing it).
  let cx = 0, cy = 0;
  for (let i = 0; i < n; i++) { cx += x[i]; cy += y[i]; }
  cx /= n; cy /= n;
  let far = 0;
  for (let i = 0; i < n; i++) far = Math.max(far, Math.hypot(x[i] - cx, y[i] - cy));
  const scale = far > 0 ? radius / far : 1;
  ids.forEach((id, i) => out.set(id, { x: (x[i] - cx) * scale, y: (y[i] - cy) * scale }));
  return out;
}
