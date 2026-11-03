/**
 * Which Next.js App Router route handler an observed request path reaches
 *. Deterministic, from file paths only: static segments beat
 * dynamic ones, then catch-alls; route groups `(x)` add no URL segment. Pages
 * Router files are not matched (the rate-limit suggestion is App Router only).
 */
type Route = { file: string; segments: string[]; pattern: string };

const ROUTE_FILE = /^(?:src\/)?app\/(.*?)\/?route\.[cm]?[jt]sx?$/;

function toRoute(file: string): Route | null {
  const match = ROUTE_FILE.exec(file);
  if (!match) return null;
  const segments = match[1].split("/").filter((s) => s && !/^\(.*\)$/.test(s) && !s.startsWith("@"));
  const pattern = "/" + segments.map((s) => {
    const dynamic = /^\[\[?(?:\.\.\.)?([^\]]+)\]\]?$/.exec(s);
    return dynamic ? `:${dynamic[1]}${s.includes("...") ? "*" : ""}` : s;
  }).join("/");
  return { file, segments, pattern: pattern === "/" ? "/" : pattern };
}

/** Lower is more specific: 0 static, 1 dynamic, 2 catch-all, 3 optional catch-all. */
function kind(segment: string): number {
  if (segment.startsWith("[[...")) return 3;
  if (segment.startsWith("[...")) return 2;
  if (segment.startsWith("[")) return 1;
  return 0;
}

function matches(route: Route, parts: string[]): number[] | null {
  const score: number[] = [];
  for (let i = 0; i < route.segments.length; i++) {
    const segment = route.segments[i];
    const k = kind(segment);
    if (k >= 2) {
      if (k === 2 && parts.length <= i) return null;
      score.push(k);
      return score;
    }
    if (i >= parts.length) return null;
    if (k === 0 && segment !== parts[i]) return null;
    score.push(k);
  }
  return parts.length === route.segments.length ? score : null;
}

function better(a: number[], b: number[]): boolean {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] ?? 9, y = b[i] ?? 9;
    if (x !== y) return x < y;
  }
  return false;
}

export function appRouteForPath(path: string, files: string[]): { file: string; pattern: string } | null {
  const parts = path.split(/[?#]/)[0].split("/").filter(Boolean);
  let best: { route: Route; score: number[] } | null = null;
  for (const file of files) {
    const route = toRoute(file);
    if (!route) continue;
    const score = matches(route, parts);
    if (score && (!best || better(score, best.score))) best = { route, score };
  }
  return best ? { file: best.route.file, pattern: best.route.pattern } : null;
}

export function matchHotPaths(
  hot: { path: string; suspiciousRequests: number }[], files: string[],
): { matched: { file: string; pattern: string; suspiciousRequests: number; paths: string[] }[]; unmatched: string[] } {
  const byFile = new Map<string, { file: string; pattern: string; suspiciousRequests: number; paths: string[] }>();
  const unmatched: string[] = [];
  for (const { path, suspiciousRequests } of hot) {
    const route = appRouteForPath(path, files);
    if (!route) { unmatched.push(path); continue; }
    const entry = byFile.get(route.file) ?? { ...route, suspiciousRequests: 0, paths: [] };
    entry.suspiciousRequests += suspiciousRequests;
    entry.paths.push(path);
    byFile.set(route.file, entry);
  }
  const matched = [...byFile.values()].map((e) => ({ ...e, paths: e.paths.sort() }))
    .sort((a, b) => b.suspiciousRequests - a.suspiciousRequests || a.file.localeCompare(b.file));
  return { matched, unmatched };
}
