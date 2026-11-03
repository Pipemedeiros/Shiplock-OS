import type { OsvVuln } from "./githubScan";

// PURE logic for the dependency-bump auto-fix PR — no network. Given OSV vuln
// data and a package.json, works out the safe target versions and produces the
// edited package.json. The GitHub write flow (branch + PR) lives in
// lib/deep/github.ts; this stays pure and unit-tested. Scope is DELIBERATELY
// narrow: dependency version bumps only. Never edits app code, DB, RLS, or auth
// (AGENTS.md permanent boundary) — those remain copy-paste findings.

// Compare two semver "core" versions (major.minor.patch), ignoring any
// pre-release/build suffix. Returns -1 | 0 | 1.
export function compareSemver(a: string, b: string): number {
  const core = (v: string) => v.trim().replace(/^[vV]/, "").split(/[-+]/)[0];
  const pa = core(a).split(".").map((n) => parseInt(n, 10) || 0);
  const pb = core(b).split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

// Smallest published `fixed` version for `name` from an OSV `affected` array.
// OSV shape: affected[].{ package:{ecosystem,name}, ranges[].events[].fixed }.
export function fixedVersionFromOsv(affected: unknown, name: string): string | null {
  if (!Array.isArray(affected)) return null;
  const fixes: string[] = [];
  for (const entry of affected) {
    const pkg = (entry as { package?: { ecosystem?: string; name?: string } }).package;
    if (!pkg || pkg.ecosystem !== "npm" || pkg.name !== name) continue;
    const ranges = (entry as { ranges?: Array<{ events?: Array<{ fixed?: string }> }> }).ranges ?? [];
    for (const range of ranges) {
      for (const ev of range.events ?? []) {
        if (typeof ev.fixed === "string" && ev.fixed) fixes.push(ev.fixed);
      }
    }
  }
  if (fixes.length === 0) return null;
  return fixes.reduce((min, v) => (compareSemver(v, min) < 0 ? v : min));
}

// The single version a package must reach to clear ALL its vulns: the highest
// of the per-vuln fixed versions. null when no vuln has a known fix.
export function pickTargetVersion(vulns: OsvVuln[]): string | null {
  const fixed = vulns.map((v) => v.fixedVersion).filter((v): v is string => !!v);
  if (fixed.length === 0) return null;
  return fixed.reduce((max, v) => (compareSemver(v, max) > 0 ? v : max));
}

interface DepBump {
  name: string;
  from: string; // the original range string, e.g. "^1.0.0"
  to: string; // the new range string, e.g. "^1.4.2"
  section: "dependencies" | "devDependencies";
}

const SECTIONS = ["dependencies", "devDependencies"] as const;

// Apply target versions to a package.json. Only bumps a dep already present
// whose current base version is BELOW the target (never downgrades, never adds
// new deps). Preserves the range operator (^ / ~ / exact). Returns the edited
// JSON string (2-space, trailing newline) and the list of changes.
export function planDependencyBumps(
  packageJson: string,
  targets: { name: string; version: string }[]
): { updated: string; changes: DepBump[] } {
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(packageJson);
  } catch {
    return { updated: packageJson, changes: [] };
  }

  const changes: DepBump[] = [];
  // One package installed at two versions gives two targets; the higher clears both.
  const targetMap = new Map<string, string>();
  for (const t of targets) {
    const seen = targetMap.get(t.name);
    if (!seen || compareSemver(t.version, seen) > 0) targetMap.set(t.name, t.version);
  }

  for (const section of SECTIONS) {
    const block = pkg[section];
    if (!block || typeof block !== "object") continue;
    const deps = block as Record<string, string>;
    for (const [name, range] of Object.entries(deps)) {
      const target = targetMap.get(name);
      if (!target || typeof range !== "string") continue;
      const prefix = range.match(/^[\^~]/)?.[0] ?? "";
      const base = range.replace(/^[\^~>=<\s]+/, "").trim();
      // Only ever touch plain numeric semver ranges. Leave workspace:, file:,
      // git/url, npm:, and wildcard ranges exactly as they are — rewriting
      // those to a version would break the dependency.
      if (!base || !/^\d/.test(base)) continue;
      // Never downgrade or churn a dep already at/above the target.
      if (compareSemver(target, base) <= 0) continue;
      const to = `${prefix}${target}`;
      deps[name] = to;
      changes.push({ name, from: range, to, section });
    }
  }

  if (changes.length === 0) return { updated: packageJson, changes: [] };
  return { updated: JSON.stringify(pkg, null, 2) + "\n", changes };
}

// PR body copy from a change list.
export function buildPrBody(changes: DepBump[]): string {
  const lines = changes
    .map((c) => `- **${c.name}**: \`${c.from}\` → \`${c.to}\``)
    .join("\n");
  return [
    "ShipLock found dependencies with known vulnerabilities and bumped them to patched versions.",
    "",
    lines,
    "",
    "Only `package.json` version ranges changed, no application code was touched. Review, run your install to refresh the lockfile, and merge if your tests pass.",
    "",
    "ShipLock",
  ].join("\n");
}
