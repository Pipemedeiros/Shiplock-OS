import type { Finding } from "./findings";

interface DiffResult {
  newFindings: Finding[];
  resolved: Finding[];
  unchanged: Finding[];
}

// Per AGENTS.md: only newFindings should ever trigger an alert; unchanged
// is always silent. Findings are matched by their stable `id` (see
// findings.ts), not by array position or object equality.
export function diffSnapshots(previous: Finding[], current: Finding[]): DiffResult {
  const previousIds = new Set(previous.map((f) => f.id));
  const currentIds = new Set(current.map((f) => f.id));

  return {
    newFindings: current.filter((f) => !previousIds.has(f.id)),
    resolved: previous.filter((f) => !currentIds.has(f.id)),
    unchanged: current.filter((f) => previousIds.has(f.id)),
  };
}
