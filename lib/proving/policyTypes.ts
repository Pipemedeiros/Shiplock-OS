// Shared policy shape. Lives here rather than in policyScan so lib/proving does
// not import the analysis layer just to name a row it passes through.
export type { PgPolicy } from "@/lib/deep/policyScan";
