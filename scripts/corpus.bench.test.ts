import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";

// Plan item H: the benchmark's two harness steps. A label pack hides what the
// product decided (severity, class) and fixes a shuffled order; answers from
// each blind labeler come back keyed by packet, and merge into labels.
const require = createRequire(import.meta.url);
type Record_ = { id: string; repository: string; commit: string; findings: { id: string; severity: string; attackClass: string; title: string; consequence?: string; file: string | null }[] };
const { labelPack, mergeAnswers } = require("./corpus.cjs") as {
  labelPack: (records: Record_[]) => { key: string; repo: string; id: string; repository: string; commit: string; file: string | null; statement: string }[];
  mergeAnswers: (pack: { key: string; repo: string; id: string }[], answers: { key: string; accurate: string; real: string }[][]) =>
    { labels: { repo: string; id: string; labelers: { accurate: string; real: string }[] }[]; unknownKeys: string[] };
};

const records: Record_[] = [{ id: "c5-a", repository: "o/a", commit: "c".repeat(40), findings: [
  { id: "github:x:1", severity: "CRITICAL", attackClass: "committed_secret", title: "T1", consequence: "C1", file: "a.ts" },
  { id: "github:x:2", severity: "WARNING", attackClass: "committed_secret", title: "T2", consequence: "C2", file: "b.ts" },
  { id: "github:x:3", severity: "INFO", attackClass: "committed_secret", title: "T3", consequence: "C3", file: "c.ts" },
] }];

describe("label pack", () => {
  const pack = labelPack(records);
  it("packs only what sets the status, without the product's verdict", () => {
    expect(pack).toHaveLength(2);
    expect(JSON.stringify(pack)).not.toMatch(/CRITICAL|WARNING|committed_secret/);
    expect(pack.map((p) => p.statement).sort()).toEqual(["T1. C1", "T2. C2"]);
  });
  it("is deterministic and keyed by an opaque id", () => {
    expect(labelPack(records)).toEqual(pack);
    for (const p of pack) expect(p.key).toMatch(/^[a-f0-9]{12}$/);
  });
  it("merges two labelers' answers by key and reports keys it does not know", () => {
    const [a, b] = pack;
    const merged = mergeAnswers(pack, [
      [{ key: a.key, accurate: "yes", real: "yes" }, { key: b.key, accurate: "no", real: "no" }],
      [{ key: a.key, accurate: "yes", real: "yes" }, { key: "zzzzzzzzzzzz", accurate: "yes", real: "yes" }],
    ]);
    expect(merged.labels.find((l) => l.id === a.id)!.labelers).toHaveLength(2);
    expect(merged.labels.find((l) => l.id === b.id)!.labelers).toHaveLength(1);
    expect(merged.unknownKeys).toEqual(["zzzzzzzzzzzz"]);
  });
});
