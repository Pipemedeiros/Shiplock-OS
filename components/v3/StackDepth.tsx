import type { StackKind } from "@/lib/agent/stack";

/**
 * How deeply the audit reasons about each kind of tool.
 *
 * "Detected" and "reasoned about" are different claims. A flat list of logos
 * lets the first quietly borrow the credibility of the second, and a customer
 * looking at a tile for their email provider should not come away believing we
 * audit it.
 *
 * The mapping is by KIND rather than by tool, because it is a statement about
 * what the collectors actually do: route inventory resolves identity, so auth
 * is reasoned about; the schema drives table-level reasoning, so a database is;
 * everything else is inventoried honestly and no more.
 */
export type Depth = "reasoned" | "detected";

const REASONED: StackKind[] = ["auth", "database", "framework"];

export function depthOf(kind: StackKind): Depth {
  return REASONED.includes(kind) ? "reasoned" : "detected";
}

const LABEL: Record<Depth, { text: string; title: string; cls: string }> = {
  reasoned: {
    text: "Reasoned about",
    title: "We follow how your code uses this and check it in every audit.",
    cls: "v3-tag-ok",
  },
  detected: {
    text: "Detected",
    title: "Found and inventoried. We do not yet reason about how it is used.",
    cls: "v3-tag-mute",
  },
};

export function StackDepth({ depth }: { depth: Depth }) {
  const label = LABEL[depth];
  return (
    <span className={`v3-tag ${label.cls}`} title={label.title}>
      {label.text}
    </span>
  );
}
