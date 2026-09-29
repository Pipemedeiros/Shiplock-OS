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

/**
 * Whether ShipLock can read a detected tool live (Felipe, 2026-09-29: any
 * stack, detected is shown, unsupported is "coming soon"). Detecting a tool
 * from code is not a binding and not a read: only Supabase and Postgres have
 * a read-only collector today, so only they are offered. Prisma and Drizzle
 * point at the database they talk to. Databases, auth, payments and hosting
 * we cannot read yet are named and marked coming soon; other kinds make no
 * connection claim.
 */
export type Connection =
  | { state: "available"; provider: "Supabase" | "Postgres" }
  | { state: "coming_soon" }
  | { state: "none" };

const LIVE: Record<string, "Supabase" | "Postgres"> = {
  supabase: "Supabase",
  "supabase-auth": "Supabase",
  postgres: "Postgres",
  prisma: "Postgres",
  drizzle: "Postgres",
};
const CONNECTABLE_KINDS: StackKind[] = ["database", "auth", "payments", "hosting"];

export function connectionFor(tool: { id: string; kind: StackKind }): Connection {
  const provider = LIVE[tool.id];
  if (provider) return { state: "available", provider };
  return CONNECTABLE_KINDS.includes(tool.kind) ? { state: "coming_soon" } : { state: "none" };
}

export function StackConnection({ connection }: { connection: Connection }) {
  if (connection.state === "none") return null;
  if (connection.state === "coming_soon") {
    return (
      <p className="v3-small" style={{ marginTop: 8 }} title="We detected it in your code. Reading its live configuration is not built yet.">
        Live connection coming soon
      </p>
    );
  }
  return (
    <a href="/dashboard/settings" className="v3-btn v3-btn-sm v3-ghost" style={{ marginTop: 10 }}>
      Connect {connection.provider}
    </a>
  );
}
