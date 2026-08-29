import type { StackKind } from "@/lib/agent/stack";

/**
 * The categories a customer's stack is grouped into, and what connecting each
 * one would let us read.
 *
 * This is the taxonomy shared by the onboarding stack step, the dashboard Stack
 * page, and the connectors that follow. It exists as one list rather than three
 * because a category invented for a screen and reshuffled later when a
 * connector lands is a migration every time.
 *
 * `connect` is the honest field. A category whose connector does not exist yet
 * carries null, and the UI says live checks for it are not available. An offer
 * to connect a service that opens nothing is worse than no offer: it spends the
 * customer's trust on a button that does not work.
 *
 * Order is by what the connection buys us, weighted by what this market
 * actually runs (Supabase State of Startups 2026: database and auth are where
 * the customer data lives, hosting is where the configuration we cannot read
 * from a repository lives).
 */

export interface ConnectionCategory {
  id: string;
  /** Shown as the group heading. */
  label: string;
  /** The stack kinds that belong in this group. */
  kinds: StackKind[];
  /**
   * What connecting reads that the repository cannot show. One sentence,
   * concrete, in the customer's terms. This is the entire argument for
   * connecting, so it states a capability rather than a benefit.
   */
  adds: string;
  /**
   * Where the connect action goes, or null when no connector exists yet.
   * Null renders as a statement, never as a disabled button.
   */
  connect: string | null;
}

export const CONNECTION_CATEGORIES: ConnectionCategory[] = [
  {
    id: "database",
    label: "Database",
    kinds: ["database"],
    adds: "Reads the row policies themselves, so a permissive one is reproduced on a disposable copy instead of inferred from your schema.",
    connect: "/dashboard/settings",
  },
  {
    id: "auth",
    label: "Authentication",
    kinds: ["auth"],
    adds: "Reads session lifetime, sign-up rules and multi-factor settings. None of it appears in your code, and all of it changes who can reach a route.",
    connect: null,
  },
  {
    id: "hosting",
    label: "Hosting",
    kinds: ["hosting"],
    adds: "Reads which environment variables exist and where they are scoped, so a server secret exposed to the browser is caught before it ships.",
    connect: null,
  },
  {
    id: "payments",
    label: "Payments",
    kinds: ["payments"],
    adds: "Reads which webhook endpoints exist and whether each one verifies signatures. An unsigned endpoint accepts a forged payment event.",
    connect: null,
  },
  {
    id: "storage",
    label: "Storage",
    kinds: ["storage"],
    adds: "Reads bucket permissions. Whether a bucket is public is a setting on the provider, not a line in your repository.",
    connect: null,
  },
  {
    id: "ai",
    label: "AI providers",
    kinds: ["ai"],
    adds: "Reads key scope and spend limits. A leaked provider key is billed to you until it is revoked.",
    connect: null,
  },
  {
    id: "email",
    label: "Email",
    kinds: ["email"],
    adds: "Reads your sending domain's authentication records, so a domain someone else can send as is caught.",
    connect: null,
  },
];

/** The category a stack kind belongs to, or null for kinds we do not group. */
export function categoryFor(kind: StackKind): ConnectionCategory | null {
  return CONNECTION_CATEGORIES.find((c) => c.kinds.includes(kind)) ?? null;
}
