import type { Severity } from "@/lib/types";

// Authorization providers, and the words each one uses about itself.
//
// The reasoner (`attackPaths.ts`) must never name a specific technology. It asks
// questions that are true of every provider — "is authorization enforced here?",
// "does a rule grant access unconditionally?" — and asks this module for the
// wording. That separation is the whole point: adding a provider becomes a
// collector plus an entry in PROVIDERS, not a rewrite of the reasoner.
//
// The line is not stylistic. A reasoner that branches on `provider === "..."`
// has re-coupled itself to one stack, and the next provider re-opens every
// path. So the rule is mechanical: **`attackPaths.ts` may read
// `vocabulary(...)`, never compare a provider id.**
//
// Why the vocabulary is per-provider rather than generic prose: "a policy on it
// grants access unconditionally" is actionable to someone who knows Postgres and
// meaningless to someone on Firestore, who needs to hear "a security rule
// allows reads with no condition". Generic wording would be portable and useless.

/**
 * Where authorization for an asset is decided.
 *
 * `postgres-rls` — declarative, in the database, as policy text we can read and
 *   (crucially) replay against a disposable replica. Supabase is one instance of
 *   this, not the category.
 * `firebase-rules` — declarative, in a separate rules engine. Readable, but a
 *   different language and a different evaluator, so proving needs its own work.
 * `app-layer` — imperative, in application code. There is nothing declarative to
 *   read, so findings here are always inference, never proof.
 */
export type AuthzProvider = "postgres-rls" | "firebase-rules" | "app-layer";

export interface ProviderVocabulary {
  id: AuthzProvider;
  /** How the customer would name this connection in conversation. */
  label: string;
  /** The mechanism's proper name, e.g. "Row Level Security". */
  mechanism: string;
  /** Mid-sentence: why an over-broad read is not stopped, when it is switched off. */
  notEnforced: string;
  /** Mid-sentence: why an over-broad read is not stopped, when a rule filters nothing. */
  unconditional: string;
  /** What the customer should add so the store itself scopes rows to their owner. */
  ownershipRemedy: (qualified: string) => string;
  /** What the customer should add in code so the query is scoped to the caller. */
  callerScopeRemedy: string;
  /** Why the store cannot help at all — the credential bypasses it entirely. */
  bypassNote: string;
  /** Human label for the auth-configuration node in the graph. */
  configLabel: string;
  /**
   * Whether the proving ground can currently REPRODUCE a leak here rather than
   * infer one. Drives whether a finding may be presented as proven, and gates
   * fix pre-validation. Only `postgres-rls` is true today, and that is a
   * statement about what we have built, not about what is possible.
   */
  provable: boolean;
}

const POSTGRES_RLS: ProviderVocabulary = {
  id: "postgres-rls",
  label: "your Postgres database",
  mechanism: "Row Level Security",
  notEnforced: "Row Level Security is switched off on it",
  unconditional: "a policy on it grants access unconditionally",
  ownershipRemedy: (qualified) =>
    `add a Row Level Security policy on ${qualified} that scopes rows to their owner`,
  callerScopeRemedy: 'scope the query to the caller (e.g. .eq("user_id", user.id))',
  bypassNote:
    "uses a service-role credential, which ignores Row Level Security completely, so every policy on the table is bypassed for this request",
  configLabel: "Authentication configuration",
  provable: true,
};

const FIREBASE_RULES: ProviderVocabulary = {
  id: "firebase-rules",
  label: "your Firestore security rules",
  mechanism: "Firestore security rules",
  notEnforced: "no security rule covers it, so the default deny is not what is running",
  unconditional: "a security rule allows reads with no condition attached",
  ownershipRemedy: (qualified) =>
    `add a security rule on ${qualified} that matches the requesting user against the document owner`,
  callerScopeRemedy: "scope the query to the caller's uid before it reaches the client",
  bypassNote:
    "uses an admin credential, which bypasses security rules entirely, so every rule on the collection is ignored for this request",
  configLabel: "Authentication configuration",
  provable: false,
};

const APP_LAYER: ProviderVocabulary = {
  id: "app-layer",
  label: "your application code",
  mechanism: "authorization in application code",
  notEnforced: "nothing in the data store restricts who may read it",
  unconditional: "the only check on it lives in application code, which this request does not apply",
  ownershipRemedy: (qualified) =>
    `move the ownership check for ${qualified} somewhere the data store enforces it, so a missed filter cannot leak rows`,
  callerScopeRemedy: "scope the query to the authenticated caller",
  bypassNote:
    "reaches the data store with a credential that carries no per-row restriction, so the code is the only control",
  configLabel: "Authentication configuration",
  provable: false,
};

const PROVIDERS: Record<AuthzProvider, ProviderVocabulary> = {
  "postgres-rls": POSTGRES_RLS,
  "firebase-rules": FIREBASE_RULES,
  "app-layer": APP_LAYER,
};

/**
 * Words for a provider.
 *
 * `null` means no database collector reported on this asset — a normal state,
 * not an error. We fall back to `app-layer` wording, which is the only honest
 * default: without a store-level rule we can read, application code IS the only
 * control we know about. Note this never asserts the store is unprotected; that
 * judgement belongs to `enforced`, which stays `null`.
 */
export function vocabulary(provider: AuthzProvider | null | undefined): ProviderVocabulary {
  return provider ? PROVIDERS[provider] : APP_LAYER;
}

/** Whether a leak on this provider could be proven rather than inferred. */
export function isProvable(provider: AuthzProvider | null | undefined): boolean {
  return provider ? PROVIDERS[provider].provable : false;
}

// Deliberately NOT here: a helper that turns `provable` into a "proven" label.
// `provable` says a leak on this provider COULD be reproduced in the proving
// ground; it says nothing about whether we ran it. Only `lib/proving/*` may
// claim a finding is proven, and only after a run where the control query
// returned a row. Collapsing the two would let a capability be reported as a
// result — which is the precise failure `isTrustworthy()` exists to prevent.

/** Severity ranking shared by the reasoner and its consumers. */
export const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 3, WARNING: 2, INFO: 1 };
