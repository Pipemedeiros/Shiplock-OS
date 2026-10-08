import { z } from "zod";
import type { RouteFact } from "@/lib/graph/routeInventory";

/**
 * Guardrails: the security properties a repository has today, as JSON rules
 * (G1, Felipe 2026-09-30). Derived only from controls ShipLock OBSERVED on a
 * route that reaches data; an unread control never becomes a rule, so a rule
 * is never a guess. The PR check enforces them deterministically (a change
 * that removes one is blocked); the customer's coding agent reads the same
 * JSON over MCP before it edits, so dashboard and agent share one truth.
 */
export const GUARDRAIL_KINDS = ["requires_signed_in_caller", "scopes_rows_to_caller", "requires_machine_secret"] as const;
export type GuardrailKind = (typeof GUARDRAIL_KINDS)[number];

const ruleSchema = z.object({
  id: z.string(),
  kind: z.enum(GUARDRAIL_KINDS),
  route: z.string(),
  file: z.string(),
  tables: z.array(z.string()),
  /** requires_signed_in_caller: the methods we read refusing an anonymous caller (R1b). Absent on older rules. */
  methods: z.array(z.string()).optional(),
  because: z.string(),
  keep: z.string(),
});
export const guardrailsSchema = z.object({
  version: z.literal(1),
  repository: z.string(),
  commit: z.string().nullable(),
  rules: z.array(ruleSchema),
});
export type Guardrails = z.infer<typeof guardrailsSchema>;
export type GuardrailRule = z.infer<typeof ruleSchema>;

const WORDING: Record<GuardrailKind, { because: (t: string) => string; keep: string }> = {
  requires_signed_in_caller: {
    because: (t) => `This route reads or writes ${t} and today refuses callers who are not signed in.`,
    keep: "Keep the session check before any data access. Do not move this route under a public path or remove the check.",
  },
  scopes_rows_to_caller: {
    because: (t) => `This route narrows ${t} to the caller's own rows today.`,
    keep: "Keep the filter on the caller's id or team in every query. A new query on these tables needs the same filter.",
  },
  requires_machine_secret: {
    because: (t) => `This route reaches ${t} and today accepts only a request carrying a secret or a signature.`,
    keep: "Keep the signature or shared-secret check before any work, compared in constant time.",
  },
};

export function deriveGuardrails(routes: RouteFact[], meta: { repository: string; commit: string | null }): Guardrails {
  const rules: GuardrailRule[] = [];
  for (const route of [...routes].sort((a, b) => a.path.localeCompare(b.path))) {
    if (route.tables.length === 0) continue;
    const kinds: GuardrailKind[] = [];
    // R1b: `authenticated` is route-wide; the rule covers only the methods we
    // did not read as never refusing, and a route where none refuses gets none.
    const refusing = route.methods.filter((m) => !(route.unrefusedMethods ?? []).includes(m));
    if (route.authenticated && route.identityReadable && refusing.length > 0) kinds.push("requires_signed_in_caller");
    if (route.ownershipFiltered && route.ownershipReadable) kinds.push("scopes_rows_to_caller");
    if (route.machineGated && route.machineGateReadable) kinds.push("requires_machine_secret");
    const tables = [...route.tables].sort();
    for (const kind of kinds) {
      rules.push({ id: `${kind}:${route.path}`, kind, route: route.path, file: route.file, tables,
        ...(kind === "requires_signed_in_caller" ? { methods: refusing } : {}),
        because: WORDING[kind].because(tables.join(", ")), keep: WORDING[kind].keep });
    }
  }
  return { version: 1, repository: meta.repository, commit: meta.commit, rules };
}

export type GuardrailViolation = GuardrailRule & { severity: "CRITICAL"; detail: string };

/**
 * A rule is checked only when the change touched its route's file or a helper
 * the route executes. It is broken when the control is readable and gone; when
 * the new code cannot be read it is reported as unread, never as passing.
 */
export function checkGuardrails(guardrails: Guardrails, routesAfter: RouteFact[], changedFiles: ReadonlySet<string>):
  { violations: GuardrailViolation[]; unread: string[] } {
  const after = new Map(routesAfter.map((route) => [route.path, route]));
  const violations: GuardrailViolation[] = [];
  const unread: string[] = [];
  for (const rule of guardrails.rules) {
    const route = after.get(rule.route);
    if (!route) continue;
    if (![route.file, ...route.via].some((file) => changedFiles.has(file))) continue;
    const [holds, readable] =
      rule.kind === "requires_signed_in_caller" ? [route.authenticated, route.identityReadable]
      : rule.kind === "scopes_rows_to_caller" ? [route.ownershipFiltered, route.ownershipReadable]
      : [route.machineGated, route.machineGateReadable];
    const stopped = rule.kind === "requires_signed_in_caller"
      ? (rule.methods ?? []).filter((m) => route.unrefusedMethods?.includes(m)) : [];
    if (holds && stopped.length === 0) continue;
    if (!readable) { unread.push(`${rule.kind} ${rule.route}`); continue; }
    const afterText = stopped.length > 0
      ? `After this change nothing in its ${stopped.join(" or ")} handler refuses a caller who is not signed in.`
      : "After this change it no longer does.";
    violations.push({ ...rule, severity: "CRITICAL",
      detail: `${rule.because.replace("today ", "before this change ")} ${afterText} ${rule.keep}` });
  }
  return { violations, unread };
}
