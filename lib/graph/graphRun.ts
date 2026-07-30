import { getSupabaseAdmin } from "@/lib/supabase";
import { findAttackPaths } from "./attackPaths";
import type { GraphInput } from "./graph";
import type { RouteFact } from "./routeInventory";

// Persistence and execution for the reasoner.
//
// Collectors run on different triggers — source per pull request, database on the
// 48h pass, traffic continuously — so each writes its facts here and the reasoner
// reads whatever is current. Without this, correlation would depend on which
// trigger happened to fire last, and paths would appear and vanish for reasons
// that have nothing to do with the customer's security.

export type Collector = "source" | "db" | "traffic";

export interface SourceFacts {
  routes: RouteFact[];
}

export interface DbFacts {
  scanTables: { name: string; rlsEnabled: boolean }[];
  policies: GraphInput["policies"];
  advisors: GraphInput["advisors"];
  authConfig: GraphInput["authConfig"];
}

export interface TrafficFacts {
  hotPaths: { path: string; suspiciousRequests: number }[];
}

/**
 * Upsert one collector's facts. Fail-soft: never break the pass that calls it.
 *
 * `merge` exists because the `db` collector has TWO independent producers on
 * different schedules: the Management API scan supplies policies, advisors and
 * auth config, while the 16-check scan supplies per-table RLS state. A plain
 * upsert would let whichever ran last erase the other's facts, and the reasoner
 * would then see a project with policies but no tables (or the reverse) and
 * quietly stop producing paths. Partial writers must merge.
 */
export async function saveFacts(
  userId: string,
  collector: Collector,
  facts: Partial<SourceFacts & DbFacts & TrafficFacts>,
  options: { merge?: boolean } = {}
): Promise<void> {
  try {
    const admin = getSupabaseAdmin();
    let next: Record<string, unknown> = { ...facts };

    if (options.merge) {
      const { data } = await admin
        .from("graph_facts")
        .select("facts")
        .eq("user_id", userId)
        .eq("collector", collector)
        .maybeSingle();
      next = { ...((data?.facts as Record<string, unknown>) ?? {}), ...facts };
    }

    await admin
      .from("graph_facts")
      .upsert(
        { user_id: userId, collector, facts: next, updated_at: new Date().toISOString() },
        { onConflict: "user_id,collector" }
      );
  } catch (err) {
    console.error(
      `[graph] failed to save ${collector} facts for ${userId}:`,
      err instanceof Error ? err.message : err
    );
  }
}

/**
 * Assemble the reasoner's input from whatever collectors have reported.
 *
 * Missing collectors are simply absent, never faked. A user with no GitHub
 * connection has no route facts, so the paths that need a route cannot fire —
 * which is correct, and much better than assuming a default.
 */
export async function loadGraphInput(userId: string): Promise<GraphInput> {
  const { data } = await getSupabaseAdmin()
    .from("graph_facts")
    .select("collector, facts")
    .eq("user_id", userId);

  const input: GraphInput = {};
  for (const row of (data ?? []) as { collector: Collector; facts: Record<string, unknown> }[]) {
    if (row.collector === "source") {
      input.routes = (row.facts as unknown as SourceFacts).routes ?? [];
    } else if (row.collector === "db") {
      const f = row.facts as unknown as DbFacts;
      input.scanTables = f.scanTables ?? [];
      input.policies = f.policies ?? [];
      input.advisors = f.advisors ?? [];
      input.authConfig = f.authConfig ?? null;
    } else if (row.collector === "traffic") {
      input.trafficHotPaths = (row.facts as unknown as TrafficFacts).hotPaths ?? [];
    }
  }
  return input;
}

/**
 * Run the reasoner and persist its paths as findings.
 *
 * Same only-new + archive-on-resolve contract as every other collector run, so
 * paths flow into the dashboard, the agent brief, MCP and the digest with no
 * extra wiring — and a path that stops reproducing closes itself, which matters
 * more here than anywhere else: the whole point of a path is that fixing ONE of
 * its steps breaks it, and the customer must see that reflected.
 */
export async function runGraphReasoner(
  userId: string
): Promise<{ total: number; newCount: number; resolvedCount: number }> {
  const input = await loadGraphInput(userId);

  // A path needs a route AND a database fact. With neither, there is nothing to
  // correlate and we must not archive existing paths on the strength of an empty
  // read — that would report every open path as fixed.
  if (!input.routes?.length && !input.scanTables?.length && !input.policies?.length) {
    return { total: 0, newCount: 0, resolvedCount: 0 };
  }

  const paths = findAttackPaths(input);
  const admin = getSupabaseAdmin();

  const { data: existing } = await admin
    .from("deep_findings")
    .select("finding_id")
    .eq("user_id", userId)
    .eq("source", "graph")
    .is("archived_at", null);

  const active = new Set((existing ?? []).map((r) => r.finding_id as string));
  const current = new Set(paths.map((p) => p.id));

  const resolved = [...active].filter((id) => !current.has(id));
  if (resolved.length > 0) {
    await admin
      .from("deep_findings")
      .update({ archived_at: new Date().toISOString() })
      .eq("user_id", userId)
      .eq("source", "graph")
      .is("archived_at", null)
      .in("finding_id", resolved);
  }

  const fresh = paths.filter((p) => !active.has(p.id));
  if (fresh.length > 0) {
    await admin.from("deep_findings").insert(
      fresh.map((p) => ({
        user_id: userId,
        source: "graph",
        finding_id: p.id,
        severity: p.severity,
        title: p.title,
        consequence: p.consequence,
      }))
    );
  }

  return { total: paths.length, newCount: fresh.length, resolvedCount: resolved.length };
}
