import { getSupabaseAdmin } from "@/lib/supabase";
import { openArena, type Arena, type ProvingHost } from "./arena";
import type { CustomerAutonomySettings } from "./guard";
import type { PgPolicy } from "./policyTypes";
import {
  buildSeedSql,
  interpretProbe,
  selectTablesToProbe,
  type ProbeOutcome,
  type ProvenFinding,
} from "./tenantProbe";
import { buildControlProbeSql, buildLeakProbeSql } from "./replica";
import { buildGateSql, buildOwnershipFix, judgeFix, buildFixApplySql, type GateReading } from "./fixValidation";
import { claudeProposer, runAdversarialAgent, type Proposer } from "./agent";

// The proving ground, end to end.
//
// For each table the reasoner suspects: open an arena, demonstrate the problem,
// let the agent look for variants the fixed probe would miss, then prove the fix
// closes it without locking anyone out. Tear the arena down whatever happens.
//
// Ordering is deliberate. The deterministic probe runs first because it is free
// and settles the common case; the agent only runs when that probe found
// nothing, so we do not spend a model call confirming what we already know.

export interface ProvingContext {
  userId: string;
  customerToken: string;
  customerRef: string;
  settings: CustomerAutonomySettings;
  /** Tables the graph flagged, in priority order. */
  suspectedTables: string[];
  /** table -> columns, for choosing an owner column. */
  schema: Map<string, string[]>;
  /** Policies per table, for the replica path. */
  policiesByTable: Map<string, PgPolicy[]>;
  /** ShipLock's own proving project. Null disables the free path. */
  host: ProvingHost | null;
  /** Injected so tests never reach a model. */
  propose?: Proposer;
}

export interface ProvingResult {
  ran: boolean;
  reason?: string;
  findings: ProvenFinding[];
  probed: number;
}

const num = (rows: Record<string, unknown>[], key: string): number => {
  const value = rows[0]?.[key];
  return typeof value === "number" ? value : Number.parseInt(String(value ?? 0), 10) || 0;
};

export async function runProvingGround(ctx: ProvingContext): Promise<ProvingResult> {
  // Cheapest refusals first — never spend money to discover we were not allowed.
  if (ctx.settings.killSwitchOn) return { ran: false, reason: "kill_switch", findings: [], probed: 0 };
  if (!ctx.settings.provingGroundEnabled) return { ran: false, reason: "not_enabled", findings: [], probed: 0 };

  const targets = selectTablesToProbe(ctx.suspectedTables, ctx.schema);
  if (targets.length === 0) return { ran: false, reason: "nothing_to_probe", findings: [], probed: 0 };

  const findings: ProvenFinding[] = [];
  let probed = 0;

  for (const { table, ownerColumn } of targets) {
    const { arena, reason } = await openArena(
      {
        customerToken: ctx.customerToken,
        customerRef: ctx.customerRef,
        settings: ctx.settings,
        table,
        ownerColumn,
        policies: ctx.policiesByTable.get(table) ?? [],
      },
      ctx.host
    );

    // No arena is not an error. The static reasoner already reported this table;
    // we simply could not upgrade inference to proof.
    if (!arena) {
      console.log(`[proving] skipped ${table}: ${reason}`);
      continue;
    }

    try {
      const finding = await proveTable(arena, table, ownerColumn, ctx);
      if (finding) findings.push(finding);
      probed++;
    } catch (err) {
      console.error(`[proving] ${table} failed:`, err instanceof Error ? err.message : err);
    } finally {
      await arena.teardown();
    }
  }

  await persistProvenFindings(ctx.userId, findings, probed);
  return { ran: probed > 0, findings, probed };
}

/**
 * One table, inside an open arena.
 *
 * The control probe gates everything: if tenant A cannot see its OWN row, the
 * arena is broken and every "no leak" result below would be meaningless. That is
 * the difference between proving something and proving nothing while reporting
 * success.
 */
async function proveTable(
  arena: Arena,
  table: string,
  ownerColumn: string,
  ctx: ProvingContext
): Promise<ProvenFinding | null> {
  // Branch arenas carry the real table; replicas were seeded at setup.
  if (arena.kind === "branch") {
    await arena.run(buildSeedSql(table, ownerColumn).sql);
  }

  const control = num(await arena.run(buildControlProbeSql(arena.schema, table, ownerColumn)), "visible");
  if (control !== 1) {
    console.log(`[proving] ${table}: control returned ${control}, not trusting this run`);
    return null;
  }

  const outcome: ProbeOutcome = {
    table,
    ownerColumn,
    leakedRows: num(await arena.run(buildLeakProbeSql(arena.schema, table, ownerColumn)), "leaked"),
    executed: true,
  };

  const direct = interpretProbe(outcome);
  if (direct) {
    return { ...direct, consequence: await withFixEvidence(direct.consequence, arena, table, ownerColumn) };
  }

  // The fixed probe found nothing. Only now is a model call worth making: the
  // agent looks for shapes the single equality test cannot express.
  const { finding } = await runAdversarialAgent(
    {
      schema: arena.schema,
      table,
      columns: ctx.schema.get(table) ?? [ownerColumn],
      policies: (ctx.policiesByTable.get(table) ?? []).map((p) => ({
        name: p.policyname,
        cmd: p.cmd,
        using: p.qual,
      })),
    },
    (sql) => arena.run(sql),
    ctx.propose ?? claudeProposer()
  );

  return finding ? { id: finding.id, severity: finding.severity, title: finding.title, consequence: finding.consequence, proven: true } : null;
}

/**
 * Demonstrates that the fix works before offering it.
 *
 * Appended to the finding rather than reported separately, because "here is the
 * problem" and "here is the fix, tested" are one thought. A fix that fails
 * validation is simply not mentioned — offering an unvalidated change is what
 * this whole apparatus exists to avoid.
 */
async function withFixEvidence(
  consequence: string,
  arena: Arena,
  table: string,
  ownerColumn: string
): Promise<string> {
  try {
    const before = await readGates(arena, table, ownerColumn);
    const candidate = buildOwnershipFix(ownerColumn);
    await arena.run(buildFixApplySql(arena.schema, table, 8, candidate));
    const after = await readGates(arena, table, ownerColumn);

    const verdict = judgeFix(before, after, candidate);
    return verdict.validated ? `${consequence}\n\n${verdict.summary}` : consequence;
  } catch {
    // Validation is an enhancement to the finding, never a precondition for it.
    return consequence;
  }
}

async function readGates(arena: Arena, table: string, ownerColumn: string): Promise<GateReading> {
  const rows = await arena.run(buildGateSql(arena.schema, table, ownerColumn));
  return { leaked: num(rows, "leaked"), own: num(rows, "own") };
}

/**
 * Persists proven findings.
 *
 * Archives only when something was actually probed. A run that proved nothing
 * because no arena opened must not close a previously PROVEN finding — that
 * would replace evidence with an absence of evidence.
 */
export async function persistProvenFindings(
  userId: string,
  findings: ProvenFinding[],
  probed: number
): Promise<{ newCount: number; resolvedCount: number }> {
  const admin = getSupabaseAdmin();

  const { data: existing } = await admin
    .from("deep_findings")
    .select("finding_id")
    .eq("user_id", userId)
    .eq("source", "proven")
    .is("archived_at", null);

  const active = new Set((existing ?? []).map((r) => r.finding_id as string));
  const current = new Set(findings.map((f) => f.id));

  let resolvedCount = 0;
  if (probed > 0) {
    const resolved = [...active].filter((id) => !current.has(id));
    if (resolved.length > 0) {
      await admin
        .from("deep_findings")
        .update({ archived_at: new Date().toISOString() })
        .eq("user_id", userId)
        .eq("source", "proven")
        .is("archived_at", null)
        .in("finding_id", resolved);
      resolvedCount = resolved.length;
    }
  }

  const fresh = findings.filter((f) => !active.has(f.id));
  if (fresh.length > 0) {
    await admin.from("deep_findings").insert(
      fresh.map((f) => ({
        user_id: userId,
        source: "proven",
        finding_id: f.id,
        severity: f.severity,
        title: f.title,
        consequence: f.consequence,
      }))
    );
  }

  return { newCount: fresh.length, resolvedCount };
}
