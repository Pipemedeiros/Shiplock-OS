import { getSupabaseAdmin } from "@/lib/supabase";
import { analyzeAuthEvents, normaliseAuthEvent } from "./authEvents";

// Persists runtime findings from the auth audit log, with the same only-new +
// archive-on-resolve contract as every other collector.
//
// Archiving matters especially here, and differently: an attack that STOPPED is
// genuinely resolved, and leaving "someone is testing stolen passwords" on the
// board a week after it ended would train people to ignore exactly the finding
// that most deserves immediate attention.

export async function runAuthLogScan(
  userId: string,
  rows: Record<string, unknown>[]
): Promise<{ total: number; newCount: number; resolvedCount: number }> {
  const events = rows
    .map(normaliseAuthEvent)
    .filter((e): e is NonNullable<typeof e> => e !== null);

  // No parseable events means we could not look — NOT that nothing happened. We
  // must not archive live findings on the strength of an unreadable response.
  if (events.length === 0) return { total: 0, newCount: 0, resolvedCount: 0 };

  const findings = analyzeAuthEvents(events);
  const admin = getSupabaseAdmin();

  const { data: existing } = await admin
    .from("deep_findings")
    .select("finding_id")
    .eq("user_id", userId)
    .eq("source", "runtime")
    .is("archived_at", null);

  const active = new Set((existing ?? []).map((r) => r.finding_id as string));
  const current = new Set(findings.map((f) => f.id));

  const resolved = [...active].filter((id) => !current.has(id));
  if (resolved.length > 0) {
    await admin
      .from("deep_findings")
      .update({ archived_at: new Date().toISOString() })
      .eq("user_id", userId)
      .eq("source", "runtime")
      .is("archived_at", null)
      .in("finding_id", resolved);
  }

  const fresh = findings.filter((f) => !active.has(f.id));
  if (fresh.length > 0) {
    await admin.from("deep_findings").insert(
      fresh.map((f) => ({
        user_id: userId,
        source: "runtime",
        finding_id: f.id,
        severity: f.severity,
        title: f.title,
        consequence: `${f.consequence}\n\nEvidence: ${f.evidence.join("; ")}.`,
      }))
    );
  }

  return { total: findings.length, newCount: fresh.length, resolvedCount: resolved.length };
}
