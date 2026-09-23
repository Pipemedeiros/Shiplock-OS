import { getSupabaseAdmin } from "@/lib/supabase";
import { probeExposedPaths, type ExposedFinding } from "./exposedPaths";
import { auditShippedBundle } from "./bundleAudit";
import { auditEmailAuth, nodeTxtResolver, domainFromUrl, isSharedHost } from "./emailAuth";
import { analyzeOriginPosture, collectOriginPosture, fetchOriginHeaders, nodeDnsResolver } from "./originExposure";

// Everything we can learn from the customer's app URL alone, in one pass:
//  - exposed-path probes (.git, database dumps, credential files)
//  - the shipped bundle audit (D6 source maps, D7 secrets in public JS)
//  - email authentication on their domain (D12 SPF/DKIM/DMARC)
//  - origin exposure: whether their edge protection can be bypassed
// Both take the same single input and hit the same host, so they share a pass
// and a source label. Findings persist into deep_findings (source='exposed-path')
// and flow into the dashboard fix list, the agent brief, MCP, and the Verified
// report counts with no extra wiring.
//
// ARCHIVING: this pass archives findings that no longer reproduce, which it did
// not used to do. That omission mattered most for exactly these checks. A D7
// finding's entire instruction is "rotate this key" — if the finding survived
// the rotation, we'd keep showing CRITICAL after the customer did the one thing
// we asked, and the weekly digest would keep counting it. A check that can't say
// "fixed" is worse than no check: it teaches people that our findings don't
// track reality.
export async function runExposedPathScan(
  userId: string,
  appUrl: string,
  { signal }: { signal?: AbortSignal } = {},
): Promise<{ total: number; newCount: number; resolvedCount: number; newFindings: ExposedFinding[] }> {
  // Independent: a failure in one must not cost us the other's findings. Each
  // records the finding-ID prefixes it could not verify in `unread`; a probe
  // that throws outright leaves its whole family unread.
  const unread: string[] = [];
  const failed = (prefix: string) => () => { unread.push(prefix); return []; };
  const [paths, bundle, email, origin] = await Promise.all([
    probeExposedPaths(appUrl, signal, unread).catch(failed("exposed:")),
    auditShippedBundle(appUrl, signal, unread).catch(failed("bundle:")),
    auditEmailAuth(appUrl, nodeTxtResolver, unread).catch(failed("email_auth:")),
    // Origin exposure. Skipped on shared platform hostnames for the same reason
    // as email auth: the customer does not control that DNS, so a finding there
    // is something they cannot act on.
    (async () => {
      const domain = domainFromUrl(appUrl);
      if (!domain || isSharedHost(domain)) return [];
      const headers = await fetchOriginHeaders(appUrl, signal);
      if (!headers) unread.push("origin:");
      const posture = await collectOriginPosture(domain, nodeDnsResolver, headers, unread);
      return posture ? analyzeOriginPosture(posture) : [];
    })().catch(failed("origin:")),
  ]);
  // Probes resolve to [] on network failure, and an empty pass archives every
  // active finding below. A cancelled pass must therefore write nothing at all.
  signal?.throwIfAborted();
  const findings = [...paths, ...bundle, ...email, ...origin];

  const admin = getSupabaseAdmin();
  const nowIso = new Date().toISOString();

  const { data: existing } = await admin
    .from("deep_findings")
    .select("finding_id")
    .eq("user_id", userId)
    .eq("source", "exposed-path")
    .is("archived_at", null);
  const active = new Set((existing ?? []).map((r) => r.finding_id as string));
  const current = new Set(findings.map((f) => f.id));

  // Resolved: was open, was actually re-checked, and doesn't reproduce now.
  // An unread check is not a fixed one.
  const resolved = [...active].filter((id) => !current.has(id) && !unread.some((p) => id.startsWith(p)));
  if (resolved.length > 0) {
    await admin
      .from("deep_findings")
      .update({ archived_at: nowIso })
      .eq("user_id", userId)
      .eq("source", "exposed-path")
      .is("archived_at", null)
      .in("finding_id", resolved);
  }

  const fresh = findings.filter((f) => !active.has(f.id));
  if (fresh.length > 0) {
    await admin.from("deep_findings").insert(
      fresh.map((f) => ({
        user_id: userId,
        source: "exposed-path",
        finding_id: f.id,
        severity: f.severity,
        title: f.title,
        consequence: f.consequence,
      }))
    );
  }

  // fresh is returned so the caller can alert on it. A newly-shipped
  // service-role key is the most alert-worthy event this product can detect;
  // leaving it to the weekly digest would mean up to seven days of exposure
  // after we already knew.
  return { total: findings.length, newCount: fresh.length, resolvedCount: resolved.length, newFindings: fresh };
}
