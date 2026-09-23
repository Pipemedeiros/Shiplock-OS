import { getSupabaseAdmin } from "@/lib/supabase";

/** ShipLock funds ONE model-assisted audit per account (3G-1, migration 081).
 * The claim is durable, bound to this run's live audit lease, reused by a
 * retry of the same run, and refused for every later run and for a recreated
 * account on the same GitHub installation. Any doubt means no spend: an
 * unreadable claim skips reasoning and the run says so. */
export type FirstScanFunding = { funded: true } | { funded: false; reason: string };

export async function claimFirstScanCredit(
  userId: string, runId: string, jobLease: { jobId: string; token: string } | undefined,
): Promise<FirstScanFunding> {
  if (!jobLease) return { funded: false, reason: "this run is not a durable audit, so ShipLock did not fund AI reasoning" };
  const { data, error } = await getSupabaseAdmin().rpc("claim_first_scan_credit", {
    p_user: userId, p_run: runId, p_job: jobLease.jobId, p_token: jobLease.token,
  });
  if (error) return { funded: false, reason: "the free AI scan could not be confirmed, so reasoning did not run" };
  if (data !== true) {
    return { funded: false, reason: "this account's free AI scan was already used; model-assisted checks now run on your own AI" };
  }
  return { funded: true };
}
