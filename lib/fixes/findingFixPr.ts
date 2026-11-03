import { getSupabaseAdmin } from "@/lib/supabase";
import { getFixFindings } from "./findings";
import { runFixPr } from "./prRun";
import { openedOutcome, type RepairOutcome } from "./repairOutcome";

/** runFixPr's refusals that no retry can change. Anything else may be a
 * transient GitHub failure and is rethrown for an uncertain, retried receipt. */
const PERMANENT: [RegExp, Exclude<RepairOutcome, { status: "opened" }>["code"]][] = [
  [/isn't applied through this route/i, "not_fixable"],
  [/not connected|no accessible|choose the repository|not selected|no longer accessible/i, "repository_unavailable"],
];

/** Opens the fix PR for one fix-card finding inside a repair job,
 * honoring the customer's reviewed edit. The finding is re-resolved server-side. */
export async function openFindingFixPr(
  userId: string, findingId: string, editedContent: string | null, repositoryId: string,
): Promise<RepairOutcome> {
  const finding = (await getFixFindings(userId)).find((item) => item.id === findingId);
  if (!finding) return { status: "failed", code: "finding_unavailable" };
  const { data: repository } = await getSupabaseAdmin().from("repositories").select("id")
    .eq("id", repositoryId).eq("user_id", userId).eq("selected", true).maybeSingle();
  if (!repository) return { status: "failed", code: "repository_unavailable" };
  try {
    const { url } = await runFixPr(userId, finding, editedContent ?? "");
    return openedOutcome(url);
  } catch (err) {
    const message = err instanceof Error ? err.message : "";
    const known = PERMANENT.find(([pattern]) => pattern.test(message));
    if (known) return { status: "failed", code: known[1] };
    throw err;
  }
}
