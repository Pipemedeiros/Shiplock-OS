/** Browser-side view of one fix click (3F-C2d). The server opens the PR in a
 * repair job; the dashboard follows the receipt to its real outcome. */
export interface RepairView {
  status: "queued" | "opened" | "failed" | "uncertain";
  url: string | null;
  failure: string | null;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export async function waitForRepair(
  receiptId: string, { attempts = 30, intervalMs = 2_000 }: { attempts?: number; intervalMs?: number } = {},
): Promise<RepairView> {
  let last: RepairView = { status: "queued", url: null, failure: null };
  for (let attempt = 0; attempt < attempts; attempt++) {
    const res = await fetch(`/api/fix/receipts/${encodeURIComponent(receiptId)}`, { cache: "no-store" });
    if (res.ok) {
      last = await res.json() as RepairView;
      if (last.status === "opened" || last.status === "failed") return last;
    }
    await sleep(intervalMs);
  }
  return last;
}

/** Plain copy for every outcome except a successful PR, which renders a link. */
export function repairMessage(view: RepairView): string {
  if (view.status === "failed") {
    switch (view.failure) {
      case "not_fixable": return "This fix needs a decision from you, so there is no pull request to open.";
      case "repository_unavailable": return "ShipLock can no longer reach that repository. Reselect it and try again.";
      case "finding_unavailable": return "This finding is no longer open, so there is nothing to fix.";
      case "fork_pull_request": return "This pull request comes from a fork, so ShipLock cannot push a fix to its branch. The change to make is listed above.";
      case "pull_request_closed": return "That pull request branch is gone, merged or deleted, so there is nothing to fix before merge.";
      case "no_changes": return "No vulnerable dependency here has a patched version yet, so there is nothing to bump.";
      default: return "GitHub refused the pull request. Try again.";
    }
  }
  return "Still working on it. The pull request will show up here once GitHub confirms it.";
}
