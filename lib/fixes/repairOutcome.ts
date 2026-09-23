/** What a clicked repair produced. Permanent refusals are `failed`; an
 * ambiguous error is thrown so the worker records `uncertain` and retries. */
export type RepairOutcome =
  | { status: "opened"; url: string; number: number }
  | { status: "failed"; code: "finding_unavailable" | "repository_unavailable" | "not_fixable" | "no_changes"
      | "fork_pull_request" | "pull_request_closed" | "source_changed" };

export function openedOutcome(url: string): RepairOutcome {
  const number = Number(url.split("/").pop());
  if (!/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/pull\/\d+$/.test(url) || !Number.isSafeInteger(number)) {
    throw new Error("GitHub returned an unexpected pull request address");
  }
  return { status: "opened", url, number };
}
