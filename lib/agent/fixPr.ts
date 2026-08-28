import type { DashboardFinding } from "./dashboardData";

/**
 * The body of a fix pull request.
 *
 * ShipLock does not machine-author authorization logic. The intent behind a
 * scoping rule lives in the customer's head -- which column identifies a tenant,
 * whether a shared record is deliberate -- and a confidently wrong patch to an
 * access check is worse than no patch at all.
 *
 * So the pull request carries the finding, the evidence, and a precise
 * instruction, on a branch of its own. A human or their coding agent finishes
 * it. That is the honest version of "we open the fix": the work is staged, the
 * reasoning travels with it, and the decision stays where it belongs.
 */

const INSTRUCTION: Record<string, string> = {
  missing_authorization:
    "Narrow the query so it can only return rows belonging to the caller. Add the tenant or owner column to the filter rather than checking it after the fetch, and return the same not-found response for a record that exists but is not theirs.",
  missing_authentication:
    "Establish who is calling before the handler touches data, and refuse the request when it cannot be established.",
  unsigned_webhook:
    "Verify the sender's signature against the raw request body before parsing it or acting on it. Reject anything that fails verification.",
  injection:
    "Pass the value as a bound parameter rather than building the statement from it.",
  unsafe_redirect:
    "Compare the destination against an allow-list before redirecting, and fall back to a known-safe path.",
  mass_assignment:
    "Accept only the fields this endpoint is meant to change, rather than spreading the request body into the update.",
  server_boundary_crossed:
    "Move the privileged access behind a server boundary so no client component can reach it.",
  secret_exposure:
    "Rotate the credential first -- it is in the history and removing the line does not un-leak it -- then move it out of the repository.",
};

export function fixBranchName(findingId: string): string {
  const slug = findingId.replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60).toLowerCase();
  return `shiplock/fix-${slug}`;
}

export function fixFilePath(findingId: string): string {
  return `.shiplock/${fixBranchName(findingId).replace("shiplock/", "")}.md`;
}

export function fixTitle(finding: DashboardFinding): string {
  return `Fix: ${finding.title}`;
}

/** The markdown committed to the branch and used as the pull-request body. */
export function fixDocument(finding: DashboardFinding): string {
  const claims = finding.claims.length
    ? finding.claims
        .map((c) => `- ${c.claim} _(${c.origin}${c.verified ? ", verified" : ", proposed"})_`)
        .join("\n")
    : "- No reasoning was recorded for this finding.";

  const instruction =
    INSTRUCTION[finding.attackClass] ??
    "Review the finding above and decide what the correct behaviour is here.";

  return [
    `# ${finding.title}`,
    "",
    finding.consequence,
    "",
    "## Where",
    "",
    `- Entry point: \`${finding.entry ?? "not recorded"}\``,
    `- File: \`${finding.file ?? "not recorded"}\``,
    finding.blastRadius ? `- Reaches: ${finding.blastRadius}` : "",
    "",
    "## Why we believe this",
    "",
    claims,
    "",
    `Confidence: **${finding.confidence}**.`,
    finding.confidence === "inferred"
      ? "Read from the code alone -- something outside the repository could compensate for it."
      : "Two or more independent readings of the code agree.",
    "",
    "## What to change",
    "",
    instruction,
    "",
    "---",
    "",
    "Opened by ShipLock on its own branch. Nothing was merged, and the default",
    "branch was not touched. Close this pull request to dismiss the finding.",
  ]
    .filter((line) => line !== "")
    .join("\n");
}
