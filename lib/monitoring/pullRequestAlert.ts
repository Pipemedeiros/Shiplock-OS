import { sendEmail } from "@/lib/email";
import { EMAIL_ALERTS_ENABLED } from "@/lib/access";

export interface PullRequestAlert {
  repository: string;
  number: number;
  title: string | null;
  findings: { severity: "CRITICAL" | "WARNING"; title: string; file: string }[];
}

/**
 * The paid alert for a pull request whose check found a concrete risk.
 * It states what was found and where, never intent, and sends the customer to
 * the dashboard to read the evidence and ask for a fix before merge. One email
 * per PR head (the job is unique per stored review); at-least-once delivery.
 */
export async function sendPullRequestAlert(email: string, alert: PullRequestAlert): Promise<"sent" | "skipped" | "failed"> {
  if (!EMAIL_ALERTS_ENABLED) return "skipped";
  const dashboard = `${(process.env.NEXT_PUBLIC_APP_URL ?? "").replace(/\/+$/, "")}/dashboard/prs`;
  const lines = alert.findings.map((finding) => `- [${finding.severity}] ${finding.title}\n  In ${finding.file}`).join("\n\n");
  const sent = await sendEmail({
    to: email,
    subject: `ShipLock: pull request #${alert.number} on ${alert.repository} introduces a security risk`,
    text: [
      `ShipLock checked pull request #${alert.number}${alert.title ? ` (${alert.title})` : ""} on ${alert.repository} and found:`,
      "",
      lines,
      "",
      `Read the evidence and ask for a fix before you merge: ${dashboard}`,
      "",
      "ShipLock opens a fix only after you click, and never merges or deploys.",
    ].join("\n"),
  }, "pull-request");
  return sent ? "sent" : "failed";
}
