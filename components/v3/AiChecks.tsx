import Link from "next/link";
import type { AiActivity, AiCheck, AiCheckState } from "@/lib/intelligence/activity";
import { AiFixButton } from "./AiFixButton";

// The customer's own AI checks (10B-2d). Unanswered work says "not checked" in
// plain words; nothing here may read as clean.
export const aiStateLabel: Record<AiCheckState, string> = {
  pending: "Waiting for your AI. Not checked yet.",
  expired: "Your AI did not answer in time. Not checked.",
  withdrawn: "Withdrawn when your AI settings changed. Not checked.",
  unavailable: "Your AI could not finish. Not checked.",
  needs_human: "Your AI flagged something that needs your judgment.",
  proposal: "Your AI proposed a change. Review it before any pull request.",
};

const pauseText = {
  not_connected: "No AI is connected, so no AI checks are being created. Checks that need no AI still run.",
  revoked: "You revoked your AI approval, so no new AI checks are being created.",
  budget: "Your AI reported reaching your monthly token limit, so new AI checks are paused until next month.",
} as const;

function scope(check: AiCheck): string {
  if (check.kind === "deep") return `Weekly deep scan · ${check.repository}`;
  if (check.pullRequest) return `#${check.pullRequest} · ${check.repository}`;
  return check.repository;
}

export function AiChecks({ activity }: { activity: AiActivity }) {
  if (!activity.available) {
    return <p className="v3-small">We could not load your AI checks. Treat their state as unknown.</p>;
  }
  return (
    <div>
      {activity.paused ? (
        <p className="v3-small" style={{ marginBottom: 12 }}>
          {pauseText[activity.paused]} <Link href="/dashboard/settings">Manage in Settings</Link>
        </p>
      ) : null}
      {activity.checks.length === 0 ? (
        <p className="v3-small">No AI checks in the last 30 days.</p>
      ) : (
        <div className="v3-list">
          {activity.checks.map((check) => (
            <div key={check.taskId} className="v3-row-pad">
              <div className="v3-between">
                <span style={{ fontSize: 13 }}>{scope(check)} <span className="v3-small">at {check.commit.slice(0, 7)}</span></span>
                <span className="v3-small">{aiStateLabel[check.state]}</span>
              </div>
              {check.answer ? (
                <div className="v3-small" style={{ marginTop: 6 }}>
                  {/* Model text, rendered as plain text: a claim ShipLock checked against GitHub, not a verdict. */}
                  <p>Your AI says: {check.answer.summary}</p>
                  {check.answer.citations.length > 0 ? (
                    <p>Cited: {check.answer.citations.map((c) => `${c.path}:${c.startLine}${c.endLine !== c.startLine ? `-${c.endLine}` : ""}`).join(", ")}</p>
                  ) : null}
                  {check.answer.editedFiles.length > 0 ? (
                    <p>Proposed change to {check.answer.editedFiles.join(", ")}. Nothing is applied until you open a pull request and merge it.</p>
                  ) : null}
                  {check.state === "proposal" && check.answer.editedFiles.length > 0 ? <AiFixButton taskId={check.taskId} /> : null}
                </div>
              ) : null}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
