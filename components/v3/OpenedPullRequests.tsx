import { GitPullRequest, ArrowUpRight } from "lucide-react";
import type { OpenedPullRequest } from "@/lib/fixes/openedPullRequests";

const utc = (iso: string) => iso.slice(0, 16).replace("T", " ") + " UTC";

/** Every pull request ShipLock opened after a click, open or merged (Q1). */
export function OpenedPullRequests({ opened }: { opened: { available: boolean; items: OpenedPullRequest[] } }) {
  const waiting = opened.items.filter((i) => !i.mergedAt).length;
  return (
    <div className="v3-card">
      <div className="v3-hd">
        <h2 className="v3-eyebrow">Opened by ShipLock</h2>
        <span className="v3-small">{waiting} waiting for approval</span>
      </div>
      <div className="v3-card-p">
        {!opened.available ? (
          <p className="v3-small">We could not load the pull requests ShipLock opened. Their state is unknown.</p>
        ) : opened.items.length === 0 ? (
          <p className="v3-small">
            Nothing is waiting. When a finding has a mechanical fix, open its pull request from Risks.
            We open one only after you click.
          </p>
        ) : (
          <div className="v3-list">
            {opened.items.map((pr) => (
              <a key={pr.id} href={pr.url} target="_blank" rel="noreferrer" className="v3-pr-row">
                <GitPullRequest size={16} className="v3-pr-icon" />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="v3-between">
                    <b style={{ fontWeight: 500, fontSize: 14 }}>{pr.lane} #{pr.number}</b>
                    <span className="v3-small">{pr.mergedAt ? "Merged" : "Open"}</span>
                  </div>
                  <p className="v3-small" style={{ marginTop: 3 }}>
                    {pr.repository}. {pr.mergedAt
                      ? `Merged ${utc(pr.mergedAt)}. ShipLock is rechecking the default branch.`
                      : "Waiting for your review. ShipLock never merges."}
                  </p>
                </div>
                <ArrowUpRight size={15} className="v3-pr-go" />
              </a>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
