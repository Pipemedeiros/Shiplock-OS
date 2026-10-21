import { Sev } from "@/components/v3/FindingParts";
import { PullRequestFixButton } from "@/components/v3/PullRequestFixButton";
import { aiStateLabel } from "@/components/v3/AiChecks";
import { aiCheckForPullRequest, type AiActivity } from "@/lib/intelligence/activity";
import type { PullRequestReviewView } from "@/lib/agent/pullRequestReviews";

const verdictLabel: Record<PullRequestReviewView["verdict"], { text: string; tone: string }> = {
  block: { text: "Blocked", tone: "crit" },
  warn: { text: "Warning", tone: "warn" },
  pass: { text: "Passed", tone: "ok" },
};

/** Your own pull requests as ShipLock checked them (8B-2): what each one
 * introduced, where, and how much of it we could read. */
function aiLine(ai: AiActivity, review: PullRequestReviewView): string {
  if (!ai.available) return "state unknown.";
  const check = aiCheckForPullRequest(ai.checks, review.repository, review.number, review.headSha);
  return check ? aiStateLabel[check.state] : "none requested for this commit. Not checked by AI.";
}

export function CheckedPullRequests({ reviews, ai }: { reviews: PullRequestReviewView[]; ai: AiActivity }) {
  return (
    <div className="v3-card">
      <div className="v3-hd">
        <h2 className="v3-eyebrow">Pull request checks</h2>
        <span className="v3-small">{reviews.length} recent</span>
      </div>
      <div className="v3-card-p">
        {reviews.length === 0 ? (
          <p className="v3-small">No pull requests checked yet. New pull requests on selected repositories are checked automatically.</p>
        ) : (
          <div className="v3-list">
            {reviews.map((review) => (
              <details key={review.id} className="v3-prrow">
                <summary>
                  {/* A partial check is never shown as passed. */}
                  {review.verdict === "pass" && !review.coverageComplete ? <span className="v3-tag warn">Partial</span> : (
                    <>
                      <span className={`v3-tag ${verdictLabel[review.verdict].tone}`}>{verdictLabel[review.verdict].text}</span>
                      {review.coverageComplete ? null : <span className="v3-tag warn">Partial</span>}
                    </>
                  )}
                  <b>{review.title ?? `Pull request #${review.number}`}</b>
                  <span className="v3-small">#{review.number} · {review.findings.length} {review.findings.length === 1 ? "issue" : "issues"}</span>
                </summary>
                <div className="v3-prrow-body">
                <p className="v3-small">
                  {review.repository}{review.headRef ? ` · ${review.headRef}` : ""}
                  {review.coverageComplete ? "" : " · some files were not read"}
                </p>
                <p className="v3-small" style={{ marginTop: 3 }}>
                  AI check: {aiLine(ai, review)}
                </p>
                {review.findings.map((finding) => (
                  <div key={finding.id} style={{ marginTop: 8 }}>
                    <div className="v3-between">
                      <span style={{ fontSize: 13 }}>{finding.title}</span>
                      <Sev severity={finding.severity} />
                    </div>
                    <p className="v3-small" style={{ marginTop: 2 }}>{finding.file}. {finding.evidence}</p>
                    {review.sameRepository && review.headRef ? (
                      <PullRequestFixButton reviewId={review.id} findingId={finding.id} />
                    ) : review.sameRepository === false ? (
                      <p className="v3-small" style={{ marginTop: 2 }}>From a fork, so the fix is yours to push.</p>
                    ) : null}
                  </div>
                ))}
                {review.url ? (
                  <a href={review.url} target="_blank" rel="noreferrer" className="v3-btn v3-btn-sm v3-ghost" style={{ marginTop: 10 }}>
                    Open on GitHub
                  </a>
                ) : null}
                </div>
              </details>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
