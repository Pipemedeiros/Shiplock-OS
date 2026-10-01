import Link from "next/link";
import { requireDashboardSession } from "@/lib/dashboard";
import { getOpenFindings } from "@/lib/agent/dashboardData";
import { getRecentPullRequestReviews, type PullRequestReviewView } from "@/lib/agent/pullRequestReviews";
import { Sev } from "@/components/v3/FindingParts";
import { PullRequestFixButton } from "@/components/v3/PullRequestFixButton";
import { aiCheckForPullRequest, getAiActivity, type AiActivity } from "@/lib/intelligence/activity";
import { aiStateLabel } from "@/components/v3/AiChecks";
import { OpenedPullRequests } from "@/components/v3/OpenedPullRequests";
import { getOpenedPullRequests } from "@/lib/fixes/openedPullRequests";
import { getCiStatuses } from "@/lib/fixes/prCiStatus";

/**
 * The pull requests ShipLock opened, waiting on a human.
 *
 * This is the page the product is for. Everything else — the audit, the graph,
 * the evidence ledger — exists so that this list is short, correct, and worth
 * the thirty seconds it takes to read one. A finding that never becomes a
 * reviewable change is a piece of homework we handed back.
 *
 * Two things are said plainly here rather than implied, because both are what
 * makes an autonomous tool safe to leave running:
 *   - Nothing is ever merged by us. The branch sits there until they merge it.
 *   - The authorization logic inside is not machine-authored. The pull request
 *     carries the finding, the evidence and a precise instruction; the decision
 *     about which column identifies a tenant stays with the person who knows.
 */
export const metadata = { title: "Pull requests" };

export default async function PullRequests() {
  const { userId } = await requireDashboardSession();
  const [findings, reviews, ai, opened] = await Promise.all([getOpenFindings(userId), getRecentPullRequestReviews(userId),
    getAiActivity(userId), getOpenedPullRequests(userId)]);
  const ci = await getCiStatuses(userId, opened.items);

  const eligible = findings.filter((f) => !f.fixPrUrl && f.fixKind === "pr");
  const manual = findings.filter((f) => !f.fixPrUrl && f.fixKind !== "pr");

  return (
    <>
      <div className="v3-page-hd">
        <div>
          <h1>Pull requests</h1>
          <p className="v3-sub" style={{ marginTop: 8, maxWidth: 620 }}>
            Every pull request you open is checked, and each fix we open is a branch of its own. We
            never merge, and we never push to your default branch. Approving is yours.
          </p>
        </div>
      </div>

      <div className="v3-stack">
        <CheckedPullRequests reviews={reviews} ai={ai} />

        {/* Every lane's clicked pull request, open or merged (Q1 / 8-R2). */}
        <OpenedPullRequests opened={opened} ci={ci} />

        {eligible.length > 0 ? (
          <div className="v3-card">
            <div className="v3-hd">
              <h2 className="v3-eyebrow">In progress</h2>
              <span className="v3-small">{eligible.length}</span>
            </div>
            <div className="v3-card-p">
              <p className="v3-small" style={{ marginBottom: 12 }}>
                These have a mechanical fix and no pull request yet. Open one from Risks when you
                are ready; nothing is opened without your click.
              </p>
              <div className="v3-list">
                {eligible.map((f) => (
                  <div key={f.rowId} className="v3-between v3-row-pad">
                    <span style={{ fontSize: 14 }}>{f.title}</span>
                    <Sev severity={f.severity} />
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : null}

        {manual.length > 0 ? (
          <div className="v3-card">
            <div className="v3-hd">
              <h2 className="v3-eyebrow">Manual fixes</h2>
              <span className="v3-small">{manual.length}</span>
            </div>
            <div className="v3-card-p">
              <p className="v3-small" style={{ marginBottom: 12 }}>
                These are decisions about your architecture rather than mechanical changes. Writing
                the patch for you would be guessing at what you meant.
              </p>
              <div className="v3-list">
                {manual.map((f) => (
                  <div key={f.rowId} className="v3-between v3-row-pad">
                    <span style={{ fontSize: 14 }}>{f.title}</span>
                    <Sev severity={f.severity} />
                  </div>
                ))}
              </div>
              <Link href="/dashboard/risks" className="v3-btn v3-btn-sm v3-ghost" style={{ marginTop: 12 }}>
                Read the reasoning
              </Link>
            </div>
          </div>
        ) : null}
      </div>
    </>
  );
}

const verdictLabel: Record<PullRequestReviewView["verdict"], string> = {
  block: "Risk found, check failed",
  warn: "Worth a look",
  pass: "Nothing found",
};

/** Your own pull requests as ShipLock checked them (8B-2): what each one
 * introduced, where, and how much of it we could read. */
function aiLine(ai: AiActivity, review: PullRequestReviewView): string {
  if (!ai.available) return "state unknown.";
  const check = aiCheckForPullRequest(ai.checks, review.repository, review.number, review.headSha);
  return check ? aiStateLabel[check.state] : "none requested for this commit. Not checked by AI.";
}

function CheckedPullRequests({ reviews, ai }: { reviews: PullRequestReviewView[]; ai: AiActivity }) {
  return (
    <div className="v3-card">
      <div className="v3-hd">
        <h2 className="v3-eyebrow">Pull request checks</h2>
        <span className="v3-small">{reviews.length} recent</span>
      </div>
      <div className="v3-card-p">
        {reviews.length === 0 ? (
          <p className="v3-small">
            No pull request has been checked yet. Each new pull request on a selected repository is
            checked automatically, and the result shows up here and on GitHub.
          </p>
        ) : (
          <div className="v3-list">
            {reviews.map((review) => (
              <div key={review.id} className="v3-row-pad">
                <div className="v3-between">
                  <b style={{ fontWeight: 500, fontSize: 14 }}>
                    {review.title ?? `Pull request #${review.number}`}
                  </b>
                  <span className="v3-small">{verdictLabel[review.verdict]}</span>
                </div>
                <p className="v3-small" style={{ marginTop: 3 }}>
                  #{review.number} · {review.repository}
                  {review.headRef ? ` · ${review.headRef}` : ""}
                  {review.coverageComplete ? "" : " · partial check, some files were not read"}
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
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
