import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
vi.mock("@/components/v3/PullRequestFixButton", () => ({ PullRequestFixButton: () => null }));
import { CheckedPullRequests } from "./CheckedPullRequests";
import type { PullRequestReviewView } from "@/lib/agent/pullRequestReviews";

const review = (over: Partial<PullRequestReviewView>): PullRequestReviewView => ({
  id: "r", repository: "o/r", number: 7, headSha: "a", title: "Add billing", url: null, headRef: "b", sameRepository: true,
  verdict: "pass", coverageComplete: true, checkedAt: "2026-10-01T00:00:00Z", findings: [], ...over,
});
const ai = { available: false } as const;

// AGENTS.md: partial input must not yield green.
describe("CheckedPullRequests", () => {
  it("shows a complete pass as passed", () => {
    expect(renderToStaticMarkup(<CheckedPullRequests reviews={[review({})]} ai={ai} />)).toContain(">Passed<");
  });

  it("never shows a partial check as passed", () => {
    const html = renderToStaticMarkup(<CheckedPullRequests reviews={[review({ coverageComplete: false })]} ai={ai} />);
    expect(html).not.toContain(">Passed<");
    expect(html).toContain(">Partial<");
  });

  it("shows a failed check as failed, and partial alongside", () => {
    const html = renderToStaticMarkup(<CheckedPullRequests reviews={[review({ verdict: "block", coverageComplete: false })]} ai={ai} />);
    expect(html).toContain(">Failed<");
    expect(html).toContain(">Partial<");
  });
});
