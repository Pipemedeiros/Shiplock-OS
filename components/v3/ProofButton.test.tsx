import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: () => {} }) }));
import { ProofPanel } from "./ProofButton";

// Q7: the four recorded outcomes, pending, and the offer, as a founder reads them.
const render = (view: Parameters<typeof ProofPanel>[0]["view"]) =>
  renderToStaticMarkup(<ProofPanel repositoryId="r1" findingId="f1" table="public.orders" view={view} />);

describe("ProofPanel (Q7 / 6A-3)", () => {
  it("offers the test with one sentence on what runs, and that the customer's database is never touched", () => {
    const html = render(null);
    expect(html).toContain("Test on a disposable copy");
    expect(html).toMatch(/synthetic/);
    expect(html).toMatch(/never touches your database/);
    expect(html).not.toMatch(/disabled/);
  });
  it.each([
    [{ state: "done", outcome: "could_not_test", reason: "no_owner_column" }, /Could not test: we could not tell which column names the owner of a row/],
    [{ state: "done", outcome: "ran", reason: null }, /Test ran, not reproduced/],
    [{ state: "done", outcome: "reproduced", reason: null }, /Reproduced on a disposable copy/],
    [{ state: "done", outcome: "aborted", reason: "statement_budget" }, /Stopped: it reached its query budget/],
  ] as const)("states the %j outcome plainly", (view, text) => {
    const html = render(view);
    expect(html).toMatch(text);
    expect(html).not.toMatch(/\bsecure\b|\bfixed\b|[–—]/i);
  });
  it("says ran is one probe on a copy, not a clean bill of health", () => {
    expect(render({ state: "done", outcome: "ran", reason: null })).toMatch(/does not show the table is protected/);
  });
  it("disables the button while a test is pending", () => {
    const html = render({ state: "pending" });
    expect(html).toMatch(/Testing on a disposable copy/);
    expect(html).toMatch(/<button[^>]*disabled/);
  });
  it("says a test that could not finish, and offers it again", () => {
    const html = render({ state: "failed" });
    expect(html).toMatch(/Stopped: the test could not finish/);
    expect(html).toContain("Test again");
  });
  it("names every reason the worker can record in plain words", async () => {
    const { REASON_TEXT } = await import("./ProofButton");
    for (const reason of ["kill_switch", "not_enabled", "repository_unselected", "finding_mismatch", "unsupported_schema", "database_unread",
      "columns_unread", "no_owner_column", "no_policies", "not_replicable", "control_failed", "replica_unavailable", "replica_error",
      "statement_budget", "time_limit", "resource_limit"]) {
      expect(REASON_TEXT[reason], reason).toBeTruthy();
      expect(REASON_TEXT[reason]).not.toMatch(/[–—_]/);
    }
  });
});
