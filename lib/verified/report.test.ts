import { describe, expect, it } from "vitest";
import { buildVerifiedReport, verifiedLive, type VerifiedReportData } from "./report";

/**
 * The Verified report is the one surface a stranger reads. A technical
 * reviewer at the customer's enterprise prospect is exactly the person who
 * will check it against reality, so every assertion here is an honesty
 * invariant rather than a formatting preference.
 *
 * The report it replaced computed "passing 16 of 16 checks" as sixteen minus a
 * scan count that is zero for an audit account, so a project that had never
 * run the check it was reporting on rendered a perfect score. That is the
 * failure this file exists to make impossible.
 */

const data = (over: Partial<VerifiedReportData> = {}): VerifiedReportData => ({
  enabled: true,
  run: {
    fullName: "acme/app",
    commitSha: "0f2a91c4c0d8b7a6e5f4321098765432abcdef01",
    finishedAt: "2026-09-01T10:00:00.000Z",
    trigger: "pull_request",
    filesRead: 1562,
    entriesFound: 285,
    tablesFound: 96,
    unassessed: {
      dataTouching: 248,
      unassessed: 40,
      dataUnreadable: 2,
      reasons: { identity: 18, scope: 20, signature: 2 },
      sample: ["/api/views", "/api/webhooks/services/[...path]"],
    },
  },
  openCritical: 0,
  openTotal: 0,
  hasDatabase: false,
  nowMs: Date.parse("2026-09-03T10:00:00.000Z"),
  ...over,
});

describe("a report with no completed audit states that, and nothing else", () => {
  it("never renders a score for a project that was never assessed", () => {
    const r = buildVerifiedReport(data({ run: null }));
    expect(r.status).toBe("never_assessed");
    expect(r.assessment).toBeNull();
    expect(r.headline).toMatch(/no completed assessment/i);
    // The specific failure of the report this replaces.
    expect(JSON.stringify(r)).not.toMatch(/16 of 16|passing/i);
  });
});

describe("the disclosure leads and is never rounded away", () => {
  it("puts the assessed fraction in the headline itself, not below it", () => {
    const r = buildVerifiedReport(data());
    expect(r.headline).toBe("No critical findings on the 208 of 248 endpoints that could be assessed");
    expect(r.assessment).toEqual({
      dataTouching: 248,
      assessed: 208,
      unassessed: 40,
      unassessedShare: 16,
      reasons: { identity: 18, scope: 20, signature: 2 },
      dataUnreadable: 2,
      known: true,
    });
  });

  it("states a large unjudged share plainly rather than softening it (corpus-c)", () => {
    const r = buildVerifiedReport(
      data({ run: { ...data().run!, unassessed: { dataTouching: 84, unassessed: 66, dataUnreadable: 0, reasons: { identity: 31, scope: 0, signature: 35 }, sample: [] } } }),
    );
    const a = r.assessment!;
    if (!a.known) throw new Error("expected a measured assessment");
    expect(a.unassessedShare).toBe(79);
    expect(r.headline).toBe("No critical findings on the 18 of 84 endpoints that could be assessed");
  });

  it("leads with unresolved criticals when there are any", () => {
    const r = buildVerifiedReport(data({ openCritical: 3, openTotal: 11 }));
    expect(r.headline).toBe("3 unresolved critical findings on the 208 of 248 endpoints that could be assessed");
  });

  // A run from before the disclosure existed has no measurement. Rendering
  // that as zero unassessed would be the original bug in a new place.
  it("distinguishes an absent measurement from a clean one", () => {
    const r = buildVerifiedReport(data({ run: { ...data().run!, unassessed: null } }));
    expect(r.assessment).toEqual({ known: false });
    expect(r.headline).toMatch(/how much of the surface/i);
    expect(r.headline).not.toMatch(/\b0 of\b|all endpoints/i);
  });
});

describe("what the report says it did not look at", () => {
  it("names database policies when no database is connected", () => {
    const r = buildVerifiedReport(data({ hasDatabase: false }));
    expect(r.notCovered.join(" ")).toMatch(/row-level|access rules in the database/i);
  });

  it("drops that line when a database is connected, and keeps the rest", () => {
    const r = buildVerifiedReport(data({ hasDatabase: true }));
    expect(r.notCovered.join(" ")).not.toMatch(/access rules in the database/i);
    expect(r.notCovered.join(" ")).toMatch(/running instance|runtime/i);
  });

  it("always says this is a read of source, never a penetration test", () => {
    expect(buildVerifiedReport(data()).notCovered.join(" ")).toMatch(/penetration test/i);
  });
});

describe("provenance of the assessment", () => {
  it("names the repository, the commit and the date", () => {
    const r = buildVerifiedReport(data());
    expect(r.repository).toBe("acme/app");
    expect(r.commit).toBe("0f2a91c");
    expect(r.assessedAt).toBe("2026-09-01T10:00:00.000Z");
    expect(r.ageDays).toBe(2);
    expect(r.stale).toBe(false);
  });

  it("marks an old assessment stale rather than quietly presenting it as current", () => {
    const r = buildVerifiedReport(data({ nowMs: Date.parse("2026-11-01T10:00:00.000Z") }));
    expect(r.stale).toBe(true);
    expect(r.ageDays).toBe(61);
  });

  it("carries no commit when the run did not record one", () => {
    expect(buildVerifiedReport(data({ run: { ...data().run!, commitSha: null } })).commit).toBeNull();
  });
});

describe("nothing that could overstate, and nothing an attacker can use", () => {
  const everything = JSON.stringify(buildVerifiedReport(data({ openCritical: 2, openTotal: 9 })));

  it("never claims the application is secure, certified or passing", () => {
    expect(everything).not.toMatch(/\bsecure\b|certified|compliant|guarantee|passing|unhackable|audited by/i);
  });

  it("leaks no finding title, endpoint or table", () => {
    // The sample endpoints are internal; the public report carries counts only.
    expect(everything).not.toMatch(/\/api\//);
  });

  it("does not depend on billing state", () => {
    expect(everything).not.toMatch(/is_paid|subscription|plan/i);
  });

  it("states the boundary of what the page asserts", () => {
    expect(buildVerifiedReport(data()).disclaimer).toMatch(/not a (security )?certification|no automated/i);
  });
});

// A1 (Felipe 2026-10-07): the public report counts confirmed issues only, the
// same rule as the dashboard status, so it never overstates a candidate.
describe("open counts on the public report", () => {
  it("counts confirmed issues only", async () => {
    const { confirmedCounts } = await import("./report");
    const row = (severity: string, claims: unknown[], attack_class = "missing_authorization") => ({ severity, confidence: "inferred", attack_class, claims });
    expect(confirmedCounts([
      row("CRITICAL", [{ claim: "x", origin: "routes", verified: true }]),
      row("CRITICAL", [{ claim: "Proof, data: a.ts:1 q", origin: "agent", verified: true }]),
      row("WARNING", [{ claim: "Proof, reach: b.ts:2 q", origin: "agent", verified: true }]),
      row("CRITICAL", [], "committed_secret"),
    ])).toEqual({ openCritical: 2, openTotal: 3 });
  });

  it("counts a live finding by the evidence it rests on, as the dashboard does", async () => {
    const { confirmedCounts } = await import("./report");
    const live = (source: string, finding_id: string, severity = "CRITICAL") => ({ source, finding_id, severity, confidence: null, attack_class: null, claims: null });
    expect(confirmedCounts([live("proven", "proof:rls:orders"), live("exposed-path", "exposed:git_exposed"),
      live("exposed-path", "email_auth:spf_missing", "WARNING"), live("github", "github:dep:x")])).toEqual({ openCritical: 2, openTotal: 2 });
  });
});

// The live site (outside view), on the public report: counts only, never the
// address or a path, and only when the founder bound it to this repository.
describe("what the live site showed, when its address is bound to this repository", () => {
  const live = { readAt: "2026-09-02T09:00:00.000Z", complete: true, pages: 8, scriptsRead: 14, scriptsSeen: 14, shippedSecrets: 0 };

  it("says a complete read found no secret keys in what the site ships, as a read, not a verdict", () => {
    const r = buildVerifiedReport(data({ live }));
    expect(r.live).toEqual(["Read completely on September 2, 2026: 8 pages and 14 scripts, as any visitor gets them.",
      "Secret keys in that JavaScript: none found."]);
    expect(JSON.stringify(r)).not.toMatch(/\bsecure\b|\bsafe\b/i);
  });

  it("says a partial read is partial, and counts shipped secrets without naming them", () => {
    const r = buildVerifiedReport(data({ live: { ...live, complete: false, scriptsRead: 24, scriptsSeen: 30, shippedSecrets: 1 } }));
    expect(r.live?.[0]).toMatch(/^Partly read on September 2, 2026: 8 pages and 24 of 30 scripts/);
    expect(r.live?.[1]).toBe("Secret keys in that JavaScript: 1 found, and the rest is unknown.");
  });

  it("is absent with no bound address, and moves the live site out of not covered only when read", () => {
    expect(buildVerifiedReport(data()).live).toBeNull();
    expect(buildVerifiedReport(data()).notCovered.join(" ")).toMatch(/live site/i);
    expect(buildVerifiedReport(data({ live })).notCovered.join(" ")).not.toMatch(/live site/i);
  });

  it("never carries the address or a path", () => {
    const everything = JSON.stringify(buildVerifiedReport(data({ live })));
    expect(everything).not.toMatch(/https?:\/\/|\/api\//);
  });
});

describe("verifiedLive joins the live read only under the report's own binding", () => {
  const base = { url: "https://app.acme.com", boundUrl: "https://app.acme.com", boundRepository: "Acme/App", reportRepository: "acme/app",
    surface: { url: "https://app.acme.com", complete: true, pagesRead: 3, scriptsRead: 9, scriptsSeen: 9 }, recordedAt: "2026-09-02T09:00:00.000Z",
    openFindingIds: ["bundle:shipped_secret:stripe_live_secret", "acme/app::github:x", "headers:hsts_missing"] };

  it("counts the read and the open shipped secrets", () => {
    expect(verifiedLive(base)).toEqual({ readAt: "2026-09-02T09:00:00.000Z", complete: true, pages: 3, scriptsRead: 9, scriptsSeen: 9, shippedSecrets: 1 });
  });

  it.each([
    ["the address changed after the binding", { boundUrl: "https://old.acme.com" }],
    ["it is bound to another repository", { boundRepository: "acme/other" }],
    ["nothing is bound", { boundRepository: null }],
    ["the read was of another address", { surface: { ...base.surface, url: "https://old.acme.com" } }],
    ["nothing was read", { surface: null }],
  ])("is null when %s", (_why, over) => {
    expect(verifiedLive({ ...base, ...over })).toBeNull();
  });
});
