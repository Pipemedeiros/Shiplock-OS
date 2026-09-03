import { describe, expect, it } from "vitest";
import { guardHypotheses, judgeHypothesis, type Hypothesis, type ReconIndex } from "./attackGuard";
import type { RouteFact } from "@/lib/graph/routeInventory";

/** A route we read completely: authenticated, unscoped, nothing unreadable. */
const readRoute = (over: Partial<RouteFact> = {}): RouteFact =>
  ({
    path: "/api/invoices/[id]", file: "app/api/invoices/[id]/route.ts",
    methods: ["GET"], tables: ["invoices"],
    authenticated: true, machineGated: false, ownershipFiltered: false,
    usesServiceRole: false, via: [],
    identityReadable: true, identityGap: null,
    ownershipReadable: true, ownershipGap: null,
    serviceRoleReadable: true, machineGateReadable: true, machineGateGap: null,
    ...over,
  }) as RouteFact;

const recon: ReconIndex = {
  entries: new Set(["/api/invoices/[id]"]),
  files: new Set(["app/api/invoices/[id]/route.ts", "lib/db.ts"]),
  tables: new Set(["invoices", "users"]),
  routes: new Map([["/api/invoices/[id]", readRoute()]]),
};

const reconWith = (over: Partial<RouteFact>): ReconIndex => ({
  ...recon,
  routes: new Map([["/api/invoices/[id]", readRoute(over)]]),
});

const valid: Hypothesis = {
  entry: "/api/invoices/[id]",
  attackClass: "missing_authorization",
  title: "Any signed-in user can read another workspace's invoices",
  consequence: "A valid account is enough to retrieve billing records belonging to other customers.",
  citedFiles: ["app/api/invoices/[id]/route.ts"],
  citedTables: ["invoices"],
};

describe("judgeHypothesis", () => {
  it("admits a hypothesis whose every concrete claim checks out", () => {
    expect(judgeHypothesis(valid, recon)).toEqual({
      allowed: true,
      attackClass: "missing_authorization",
      // Only citations we verified survive, so nothing downstream can turn an
      // unrecognised one into a claim.
      citedFacts: [],
    });
  });

  it("refuses a route the model invented", () => {
    // The failure this exists to stop: a finding pointing at code that is not
    // there. It reads exactly like a real one and destroys trust on contact.
    const verdict = judgeHypothesis({ ...valid, entry: "/api/admin/users" }, recon);
    expect(verdict).toEqual({ allowed: false, reason: 'entry "/api/admin/users" is not in the route inventory' });
  });

  it("refuses a file we never read", () => {
    const verdict = judgeHypothesis({ ...valid, citedFiles: ["app/api/secret/route.ts"] }, recon);
    expect(verdict.allowed).toBe(false);
  });

  it("refuses a table that is not in the schema we read", () => {
    // Models are good at guessing that a billing app has a payment_methods
    // table. Guessing correctly is still guessing.
    const verdict = judgeHypothesis({ ...valid, citedTables: ["payment_methods"] }, recon);
    expect(verdict).toEqual({ allowed: false, reason: 'cited table "payment_methods" is not in the schema we read' });
  });

  it("refuses a claim with no location at all", () => {
    expect(judgeHypothesis({ ...valid, citedFiles: [] }, recon)).toEqual({ allowed: false, reason: "no file or live fact cited" });
  });

  it("refuses a vulnerability class outside the taxonomy", () => {
    const verdict = judgeHypothesis({ ...valid, attackClass: "nuclear_launch" }, recon);
    expect(verdict.allowed).toBe(false);
  });

  it("refuses markup in prose, which would reach a pull-request body", () => {
    const verdict = judgeHypothesis({ ...valid, title: "Broken <img src=x onerror=alert(1)>" }, recon);
    expect(verdict).toEqual({ allowed: false, reason: "control characters or markup in prose" });
  });

  it("refuses unbounded prose", () => {
    expect(judgeHypothesis({ ...valid, consequence: "x".repeat(401) }, recon).allowed).toBe(false);
    expect(judgeHypothesis({ ...valid, title: "x".repeat(161) }, recon).allowed).toBe(false);
  });

  it("refuses a non-object", () => {
    expect(judgeHypothesis(null as unknown as Hypothesis, recon).allowed).toBe(false);
  });
});

describe("guardHypotheses", () => {
  it("separates admitted from rejected and keeps the reasons", () => {
    const result = guardHypotheses([valid, { ...valid, entry: "/api/nope" }], recon);
    expect(result.admitted).toHaveLength(1);
    expect(result.rejected).toHaveLength(1);
    expect(result.rejected[0].reason).toContain("not in the route inventory");
  });

  it("treats a non-array response as a total rejection, never as zero findings", () => {
    // A model that returns prose instead of JSON must not read as "your code is
    // clean". That is the silence-as-safety failure this repo has shipped.
    const result = guardHypotheses("I could not find anything", recon);
    expect(result.admitted).toEqual([]);
    expect(result.rejected[0].reason).toBe("model did not return an array");
  });
});

describe("live provider facts as a location", () => {
  // A fact read from a provider's API has no file to cite. Before this, the
  // guard refused every such hypothesis twice over: rule 3 demanded a file, and
  // rule 2 demanded a route. Widening rule 3 is what lets the reasoning layer
  // use the half of the system that is not in the repository, and it changes
  // nothing about the invariant: every citation is still checked against what
  // WE observed.
  const recon = {
    entries: new Set(["/api/invoices/[id]"]),
    files: new Set(["app/api/invoices/[id]/route.ts"]),
    tables: new Set(["invoices"]),
    facts: new Set(["vercel:env:STRIPE_SECRET_KEY"]),
    routes: new Map(),
  };

  const base = {
    entry: "/api/invoices/[id]",
    attackClass: "missing_authorization",
    title: "Unscoped invoice read",
    consequence: "Any signed-in user can read another workspace's invoices.",
  };

  it("admits a hypothesis whose only location is a fact we collected", () => {
    const verdict = judgeHypothesis(
      { ...base, citedFiles: [], citedFacts: ["vercel:env:STRIPE_SECRET_KEY"] },
      recon,
    );
    expect(verdict.allowed).toBe(true);
  });

  it("refuses a fact id we never observed, exactly as it refuses an invented file", () => {
    const verdict = judgeHypothesis(
      { ...base, citedFiles: [], citedFacts: ["clerk:signups_open"] },
      recon,
    );
    expect(verdict).toEqual({
      allowed: false,
      reason: 'cited fact "clerk:signups_open" was not observed in this run',
    });
  });

  it("refuses a fact citation when no facts were collected at all", () => {
    // recon.facts absent must mean "cite nothing", never "cite anything".
    const verdict = judgeHypothesis(
      { ...base, citedFiles: [], citedFacts: ["vercel:env:STRIPE_SECRET_KEY"] },
      { entries: recon.entries, files: recon.files, tables: recon.tables, routes: new Map() },
    );
    expect(verdict.allowed).toBe(false);
  });

  it("accepts a live fact as the entry, for a finding that has no route", () => {
    // A credential the host ships to the browser has no route to point at.
    // Before this, the agent could read the fact and then had nowhere to hang
    // the finding, so a correct observation was thrown away.
    const verdict = judgeHypothesis(
      {
        entry: "vercel:env:STRIPE_SECRET_KEY",
        attackClass: "secret_exposure",
        title: "Stripe secret key present in the browser build",
        consequence: "Anyone loading the site can read the key and call the Stripe API as you.",
        citedFiles: [],
        citedFacts: ["vercel:env:STRIPE_SECRET_KEY"],
      },
      recon,
    );
    expect(verdict.allowed).toBe(true);
  });

  it("still refuses an entry that is neither a known route nor an observed fact", () => {
    const verdict = judgeHypothesis(
      { ...base, entry: "vercel:env:INVENTED", citedFiles: [], citedFacts: ["vercel:env:STRIPE_SECRET_KEY"] },
      recon,
    );
    expect(verdict.allowed).toBe(false);
    if (!verdict.allowed) expect(verdict.reason).toMatch(/route inventory/);
  });

  it("still refuses a hypothesis with neither a file nor a fact", () => {
    const verdict = judgeHypothesis({ ...base, citedFiles: [], citedFacts: [] }, recon);
    expect(verdict).toEqual({ allowed: false, reason: "no file or live fact cited" });
  });

  it("still checks files when both are cited", () => {
    const verdict = judgeHypothesis(
      { ...base, citedFiles: ["app/api/invented.ts"], citedFacts: ["vercel:env:STRIPE_SECRET_KEY"] },
      recon,
    );
    expect(verdict.allowed).toBe(false);
  });

  it("does not accept a non-string fact id", () => {
    const verdict = judgeHypothesis(
      { ...base, citedFiles: [], citedFacts: [{ toString: () => "vercel:env:STRIPE_SECRET_KEY" }] as never },
      recon,
    );
    expect(verdict.allowed).toBe(false);
  });
});

describe("a junk citation does not discard a grounded finding", () => {
  const recon = {
    entries: new Set(["/api/update-avatar"]),
    files: new Set(["app/api/update-avatar/route.ts"]),
    tables: new Set(["users"]),
    routes: new Map(),
  };

  const base = {
    entry: "/api/update-avatar",
    attackClass: "missing_authorization",
    title: "Body-supplied user id",
    consequence: "Anyone can update any user's row by sending a different id.",
    citedFiles: ["app/api/update-avatar/route.ts"],
  };

  it("keeps the finding and drops the unrecognised citation", () => {
    // A real repository lost a real vulnerability to this. The model returned
    // citedFacts: ["anonymous"], copied off the route line, and the whole
    // finding was discarded even though it cited the correct file.
    const verdict = judgeHypothesis({ ...base, citedFacts: ["anonymous"] }, recon);
    expect(verdict.allowed).toBe(true);
    // The junk citation must not survive into the finding as evidence.
    if (verdict.allowed) expect(verdict.citedFacts).toEqual([]);
  });

  it("still refuses when the junk citation was the only grounding", () => {
    const verdict = judgeHypothesis({ ...base, citedFiles: [], citedFacts: ["anonymous"] }, recon);
    expect(verdict.allowed).toBe(false);
  });
});

// The class/fact compatibility matrix. Every other rule here asks whether the
// model cited something we observed; these ask whether what it CLAIMS about it
// agrees with what we observed.
describe("a claim contradicted by our own facts", () => {
  const judge = (h: Partial<Hypothesis>, over: Partial<RouteFact>) =>
    judgeHypothesis({ ...valid, ...h } as Hypothesis, reconWith(over));

  it("refuses missing_authorization when we read a filter", () => {
    const v = judge({ attackClass: "missing_authorization" }, { ownershipFiltered: true });
    expect(v.allowed).toBe(false);
    expect(!v.allowed && v.reason).toMatch(/narrowed to the caller/);
    expect(!v.allowed && v.unassessed).toBeUndefined(); // contradicted, not unassessed
  });

  it("refuses missing_authorization when the filter is unreadable", () => {
    const v = judge(
      { attackClass: "missing_authorization" },
      { ownershipFiltered: false, ownershipReadable: false, ownershipGap: "the tenant arrives on a context object" },
    );
    expect(v.allowed).toBe(false);
    expect(!v.allowed && v.unassessed).toBe("/api/invoices/[id]"); // reaches Coverage
  });

  it("refuses missing_authentication when we read a credential check", () => {
    expect(judge({ attackClass: "missing_authentication" }, { authenticated: true }).allowed).toBe(false);
    expect(judge({ attackClass: "missing_authentication" }, { authenticated: false, machineGated: true }).allowed).toBe(false);
  });

  it("refuses missing_authentication when identity is unreadable", () => {
    const v = judge(
      { attackClass: "missing_authentication" },
      { authenticated: false, identityReadable: false, identityGap: "the handler is wrapped in withWorkspace()" },
    );
    expect(v.allowed).toBe(false);
    expect(!v.allowed && v.unassessed).toBe("/api/invoices/[id]");
  });

  it("refuses unsigned_webhook when we read a signature check", () => {
    expect(judge({ attackClass: "unsigned_webhook" }, { machineGated: true }).allowed).toBe(false);
  });

  it("refuses unsigned_webhook when the gate is one file away", () => {
    const v = judge(
      { attackClass: "unsigned_webhook" },
      { machineGated: false, machineGateReadable: false, machineGateGap: "a signature check appears in lib/verify.ts" },
    );
    expect(v.allowed).toBe(false);
    expect(!v.allowed && v.unassessed).toBe("/api/invoices/[id]");
  });

  // THE OTHER DIRECTION. The guard must not become a way to refuse everything.
  it("STILL admits missing_authorization on a route we read as unscoped", () => {
    const v = judge({ attackClass: "missing_authorization" }, { ownershipFiltered: false, ownershipReadable: true });
    expect(v.allowed).toBe(true);
  });

  it("STILL admits missing_authentication on a route we read as open", () => {
    const v = judge(
      { attackClass: "missing_authentication" },
      { authenticated: false, machineGated: false, identityReadable: true },
    );
    expect(v.allowed).toBe(true);
  });

  // The five classes with no route fact that can contradict them. A perfectly
  // authenticated, perfectly scoped route can still concatenate user input into
  // SQL, so demanding a readable auth fact here would refuse true findings.
  it("does not gate the content classes on auth facts", () => {
    for (const cls of ["injection", "mass_assignment", "unsafe_redirect", "secret_exposure", "server_boundary_crossed"] as const) {
      const v = judge({ attackClass: cls }, { authenticated: true, ownershipFiltered: true, ownershipReadable: false });
      expect(v.allowed, `${cls} must not be refused on route facts`).toBe(true);
    }
  });

  it("reports unassessed routes once, for Coverage", () => {
    const r = guardHypotheses(
      [
        { ...valid, attackClass: "missing_authorization" },
        { ...valid, attackClass: "missing_authorization", title: "Another" },
      ],
      reconWith({ ownershipFiltered: false, ownershipReadable: false, ownershipGap: "a wrapper" }),
    );
    expect(r.admitted).toHaveLength(0);
    expect(r.unassessed).toEqual(["/api/invoices/[id]"]);
  });
});

// The entry-format bug. The prompt used to render `${path} [${methods}]`, the
// model copied "/api/feedback [ALL]" verbatim, and the guard rejected every
// hypothesis in the run — producing a silent zero that looked identical to a
// clean audit. Found in stage 4; it had been voiding whole runs for four
// measurement stages.
describe("a run discarded wholesale is not a clean run", () => {
  it("records the entries it could not match", () => {
    const r = guardHypotheses(
      [
        { ...valid, entry: "/api/invoices/[id] [ALL]" },
        { ...valid, entry: "/api/invoices/[id] [GET]", title: "Second" },
      ],
      recon,
    );
    expect(r.admitted).toHaveLength(0);
    expect(r.unmatchedEntries).toEqual(["/api/invoices/[id] [ALL]", "/api/invoices/[id] [GET]"]);
  });

  it("does not report unmatched entries when the run was fine", () => {
    const r = guardHypotheses([valid], recon);
    expect(r.admitted).toHaveLength(1);
    expect(r.unmatchedEntries).toEqual([]);
  });

  it("separates a genuinely empty answer from a discarded one", () => {
    // The distinction the trace could not previously draw.
    const empty = guardHypotheses([], recon);
    expect(empty.admitted).toHaveLength(0);
    expect(empty.unmatchedEntries).toEqual([]);
  });
});
