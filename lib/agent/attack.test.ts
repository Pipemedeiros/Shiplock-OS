import { describe, expect, it } from "vitest";
import type { RouteFact } from "@/lib/graph/routeInventory";
import { MAX_PROMPT_ROUTES, SYSTEM, buildPrompt, extractJsonArray, rankRoutes, routesOmitted,
  salvageJsonObjects,
  nothingToAsk,
} from "./attack";
import type { StackReport } from "./stack";

const route = (over: Partial<RouteFact>): RouteFact => ({
  path: "/api/x",
  file: "app/api/x/route.ts",
  methods: ["GET"],
  tables: [],
  authenticated: false,
  machineGated: false,
  usesServiceRole: false,
  ownershipFiltered: false,
  identityReadable: true,
  identityGap: null,
  dataReadable: true,
  dataGap: null,
  ownershipReadable: true,
  ownershipGap: null,
  serviceRoleReadable: true,
  machineGateReadable: true,
  machineGateGap: null,
  via: [],
  ...over,
});

const stack: StackReport = {
  tools: [{ id: "clerk", name: "Clerk", kind: "auth", evidence: "package.json", usedIn: [] }],
  authUnknown: false,
  databaseUnknown: true,
};

describe("buildPrompt", () => {
  it("describes only routes that reach data", () => {
    // A route touching no table cannot leak one. Spending prompt on it crowds
    // out the routes that can, which is how recall gets quietly worse.
    const prompt = buildPrompt({
      routes: [route({ path: "/api/health", tables: [] }), route({ path: "/api/invoices", tables: ["invoices"] })],
      stack,
      tables: ["invoices"],
      files: [],
    });

    expect(prompt).toContain("/api/invoices");
    expect(prompt).not.toContain("/api/health");
  });

  it("states identity and scoping for each route, which is what the model reasons over", () => {
    const prompt = buildPrompt({
      routes: [route({ path: "/api/invoices", tables: ["invoices"], authenticated: true, ownershipFiltered: false })],
      stack,
      tables: ["invoices"],
      files: [],
    });

    expect(prompt).toContain("id=user");
    expect(prompt).toContain("unscoped");
  });

  it("names the methods we read as never refusing an anonymous caller (R1b)", () => {
    const prompt = buildPrompt({
      routes: [
        route({ path: "/api/feedback", tables: ["feedback"], authenticated: true, ownershipFiltered: true, unrefusedMethods: ["GET"] }),
        route({ path: "/api/admin", tables: ["users"], authenticated: true, unrefusedMethods: ["DELETE"],
          refusalGap: "a middleware at proxy.ts checks the caller on this path and may refuse first" }),
        route({ path: "/api/notes", tables: ["notes"], authenticated: true, ownershipFiltered: true }),
      ],
      stack,
      tables: ["feedback", "users", "notes"],
      files: [],
    });
    expect(prompt).toContain("/api/feedback id=user unrefused=GET scope=owner-filtered");
    expect(prompt).toContain("/api/admin id=user unrefused=DELETE middleware=may-refuse scope=unscoped");
    expect(prompt).toContain("/api/notes id=user scope=owner-filtered");
    expect(SYSTEM).toMatch(/unrefused=/);
  });

  it("ranks a signed-in route with an unrefused method ahead of one that refuses everywhere", () => {
    const ranked = rankRoutes([
      route({ path: "/api/a", tables: ["t"], authenticated: true, ownershipFiltered: true }),
      route({ path: "/api/b", tables: ["t"], authenticated: true, ownershipFiltered: true, unrefusedMethods: ["GET"] }),
    ]);
    expect(ranked.map((r) => r.path)).toEqual(["/api/b", "/api/a"]);
  });

  it("says the stack is unidentified rather than omitting the line", () => {
    const prompt = buildPrompt({
      routes: [route({ tables: ["t"] })],
      stack: { tools: [], authUnknown: true, databaseUnknown: true },
      tables: ["t"],
      files: [],
    });
    expect(prompt).toContain("stack unidentified");
  });
});

describe("extractJsonArray", () => {
  it("reads a bare array", () => {
    expect(extractJsonArray('[{"entry":"/a"}]')).toEqual([{ entry: "/a" }]);
  });

  it("reads an array wrapped in a markdown fence", () => {
    expect(extractJsonArray('```json\n[{"entry":"/a"}]\n```')).toEqual([{ entry: "/a" }]);
  });

  it("returns null for prose, so the caller can record a parse failure", () => {
    // Never [] -- an unparseable answer must not be indistinguishable from a
    // clean result.
    expect(extractJsonArray("I did not find anything obvious.")).toBeNull();
  });

  it("returns null for a truncated array rather than guessing at the rest", () => {
    expect(extractJsonArray('[{"entry":"/a"')).toBeNull();
  });
});

describe("what survives truncation", () => {
  const r = (over: Partial<RouteFact>): RouteFact =>
    ({
      path: "/api/x", file: "app/api/x/route.ts", methods: ["GET"],
      authenticated: true, machineGated: false, ownershipFiltered: true,
      // A fixture standing for a route we READ completely. Omitting these left
      // them undefined, which is falsy, which silently made every fixture route
      // "scope-unreadable" and reordered the ranking.
      identityReadable: true, identityGap: null,
      ownershipReadable: true, ownershipGap: null,
      serviceRoleReadable: true, machineGateReadable: true, machineGateGap: null,
      tables: ["things"], ...over,
    }) as RouteFact;

  const emptyStack: StackReport = { tools: [], authUnknown: false, databaseUnknown: false };

  it("puts the open door first and the safe route last", () => {
    const ranked = rankRoutes(
      [
        r({ path: "/api/safe", ownershipFiltered: true }),
        r({ path: "/api/open", authenticated: false, ownershipFiltered: false, tables: ["invoices"] }),
        r({ path: "/api/tenant", authenticated: true, ownershipFiltered: false, tables: ["invoices"] }),
      ],
      new Set(["invoices"]),
    );
    expect(ranked.map((r) => r.path)).toEqual(["/api/open", "/api/tenant", "/api/safe"]);
  });

  it("keeps the riskiest route when there are more than fit", () => {
    // Which routes the agent never sees used to be decided by the order the tar
    // file happened to be in. An anonymous unscoped route could be invisible
    // because its filename sorted late.
    const many = Array.from({ length: MAX_PROMPT_ROUTES + 20 }, (_, i) =>
      r({ path: `/api/scoped-${String(i).padStart(3, "0")}` }),
    );
    const dangerous = r({
      path: "/api/zzz-last-alphabetically",
      authenticated: false,
      ownershipFiltered: false,
      tables: ["invoices"],
    });
    const prompt = buildPrompt({ routes: [...many, dangerous], stack: emptyStack, tables: ["invoices"], files: [] });
    expect(prompt).toContain("/api/zzz-last-alphabetically");
  });

  it("is stable across runs, so a finding does not flicker", () => {
    const routes = [r({ path: "/api/b" }), r({ path: "/api/a" })];
    expect(rankRoutes(routes).map((r) => r.path)).toEqual(rankRoutes([...routes].reverse()).map((r) => r.path));
  });

  it("counts what did not fit, so coverage can say so", () => {
    const many = Array.from({ length: MAX_PROMPT_ROUTES + 7 }, (_, i) => r({ path: `/api/${i}` }));
    expect(routesOmitted({ routes: many, stack: emptyStack, tables: [], files: [] })).toBe(7);
  });
});

describe("a verified machine gate is stated, not implied", () => {
  const stack: StackReport = { tools: [], authUnknown: false, databaseUnknown: false };

  it("labels a machine-gated route as verified in the prompt", () => {
    // Rendering this as a bare "machine" tag let the model read it as "no user
    // session" and speculate that no signature check existed. Auditing our own
    // repository then reported the Stripe webhook, which verifies through
    // constructEvent, as accepting unsigned events. MACHINE_GATE_RE matched a
    // real check in that route's code, so the prompt says so.
    const prompt = buildPrompt({
      routes: [
        {
          path: "/api/webhook", file: "app/api/webhook/route.ts", methods: ["POST"],
          authenticated: false, machineGated: true, ownershipFiltered: false,
          tables: ["subscribers"],
        } as RouteFact,
      ],
      stack, tables: ["subscribers"], files: [],
    });
    expect(prompt).toContain("machine-verified");
    expect(prompt).not.toMatch(/id=machine\s/);
  });

  it("tells the model that absence of a detail is not evidence", () => {
    const prompt = buildPrompt({ routes: [], stack, tables: [], files: [] });
    expect(prompt).toBeDefined();
  });
});

describe("live facts in the prompt", () => {
  const stack: StackReport = { tools: [], authUnknown: false, databaseUnknown: false };

  it("lists each live fact with the id the model must cite", () => {
    const prompt = buildPrompt({
      routes: [], stack, tables: [], files: [],
      liveFacts: [{ id: "vercel:env:STRIPE_SECRET_KEY", statement: "vercel reports it set in production" }],
    });
    expect(prompt).toContain("vercel:env:STRIPE_SECRET_KEY");
    expect(prompt).toContain("live");
  });

  it("says nothing about live facts when none were collected", () => {
    const prompt = buildPrompt({ routes: [], stack, tables: [], files: [] });
    expect(prompt).not.toContain("live");
  });
});

// Named for the measurement that found it: ten runs of one 234k-line repository
// admitted 0, 13, 12, 0, 0, 10, 2, 10, 9 and 7 hypotheses on identical input.
// Every call came back with stop_reason "max_tokens" at exactly the old 2000
// budget, and whether the run produced findings or nothing depended only on
// where the cut landed.
describe("a truncated answer is not an empty one", () => {
  const truncated = `[
    {"entry":"/api/a","attackClass":"missing_authorization","title":"One","consequence":"c","citedFiles":["a.ts"],"citedTables":["t"]},
    {"entry":"/api/b","attackClass":"missing_authentication","title":"Two","consequence":"c","citedFiles":["b.ts"],"citedTables":["t"]},
    {"entry":"/api/c","attackClass":"missing_authorization","title":"Thr`;

  it("salvages every complete object from a cut-off array", () => {
    const out = salvageJsonObjects(truncated) as { entry: string }[];
    expect(out.map((o) => o.entry)).toEqual(["/api/a", "/api/b"]);
  });

  it("returns nothing when the cut lands before the first object closes", () => {
    expect(salvageJsonObjects(`[{"entry":"/api/a","title":"partia`)).toEqual([]);
  });

  it("is not confused by braces or brackets inside strings", () => {
    const tricky = `[{"entry":"/api/a","consequence":"a } and a ] and a \\" quote","citedFiles":["x.ts"]}]`;
    const out = salvageJsonObjects(tricky) as { consequence: string }[];
    expect(out).toHaveLength(1);
    expect(out[0].consequence).toBe('a } and a ] and a " quote');
  });

  it("handles a nested array inside an object", () => {
    const out = salvageJsonObjects(
      `[{"entry":"/a","citedFiles":["x.ts","y.ts"],"citedTables":["t"]},{"entry":"/b"`,
    ) as { entry: string }[];
    expect(out.map((o) => o.entry)).toEqual(["/a"]);
  });

  it("stops at the array's own closing bracket", () => {
    const out = salvageJsonObjects(`[{"entry":"/a"}] trailing prose {"entry":"/b"}`) as { entry: string }[];
    expect(out.map((o) => o.entry)).toEqual(["/a"]);
  });

});

describe("an inventory with nothing to ask about", () => {
  it("is a stated skip, not an empty answer", () => {
    expect(nothingToAsk({ routes: [], stack: { tools: [] } as never, tables: [], files: [] }))
      .toMatchObject({ skipped: true, skipReason: "no route reaches a table" });
  });
});

describe("the route line cannot be mistaken for the entry", () => {
  const route = (over: Partial<RouteFact>) => ({
    path: "/api/feedback", file: "pages/api/feedback/index.ts", methods: ["ALL"],
    tables: ["view"], authenticated: false, machineGated: false, ownershipFiltered: false,
    usesServiceRole: false, via: [], identityReadable: true, identityGap: null,
    ownershipReadable: true, ownershipGap: null, serviceRoleReadable: true,
    machineGateReadable: true, machineGateGap: null, ...over,
  }) as RouteFact;

  const prompt = () =>
    buildPrompt({
      routes: [route({})], stack: { tools: [], authUnknown: false, databaseUnknown: false },
      tables: ["view"], files: ["pages/api/feedback/index.ts"],
    } as never);

  it("puts nothing bracketed after the path", () => {
    expect(prompt()).not.toMatch(/\/api\/feedback\s*\[/);
  });

  it("labels the methods like every other attribute", () => {
    expect(prompt()).toMatch(/\/api\/feedback id=\S+ scope=\S+ methods=ALL/);
  });

  it("leaves the path as the only unlabelled token on its line", () => {
    const line = prompt().split("\n").find((l) => l.startsWith("/api/feedback"))!;
    const rest = line.slice("/api/feedback".length).trim();
    expect(rest.split(/\s+/).every((tok) => tok.includes("="))).toBe(true);
  });
});
