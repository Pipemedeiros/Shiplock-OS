import { describe, expect, it } from "vitest";
import { summarizeUnassessed, unassessedNote } from "./unassessed";
import type { RouteFact } from "@/lib/graph/routeInventory";

const fact = (over: Partial<RouteFact>): RouteFact => ({
  path: "/api/x",
  file: "app/api/x/route.ts",
  methods: ["GET"],
  tables: ["orders"],
  authenticated: true,
  machineGated: false,
  machineGateReadable: true,
  machineGateGap: null,
  usesServiceRole: false,
  serviceRoleReadable: true,
  ownershipFiltered: true,
  ownershipReadable: true,
  ownershipGap: null,
  identityReadable: true,
  identityGap: null,
  dataReadable: true,
  dataGap: null,
  via: [],
  ...over,
});

describe("the unassessed disclosure is derived from facts, not from the model", () => {
  it("is null only when everything reaching data was judged and every route's data access was followed", () => {
    expect(unassessedNote([fact({}), fact({ path: "/api/y", tables: [] })])).toBeNull();
  });

  it("counts each unjudged route once, under its first reason", () => {
    const s = summarizeUnassessed([
      fact({ path: "/api/a", identityReadable: false, ownershipReadable: false }),
      fact({ path: "/api/b", ownershipReadable: false }),
      fact({ path: "/api/c", machineGateReadable: false }),
      fact({ path: "/api/d" }),
      fact({ path: "/api/e", tables: [], dataReadable: false, dataGap: "imports @/lib/x" }),
      fact({ path: "/api/f", tables: [] }),
    ]);
    expect(s.dataTouching).toBe(4);
    expect(s.unassessed).toBe(3);
    expect(s.reasons).toEqual({ identity: 1, scope: 1, signature: 1 });
    expect(s.dataUnreadable).toBe(1);
  });

  it("leads with the proportion, breaks down by reason, names a sample", () => {
    const routes = [
      fact({ path: "/api/a", tables: ["orders", "users"], identityReadable: false, ownershipReadable: false }),
      fact({ path: "/api/b", ownershipReadable: false }),
      fact({ path: "/api/c" }),
      fact({ path: "/api/d" }),
      fact({ path: "/api/e", tables: [], dataReadable: false, dataGap: "imports @/lib/x" }),
    ];
    const note = unassessedNote(routes)!;
    expect(note.name).toBe("2 of 4 endpoints that reach data could not be judged (50%)");
    expect(note.why).toMatch(/on 1 endpoint the check that decides who is calling/);
    expect(note.why).toMatch(/on 1 endpoint we could not tell whether the query is narrowed/);
    expect(note.why).toMatch(/1 endpoint reach no table we could see/);
    expect(note.why).toMatch(/Among them: \/api\/a, \/api\/b, \/api\/e\./);
    expect(note.effect).toMatch(/not confirmed safe/);
  });

  it("names at most five, the ones over the most tables first", () => {
    const routes = Array.from({ length: 9 }, (_, i) => fact({ path: `/api/r${i}`, tables: Array(i + 1).fill("t"), identityReadable: false }));
    const note = unassessedNote(routes)!;
    expect(note.why).toMatch(/Among them: \/api\/r8, \/api\/r7, \/api\/r6, \/api\/r5, \/api\/r4\./);
  });

  it("still discloses when nothing reaching data was unjudged but data access was out of view", () => {
    const note = unassessedNote([fact({}), fact({ path: "/api/e", tables: [], dataReadable: false })])!;
    expect(note.name).toBe("1 endpoint whose data access we could not follow");
  });

  it("never mentions a field name", () => {
    const note = unassessedNote([fact({ identityReadable: false, ownershipReadable: false, machineGateReadable: false })])!;
    expect(`${note.name} ${note.why} ${note.effect}`).not.toMatch(/Readable|ownership|machineGate/);
  });
});
