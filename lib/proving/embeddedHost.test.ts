import { describe, expect, it } from "vitest";
import { openEmbeddedHost } from "./embeddedHost";
import { buildControlProbeSql, buildLeakProbeSql, buildReplicaPlan } from "./replica";

// 6A-2a: the replica runs on an embedded, in-process Postgres (PGlite), not a
// paid hosted project (Felipe 2026-09-23). These tests execute real SQL.
const policy = (qual: string) => ({ schemaname: "public", tablename: "orders", policyname: "p", cmd: "SELECT",
  qual, with_check: null, roles: ["authenticated"] });

async function probe(qual: string) {
  const host = await openEmbeddedHost();
  try {
    const plan = buildReplicaPlan("run1", "orders", "user_id", [policy(qual)]);
    await host.run(host.projectRef, plan.setupSql);
    const control = await host.run(host.projectRef, buildControlProbeSql(plan.schema, "orders", "user_id"));
    const leak = await host.run(host.projectRef, buildLeakProbeSql(plan.schema, "orders", "user_id"));
    await host.run(host.projectRef, plan.teardownSql);
    return { control: control[0]?.visible, leaked: leak[0]?.leaked };
  } finally {
    await host.close();
  }
}

describe("embedded proving host (6A-2a)", () => {
  it("reproduces a leak from a policy that lets anyone read every row", async () => {
    expect(await probe("true")).toEqual({ control: 1, leaked: 1 });
  });
  it("shows an owner-scoped policy isolating tenants, with a working control", async () => {
    expect(await probe("user_id = auth.uid()")).toEqual({ control: 1, leaked: 0 });
  });
  it("refuses any project ref but its own, and has no network or file access for SQL", async () => {
    const host = await openEmbeddedHost();
    try {
      await expect(host.run("customer-prod-ref", "select 1")).rejects.toThrow(/embedded/);
      await expect(host.run(host.projectRef, "copy (select 1) to program 'id'")).rejects.toThrow();
    } finally {
      await host.close();
    }
  });
  it("stops a runaway statement at its time limit", async () => {
    const host = await openEmbeddedHost({ statementTimeoutMs: 200 });
    try {
      await expect(host.run(host.projectRef, "select count(*) from generate_series(1, 1000000000)")).rejects.toThrow();
    } finally {
      await host.close();
    }
  }, 20_000);
});
