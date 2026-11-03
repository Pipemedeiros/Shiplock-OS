import { describe, expect, it } from "vitest";
import { openEmbeddedHost } from "./embeddedHost";
import { buildControlProbeSql, buildLeakProbeSql, buildReplicaPlan } from "./replica";

// The replica runs on an embedded, in-process Postgres (PGlite), not a
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

describe("embedded proving host", () => {
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

  // The statement limit bounds customer SQL. The host's own setup ran under it
  // too, so a slow machine killed the replica before any statement (CI,
  // 2026-11-02: setup past 200 ms).
  it("opens even when its setup outlasts the statement limit, which still applies", async () => {
    const host = await openEmbeddedHost({ statementTimeoutMs: 1 });
    try {
      await expect(host.run(host.projectRef, "select count(*) from generate_series(1, 1000000000)")).rejects.toThrow(/exceeded 1 ms/);
    } finally {
      await host.close();
    }
  }, 20_000);
});

// A policy is customer text the replica executes. One that allocates
// without bound once aborted the whole server process; it must end only the
// replica, as an error the proof worker records as aborted.
describe("embedded host resource limits", () => {
  it("ends a spilling allocation bomb in a policy as an error, not a 7 GB process", async () => {
    const host = await openEmbeddedHost({ statementTimeoutMs: 60_000 });
    try {
      const plan = buildReplicaPlan("bomb", "orders", "user_id",
        [policy("(select count(*) from (select array_agg(g) a from generate_series(1, 400000000) g) s) > 0")]);
      await host.run(host.projectRef, plan.setupSql);
      await expect(host.run(host.projectRef, buildControlProbeSql(plan.schema, "orders", "user_id"))).rejects.toThrow(/temp_file_limit/);
      // A probe cannot lift the limit: it runs as authenticated, not superuser.
      await expect(host.run(host.projectRef, "begin; set local role authenticated; set temp_file_limit = -1; commit;")).rejects.toThrow(/permission denied/);
      // And a failed probe does not leave the session unusable for teardown.
      await expect(host.run(host.projectRef, plan.teardownSql)).resolves.toEqual([]);
    } finally {
      await host.close();
    }
  }, 120_000);
  it("returns at most a bounded prefix of rows", async () => {
    const host = await openEmbeddedHost();
    try {
      expect(await host.run(host.projectRef, "select g from generate_series(1, 5000) g")).toHaveLength(200);
    } finally {
      await host.close();
    }
  });
});
