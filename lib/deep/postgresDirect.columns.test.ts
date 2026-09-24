import { beforeEach, expect, it, vi } from "vitest";
const client = vi.hoisted(() => ({ connect: vi.fn(), query: vi.fn(), end: vi.fn() }));
vi.mock("pg", () => ({ Client: vi.fn(function () { return client; }) }));
import { collectDirectFacts, parseConnectionString } from "./postgresDirect";
const collect = () => collectDirectFacts(parseConnectionString("postgres://reader:pw@db.example.com/app"), { lookup: async () => ["93.184.216.34"] });
let grantFailure = false;
let columnFailure = false;
beforeEach(() => {
  vi.clearAllMocks(); grantFailure = false; columnFailure = false;
  client.connect.mockResolvedValue(undefined); client.end.mockResolvedValue(undefined);
  let aborted = false;
  client.query.mockImplementation(async (sql: string) => {
    if (sql.startsWith("ROLLBACK TO")) { aborted = false; return { rows: [] }; }
    if (aborted) throw new Error("transaction aborted");
    if (sql.includes("pg_roles")) return { rows: [{ rolsuper: false, rolbypassrls: false }] };
    if (sql.includes("count(")) return { rows: [{ count: "0" }] };
    if (sql.includes("column_privileges") && grantFailure) { aborted = true; throw new Error("unread grants"); }
    if (sql.includes("information_schema.columns")) {
      if (columnFailure) { aborted = true; throw new Error("unread columns"); }
      return { rows: [{ table_name: "orders", column_name: "owner_id", data_type: "uuid", value: "secret" }] };
    }
    return { rows: [] };
  });
});
it("reads only bounded public column metadata inside the existing read-only session", async () => {
  expect((await collect()).columns).toEqual([{ table: "orders", column: "owner_id", type: "uuid" }]);
  expect(client.query.mock.calls.map(([s]) => s).find(s => s.includes("information_schema.columns")))
    .toMatch(/table_schema = 'public'[\s\S]*limit 3001/);
  expect(client.query).toHaveBeenCalledWith("BEGIN TRANSACTION READ ONLY");
});
it("recovers an optional columns query failure without inventing an empty result", async () => {
  columnFailure = true;
  expect((await collect()).columns).toBeUndefined();
  expect(client.query).toHaveBeenCalledWith("ROLLBACK TO SAVEPOINT shiplock_columns", undefined);
});
it("recovers an earlier grant failure so columns can still be read", async () => {
  grantFailure = true;
  expect(await collect()).toMatchObject({ grants: null, columns: [{ table: "orders", column: "owner_id", type: "uuid" }] });
});
