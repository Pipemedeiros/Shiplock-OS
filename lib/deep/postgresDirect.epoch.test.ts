import { beforeEach, describe, expect, it, vi } from "vitest";

// A direct-Postgres connect mints a new epoch; disconnect clears it.
const mocks = vi.hoisted(() => ({ update: vi.fn(), collect: vi.fn() }));
vi.mock("@/lib/crypto", () => ({ encrypt: (v: string) => `enc(${v})`, decrypt: (v: string) => v }));
vi.mock("./postgresDirect", async (original) => ({
  ...await original<typeof import("./postgresDirect")>(), collectDirectFacts: mocks.collect,
}));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: () => {
  const chain = { eq: () => chain, is: () => chain, then: (r: (v: unknown) => unknown) => Promise.resolve({ error: null }).then(r) };
  return { update: (payload: unknown) => { mocks.update(payload); return chain; } };
} }) }));

import { connectDirectPostgres, disconnectDirectPostgres } from "./postgresDirectRun";

const dsn = "postgres://reader:secret@db.example.com/app";

beforeEach(() => {
  vi.clearAllMocks();
  mocks.collect.mockResolvedValue({ policies: [], scanTables: [], grants: [] });
});

describe("direct-Postgres connection epoch", () => {
  it("mints a fresh epoch on each connect", async () => {
    await connectDirectPostgres("u1", dsn);
    await connectDirectPostgres("u1", dsn);
    const epochs = mocks.update.mock.calls.map(([p]) => (p as Record<string, string>).postgres_connection_epoch);
    expect(epochs[0]).toMatch(/^[a-f0-9]{64}$/);
    expect(epochs[0]).not.toBe(epochs[1]);
  });

  it("clears the epoch on disconnect", async () => {
    await disconnectDirectPostgres("u1");
    expect(mocks.update).toHaveBeenCalledWith(expect.objectContaining({
      postgres_dsn_encrypted: null, postgres_connection_epoch: null,
    }));
  });
});
