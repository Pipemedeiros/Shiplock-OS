import { describe, expect, it, vi } from "vitest";
import { resultProvesLeak, runAdversarialAgent, type AgentContext } from "./agent";
import { TENANT_A, TENANT_B } from "./tenantProbe";

const ctx: AgentContext = {
  schema: "proving_abc",
  table: "invoices",
  columns: ["id", "user_id", "amount"],
  policies: [{ name: "p_0", cmd: "SELECT", using: "true" }],
};

const leakRow = { id: "1", user_id: TENANT_B };
const ownRow = { id: "2", user_id: TENANT_A };

describe("resultProvesLeak", () => {
  // A row count alone is not evidence; a query can legitimately return A's rows.
  it("requires the OTHER tenant's id to actually appear", () => {
    expect(resultProvesLeak([leakRow])).toBe(true);
    expect(resultProvesLeak([ownRow])).toBe(false);
    expect(resultProvesLeak([])).toBe(false);
  });

  it("does not treat a non-empty result as a leak by itself", () => {
    expect(resultProvesLeak([{ count: 5 }])).toBe(false);
  });

  it("finds the identifier in any column", () => {
    expect(resultProvesLeak([{ anything: `owner=${TENANT_B}` }])).toBe(true);
  });
});

describe("runAdversarialAgent", () => {
  it("reports a finding when a proposal returns the other tenant's row", async () => {
    const propose = vi.fn().mockResolvedValue([`select * from proving_abc.invoices`]);
    const run = vi.fn().mockResolvedValue([leakRow]);
    const { finding, attempts } = await runAdversarialAgent(ctx, run, propose);
    expect(finding?.severity).toBe("CRITICAL");
    expect(finding?.proven).toBe(true);
    expect(attempts).toHaveLength(1);
  });

  it("stops as soon as it proves the leak — no more spending", async () => {
    const propose = vi.fn().mockResolvedValue([
      `select * from proving_abc.invoices`,
      `select 1 from proving_abc.invoices`,
    ]);
    const run = vi.fn().mockResolvedValue([leakRow]);
    await runAdversarialAgent(ctx, run, propose);
    expect(run).toHaveBeenCalledTimes(1);
  });

  it("reports nothing when isolation holds", async () => {
    const propose = vi.fn().mockResolvedValue([`select * from proving_abc.invoices`]);
    const run = vi.fn().mockResolvedValue([ownRow]);
    const { finding } = await runAdversarialAgent(ctx, run, propose);
    expect(finding).toBeNull();
  });

  // The model contributes ideas, never authority.
  it("REFUSES an out-of-bounds proposal without executing it", async () => {
    const propose = vi.fn().mockResolvedValue([`select * from auth.users`]);
    const run = vi.fn();
    const { finding, attempts } = await runAdversarialAgent(ctx, run, propose);
    expect(run).not.toHaveBeenCalled();
    expect(finding).toBeNull();
    expect(attempts[0].allowed).toBe(false);
  });

  it("refuses a write even if the model insists", async () => {
    const propose = vi.fn().mockResolvedValue([`drop table proving_abc.invoices`]);
    const run = vi.fn();
    await runAdversarialAgent(ctx, run, propose);
    expect(run).not.toHaveBeenCalled();
  });

  // Refusals are evidence, not something to swallow.
  it("records refused proposals in the attempt trail", async () => {
    const propose = vi
      .fn()
      .mockResolvedValueOnce([`select * from information_schema.columns`])
      .mockResolvedValue([]);
    const { attempts } = await runAdversarialAgent(ctx, vi.fn(), propose);
    expect(attempts[0].allowed).toBe(false);
    expect(attempts[0].reason).toContain("system or platform schema");
  });

  it("survives a query that errors and keeps going", async () => {
    const propose = vi
      .fn()
      .mockResolvedValueOnce([`select * from proving_abc.invoices`])
      .mockResolvedValueOnce([`select id from proving_abc.invoices`])
      .mockResolvedValue([]);
    const run = vi.fn().mockRejectedValueOnce(new Error("syntax")).mockResolvedValue([leakRow]);
    const { finding } = await runAdversarialAgent(ctx, run, propose);
    expect(finding).not.toBeNull();
  });

  it("stops when the proposer runs dry", async () => {
    const propose = vi.fn().mockResolvedValue([]);
    const { finding, attempts } = await runAdversarialAgent(ctx, vi.fn(), propose);
    expect(finding).toBeNull();
    expect(attempts).toEqual([]);
    expect(propose).toHaveBeenCalledTimes(1);
  });

  // Cost and blast radius bounded before capability.
  it("caps the number of rounds", async () => {
    const propose = vi.fn().mockResolvedValue([`select * from proving_abc.invoices`]);
    const run = vi.fn().mockResolvedValue([ownRow]);
    await runAdversarialAgent(ctx, run, propose, 2);
    expect(propose).toHaveBeenCalledTimes(2);
  });

  it("caps queries per round", async () => {
    const many = Array.from({ length: 20 }, (_, i) => `select ${i} from proving_abc.invoices`);
    const propose = vi.fn().mockResolvedValue(many);
    const run = vi.fn().mockResolvedValue([ownRow]);
    await runAdversarialAgent(ctx, run, propose, 1);
    expect(run.mock.calls.length).toBeLessThanOrEqual(4);
  });

  it("puts the proving query and the attempt summary in the finding", async () => {
    const propose = vi.fn().mockResolvedValue([`select * from proving_abc.invoices`]);
    const { finding } = await runAdversarialAgent(ctx, vi.fn().mockResolvedValue([leakRow]), propose);
    expect(finding!.consequence).toContain("select * from proving_abc.invoices");
    expect(finding!.consequence).toContain("queries proposed");
    expect(finding!.consequence).toContain("none of your data");
  });
});
