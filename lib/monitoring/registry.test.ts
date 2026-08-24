import { describe, it, expect, vi } from "vitest";
import { runCollectors, type CollectorSpec, type CollectorContext } from "./registry";

const ctx: CollectorContext = {
  profile: {
    id: "u1",
    email: "a@b.com",
    monitored_project_url: "https://p.supabase.co",
    monitored_anon_key_encrypted: "enc",
    monitored_app_url: "https://app.example.com",
  },
  anonKey: "anon",
  triggerSource: "scheduled_48h",
  previousFindings: [],
};

function spec(over: Partial<CollectorSpec> & Pick<CollectorSpec, "id">): CollectorSpec {
  return {
    layer: "db",
    eligibleTriggers: ["hourly", "deploy", "scheduled_48h"],
    timeoutMs: 1_000,
    run: async () => ({}),
    ...over,
  };
}

describe("runCollectors — isolation", () => {
  it("one failing collector does not cost the others their results", async () => {
    const good = spec({
      id: "good",
      run: async () => ({ snapshotFindings: [{ id: "f1" }] as never }),
    });
    const bad = spec({
      id: "bad",
      run: async () => {
        throw new Error("collector exploded");
      },
    });
    const alsoGood = spec({
      id: "also-good",
      run: async () => ({ newFindings: [{ id: "f2" }] as never }),
    });

    const { results, outcomes } = await runCollectors([good, bad, alsoGood], ctx);

    expect(results).toHaveLength(2);
    expect(outcomes.map((o) => o.status)).toEqual(["ok", "failed", "ok"]);
  });

  it("a hanging collector is cut loose at its timeout, and the rest still run", async () => {
    const hangs = spec({
      id: "hangs",
      timeoutMs: 20,
      run: () => new Promise(() => {}), // never settles
    });
    const after = spec({
      id: "after",
      run: async () => ({ snapshotFindings: [] }),
    });

    const { results, outcomes } = await runCollectors([hangs, after], ctx);

    expect(outcomes[0]).toMatchObject({ id: "hangs", status: "timeout" });
    expect(outcomes[1]).toMatchObject({ id: "after", status: "ok" });
    expect(results).toHaveLength(1);
  });
});

describe("runCollectors — eligibility", () => {
  it("skips collectors not eligible for this trigger, without running them", async () => {
    const run = vi.fn(async () => ({}));
    const fullOnly = spec({ id: "full-only", eligibleTriggers: ["scheduled_48h"], run });

    const { outcomes } = await runCollectors([fullOnly], { ...ctx, triggerSource: "hourly" });

    expect(run).not.toHaveBeenCalled();
    expect(outcomes[0]).toMatchObject({ id: "full-only", status: "skipped" });
  });

  it("skips a collector whose appliesTo gate is false — not applicable is not failure", async () => {
    const run = vi.fn(async () => ({}));
    const needsAppUrl = spec({
      id: "needs-app-url",
      appliesTo: (c) => Boolean(c.profile.monitored_app_url),
      run,
    });

    const { outcomes } = await runCollectors([needsAppUrl], {
      ...ctx,
      profile: { ...ctx.profile, monitored_app_url: null },
    });

    expect(run).not.toHaveBeenCalled();
    expect(outcomes[0].status).toBe("skipped");
  });
});

describe("runCollectors — extensibility", () => {
  // The whole point of the registry: adding collector #16 is a registry entry,
  // not an edit to the orchestrator. If this test ever needs to change the
  // orchestrator to pass, the abstraction has leaked.
  it("runs a brand-new collector with no orchestrator changes", async () => {
    const brandNew = spec({
      id: "some-future-layer",
      layer: "runtime",
      run: async () => ({ snapshotFindings: [{ id: "new-layer-finding" }] as never }),
    });

    const { results, outcomes } = await runCollectors([brandNew], ctx);

    expect(outcomes[0]).toMatchObject({ id: "some-future-layer", status: "ok" });
    expect(results[0].snapshotFindings).toHaveLength(1);
  });

  it("records duration per collector, so a slow layer is attributable", async () => {
    const slowish = spec({
      id: "slowish",
      run: async () => {
        await new Promise((r) => setTimeout(r, 15));
        return {};
      },
    });

    const { outcomes } = await runCollectors([slowish], ctx);

    expect(outcomes[0].durationMs).toBeGreaterThanOrEqual(10);
  });
});
