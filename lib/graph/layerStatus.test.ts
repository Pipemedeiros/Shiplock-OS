import { describe, it, expect } from "vitest";
import { describeLayerStatus, type LayerStatus } from "./layerStatus";
import { correlationLayers } from "./layerLabels";

function status(connected: string[]): LayerStatus {
  const all = [
    { id: "code", label: "code" },
    { id: "database", label: "database" },
    { id: "traffic", label: "traffic" },
    { id: "email-dns", label: "email/DNS" },
  ] as const;
  const layers = all.map((l) => ({
    ...l,
    connected: connected.includes(l.label),
    unlocks: "",
  })) as LayerStatus["layers"];
  return {
    layers,
    connectedCount: layers.filter((l) => l.connected).length,
    totalCount: layers.length,
    nextUp: layers.find((l) => !l.connected) ?? null,
  };
}

describe("describeLayerStatus", () => {
  it("counts what is wired up, and never states a percentage", () => {
    const line = describeLayerStatus(status(["code", "database"]));
    expect(line).toBe("2 of 4 layers correlated — code, database.");
    expect(line).not.toMatch(/%/);
  });

  it("names every connected layer, so the claim is checkable", () => {
    expect(describeLayerStatus(status(["code", "database", "traffic", "email/DNS"]))).toBe(
      "4 of 4 layers correlated — code, database, traffic, email/DNS."
    );
  });

  it("says nothing is correlated rather than reporting 0%", () => {
    expect(describeLayerStatus(status([]))).toBe(
      "No layers correlated yet — connect your stack to begin."
    );
  });

  // Guards CLAUDE.md's "no letter grade anywhere in the product" rule against
  // this surface quietly reintroducing a score.
  it("never emits a grade or a score", () => {
    for (const combo of [[], ["code"], ["code", "database"], ["code", "database", "traffic"]]) {
      const line = describeLayerStatus(status(combo));
      expect(line).not.toMatch(/\b[A-F][+-]?\b\s*(grade|rating)/i);
      expect(line).not.toMatch(/\bscore\b/i);
    }
  });
});

describe("correlationLayers", () => {
  it("translates internal collector names into the customer's vocabulary", () => {
    // The customer connected GitHub and Supabase; "source" and "db" would make
    // them translate.
    const layers = correlationLayers(["source", "db"]);
    expect(layers.find((l) => l.label === "code")?.agreed).toBe(true);
    expect(layers.find((l) => l.label === "database")?.agreed).toBe(true);
  });

  it("folds config into database — an auth setting is not a layer a founder owns separately", () => {
    const layers = correlationLayers(["config"]);
    expect(layers.find((l) => l.label === "database")?.agreed).toBe(true);
  });

  it("returns unlit layers too, because 'traffic had nothing to say' is information", () => {
    const layers = correlationLayers(["source", "db"]);
    expect(layers).toHaveLength(4);
    expect(layers.find((l) => l.label === "traffic")?.agreed).toBe(false);
  });

  it("keeps a stable display order across findings", () => {
    expect(correlationLayers(["traffic", "source"]).map((l) => l.label)).toEqual(
      correlationLayers(["db"]).map((l) => l.label)
    );
  });

  it("handles a missing or empty surfaces list without throwing", () => {
    expect(correlationLayers(undefined).every((l) => !l.agreed)).toBe(true);
    expect(correlationLayers([]).every((l) => !l.agreed)).toBe(true);
  });

  it("ignores an unknown collector name rather than rendering a mystery layer", () => {
    const layers = correlationLayers(["source", "some-future-collector"]);
    expect(layers.filter((l) => l.agreed).map((l) => l.label)).toEqual(["code"]);
  });
});
