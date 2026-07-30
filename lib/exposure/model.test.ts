import { describe, expect, it } from "vitest";
import {
  buildInventory,
  classifyColumn,
  estimateExposure,
  formatMoney,
  SOURCES,
  summariseExposure,
  type TableInventory,
} from "./model";

const cols = (table: string, ...columns: string[]) => columns.map((column) => ({ table, column }));

describe("column classification", () => {
  it("classifies each PII category", () => {
    const cases: [string, string][] = [
      ["ssn", "government"],
      ["passport_number", "government"],
      ["card_number", "financial"],
      ["iban", "financial"],
      ["password_hash", "credential"],
      ["access_token", "credential"],
      ["diagnosis", "health"],
      ["email", "contact"],
      ["phone", "contact"],
      ["postal_code", "contact"],
      ["latitude", "location"],
      ["full_name", "identity"],
      ["date_of_birth", "identity"],
      ["message_body", "content"],
    ];
    for (const [column, category] of cases) {
      expect(classifyColumn(column)?.category, column).toBe(category);
    }
  });

  // A column we don't recognise is NOT quietly treated as harmless — it is
  // counted and surfaced, so the inventory reads as partial.
  it("leaves an unrecognised column unclassified", () => {
    expect(classifyColumn("widget_count")).toBeNull();
    expect(classifyColumn("id")).toBeNull();
    expect(classifyColumn("created_at")).toBeNull();
  });

  it("prefers the more severe category when names overlap", () => {
    // "billing_address" is financial rather than merely contact.
    expect(classifyColumn("billing_address")?.category).toBe("financial");
  });
});

describe("buildInventory", () => {
  it("groups columns by table and category", () => {
    const inv = buildInventory([
      ...cols("profiles", "id", "email", "full_name", "created_at"),
      ...cols("payments", "card_number"),
    ]);
    expect(inv.map((i) => i.table)).toEqual(["payments", "profiles"]);
    const profiles = inv.find((i) => i.table === "profiles")!;
    expect(profiles.categories.map((c) => c.category).sort()).toEqual(["contact", "identity"]);
    expect(profiles.unclassifiedColumns).toBe(2);
  });

  it("reports a row count only when measured", () => {
    const inv = buildInventory(cols("profiles", "email"), new Map([["profiles", 4231]]));
    expect(inv[0].rowCount).toBe(4231);
    expect(buildInventory(cols("profiles", "email"))[0].rowCount).toBeNull();
  });

  it("returns a table with no PII and no categories", () => {
    const inv = buildInventory(cols("feature_flags", "id", "name_key", "enabled"));
    expect(inv[0].categories).toEqual([]);
  });

  it("handles an empty schema", () => {
    expect(buildInventory([])).toEqual([]);
  });
});

describe("estimateExposure", () => {
  const profiles: TableInventory = {
    table: "profiles",
    categories: [
      { category: "contact", label: "contact details", columns: ["email"] },
      { category: "identity", label: "names and personal details", columns: ["full_name"] },
    ],
    unclassifiedColumns: 1,
    rowCount: 4231,
  };

  it("computes rows x the cited per-record figure", () => {
    const e = estimateExposure(profiles)!;
    expect(e.estimate).toBe(4231 * 160);
  });

  // Guardrail 2: show the arithmetic, no black box.
  it("shows the full arithmetic with the source and year", () => {
    const e = estimateExposure(profiles)!;
    expect(e.arithmetic).toContain("4,231 rows");
    expect(e.arithmetic).toContain("$160 per record");
    expect(e.arithmetic).toContain("IBM Cost of a Data Breach, 2026");
  });

  // Guardrail 1 + 3: never a prediction, never legal advice, always cited.
  it("carries the caveat naming it an estimate and not legal advice", () => {
    const { caveat } = estimateExposure(profiles)!;
    expect(caveat).toContain("not a prediction and not legal advice");
    expect(caveat).toContain("published averages");
    expect(caveat).toContain("excludes regulatory action");
  });

  it("never uses the language of litigation", () => {
    const e = estimateExposure(profiles)!;
    const text = `${e.arithmetic} ${e.caveat}`;
    expect(text).not.toMatch(/you will be sued|damages|liability of|penalty of/i);
  });

  // Guardrail 6: no estimated row counts. Ever.
  it("returns NOTHING when the row count was not measured", () => {
    expect(estimateExposure({ ...profiles, rowCount: null })).toBeNull();
    expect(estimateExposure({ ...profiles, rowCount: 0 })).toBeNull();
  });

  it("returns nothing for a table holding no PII", () => {
    expect(estimateExposure({ ...profiles, categories: [] })).toBeNull();
  });
});

describe("summariseExposure", () => {
  const inventories: TableInventory[] = [
    {
      table: "profiles",
      categories: [{ category: "contact", label: "contact details", columns: ["email"] }],
      unclassifiedColumns: 0,
      rowCount: 4231,
    },
    {
      table: "payments",
      categories: [{ category: "financial", label: "financial details", columns: ["card_number"] }],
      unclassifiedColumns: 0,
      rowCount: 120,
    },
    {
      table: "messages",
      categories: [{ category: "content", label: "private content", columns: ["body"] }],
      unclassifiedColumns: 0,
      rowCount: null,
    },
    { table: "feature_flags", categories: [], unclassifiedColumns: 3, rowCount: 9 },
  ];

  it("orders by exposure, largest first", () => {
    expect(summariseExposure(inventories).estimates.map((e) => e.table)).toEqual(["profiles", "payments"]);
  });

  it("totals only what it actually measured", () => {
    const s = summariseExposure(inventories);
    expect(s.totalRecords).toBe(4231 + 120);
    expect(s.totalEstimate).toBe((4231 + 120) * 160);
  });

  // The gap is named rather than hidden, so the total never reads as complete.
  it("names PII tables it could not count", () => {
    expect(summariseExposure(inventories).uncountedTables).toEqual(["messages"]);
  });

  // Guardrail 4: structure only, never a number for this customer.
  it("describes the regulatory structure without applying it", () => {
    const { regulatoryNote } = summariseExposure(inventories);
    expect(regulatoryNote).toContain("2% or 4%");
    expect(regulatoryNote).toContain("deliberately not included");
    expect(regulatoryNote).toContain("your own lawyer");
    expect(regulatoryNote).not.toMatch(/\$[\d,]+/);
  });

  it("handles a project with no PII at all", () => {
    const s = summariseExposure([{ table: "flags", categories: [], unclassifiedColumns: 1, rowCount: 5 }]);
    expect(s.estimates).toEqual([]);
    expect(s.totalEstimate).toBe(0);
    expect(s.uncountedTables).toEqual([]);
  });
});

describe("presentation", () => {
  it("formats money readably", () => {
    expect(formatMoney(676_960)).toBe("$676,960");
  });

  it("keeps every published figure carrying its source", () => {
    for (const entry of Object.values(SOURCES)) {
      expect(entry.source).toContain("2026");
    }
  });
});

// Verified against ShipLock's own schema, where the prefix-only pattern
// classified none of the seven real credential columns.
describe("credential columns carry the keyword as a suffix", () => {
  it("classifies suffixed credential names", () => {
    for (const c of [
      "token_hash",
      "traffic_ingest_token",
      "verified_report_token",
      "supabase_mgmt_token_encrypted",
      "monitored_anon_key_encrypted",
      "stripe_secret",
      "user_password",
    ]) {
      expect(classifyColumn(c)?.category, c).toBe("credential");
    }
  });

  // Overstating exposure is the one direction this model must not fail in.
  it("does NOT treat a token COUNT as a credential", () => {
    expect(classifyColumn("token_count")).toBeNull();
    expect(classifyColumn("input_tokens")).toBeNull();
  });
});

// A bare `_key` branch would wrongly catch ordinary structural columns, so the
// credential key names are enumerated instead.
describe("key columns", () => {
  it("does not treat structural keys as credentials", () => {
    for (const c of ["sort_key", "cache_key", "idempotency_key", "primary_key", "partition_key"]) {
      expect(classifyColumn(c), c).toBeNull();
    }
  });
});
