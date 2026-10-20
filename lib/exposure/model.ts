// A21 — PII inventory and the exposure model (PRODUCT-DESIGN.md §13.5).
//
// The most useful screen in the product at the buying moment, and the most
// dangerous one if done carelessly. A misleading exposure estimate is a
// trust and legal risk, and a number like this is
// exactly where that bites. So the guardrails are code, not guidance:
//
//   1. Never "you will be sued for $X" — it is an exposure estimate from
//      published averages, and every output says so.
//   2. Show the arithmetic. Row count x cited figure. No proprietary score.
//   3. Cite every figure inline, with its year.
//   4. Never estimate fines for a specific customer. Describe the regulatory
//      STRUCTURE and let them do that maths.
//   5. No urgency theatre. The number is frightening enough stated calmly.
//   6. Only computed on data we actually measured. No estimated row counts, no
//      assumed PII. If we don't know, we say we don't know.
//
// AND THE ONE THE PRODUCT PROMISE DEMANDS: this works on SCHEMA ONLY. It reads
// column NAMES and a row COUNT. It never reads a row, a value, or a sample.
// "ShipLock never reads your users' data" is a customer-facing promise, and an
// exposure estimator is precisely the feature that would quietly break it —
// classifying by inspecting values would be more accurate and is therefore the
// tempting thing to do. It is forbidden. The types below cannot even carry a
// value: there is nowhere to put one.

export type PiiCategory =
  | "identity" // name, username, date of birth
  | "contact" // email, phone, address
  | "financial" // card, bank, payment identifiers
  | "credential" // password hashes, tokens, keys
  | "government" // SSN, passport, national id
  | "health" // medical, diagnosis, prescription
  | "location" // coordinates, precise location
  | "content"; // private messages, documents, notes

export interface CategoryRule {
  category: PiiCategory;
  re: RegExp;
  /** What a leak of this class actually does to the customer's users. */
  label: string;
}

/**
 * Column-name classification. Name-based BY DESIGN, not as a shortcut — see the
 * schema-only rule above.
 *
 * Conservative: a column we don't recognise is simply not classified, and the
 * output says how many columns went unclassified so nobody mistakes this for a
 * complete inventory.
 *
 * Each pattern allows a trailing `_suffix`, because column names compose that
 * way — `passport_number`, `ssn_hash`, `email_address`. A plain word boundary
 * cannot match those at all, since `_` is itself a word character.
 */
const RULES: CategoryRule[] = [
  { category: "government", re: /\b(ssn|social_security|national_id|passport|tax_id|nino|sin_number|driver_?licen[sc]e)(?:_\w+)?\b/i, label: "government identifiers" },
  { category: "financial", re: /\b(card_number|cardnumber|pan|iban|account_number|routing|cvv|bank_|payment_method|stripe_customer|billing_address)(?:_\w+)?\b/i, label: "financial details" },
  // Credential columns usually carry the keyword as a SUFFIX
  // (`traffic_ingest_token`, `token_hash`, `supabase_mgmt_token_encrypted`), so
  // a prefix-anchored pattern misses most real ones — verified against our own
  // schema, where it initially classified none of the seven credential columns
  // in api_tokens and user_profiles. Bare `token` is deliberately NOT included:
  // `token_count` in an LLM app would over-report exposure, and overstating is
  // the one direction this model must not fail in.
  {
    category: "credential",
    // Two branches. The second matches any `<something>_token` name, which is
    // how credential columns are actually named, while still excluding
    // `input_tokens` (plural) and `token_count` (token is not the suffix) —
    // both of which are counters, and flagging them would overstate exposure.
    re: /\b(?:\w+_)?(password|passwd|pwd|secret|api_?key|anon_key|service_key|secret_key|signing_key|encryption_key|private_key|token_hash|otp|mfa_secret|totp)(?:_\w+)?\b|\b\w+_token(?:_\w+)?\b/i,
    label: "credentials",
  },
  { category: "health", re: /\b(diagnosis|medical|prescription|health_|patient_|blood_|allergy|treatment|icd_?10)(?:_\w+)?\b/i, label: "health information" },
  { category: "contact", re: /\b(email|e_mail|phone|mobile|telephone|address_line|street|postcode|postal_code|zip_code)(?:_\w+)?\b/i, label: "contact details" },
  { category: "location", re: /\b(latitude|longitude|lat|lng|geo_|coordinates|last_location)(?:_\w+)?\b/i, label: "location history" },
  { category: "identity", re: /\b(first_name|last_name|full_name|given_name|surname|display_name|username|date_of_birth|dob|birth_date|gender)(?:_\w+)?\b/i, label: "names and personal details" },
  { category: "content", re: /\b(message|body|content|note|comment|document|attachment|transcript|chat_)(?:_\w+)?\b/i, label: "private content" },
];

export interface ColumnRef {
  table: string;
  column: string;
}

export interface TableInventory {
  table: string;
  /** Categories found, with the columns that produced them. */
  categories: { category: PiiCategory; label: string; columns: string[] }[];
  /** Columns we could not classify — reported, so this reads as partial. */
  unclassifiedColumns: number;
  /** Measured row count. `null` when we did not measure it — never estimated. */
  rowCount: number | null;
}

export function classifyColumn(column: string): CategoryRule | null {
  for (const rule of RULES) if (rule.re.test(column)) return rule;
  return null;
}

/**
 * Builds the inventory from schema alone.
 *
 * @param columns column references — names only, no values, by construction
 * @param rowCounts measured counts per table; a table absent here reports null
 */
export function buildInventory(
  columns: ColumnRef[],
  rowCounts: Map<string, number> = new Map()
): TableInventory[] {
  const byTable = new Map<string, ColumnRef[]>();
  for (const ref of columns) {
    const list = byTable.get(ref.table) ?? [];
    list.push(ref);
    byTable.set(ref.table, list);
  }

  const out: TableInventory[] = [];
  for (const [table, refs] of byTable) {
    const grouped = new Map<PiiCategory, { label: string; columns: string[] }>();
    let unclassified = 0;

    for (const ref of refs) {
      const rule = classifyColumn(ref.column);
      if (!rule) {
        unclassified++;
        continue;
      }
      const entry = grouped.get(rule.category) ?? { label: rule.label, columns: [] };
      entry.columns.push(ref.column);
      grouped.set(rule.category, entry);
    }

    out.push({
      table,
      categories: [...grouped.entries()]
        .map(([category, v]) => ({ category, label: v.label, columns: v.columns.sort() }))
        .sort((a, b) => a.category.localeCompare(b.category)),
      unclassifiedColumns: unclassified,
      rowCount: rowCounts.get(table) ?? null,
    });
  }

  return out.sort((a, b) => a.table.localeCompare(b.table));
}

// ── The exposure estimate ──────────────────────────────────────────────────

/**
 * Every figure is published, cited, and carries its year. No blended numbers, no
 * adjustments of our own invention — if we cannot cite it, it does not appear.
 */
export const SOURCES = {
  perRecord: {
    value: 160,
    label: "$160 per record for customer PII",
    source: "IBM Cost of a Data Breach, 2026",
  },
  smbAverage: {
    value: 3_310_000,
    label: "$3.31M average breach cost for firms under 500 employees",
    source: "IBM Cost of a Data Breach, 2026",
  },
  dwellTime: {
    label: "median time to identify a breach of this class exceeds 200 days",
    source: "IBM Cost of a Data Breach, 2026",
  },
} as const;

export interface ExposureEstimate {
  table: string;
  rowCount: number;
  categories: string[];
  /** rowCount x perRecord. The whole calculation, nothing hidden. */
  estimate: number;
  /** The arithmetic, in words, for display. */
  arithmetic: string;
  /** Mandatory framing. Rendered with the number, never separately. */
  caveat: string;
}

export function formatMoney(n: number): string {
  return `$${Math.round(n).toLocaleString("en-US")}`;
}

/**
 * Estimates notification-and-response exposure for ONE table.
 *
 * Returns null when the row count was not measured. Guardrail 6: we do not
 * estimate row counts, and a table we could not count simply has no number —
 * which is far better than a plausible-looking figure built on a guess.
 */
export function estimateExposure(inventory: TableInventory): ExposureEstimate | null {
  if (inventory.rowCount === null || inventory.rowCount <= 0) return null;
  if (inventory.categories.length === 0) return null;

  const estimate = inventory.rowCount * SOURCES.perRecord.value;

  return {
    table: inventory.table,
    rowCount: inventory.rowCount,
    categories: inventory.categories.map((c) => c.label),
    estimate,
    arithmetic:
      `${inventory.rowCount.toLocaleString("en-US")} rows x ${SOURCES.perRecord.label} ` +
      `(${SOURCES.perRecord.source}) = ${formatMoney(estimate)}`,
    caveat:
      `This is an exposure estimate built from published averages, not a prediction and not legal advice. ` +
      `It covers notification and response (the costs you would incur regardless of whether anyone sued you) and excludes regulatory action entirely, because that depends on your jurisdiction and conduct rather than on row counts. ` +
      `${SOURCES.dwellTime.label.charAt(0).toUpperCase()}${SOURCES.dwellTime.label.slice(1)} (${SOURCES.dwellTime.source}), and breaches found late cost roughly double.`,
  };
}

export interface ExposureSummary {
  estimates: ExposureEstimate[];
  totalRecords: number;
  totalEstimate: number;
  /** Tables holding PII we could not count, named so the gap is visible. */
  uncountedTables: string[];
  /** The regulatory STRUCTURE, never a number for this customer. */
  regulatoryNote: string;
}

export function summariseExposure(inventories: TableInventory[]): ExposureSummary {
  const estimates = inventories
    .map(estimateExposure)
    .filter((e): e is ExposureEstimate => e !== null)
    .sort((a, b) => b.estimate - a.estimate);

  const uncountedTables = inventories
    .filter((i) => i.categories.length > 0 && (i.rowCount === null || i.rowCount <= 0))
    .map((i) => i.table);

  return {
    estimates,
    totalRecords: estimates.reduce((sum, e) => sum + e.rowCount, 0),
    totalEstimate: estimates.reduce((sum, e) => sum + e.estimate, 0),
    uncountedTables,
    // Guardrail 4: structure only. We describe how the ceilings work; we do not
    // apply them to this customer, because doing so would be a legal opinion we
    // are not qualified to give and would be wrong more often than right.
    regulatoryNote:
      `Fines are deliberately not included above. GDPR sets ceilings of 2% or 4% of global annual turnover depending on which obligation was breached, and US state laws vary by state and by the kind of data involved. ` +
      `Which ceiling applies, and where in the range a regulator lands, depends on your jurisdiction, your users' locations, and how you respond, none of which is something a row count can tell you. ` +
      `We describe the structure so you can do that arithmetic with your own lawyer rather than take a number from us.`,
  };
}
