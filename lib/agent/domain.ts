import type { RouteFact } from "@/lib/graph/routeInventory";

/**
 * What this business actually is, read out of its own schema and routes.
 *
 * A security tool that does not know what the application DOES can only find
 * bugs that are wrong in every application -- a missing signature check, a
 * logged secret. The expensive bugs are the ones that are wrong only in this
 * one: a row that must never cross between tenants, an amount a customer must
 * not be able to set, a role that must not be self-assigned. None of those are
 * visible in a single file. They are visible in the SHAPE of the schema.
 *
 * So this is deliberately not a summary for the customer to read. It is the
 * missing half of the attack prompt: the difference between asking a model
 * "find bugs in these routes" and asking it "this is a multi-tenant billing
 * product where invoices belong to a workspace -- find the routes that forget
 * that". The second question produces hypotheses about the customer's actual
 * risk; the first produces a linter.
 *
 * Everything here is derived from names, and names can lie. That is why the
 * output is EVIDENCE for the model to reason with and never a finding on its
 * own -- nothing in this file may produce something a customer sees as a
 * conclusion. The guard still requires every hypothesis to cite an observed
 * route, file or table.
 */

type Tenancy = "multi_tenant" | "per_user" | "unknown";

export interface DomainModel {
  /** One line, in the product's own vocabulary. Used in the prompt. */
  summary: string;
  tenancy: Tenancy;
  /** The column name that appears to separate customers from each other. */
  tenantKey: string | null;
  /** Tables whose names say they hold something worth stealing. */
  sensitive: string[];
  /** Domain nouns, most connected first — what this product is made of. */
  entities: string[];
  /** True when the schema models roles or permissions of its own. */
  hasRoles: boolean;
  /** True when money moves through this application. */
  handlesMoney: boolean;
}

// A tenant key is the column that answers "whose row is this". Ordered: the
// first match wins, because an app with both workspace_id and user_id is
// separated by workspace, and treating user_id as the boundary there would
// under-report exactly the cross-tenant read we care most about.
const TENANT_KEYS = [
  "organization_id", "organisation_id", "org_id", "workspace_id", "tenant_id",
  "account_id", "team_id", "company_id", "project_id", "site_id", "store_id",
];

const USER_KEYS = ["user_id", "owner_id", "author_id", "customer_id", "created_by", "profile_id"];

const SENSITIVE = [
  "user", "profile", "account", "customer", "member", "employee",
  "invoice", "payment", "charge", "subscription", "transaction", "order", "billing",
  "message", "conversation", "thread", "chat", "email", "notification",
  "document", "file", "upload", "attachment", "asset",
  "patient", "record", "health", "claim", "application", "submission",
  "credential", "token", "session", "key", "secret", "api_key",
  "lead", "contact", "deal", "opportunity", "candidate",
];

const MONEY = ["invoice", "payment", "charge", "subscription", "transaction", "order", "price", "billing", "refund", "payout"];
const ROLE = ["role", "permission", "membership", "member", "grant", "policy", "access"];

const STOPWORDS = new Set([
  "id", "ids", "table", "tables", "public", "data", "temp", "tmp", "test", "log", "logs",
  "migration", "migrations", "schema", "index", "audit",
]);

function singular(word: string): string {
  if (word.endsWith("ies")) return `${word.slice(0, -3)}y`;
  if (word.endsWith("sses") || word.endsWith("ches") || word.endsWith("shes")) return word.slice(0, -2);
  if (word.endsWith("s") && !word.endsWith("ss")) return word.slice(0, -1);
  return word;
}

function matches(name: string, list: string[]): boolean {
  const parts = name.toLowerCase().split(/[_\-\s]+/).map(singular);
  return list.some((needle) => parts.includes(needle) || name.toLowerCase().includes(needle));
}

/**
 * Reads the business out of the schema and the routes.
 *
 * `columns` is optional because the GitHub-only path may not have parsed a
 * schema file it could read. Absent columns means the tenancy answer is
 * `unknown` -- never `per_user` by default, because guessing "each row belongs
 * to one user" in a workspace product is exactly the assumption that makes a
 * cross-tenant leak invisible.
 */
export function inferDomain(
  tables: string[],
  routes: RouteFact[],
  columns: string[] = [],
): DomainModel {
  const lowerColumns = columns.map((c) => c.toLowerCase());
  const tenantKey = TENANT_KEYS.find((k) => lowerColumns.includes(k)) ?? null;
  const userKey = USER_KEYS.find((k) => lowerColumns.includes(k)) ?? null;

  const tenancy: Tenancy = tenantKey ? "multi_tenant" : userKey ? "per_user" : "unknown";

  const sensitive = tables.filter((t) => matches(t, SENSITIVE));
  const handlesMoney = tables.some((t) => matches(t, MONEY));
  const hasRoles = tables.some((t) => matches(t, ROLE));

  // How many routes touch each table: the most-reached tables are what this
  // product is about, which is a better signal than alphabetical order.
  const reach = new Map<string, number>();
  for (const route of routes) {
    for (const table of route.tables) reach.set(table, (reach.get(table) ?? 0) + 1);
  }

  const entities = [...tables]
    .filter((t) => !STOPWORDS.has(t.toLowerCase()))
    .sort((a, b) => (reach.get(b) ?? 0) - (reach.get(a) ?? 0))
    .slice(0, 8);

  const shape =
    tenancy === "multi_tenant"
      ? `multi-tenant (rows separated by ${tenantKey})`
      : tenancy === "per_user"
        ? `single-user ownership (rows belong to ${userKey})`
        : "ownership boundary not identified in the schema";

  const traits = [
    handlesMoney ? "handles money" : null,
    hasRoles ? "models roles" : null,
    sensitive.length
      ? `${sensitive.length} ${sensitive.length === 1 ? "table holds" : "tables hold"} personal or financial records`
      : null,
  ].filter(Boolean);

  const summary = [
    `A ${shape} application built around ${entities.slice(0, 4).join(", ") || "no identified entities"}.`,
    traits.length ? `It ${traits.join(", ")}.` : "",
  ]
    .filter(Boolean)
    .join(" ");

  return { summary, tenancy, tenantKey, sensitive, entities, hasRoles, handlesMoney };
}

/**
 * The domain as prompt lines.
 *
 * Kept to a handful of tokens on purpose: the token-efficiency doctrine caps
 * the user prompt, and every line spent describing the business is a line not
 * spent describing a route. These earn their place because they change what the
 * model looks FOR, not merely what it knows.
 */
export function domainPromptLines(domain: DomainModel): string[] {
  const lines = [`business ${domain.summary}`];
  if (domain.tenantKey) {
    lines.push(
      `boundary rows are separated by ${domain.tenantKey}; a route that reads a table without it crosses customers`,
    );
  }
  if (domain.sensitive.length) {
    lines.push(`sensitive ${domain.sensitive.slice(0, 12).join(",")}`);
  }
  if (domain.handlesMoney) {
    lines.push("money amounts and prices are set here; a client-settable amount is a real finding");
  }
  if (domain.hasRoles) {
    lines.push("roles exist in the schema; self-assignment of a role is a real finding");
  }
  return lines;
}
