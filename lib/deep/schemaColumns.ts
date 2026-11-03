import { z } from "zod";

// One public-schema observation, bounded before persistence. A capped result
// is unread, not a complete-looking prefix. No defaults or row values.
// Postgres identifiers as apps name them, including Prisma camelCase.
const name = z.string().regex(/^[A-Za-z_][A-Za-z0-9_$]{0,62}$/);
export const SchemaColumns = z.array(z.object({
  table: name, column: name, type: z.string().min(1).max(128),
})).max(3000).refine(rows => new Set(rows.map(r => r.table)).size <= 200)
  .refine(rows => new Set(rows.map(r => `${r.table}.${r.column}`)).size === rows.length);
export type SchemaColumn = z.infer<typeof SchemaColumns>[number];
/** Validates schema column rows read from the database. */
export const parseSchemaColumns = (rows: unknown): SchemaColumn[] => SchemaColumns.parse(rows);
const SCHEMA_COLUMNS_SELECT = `select table_name, column_name, data_type
  from information_schema.columns where table_schema = 'public'
  order by table_name, ordinal_position`;
/** For the bounded snapshot only: one past the cap, so a capped read is unread. */
export const SCHEMA_COLUMNS_SQL = `${SCHEMA_COLUMNS_SELECT} limit 3001`;
/** The full list, for the exposure inventory, which predates the snapshot cap. */
export const ALL_SCHEMA_COLUMNS_SQL = SCHEMA_COLUMNS_SELECT;
/** The bounded snapshot copy, or undefined (unread) when over the cap or odd. */
export const boundedSchemaColumns = (rows: unknown): SchemaColumn[] | undefined => {
  const parsed = SchemaColumns.safeParse(rows);
  return parsed.success ? parsed.data : undefined;
};
