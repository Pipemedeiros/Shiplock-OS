import { z } from "zod";

// One public-schema observation, bounded before persistence. A capped result
// is unread, not a complete-looking prefix. No defaults or row values.
const name = z.string().regex(/^[a-z_][a-z0-9_]{0,62}$/);
export const SchemaColumns = z.array(z.object({
  table: name, column: name, type: z.string().min(1).max(128),
})).max(3000).refine(rows => new Set(rows.map(r => r.table)).size <= 200)
  .refine(rows => new Set(rows.map(r => `${r.table}.${r.column}`)).size === rows.length);
export type SchemaColumn = z.infer<typeof SchemaColumns>[number];
export const parseSchemaColumns = (rows: unknown): SchemaColumn[] => SchemaColumns.parse(rows);
export const SCHEMA_COLUMNS_SQL = `select table_name, column_name, data_type
  from information_schema.columns where table_schema = 'public'
  order by table_name, ordinal_position limit 3001`;
