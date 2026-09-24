import { expect, it } from "vitest";
import { parseSchemaColumns } from "./schemaColumns";

it("keeps only bounded column metadata, never values", () => {
  expect(parseSchemaColumns([{ table: "orders", column: "owner_id", type: "uuid", value: "secret" }]))
    .toEqual([{ table: "orders", column: "owner_id", type: "uuid" }]);
  expect(parseSchemaColumns([])).toEqual([]);
});
it("refuses malformed, duplicate or capped schemas rather than returning a partial inventory", () => {
  for (const rows of [null, [{ table: "orders", column: "owner_id" }],
    [{ table: "private.orders", column: "id", type: "uuid" }],
    Array.from({ length: 201 }, (_, i) => ({ table: `t${i}`, column: "id", type: "uuid" })),
    Array.from({ length: 3001 }, (_, i) => ({ table: "t", column: `c${i}`, type: "text" })),
    Array(2).fill({ table: "t", column: "id", type: "uuid" })]) {
    expect(() => parseSchemaColumns(rows)).toThrow();
  }
});

it("accepts the column names real apps use, such as Prisma's camelCase (review of Q6a)", () => {
  expect(parseSchemaColumns([{ table: "Order", column: "userId", type: "uuid" }, { table: "orders", column: "createdAt", type: "timestamp" }]))
    .toHaveLength(2);
});
