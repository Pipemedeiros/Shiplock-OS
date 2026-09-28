import { describe, expect, it } from "vitest";
import { findUserControlledDeletes } from "./userControlledKeys";

// Step 7F tRPC gaps found by the round 4 held-out adversary (2026-09-28).
// The first three cases are round 4's own; the rest guard the fix. Synthetic.
const one = (body: string, entry = "remove") => findUserControlledDeletes(body, entry);
const procedure = (body: string) =>
  `export const remove = protectedProcedure.input(schema).mutation(async ({ input, ctx }) => {\n${body}\n});`;

describe("findUserControlledDeletes: tRPC procedures", () => {
  it("treats the procedure's destructured input as caller input", () => {
    expect(one(procedure(`await deleteObject(input.key);`)))
      .toEqual([{ entry: "remove", sink: "deleteObject", source: "input.key" }]);
  });

  it("follows input through an unfiltered lookup to the row's key", () => {
    expect(one(procedure(`const file = await prisma.file.findUnique({ where: { id: input.fileId } });\nawait deleteObject(file.key);`)))
      .toHaveLength(1);
  });

  it("reads ctx.session.user.id as the caller's identity in an ownership check", () => {
    expect(one(procedure(`const file = await prisma.file.findUnique({ where: { id: input.fileId } });\nif (!file || file.userId !== ctx.session.user.id) throw new TRPCError({ code: "FORBIDDEN" });\nawait deleteObject(file.key);`)))
      .toEqual([]);
  });

  it("reads ctx.session.user.id as identity in an owner-filtered query", () => {
    expect(one(procedure(`const file = await prisma.file.findFirst({ where: { id: input.fileId, userId: ctx.session.user.id } });\nawait deleteObject(file.key);`)))
      .toEqual([]);
  });

  it("treats an editable field of ctx.session.user as caller-controlled", () => {
    expect(one(procedure(`await del(ctx.session.user.image);`)))
      .toEqual([{ entry: "remove", sink: "del", source: "ctx.session.user.image" }]);
  });

  it("does not taint an input parameter renamed from something else, or a local named input", () => {
    expect(one(`const input = CONFIG.exportPath;\nawait deleteObject(input);`, "GET")).toEqual([]);
    expect(one(`export const remove = handler(async ({ data: input }) => {\n  await deleteObject(input.key);\n});`)).toEqual([]);
  });
});
