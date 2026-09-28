import { describe, expect, it } from "vitest";
import { findUserControlledDeletes } from "./userControlledKeys";

// Step 7F: the non-tRPC gaps from the round 4 held-out adversary (2026-09-28).
// The first case in each group is round 4's own; the rest guard the fix.
// Synthetic fixtures only.
const one = (body: string, entry = "remove") => findUserControlledDeletes(body, entry);

describe("round 4: caller input carried through array helpers and spreads", () => {
  it("keeps taint through split().pop()", () => {
    expect(one(`export async function DELETE(req: NextRequest) {\n  const name = req.nextUrl.pathname.split("/").pop()!;\n  await fs.promises.unlink(path.join(UPLOAD_DIR, name));\n}`, "DELETE")).toHaveLength(1);
    expect(one(`const first = parsedInput.keys.shift();\nawait deleteObject(first);`)).toHaveLength(1);
  });

  it("keeps taint through reduce over caller input", () => {
    expect(one(`const keys = parsedInput.items.reduce((acc: string[], i: { key: string }) => [...acc, i.key], []);\nawait utapi.deleteFiles(keys);`)).toHaveLength(1);
  });

  it("reads spread elements in array and object literals", () => {
    expect(one(`await utapi.deleteFiles([...parsedInput.keys, "system-default.png"]);`)).toHaveLength(1);
    expect(one(`const params = { Bucket: BUCKET, ...parsedInput };\nawait s3.send(new DeleteObjectCommand(params));`)).toHaveLength(1);
  });

  it("does not taint reduce or spreads over server values", () => {
    expect(one(`const owned = await prisma.file.findMany({ where: { userId: ctx.user.id } });\nconst keys = owned.reduce((acc: string[], f) => [...acc, f.key], []);\nawait utapi.deleteFiles([...keys]);`)).toEqual([]);
  });
});

describe("round 4: Azure Blob and Cloudflare bindings as deletion sinks", () => {
  it("Azure blob client delete with a body name", () => {
    expect(one(`const { name } = await req.json();\nawait containerClient.getBlockBlobClient(name).delete();`, "POST")).toHaveLength(1);
    expect(one(`const { name } = await req.json();\nawait containerClient.getBlobClient(name).deleteIfExists();`, "POST")).toHaveLength(1);
    expect(one(`await containerClient.deleteBlob(parsedInput.name);`)).toHaveLength(1);
  });

  it("Cloudflare binding delete with parsedInput", () => {
    expect(one(`await env.UPLOADS.delete(parsedInput.key);`)).toEqual([{ entry: "remove", sink: "env.UPLOADS.delete", source: "parsedInput.key" }]);
    expect(one(`await c.env.ASSETS.delete(parsedInput.key);`)).toHaveLength(1);
  });

  it("does not treat other .delete() calls as storage deletion", () => {
    expect(one(`const url = new URL(req.url);\nurl.searchParams.delete(parsedInput.key);\nreturn url;`)).toEqual([]);
    expect(one(`headers.delete(parsedInput.name);`)).toEqual([]);
    expect(one(`await prisma.file.delete({ where: { id: parsedInput.id } });`)).toEqual([]);
    expect(one(`env.cache.delete(parsedInput.key);`)).toEqual([]);
  });

  it("does not flag an Azure blob named only from the caller's identity", () => {
    expect(one(`await containerClient.getBlockBlobClient(\`avatars/\${ctx.user.id}.png\`).delete();`)).toEqual([]);
  });
});

describe("round 4: ownership held in a boolean before the guard", () => {
  const lookup = `const file = await prisma.file.findUnique({ where: { id: parsedInput.id } });\n`;

  it("a const boolean ownership check guards the deletion", () => {
    expect(one(`${lookup}const isOwner = file?.userId === ctx.user.id;\nif (!isOwner) throw new Error("forbidden");\nawait deleteObject(file.key);`)).toEqual([]);
    expect(one(`${lookup}const notOwner = file.userId !== ctx.user.id;\nif (notOwner) throw new Error("forbidden");\nawait deleteObject(file.key);`)).toEqual([]);
  });

  it("a let boolean can be reassigned, so it proves nothing", () => {
    expect(one(`${lookup}let isOwner = file.userId === ctx.user.id;\nisOwner = true;\nif (!isOwner) throw new Error("forbidden");\nawait deleteObject(file.key);`)).toHaveLength(1);
  });

  it("an ownership boolean that is never checked proves nothing", () => {
    expect(one(`${lookup}const isOwner = file.userId === ctx.user.id;\nawait deleteObject(file.key);`)).toHaveLength(1);
  });
});

describe("round 4: ownership helpers beyond the assert/owns prefixes", () => {
  it("requireOwnership given the looked-up value and the caller clears it", () => {
    expect(one(`const key = parsedInput.key;\nrequireOwnership(await getFile(key), ctx.user.id);\nawait deleteObject(key);`)).toEqual([]);
    expect(one(`const key = parsedInput.key;\nawait ensureOwner(key, session.user.id);\nawait deleteObject(key);`)).toEqual([]);
  });

  it("an authentication helper is not an ownership check", () => {
    expect(one(`const key = parsedInput.key;\nrequireAuth(ctx.user.id);\nawait deleteObject(key);`)).toHaveLength(1);
    expect(one(`const key = parsedInput.key;\nrequireOwnership(await getFile(key), parsedInput.userId);\nawait deleteObject(key);`)).toHaveLength(1);
  });
});
