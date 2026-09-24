import { describe, expect, it } from "vitest";
import { findUserControlledDeletes } from "./userControlledKeys";

// Step 7F: a destructive storage call whose key the caller controls, with no
// check that the key is theirs. Synthetic fixtures only.
const one = (body: string, entry = "remove") => findUserControlledDeletes(body, entry);

describe("findUserControlledDeletes", () => {
  it("flags a key taken from the caller's own record field", () => {
    expect(one(`const key = ctx.user.image;\nawait s3.send(new DeleteObjectCommand({ Bucket: b, Key: key }));`))
      .toEqual([{ entry: "remove", sink: "DeleteObjectCommand", source: "ctx.user.image" }]);
  });
  it("flags request input used directly as the key", () => {
    expect(one(`await storage.delete(parsedInput.path);`)).toEqual([{ entry: "remove", sink: "storage.delete", source: "parsedInput.path" }]);
    expect(one(`const { url } = await req.json();\nawait del(url);`)).toEqual([{ entry: "remove", sink: "del", source: "req.json()" }]);
    expect(one(`const f = formData.get("file") as string;\nawait deleteFile(f);`)).toEqual([{ entry: "remove", sink: "deleteFile", source: "formData.get" }]);
  });
  it("follows one level of assignment and template building", () => {
    expect(one(`const name = parsedInput.name;\nconst key = \`uploads/\${name}\`;\nawait deleteObject(key);`))
      .toEqual([{ entry: "remove", sink: "deleteObject", source: "parsedInput.name" }]);
  });
  it("does not flag a key checked against the caller", () => {
    expect(one(`const key = parsedInput.key;\nif (!key.startsWith(\`avatars/\${ctx.user.id}\`)) throw new Error("no");\nawait deleteObject(key);`)).toEqual([]);
    expect(one(`const key = ctx.user.image;\nassertAssetKey(key, ctx.user.id);\nawait deleteObject(key);`)).toEqual([]);
    expect(one(`const key = parsedInput.key;\nif (!isOwnedBy(key, session.user.id)) return;\nawait deleteFile(key);`)).toEqual([]);
  });
  it("does not flag a key built only from server values or read from an owner-filtered query", () => {
    expect(one(`await deleteObject(\`avatars/\${ctx.user.id}.png\`);`)).toEqual([]);
    expect(one(`const doc = await prisma.document.findFirst({ where: { id: parsedInput.id, userId: ctx.user.id } });\nawait deleteFile(doc.fileKey);`)).toEqual([]);
  });
  it("ignores non-deletion calls and unrelated del/rm helpers", () => {
    expect(one(`await s3.send(new PutObjectCommand({ Key: parsedInput.key }));`)).toEqual([]);
    expect(one(`const r = rm(parsedInput.x);`)).toEqual([]);
  });

  it("a caller's own directory does not contain a raw name that can climb out with ../", () => {
    expect(one(`await fs.promises.unlink(path.join(UPLOAD_DIR, session.user.id, parsedInput.name));`)).toHaveLength(1);
    expect(one(`await fs.promises.unlink(path.join(UPLOAD_DIR, session.user.id, path.basename(parsedInput.name)));`)).toEqual([]);
  });
});
