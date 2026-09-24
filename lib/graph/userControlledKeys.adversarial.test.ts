import { describe, expect, it } from "vitest";
import { findUserControlledDeletes } from "./userControlledKeys";

// Adversarial cases for Step 7F. Each asserts the correct security answer,
// not the rule's current behaviour. Synthetic fixtures only.
const one = (body: string, entry = "remove") => findUserControlledDeletes(body, entry);

describe("findUserControlledDeletes: false negatives (real caller-controlled deletions)", () => {
  // FN: node's fs.unlink is the most common file deletion; the caller picks the filename.
  it("fs.promises.unlink with a request filename", () => {
    expect(one(`const { name } = await req.json();\nawait fs.promises.unlink(path.join(UPLOAD_DIR, name));`).length).toBeGreaterThan(0);
  });

  // FN: Supabase Storage deletion is .remove([paths]); the path comes from the body.
  it("supabase storage remove with a body path", () => {
    expect(one(`const body = await request.json();\nawait supabase.storage.from("avatars").remove([body.path]);`).length).toBeGreaterThan(0);
  });

  // FN: UploadThing's server deletion API; the key is the server action's input.
  it("utapi.deleteFiles with parsedInput key", () => {
    expect(one(`await utapi.deleteFiles(parsedInput.fileKey);`).length).toBeGreaterThan(0);
  });

  // FN: a server action's plain parameter is caller-controlled, same as parsedInput.
  it("server action parameter used as the key", () => {
    expect(one(`"use server";\nexport async function removeAttachment(fileKey: string) {\n  await deleteObject(fileKey);\n}`, "removeAttachment").length).toBeGreaterThan(0);
  });

  // FN: bulk delete iterates caller-supplied keys; for-of binding carries the taint.
  it("for-of over caller-supplied keys", () => {
    expect(one(`for (const key of parsedInput.keys) {\n  await deleteObject(key);\n}`).length).toBeGreaterThan(0);
  });

  // FN: the same bulk delete written with Promise.all and an arrow parameter.
  it("Promise.all map over caller-supplied keys", () => {
    expect(one(`await Promise.all(parsedInput.keys.map((k: string) => deleteObject(k)));`).length).toBeGreaterThan(0);
  });

  // FN: declared first, assigned later; the taint is identical to a const initializer.
  it("let declared then assigned from input", () => {
    expect(one(`let key: string;\nkey = parsedInput.key;\nawait deleteObject(key);`).length).toBeGreaterThan(0);
  });

  // FN: rest-spread destructuring still carries the caller's fields.
  it("rest spread of the input", () => {
    expect(one(`const { id, ...rest } = parsedInput;\nawait deleteObject(rest.key);`).length).toBeGreaterThan(0);
  });

  // FN: an awaited body-reading helper returns request input.
  it("awaited helper that parses the request body", () => {
    expect(one(`const { fileKey } = await readJsonBody(req);\nawait deleteObject(fileKey);`).length).toBeGreaterThan(0);
  });

  // FN: the prefix check compares against an org id the caller also supplied, so it proves nothing.
  it("startsWith against a caller-supplied orgId", () => {
    expect(one(`const { key, orgId } = parsedInput;\nif (!key.startsWith(\`orgs/\${orgId}/\`)) throw new Error("bad key");\nawait deleteObject(key);`).length).toBeGreaterThan(0);
  });

  // FN: a format validator is not an ownership check; any well-formed foreign key passes.
  it("format validation mistaken for ownership", () => {
    expect(one(`const key = parsedInput.key;\nvalidateKeyFormat(key);\nawait deleteObject(key);`).length).toBeGreaterThan(0);
  });

  // FN: an unfiltered lookup by caller-supplied id is an IDOR; the caller still chooses the object.
  it("db read by caller id with no owner filter", () => {
    expect(one(`const file = await prisma.file.findUnique({ where: { id: parsedInput.id } });\nawait deleteObject(file.key);`).length).toBeGreaterThan(0);
  });
});

describe("findUserControlledDeletes: false positives (safe code)", () => {
  // FP: a cron cleanup deletes a path read from the service's own table; no caller input exists.
  it("cron cleanup of a path from a server query result named data", () => {
    expect(one(`const { data } = await supabaseAdmin.from("exports").select("path").lt("expires_at", now).limit(1).single();\nawait del(data.path);`, "GET")).toEqual([]);
  });

  // FP: ownership is proven by an owner-filtered count before deleting.
  it("ownership verified by an owner-filtered count", () => {
    expect(one(`const key = parsedInput.key;\nconst owned = await prisma.file.count({ where: { key, userId: ctx.user.id } });\nif (!owned) throw new Error("not found");\nawait deleteObject(key);`)).toEqual([]);
  });

  // FP: the key's owner segment is split out and compared with the session user.
  it("owner segment split and compared", () => {
    expect(one(`const key = parsedInput.key;\nconst [ownerId] = key.split("/");\nif (ownerId !== session.user.id) throw new Error("forbidden");\nawait deleteObject(key);`)).toEqual([]);
  });

  // FP: the caller's id is only used to look up their own file server-side; the key is from that row.
  it("key from a scoped server lookup helper", () => {
    expect(one(`const { id } = await req.json();\nconst file = await getFileForUser(id, session.user.id);\nif (!file) return new Response(null, { status: 404 });\nawait deleteObject(file.key);`)).toEqual([]);
  });

  // FP: rollback deletes the blob the server just created; its url is server-issued.
  it("rollback of a blob the handler just uploaded", () => {
    expect(one(`const file = formData.get("file") as File;\nconst blob = await put(\`uploads/\${session.user.id}/\${crypto.randomUUID()}\`, file, { access: "public" });\nif (!(await saveRecord(blob.url))) await del(blob.url);`)).toEqual([]);
  });

  // FP: input is an allowlisted enum and the key is scoped to the caller's id.
  it("allowlisted kind with the caller's id in the key", () => {
    expect(one(`const kind = parsedInput.kind;\nif (!["avatar", "banner"].includes(kind)) throw new Error("bad kind");\nawait deleteObject(\`\${kind}s/\${ctx.user.id}.png\`);`)).toEqual([]);
  });

  // FP: basename strips traversal and the directory is the caller's own folder.
  it("basename inside the caller's own directory", () => {
    expect(one(`const name = path.basename(parsedInput.name);\nawait unlink(path.join(UPLOAD_DIR, session.user.id, name));`)).toEqual([]);
  });

  // FP: a local seed script deletes a path from its own checked-in config; there is no caller.
  it("seed script reading its own config file", () => {
    expect(one(`const data = JSON.parse(await readFile("scripts/seed.json", "utf8"));\nawait unlink(data.outputPath);`, "seed")).toEqual([]);
  });
});
